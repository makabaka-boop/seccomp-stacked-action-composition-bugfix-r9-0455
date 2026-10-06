"""Compose two same-arch policies into one filter equivalent to loading the
left policy first and the right policy second (kernel filter stacking).

Kernel precedence (https://docs.kernel.org/userspace-api/seccomp_filter.html):
both filters must allow for the call to run; KILL_PROCESS beats ERRNO; ERRNO
beats ALLOW; when both sides return ERRNO the later (right) filter's data
wins.  The merged program keeps each side's first-match rule order and
default action, shares the identical architecture/x32 gates (emitted once),
and routes every left verdict into a right-hand copy specialized for it:

    left KILL        -> RET KILL_PROCESS            (right never consulted)
    left ALLOW       -> right vanilla copy          (right verdict is final)
    left ERRNO(e)    -> right copy whose ALLOW RETs become ERRNO(e)

Every terminal RET records which side's verdict decided the return, and the
bundle maps each instruction back to the originating rule, default, or gate
of the policy it came from.
"""

import base64

from bpf import Insn, RET_K, SECCOMP_RET_KILL_PROCESS
from compiler import (
    Builder,
    PolicyError,
    action_name,
    action_ret,
    emit_dispatch,
    emit_gates,
    finalize_offsets,
    pack_filter,
    parse_policy,
    relax,
    verify,
)


def _combined_terminal(copy_key, right_action):
    """(combined action, decider) for a right-side terminal RET.

    copy_key is None for the vanilla copy (entered when the left verdict is
    ALLOW) or the left errno value that routed into this specialized copy.
    This is the compiler-side half of the kernel's stacking precedence; the
    independent oracle for it is evaluator.combine_verdicts.
    """
    if right_action[0] == "K":
        return ("K",), "right"
    if right_action[0] == "E":
        # right ERRNO wins over left ALLOW and carries the right's data
        # even when the left side returned ERRNO too
        return right_action, "right"
    if copy_key is None:
        return ("A",), "both"
    return ("E", copy_key), "left"


def build_pair_ir(left, right):
    """Labeled IR equivalent to loading `left` then `right` (same arch).

    Returns (builder, number_of_right_copies).  All control flow is forward;
    relaxation and verification are the shared compiler pipeline.
    """
    if left["arch_name"] != right["arch_name"]:
        raise PolicyError(
            "cannot merge %s with %s: policies must target the same "
            "architecture" % (left["arch_name"], right["arch_name"])
        )

    b = Builder()
    regions = []  # (start elem index, note prefix) for provenance tagging

    kill_lbl = b.fresh("kill")
    emit_gates(b, left, kill_lbl)  # identical for both sides: emitted once

    # ---- left half: full dispatch; terminals route by verdict class ----
    regions.append((len(b.elems), ("L",)))
    right_entries = {}

    def right_copy(key):
        # key: None -> vanilla copy (left ALLOW); errno value -> copy whose
        # ALLOW terminals become that errno
        if key not in right_entries:
            right_entries[key] = b.fresh("right")
        return right_entries[key]

    left_terms = {}

    def left_route(action):
        if action not in left_terms:
            left_terms[action] = b.fresh("lterm")
        return left_terms[action]

    left_default = b.fresh("ldefault")
    emit_dispatch(
        b, left, left_route, left_default, nr_loaded=bool(left["arch"]["x32_bit"])
    )

    def emit_left_terminal(action, lbl, kind):
        b.mark(lbl)
        if action[0] == "K":
            # left KILL decides alone: the right half is never consulted
            b.plain(Insn(RET_K, k=SECCOMP_RET_KILL_PROCESS, note=(kind, action)))
        elif action[0] == "A":
            b.ja(right_copy(None), note=(kind, action))
        else:
            b.ja(right_copy(action[1]), note=(kind, action))

    emit_left_terminal(left["default"], left_default, "default")
    for action, lbl in left_terms.items():
        emit_left_terminal(action, lbl, "term")

    # ---- right half: one copy per left verdict class that can reach it ----
    for key, entry in right_entries.items():
        regions.append((len(b.elems), ("R", key)))
        b.mark(entry)
        right_terms = {}

        def right_route(action, _terms=right_terms):
            if action not in _terms:
                _terms[action] = b.fresh("rterm")
            return _terms[action]

        right_default = b.fresh("rdefault")
        emit_dispatch(b, right, right_route, right_default, nr_loaded=False)
        b.mark(right_default)
        combined, _ = _combined_terminal(key, right["default"])
        b.plain(
            Insn(RET_K, k=action_ret(combined), note=("default", right["default"]))
        )
        for action, lbl in right_terms.items():
            b.mark(lbl)
            combined, _ = _combined_terminal(key, action)
            b.plain(Insn(RET_K, k=action_ret(combined), note=("term", action)))

    # ---- shared gate kill (architecture / x32 gate target) ----
    regions.append((len(b.elems), None))
    b.mark(kill_lbl)
    b.plain(Insn(RET_K, k=SECCOMP_RET_KILL_PROCESS, note=("gate",)))

    # provenance tagging: prepend each region's side marker to its notes
    bounds = [start for start, _ in regions[1:]] + [len(b.elems)]
    for (start, prefix), end in zip(regions, bounds):
        if prefix is None:
            continue
        for el in b.elems[start:end]:
            if isinstance(el, Insn) and el.note:
                el.note = prefix + el.note
    return b, len(right_entries)


def compile_pair_ir(first, second):
    """Parse both policies and build the merged program.

    Returns (left, right, insns, n_trampolines, n_right_copies).
    Raises PolicyError for corrupt policies, architecture mismatch, or a
    merged program over the kernel instruction limit.
    """
    left = parse_policy(first)
    right = parse_policy(second)
    b, n_copies = build_pair_ir(left, right)
    insns, pos, n_tramp = relax(b)
    finalize_offsets(insns, pos)
    verify(insns)
    return left, right, insns, n_tramp, n_copies


# ---------------------------------------------------------------------------
# Provenance: instruction note -> source record
# ---------------------------------------------------------------------------
def _source_for(note):
    if not note:
        return {"side": "both", "role": "internal"}
    tag = note[0]
    if tag == "arch":
        return {"side": "both", "role": "arch-gate"}
    if tag == "x32":
        return {"side": "both", "role": "x32-gate"}
    if tag == "gate":
        return {
            "side": "both",
            "role": "terminal",
            "action": "KILL_PROCESS",
            "decides": "both",
            "via": "arch/x32 gate",
        }
    if tag == "tramp":
        side = "both"
        if len(note) > 1:
            side = {"L": "left", "R": "right"}.get(note[1], "both")
        return {"side": side, "role": "trampoline"}
    if tag == "L":
        kind = note[1]
        if kind == "dispatch":
            return {"side": "left", "role": "dispatch", "rule": note[2]}
        if kind == "cmp":
            return {
                "side": "left",
                "role": "compare",
                "rule": note[2],
                "path": note[3],
            }
        action = note[2]
        src = {
            "side": "left",
            "from": "default" if kind == "default" else "rule-action",
            "verdict": action_name(action),
        }
        if action[0] == "K":
            src.update(role="terminal", action="KILL_PROCESS", decides="left")
        else:
            src["role"] = "route"
            src["right_copy"] = None if action[0] == "A" else action[1]
        return src
    if tag == "R":
        key, kind = note[1], note[2]
        if kind == "dispatch":
            return {"side": "right", "copy": key, "role": "dispatch", "rule": note[3]}
        if kind == "cmp":
            return {
                "side": "right",
                "copy": key,
                "role": "compare",
                "rule": note[3],
                "path": note[4],
            }
        action = note[3]
        combined, decides = _combined_terminal(key, action)
        return {
            "side": "right",
            "copy": key,
            "role": "terminal",
            "from": "default" if kind == "default" else "rule-action",
            "verdict": action_name(action),
            "action": action_name(combined),
            "decides": decides,
        }
    raise PolicyError("internal: unknown note %r" % (note,))


def _policy_summary(p):
    return {
        "default": action_name(p["default"]),
        "rules": [
            {
                "index": i,
                "syscall": r["nr"],
                "action": action_name(r["action"]),
                "comparisons": r["ncond"],
            }
            for i, r in enumerate(p["rules"])
        ],
    }


def compile_pair(first, second):
    """Compile two policy texts into the merged-filter bundle."""
    left, right, insns, n_tramp, n_copies = compile_pair_ir(first, second)
    return {
        "arch": left["arch_name"],
        "semantics": (
            "load left, then right: KILL_PROCESS > ERRNO > ALLOW; "
            "equal ERRNO yields the right filter's data"
        ),
        "filter": base64.b64encode(pack_filter(insns)).decode(),
        "policies": {"left": _policy_summary(left), "right": _policy_summary(right)},
        "instructions": [
            {
                "pc": pc,
                "code": ins.code,
                "jt": ins.jt,
                "jf": ins.jf,
                "k": ins.k,
                "source": _source_for(ins.note),
            }
            for pc, ins in enumerate(insns)
        ],
        "stats": {
            "instructions": len(insns),
            "long_jump_trampolines": n_tramp,
            "right_body_copies": n_copies,
        },
    }

#!/usr/bin/env python3
"""Differential test for two-policy composition (tools/composition.py).

The merged filter's RAW BYTES are run through the independent cBPF
interpreter and checked against the independent stacked oracle
(evaluator.evaluate_stacked -- the model of loading the left policy first
and the right policy second).  The bundle's provenance map is checked at
the same time: the terminal RET reached by every run must name the side the
oracle's decider model says determined the return.  Rejection paths
(mismatched architectures, corrupt policies, over-limit products) must fail
as a whole, and the CLI must preserve a previous output file on failure.
"""

import base64
import json
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import bpf as B
import interp
import evaluator
import difftest
from compiler import PolicyError
from composition import compile_pair, compile_pair_ir

X86 = evaluator.ARCH_AUDIT["x86_64"]
AA = evaluator.ARCH_AUDIT["aarch64"]
BIG = 1 << 32

dec_action = difftest.dec_action

POL = os.path.join(HERE, "..", "policies")


def load_policy_text(name):
    with open(os.path.join(POL, name), "r", encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Structural checks on a merged bundle (independent of composition.py)
# ---------------------------------------------------------------------------
def check_merged_structure(bundle, doc_left, doc_right):
    ins = bundle["instructions"]
    n = len(ins)
    assert 0 < n <= B.MAX_FILTER_INSNS, "merged size outside kernel limit"
    assert ins[-1]["code"] == B.RET_K, "merged filter does not end in RET"
    # raw bytes must match the instruction table exactly
    blob = base64.b64decode(bundle["filter"])
    assert len(blob) == 8 * n, "filter bytes / instruction table mismatch"
    prog = interp.load_program(blob)
    for i, (code, jt, jf, k) in enumerate(prog):
        row = ins[i]
        assert (row["code"], row["jt"], row["jf"], row["k"]) == (code, jt, jf, k)
    saw_words = {a: [False, False] for a in range(6)}
    for i, row in enumerate(ins):
        c, jt, jf, k = row["code"], row["jt"], row["jf"], row["k"]
        src = row["source"]
        assert src["side"] in ("left", "right", "both"), src
        if c == B.LD_ABS_W:
            assert k + 4 <= 64, "load past seccomp_data"
            for a in range(6):
                if k == B.OFF_ARGS + 8 * a:
                    saw_words[a][0] = True
                if k == B.OFF_ARGS + 8 * a + 4:
                    saw_words[a][1] = True
        if c in (B.JMP_JEQ_K, B.JMP_JGT_K, B.JMP_JGE_K):
            assert jt <= 255 and jf <= 255, "u8 jump violated"
            assert 0 <= i + 1 + jt < n and 0 <= i + 1 + jf < n
        if c == B.JMP_JA:
            assert 0 <= i + 1 + k < n
        if c == B.RET_K:
            assert src["role"] == "terminal", "RET without terminal source"
            assert src["decides"] in ("left", "right", "both"), src
    # every argument compared on either side must use BOTH 32-bit words.
    # (right-side comparisons exist only when some left verdict can route
    # into a right copy, i.e. left has a non-kill rule action or default)
    used = set()
    for rule in doc_left.get("rules", []):
        difftest_walk(rule.get("when"), used)
    left_can_route = doc_left.get("default", "kill") != "kill" or any(
        r["action"] != "kill" for r in doc_left.get("rules", [])
    )
    if left_can_route:
        for rule in doc_right.get("rules", []):
            difftest_walk(rule.get("when"), used)
    for a in used:
        assert saw_words[a] == [True, True], (
            "arg %d comparison truncated to 32 bits in merged filter" % a
        )


def difftest_walk(node, used):
    if node is None:
        return
    key, body = next(iter(node.items()))
    if key == "arg":
        used.add(int(body["arg"]))
    elif key == "not":
        difftest_walk(body, used)
    else:
        for child in body:
            difftest_walk(child, used)


# ---------------------------------------------------------------------------
# One merged decision vs the stacked oracle (action + deciding side)
# ---------------------------------------------------------------------------
def run_merged(bundle, prog, oracle_left, oracle_right, nr, arch, args):
    data = {"nr": nr, "arch": arch, "args": args}
    want = evaluator.evaluate_stacked(oracle_left, oracle_right, data)
    who = evaluator.stacked_decider(oracle_left, oracle_right, data)
    blob_data = interp.pack_seccomp_data(nr, arch, args)
    ret_k, ret_pc = interp.run_ex(prog, blob_data)
    got = dec_action(ret_k)
    src = bundle["instructions"][ret_pc]["source"]
    return got, want, src, who


def main():
    failures = 0
    checked = 0

    def report(ok, what, *detail):
        nonlocal failures
        if not ok:
            failures += 1
            print("MISMATCH %s %s" % (what, " ".join(map(str, detail))))

    # ---- A) shipped probe.json x compose_right.json, hand-picked cases ----
    text_l = load_policy_text("probe.json")
    text_r = load_policy_text("compose_right.json")
    bundle = compile_pair(text_l, text_r)
    doc_l, doc_r = json.loads(text_l), json.loads(text_r)
    check_merged_structure(bundle, doc_l, doc_r)
    prog = interp.load_program(base64.b64decode(bundle["filter"]))
    ol = evaluator.load(text_l, is_text=True)
    orr = evaluator.load(text_r, is_text=True)

    z = [0] * 6

    def case(nr, args, exp_action, exp_who, why, arch=X86):
        nonlocal checked
        args = (args + [0] * 6)[:6]
        got, want, src, who = run_merged(
            bundle, prog, ol, orr, nr, arch, args
        )
        checked += 1
        ok = (
            got == want == exp_action
            and who == exp_who
            and src.get("decides") == exp_who
        )
        report(
            ok,
            "fixed[%s]" % why,
            "got=%s want=%s src=%s who=%s" % (got, want, src, who),
        )

    case(39, z, ("allow",), "both", "allow+allow -> allow")
    case(1, z, ("errno", 44), "right", "left allow, right errno44")
    case(3, [999999], ("errno", 92), "left", "left errno92, right allow")
    case(3, [0, 1000], ("errno", 99), "left", "left errno99, right allow")
    case(3, [0, BIG], ("errno", 33), "right", "left default5, right errno33 (arg1>=2^32)")
    case(3, [0, BIG - 1], ("errno", 5), "left", "2^32-1 below right's 2^32 gate")
    case(3, [0, BIG * 7 + 5], ("errno", 33), "right", "64-bit arg1 on both sides")
    case(3, [999999, BIG], ("errno", 33), "right", "both errno: right data wins")
    case(401, z, ("kill",), "right", "left default5, right kill")
    case(400, z, ("errno", 5), "left", "left default5, right default allow")
    case(28, [0, 0, 0], ("errno", 88), "left", "left errno88, right allow")
    case(28, [0, 0, BIG + 9], ("errno", 5), "left", "nested NOT + 64-bit arg")
    case(231, z, ("allow",), "both", "exit_group allow+allow")
    case(39 | 0x40000000, z, ("kill",), "both", "x32 bit -> shared gate kill")
    case(39, z, ("kill",), "both", "foreign arch -> shared gate kill", arch=AA)
    print("fixed pair cases: checked=%d" % checked)

    # ---- B) long-jump pairs in both directions (trampoline stress) ----
    lj = load_policy_text("longjump.json")
    for name, first, second in (
        ("longjump+probe", lj, text_l),
        ("probe+longjump", text_l, lj),
        ("longjump+longjump", lj, lj),
    ):
        left_p, right_p, insns, n_tramp, n_copies = compile_pair_ir(first, second)
        assert n_tramp > 0, "%s: merged filter lost its long jumps" % name
        assert len(insns) <= B.MAX_FILTER_INSNS
        b2 = compile_pair(first, second)
        check_merged_structure(b2, json.loads(first), json.loads(second))
        prog2 = interp.load_program(base64.b64decode(b2["filter"]))
        o1 = evaluator.load(first, is_text=True)
        o2 = evaluator.load(second, is_text=True)
        in_range = [0] * 6
        for i in range(30):
            in_range[i % 6] = BIG + 1000 + i + 3
        cases = [
            (39, in_range, None, None, "ranges hit"),
            (39, z, None, None, "ranges miss"),
            (3, [999999] + [0] * 5, None, None, "close 999999"),
            (39, z, None, None, "foreign arch"),
        ]
        for nr, args, _a, _w, why in cases:
            arch = AA if why == "foreign arch" else X86
            got, want, src, who = run_merged(b2, prog2, o1, o2, nr, arch, args)
            checked += 1
            ok = got == want and src.get("decides") == who
            report(
                ok,
                "%s[%s]" % (name, why),
                "got=%s want=%s src=%s who=%s" % (got, want, src, who),
            )
        print("%s: insns=%d trampolines=%d right_copies=%d"
              % (name, len(insns), n_tramp, n_copies))

    # ---- C) random pair fuzz: action + decider + structure ----
    rng = random.Random(20261006)
    N_PAIRS = 400
    N_DATA = 60
    rejected_oversize = 0
    max_insns_seen = 0
    for pi in range(N_PAIRS):
        dl = difftest.rnd_policy(rng)
        dr = difftest.rnd_policy(rng)
        dr["arch"] = dl["arch"]  # same-arch pair (mismatch covered below)
        tl, tr = json.dumps(dl), json.dumps(dr)
        try:
            bundle = compile_pair(tl, tr)
        except PolicyError as e:
            # only the kernel instruction limit may reject valid policies
            assert "too large" in str(e), "unexpected rejection: %s" % e
            rejected_oversize += 1
            continue
        check_merged_structure(bundle, dl, dr)
        max_insns_seen = max(max_insns_seen, len(bundle["instructions"]))
        prog = interp.load_program(base64.b64decode(bundle["filter"]))
        ol = evaluator.load(tl, is_text=True)
        orr = evaluator.load(tr, is_text=True)
        for _ in range(N_DATA):
            nr, arch, args = difftest.rnd_data(rng, rng.choice([dl, dr]))
            got, want, src, who = run_merged(bundle, prog, ol, orr, nr, arch, args)
            checked += 1
            if got != want or src.get("decides") != who:
                failures += 1
                print(
                    "MISMATCH fuzz pair#%d nr=%#x arch=%#x args=%s\n"
                    "  got=%s want=%s src=%s who=%s\n  left=%s\n  right=%s"
                    % (pi, nr, arch, args, got, want, src, who,
                       tl[:200], tr[:200])
                )
                if failures > 10:
                    break
        if failures > 10:
            break
    print(
        "random pairs=%d (oversize rejected=%d), total comparisons=%d, "
        "max merged insns=%d" % (N_PAIRS, rejected_oversize, checked, max_insns_seen)
    )

    # ---- D) rejection paths: fail as a whole ----
    def must_fail(t1, t2, needle):
        try:
            compile_pair(t1, t2)
        except PolicyError as e:
            assert needle in str(e), (needle, str(e))
            return
        raise AssertionError("should have failed: %s" % needle)

    valid_x86 = json.dumps(
        {"arch": "x86_64", "default": "allow",
         "rules": [{"syscall": 1, "action": "allow"}]}
    )
    valid_aa = json.dumps({"arch": "aarch64", "default": "allow", "rules": []})
    must_fail(valid_x86, valid_aa, "same architecture")  # invalid arch combo
    must_fail(valid_aa, valid_x86, "same architecture")
    must_fail('{"arch":', valid_x86, "JSON")  # corrupt left
    must_fail(valid_x86, '{"arch":', "JSON")  # corrupt right
    must_fail(json.dumps({"arch": "mips", "default": "kill", "rules": []}),
              valid_x86, "arch")
    must_fail(json.dumps({"arch": "x86_64", "default": "kill",
                          "rules": [{"syscall": 0x40000001, "action": "allow"}]}),
              valid_x86, "x32")
    leaves = [{"arg": {"arg": i % 6, "op": "eq", "value": str(i)}}
              for i in range(31)]
    must_fail(json.dumps({"arch": "x86_64", "default": "kill",
                          "rules": [{"syscall": 1, "action": "allow",
                                     "when": {"and": leaves}}]}),
              valid_x86, "30")
    # over-limit product: 13 distinct left errnos x longjump right body
    fat_left = json.dumps({
        "arch": "x86_64",
        "default": {"errno": "13"},
        "rules": [{"syscall": i + 1, "action": {"errno": str(i + 1)}}
                  for i in range(12)],
    })
    must_fail(fat_left, lj, "too large")
    print("rejection paths: ok")

    # ---- E) CLI: success writes a bundle; failures preserve old output ----
    tool = os.path.join(HERE, "seccompcompose")
    with tempfile.TemporaryDirectory() as td:
        lp = os.path.join(td, "left.json")
        rp = os.path.join(td, "right.json")
        out = os.path.join(td, "merged.json")
        with open(lp, "w") as f:
            f.write(text_l)
        with open(rp, "w") as f:
            f.write(text_r)

        def cli_run():
            return subprocess.run(
                [sys.executable, tool, lp, rp, out],
                capture_output=True, text=True,
            )

        r = cli_run()
        assert r.returncode == 0, r.stderr
        with open(out) as f:
            written = json.load(f)
        assert len(base64.b64decode(written["filter"])) % 8 == 0
        before = open(out, "rb").read()

        with open(rp, "w") as f:
            f.write("{corrupt")
        r = cli_run()
        assert r.returncode == 1, (r.returncode, r.stderr)
        assert open(out, "rb").read() == before, "corrupt right clobbered output"

        with open(rp, "w") as f:
            f.write(valid_aa)
        r = cli_run()
        assert r.returncode == 1, (r.returncode, r.stderr)
        assert open(out, "rb").read() == before, "arch mismatch clobbered output"

        with open(rp, "w") as f:
            f.write(lj)
        with open(lp, "w") as f:
            f.write(fat_left)
        r = cli_run()
        assert r.returncode == 1, (r.returncode, r.stderr)
        assert open(out, "rb").read() == before, "oversize clobbered output"
    print("cli behaviour: ok")

    if failures:
        print("FAIL: %d mismatches" % failures)
        return 1
    print("ALL COMPOSITION CHECKS PASSED (%d decisions)" % checked)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

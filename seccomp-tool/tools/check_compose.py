#!/usr/bin/env python3
"""check_compose.py -- real-kernel check of a merged filter.

For every fixed case, three results must agree:

  1. the independent stacked oracle (evaluator.evaluate_stacked),
  2. the MERGED filter installed alone in one child (probe smoke mode),
  3. the LEFT then RIGHT filters installed sequentially in one child
     (probe stack mode) -- the kernel's real filter stacking, which the
     merged filter must reproduce.

Usage: check_compose.py PROBE ARCH LEFT_JSON RIGHT_JSON
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import evaluator
from compiler import compile_policy, pack_filter
from composition import compile_pair

BIG = 1 << 32

# (tag, x86_64 nr, args) -- args are 64-bit; must match the pair
# policies/probe.json + policies/compose_right.json
CASES = [
    ("allow_allow", 39, [0, 0, 0, 0, 0, 0]),
    ("allow_errno44", 1, [0, 0, 0, 0, 0, 0]),
    ("errno92_allow", 3, [999999, 0, 0, 0, 0, 0]),
    ("errno99_allow", 3, [0, 1000, 0, 0, 0, 0]),
    ("errno5_errno33_2p32", 3, [0, BIG, 0, 0, 0, 0]),
    ("boundary_2p32_minus1", 3, [0, BIG - 1, 0, 0, 0, 0]),
    ("both_errno_right_data", 3, [999999, BIG, 0, 0, 0, 0]),
    ("right_kill", 401, [0, 0, 0, 0, 0, 0]),
    ("default_default", 400, [0, 0, 0, 0, 0, 0]),
    ("errno88_allow", 28, [0, 0, 0, 0, 0, 0]),
    ("nested_2p32_9", 28, [0, 0, BIG + 9, 0, 0, 0]),
    ("x32_tagged", 39 | 0x40000000, [0, 0, 0, 0, 0, 0]),
]

# x86_64 nr -> aarch64 nr for the aarch64 twins of the pair policies
NR_AARCH64 = {39: 172, 1: 64, 3: 57, 401: 401, 400: 999, 28: 233}

# natural kernel errno for cases the merged filter allows (side-effect free)
NATURAL_ERRNO = {"allow_allow": 0}


def run_probe(probe, filt, arch, mode, nr, args, extra=None):
    cmd = [probe, filt, arch, mode]
    if extra is not None:
        cmd.append(extra)
    cmd += [str(nr)] + [str(a) for a in args]
    p = subprocess.run(cmd, capture_output=True, text=True)
    line = p.stdout.strip()
    m = re.search(r"EXIT errno=(\d+)", line)
    if m:
        return ("exit", int(m.group(1))), line
    m = re.search(r"KILL signal=(\d+)", line)
    if m:
        return ("kill", int(m.group(1))), line
    return ("other", line), line


def matches(obs, exp, tag):
    if exp[0] == "kill":
        return obs[0] == "kill" and obs[1] == 31
    if exp[0] == "errno":
        return obs == ("exit", exp[1])
    return obs == ("exit", NATURAL_ERRNO.get(tag, 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("probe_bin")
    ap.add_argument("arch", choices=("x86_64", "aarch64"))
    ap.add_argument("left_json")
    ap.add_argument("right_json")
    args = ap.parse_args()

    text_l = open(args.left_json).read()
    text_r = open(args.right_json).read()
    oracle_l = evaluator.load(text_l, is_text=True)
    oracle_r = evaluator.load(text_r, is_text=True)
    audit = evaluator.ARCH_AUDIT[args.arch]

    _, ins_l, _ = compile_policy(text_l)
    _, ins_r, _ = compile_policy(text_r)
    bundle = compile_pair(text_l, text_r)

    fails = 0
    checked = 0
    with tempfile.TemporaryDirectory() as td:
        f_l = os.path.join(td, "left.filter")
        f_r = os.path.join(td, "right.filter")
        f_m = os.path.join(td, "merged.filter")
        for path, blob in (
            (f_l, pack_filter(ins_l)),
            (f_r, pack_filter(ins_r)),
            (f_m, base64.b64decode(bundle["filter"])),
        ):
            with open(path, "wb") as f:
                f.write(blob)

        print("== compose kernel probe arch=%s left=%s right=%s =="
              % (args.arch, args.left_json, args.right_json))
        for tag, nr_x86, vec in CASES:
            if args.arch == "aarch64":
                if tag == "x32_tagged":
                    continue  # no x32 ABI bit on aarch64
                nr = NR_AARCH64.get(nr_x86, nr_x86)
            else:
                nr = nr_x86
            data = {"nr": nr & 0xFFFFFFFF, "arch": audit, "args": vec}
            exp = evaluator.evaluate_stacked(oracle_l, oracle_r, data)
            obs_m, line_m = run_probe(
                args.probe_bin, f_m, args.arch, "smoke", nr, vec)
            obs_s, line_s = run_probe(
                args.probe_bin, f_l, args.arch, "stack", nr, vec, extra=f_r)
            checked += 1
            ok_m = matches(obs_m, exp, tag)
            ok_s = matches(obs_s, exp, tag)
            ok = ok_m and ok_s
            print("%-24s %s merged[%s] stacked[%s] oracle=%s"
                  % (tag, "PASS" if ok else "FAIL",
                     "" if ok_m else "FAIL:" + line_m,
                     "" if ok_s else "FAIL:" + line_s,
                     exp))
            if not ok:
                fails += 1

    print("compose kernel-verified cases=%d failures=%d => %s"
          % (checked, fails, "PASS" if fails == 0 else "FAIL"))
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())

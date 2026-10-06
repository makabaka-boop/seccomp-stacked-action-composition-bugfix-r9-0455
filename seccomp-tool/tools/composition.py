import base64
from bpf import (
    Insn,
    RET_K,
    JMP_JA,
    SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO,
    SECCOMP_RET_KILL_PROCESS,
    MAX_FILTER_INSNS,
)
from compiler import compile_policy, pack_filter, verify, PolicyError


def bundle(arch, instructions, sources):
    return {
        "arch": arch,
        "filter": base64.b64encode(pack_filter(instructions)).decode(),
        "instructions": [
            {
                "pc": pc,
                "code": ins.code,
                "jt": ins.jt,
                "jf": ins.jf,
                "k": ins.k,
                "source": sources[pc],
            }
            for pc, ins in enumerate(instructions)
        ],
    }


def compile_pair(first, second):
    left, l, _ = compile_policy(first)
    right, r, _ = compile_policy(second)
    instructions = list(l) + list(r)
    sources = [
        {"policy": 0, "original_pc": i, "note": ins.note} for i, ins in enumerate(l)
    ] + [{"policy": 1, "original_pc": i, "note": ins.note} for i, ins in enumerate(r)]
    return bundle(left["arch"], instructions, sources)

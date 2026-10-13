#!/usr/bin/env python3
"""Select title functions for the difftest harness.

--hottest: rank functions by the map trace's dynamic block hits (the trace's
           executed indirect sites mapped to their containing FDE function).
--simple:  scan the FDE ranges for functions with no calls and no indirect
           branches, so the AOT compiler can compile them without a call graph.

Run: PYTHONPATH=<work>/tools-py python3 difftest/select_functions.py <targets.json> <fde-ranges.json> <eboot.elf> <out.json> hottest|simple [count]
"""
import bisect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import difftest  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_64  # noqa: E402
from capstone.x86 import X86_OP_IMM  # noqa: E402


def hottest(targets_path, sizes, count):
    starts = sorted(sizes)
    aggregate = {}
    for block in json.loads(Path(targets_path).read_text())["first_executed_blocks"]:
        address = block["address"]
        function = starts[bisect.bisect_right(starts, address) - 1]
        aggregate[function] = aggregate.get(function, 0) + block["hits"]
    return [{"function": hex(function), "hits": hits} for function, hits in
            sorted(aggregate.items(), key=lambda item: -item[1])[:count]]


def simple(elf_path, sizes, count):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    title = difftest.Title(elf_path)
    useful = set("mov add sub xor and or lea cmp test imul shl shr sar neg not inc dec movzx movsx movsxd".split())
    selected = []
    for function, size in sorted(sizes.items()):
        if size < 8 or size > 1024:
            continue
        code = title.code(function, size)
        if code is None:
            continue
        ok, has_useful = True, False
        for instruction in decoder.disasm(code, function):
            if instruction.mnemonic in ("call", "ud2", "int3"):
                ok = False
                break
            if instruction.mnemonic == "jmp" and (not instruction.operands or instruction.operands[0].type != X86_OP_IMM):
                ok = False
                break
            if instruction.mnemonic.startswith("j") and instruction.operands and instruction.operands[0].type != X86_OP_IMM:
                ok = False
                break
            if instruction.mnemonic in useful:
                has_useful = True
        if ok and has_useful:
            selected.append({"function": hex(function), "hits": 0})
        if len(selected) >= count:
            break
    return selected


def main():
    if len(sys.argv) < 6:
        raise SystemExit(__doc__)
    targets_path, ranges_path, elf_path, out_path, mode = sys.argv[1:6]
    count = int(sys.argv[6]) if len(sys.argv) > 6 else 500
    sizes = difftest.fde_sizes(ranges_path)
    selected = hottest(targets_path, sizes, count) if mode == "hottest" else simple(elf_path, sizes, count)
    Path(out_path).write_text(json.dumps(selected, indent=1))
    print(f"{mode}: {len(selected)} functions -> {out_path}")


if __name__ == "__main__":
    main()

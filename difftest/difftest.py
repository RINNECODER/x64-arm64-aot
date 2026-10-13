#!/usr/bin/env python3
"""Phase 2 differential-test harness: compile title functions with core/aot.

The AOT compiler wants a complete ELF contract. For a title function we build a
synthetic ET_DYN that maps the function (and the transitive closure of its direct
callees) at their original addresses, plus a zeroed data segment per referenced
region and one for the dynamic tables. Direct calls to functions outside the
closure, indirect calls and indirect jumps reject the function, which is the
expected "blocked" outcome; the reason is recorded per function.

Run:  PYTHONPATH=core/aot:<work>/tools-py python3 difftest/difftest.py <eboot.elf> <selection.json> <fde-starts.txt> <out-dir> [closure-limit]
"""
import hashlib
import io
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
from elftools.elf.elffile import ELFFile

AOT = Path(__file__).resolve().parent.parent / "core" / "aot"
sys.path.insert(0, str(AOT))

from compiler import Image, Rejected, compile_image  # noqa: E402

IMAGE_END = 0x9c2ba50
DECODER = Cs(CS_ARCH_X86, CS_MODE_64)
DECODER.detail = True


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fde_sizes(path):
    text = Path(path).read_text()
    if text.lstrip().startswith("{"):
        return {int(key, 16): value for key, value in json.loads(text).items()}
    starts = sorted(int(line, 16) for line in text.split() if line)
    return {start: (starts[index + 1] - start if index + 1 < len(starts) else 0x100)
            for index, start in enumerate(starts)}


class Title:
    def __init__(self, elf_path):
        self.raw = Path(elf_path).read_bytes()
        self.elf = ELFFile(io.BytesIO(self.raw))
        self.segments = [s for s in self.elf.iter_segments() if s["p_type"] == "PT_LOAD"]

    def code(self, address, size):
        for segment in self.segments:
            if segment["p_flags"] & 1 and segment["p_vaddr"] <= address < segment["p_vaddr"] + segment["p_filesz"]:
                offset = segment["p_offset"] + (address - segment["p_vaddr"])
                return self.raw[offset:offset + size]
        return None


def references(code, address):
    """Addresses referenced by RIP-relative/absolute operands and image immediates."""
    found = {}
    for ins in DECODER.disasm(code, address):
        for operand in ins.operands:
            if operand.type == X86_OP_MEM and operand.mem.index == 0:
                if operand.mem.base == X86_REG_RIP:
                    target = ins.address + ins.size + operand.mem.disp
                elif operand.mem.base == 0:
                    target = operand.mem.disp
                else:
                    continue
                if 0 < target < IMAGE_END:
                    found[target] = max(found.get(target, 1), max(operand.size, 1))
            elif operand.type == X86_OP_IMM and 0x1000 <= operand.imm < IMAGE_END:
                found[operand.imm] = max(found.get(operand.imm, 1), 8)
    return found


def direct_targets(code, address):
    targets = []
    for ins in DECODER.disasm(code, address):
        if ins.mnemonic in ("call", "jmp") and ins.operands and ins.operands[0].type == X86_OP_IMM:
            targets.append(ins.operands[0].imm)
    return targets


def closure(title, sizes, root, limit):
    """The root plus the transitive closure of direct call/jmp targets that are
    FDE function starts, bounded by `limit` functions."""
    ordered, seen = [root], {root}
    pending = [root]
    while pending and len(ordered) < limit:
        address = pending.pop(0)
        code = title.code(address, sizes[address])
        if code is None:
            continue
        for target in direct_targets(code, address):
            if target in sizes and target not in seen:
                seen.add(target)
                ordered.append(target)
                pending.append(target)
    return ordered


def page_region(address, size, page=0x1000):
    start = address & ~(page - 1)
    end = (address + size + page - 1) & ~(page - 1)
    return start, end - start


def build_synthetic(functions, referenced, uniform=False, dispatch=False, guest_base=0):
    """functions: [(address, code)]; referenced: {address: size}."""
    regions = {}
    function_ranges = [(a, a + len(c)) for a, c in functions]
    for target, size in referenced.items():
        start, length = page_region(target, size)
        end = start + length
        if any(start < fend and a < end for a, fend in function_ranges):
            continue  # overlaps a mapped function; the exec segment already covers it
        regions[start] = max(regions.get(start, 0), length)
    merged = []
    for start, length in sorted(regions.items()):
        if merged and start <= merged[-1][0] + merged[-1][1]:
            previous_start, previous_length = merged[-1]
            merged[-1] = (previous_start, max(previous_length, start + length - previous_start))
        else:
            merged.append((start, length))
    regions = dict(merged)

    header_size = 64
    code_offset = 0x1000
    code_size = sum(len(code) for _, code in functions)
    data_base = code_offset + code_size
    dynamic_offset = data_base + sum(regions.values())
    dynsym_offset = dynamic_offset + 0x400
    strings_offset = dynamic_offset + 0x800
    dynamic_size = 16 * 6
    section_offset = dynamic_offset + 0x1000
    names = b"\0.dynsym\0.dynstr\0.dynamic\0.shstrtab\0"
    total = section_offset + 0x400
    table_size = total - dynamic_offset
    phnum = 3 + len(functions) + len(regions)
    image = bytearray(total)
    struct.pack_into("<16sHHIQQQIHHHHHH", image, 0, b"\x7fELF\x02\x01\x01" + bytes(9),
                     3, 62, 1, functions[0][0], header_size, section_offset, 0, 64, 56, phnum, 64, 5, 4)
    index, cursor = 0, code_offset
    for address, code in functions:
        struct.pack_into("<IIQQQQQQ", image, header_size + index * 56, 1, 5, cursor, address, address, len(code), len(code), 0x1000)
        image[cursor:cursor + len(code)] = code
        cursor += len(code)
        index += 1
    for start, length in sorted(regions.items()):
        struct.pack_into("<IIQQQQQQ", image, header_size + index * 56, 1, 6, data_base, start, start, 0, length, 0x1000)
        data_base += length
        index += 1
    struct.pack_into("<IIQQQQQQ", image, header_size + index * 56, 1, 6, dynamic_offset, dynamic_offset, dynamic_offset,
                     table_size, table_size, 0x1000)
    index += 1
    struct.pack_into("<IIQQQQQQ", image, header_size + index * 56, 2, 6, dynamic_offset, dynamic_offset, dynamic_offset,
                     dynamic_size, dynamic_size, 8)
    tags = [(6, dynsym_offset), (11, 24), (5, strings_offset), (10, len(names)), (9, 24), (0, 0)]
    for offset, (tag, value) in enumerate(tags):
        struct.pack_into("<qQ", image, dynamic_offset + offset * 16, tag, value)
    image[strings_offset:strings_offset + len(names)] = names
    sections = [
        (1, 11, 2, dynsym_offset, dynsym_offset, 24, 2, 1, 8, 24),
        (9, 3, 2, strings_offset, strings_offset, len(names), 0, 0, 1, 0),
        (17, 6, 3, dynamic_offset, dynamic_offset, dynamic_size, 2, 0, 8, 16),
        (26, 3, 0, 0, strings_offset, len(names), 0, 0, 1, 0),
    ]
    for offset, values in enumerate(sections, 1):
        struct.pack_into("<IIQQQQIIQQ", image, section_offset + offset * 64, *values)
    data = [{"address": start, "size": length} for start, length in sorted(regions.items())]
    data.append({"address": dynamic_offset, "size": table_size})
    contracts = {
        "schema": 1,
        "sha256": hashlib.sha256(image).hexdigest(),
        "functions": [{"name": (f"sub_{address:x}" if uniform else f"func_{address:x}"), "address": address, "size": len(code),
                       **({"uniform": True, "result": "void"} if uniform else {"result": "i64"}), "parameters": []}
                      for address, code in functions],
        "imports": {},
        "data": data,
        "pointer_relocations": [],
    }
    if dispatch:
        contracts["dispatch"] = True
    if guest_base:
        contracts["guest_base"] = guest_base
    return bytes(image), contracts


def compile_one(title, sizes, address, limit, work_dir=None, uniform=False, dispatch=False):
    functions = [address] if dispatch else closure(title, sizes, address, limit)
    codes = [(a, title.code(a, sizes[a])) for a in functions]
    codes = [(a, c) for a, c in codes if c]
    referenced = {}
    for a, c in codes:
        for target, size in references(c, a).items():
            referenced[target] = max(referenced.get(target, 1), size)
    image, contracts = build_synthetic(codes, referenced, uniform, dispatch)
    with tempfile.TemporaryDirectory(prefix="anyps5-difftest-") as directory:
        path = Path(directory) / "input.elf"
        path.write_bytes(image)
        try:
            ir, report = compile_image(Image(path, contracts))
        except (Rejected, KeyError, ValueError) as error:
            return {"status": "rejected", "reason": str(error)[:400], "closure": len(codes), "references": len(referenced)}
    image_path = ""
    if work_dir is not None:
        work_dir.mkdir(parents=True, exist_ok=True)
        saved = work_dir / f"{address:x}.elf"
        saved.write_bytes(image)
        image_path = str(saved)
    return {"status": "compiled", "closure": len(codes), "references": len(referenced),
            "image": image_path, "ir": ir, "ir_lines": ir.count("\n"), "functions": report["functions"]}


def main():
    if len(sys.argv) < 5:
        raise SystemExit(__doc__)
    elf_path, selection_path, starts_path, out_dir = (Path(sys.argv[1]), Path(sys.argv[2]),
                                                       Path(sys.argv[3]), Path(sys.argv[4]))
    limit = int(sys.argv[5]) if len(sys.argv) > 5 else 200
    uniform = "--uniform" in sys.argv
    dispatch = "--dispatch" in sys.argv
    out_dir.mkdir(parents=True, exist_ok=True)
    sizes = fde_sizes(starts_path)
    title = Title(elf_path)
    selected = json.loads(selection_path.read_text())
    images = out_dir / "images"
    results = {}
    compiled = 0
    for item in selected:
        address = int(item["function"], 16)
        size = sizes.get(address, 0)
        if not size or title.code(address, size) is None:
            results[item["function"]] = {"status": "no-fde-range", "hits": item["hits"]}
            continue
        try:
            result = compile_one(title, sizes, address, limit, images, uniform, dispatch)
        except Exception as error:
            result = {"status": "harness-error", "reason": str(error)[:400]}
        result["hits"] = item["hits"]
        result["size"] = size
        results[item["function"]] = result
        if result["status"] == "compiled":
            compiled += 1
    (out_dir / "compile-results.json").write_text(json.dumps(results, indent=1))
    print(f"selected={len(selected)} compiled={compiled} rejected={sum(1 for r in results.values() if r['status'] == 'rejected')}")
    if "--replay" in sys.argv:
        replay_compiled(title, sizes, results, out_dir, uniform=uniform)
    return 0


def replay_compiled(title, sizes, results, out_dir, cases=1000, uniform=False):
    """Replay each compiled function with a zeroed register/memory case: the AOT
    ARM64 function against the original x86 bytes in a Rosetta-relinked layout.
    Each case runs in its own process so a crash is contained."""
    matched = mismatched = x86_fault = arm_fault = 0
    replay_dir = out_dir / "replay"
    replay_dir.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve().parent / "replay_one.py"
    for address_hex, result in list(results.items()):
        if result["status"] != "compiled" or cases <= 0 or not result.get("image"):
            continue
        cases -= 1
        address = int(address_hex, 16)
        ir_path = replay_dir / f"{address:x}.ll"
        ir_path.write_text(result["ir"])
        completed = subprocess.run([sys.executable, str(script), str(ir_path), result["image"], address_hex] + (["uniform"] if uniform else []),
                                   capture_output=True, text=True)
        if completed.returncode != 0:
            result["replay"] = {"status": "arm64-fault", "exit": completed.returncode, "stderr": completed.stderr[-200:]}
            arm_fault += 1
            continue
        outcome = json.loads(completed.stdout)
        result["replay"] = outcome
        if outcome.get("status") == "x86-fault":
            x86_fault += 1
        elif outcome["match"]:
            matched += 1
        else:
            mismatched += 1
    (out_dir / "compile-results.json").write_text(json.dumps(results, indent=1))
    print(f"replay: matched={matched} mismatched={mismatched} x86_fault={x86_fault} arm64_fault={arm_fault}")


if __name__ == "__main__":
    sys.exit(main())

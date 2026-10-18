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


def real_closure(title, sizes, root, profile, limit):
    """The root plus the transitive closure of its direct calls/jmps and fall-through tail calls,
    taken from the real module profile.

    `sizes` must be the profile's function table (a superset of the FDE starts): a tail call can
    land on an interior entry that is not an FDE start, and that is exactly the case the synthetic
    closure cannot resolve. Indirect target sets are deliberately *not* followed here; they pull in
    the whole title. `indirect_stubs` declares them instead."""
    ordered, seen = [root], {root}
    pending = [root]
    while pending and len(ordered) < limit:
        address = pending.pop(0)
        size = sizes.get(address) or 0
        code = title.code(address, size) if size else None
        targets = set(direct_targets(code, address)) if code else set()
        if size:
            targets.add(address + size)
        for target in sorted(targets):
            if target in sizes and target not in seen:
                seen.add(target)
                ordered.append(target)
                pending.append(target)
    return ordered


def indirect_stubs(profile, functions):
    """The declared indirect target sets of `functions`, as addresses that need a stub declaration."""
    stubs = set()
    for address in functions:
        for _site, index, _kind in profile.indirect_records(address):
            stubs.update(profile.targets_of(index))
    return {target for target in stubs if profile.has(target)}


def build_synthetic(functions, referenced, uniform=False, dispatch=False, guest_base=0, guest_data=False,
                    external=(), specs=None, target_sets=None):
    """functions: [(address, code)]; referenced: {address: size}.

    With guest_data the compiler does not emit the data segments; it references them at their guest
    vaddrs and the runtime maps the image's segments. A referenced region that overlaps a mapped
    function is still skipped: the compiler treats a reference into the function's own code page as
    data, and mapping a zero-filled page over it drives the code into a wild jump.

    `external` names functions whose bodies the harness supplies natively (recorded-call replay
    stubs): the image declares them, so a direct call resolves to a uniform call, but no body is
    emitted.

    `specs` are the real module-profile contracts (indirect-call annotations and signatures);
    `target_sets` is the shared indirect target-set pool those annotations index. With them an
    indirect call resolves to a declared uniform target set instead of rejecting."""
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
    # The program-header table is written at offset 64; the code must start after it, or a closure
    # with more than ~72 functions/regions writes its headers over the first function's bytes (and
    # past the buffer once the table is longer than the whole image).
    phnum = 3 + len(functions) + len(regions)
    code_offset = max(0x1000, (header_size + phnum * 56 + 0xfff) & ~0xfff)
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
    declared = []
    for address, code in functions:
        entry = dict((specs or {}).get(address) or {})
        entry.update({"name": (f"sub_{address:x}" if uniform else f"func_{address:x}"), "address": address,
                      "size": len(code), **({"uniform": True, "result": "void"} if uniform else {"result": "i64"}),
                      "parameters": entry.get("parameters", [])})
        if address in external:
            entry["external"] = True
        declared.append(entry)
    contracts = {
        "schema": 1,
        "sha256": hashlib.sha256(image).hexdigest(),
        "functions": declared,
        "imports": {},
        "data": data,
        "pointer_relocations": [],
    }
    if target_sets:
        contracts["target_sets"] = target_sets
    if dispatch:
        contracts["dispatch"] = True
    if guest_base:
        contracts["guest_base"] = guest_base
    if guest_data:
        contracts["guest_data"] = True
    return bytes(image), contracts


def build_guest_contracts(raw, codes, uniform=False, guest_base=0):
    """Placeholder kept for callers that build contracts from the real image; the difftest uses
    build_synthetic(..., guest_data=True) so the synthetic image stays the single input."""
    raise NotImplementedError


def compile_one(title, sizes, address, limit, work_dir=None, uniform=False, dispatch=False,
                guest_data=False, guest_base=0, external=(), functions=None, profile=None):
    specs = target_sets = None
    if profile is not None:
        if functions is None:
            functions = real_closure(title, sizes, address, profile, limit)
        stubs = indirect_stubs(profile, functions) - set(functions)
        functions = list(functions) + sorted(stubs)
        specs = {item: profile.spec(item, f"sub_{item:x}" if uniform else f"func_{item:x}", stub=item in stubs)
                 for item in functions if profile.has(item)}
        target_sets = profile.target_sets
    if functions is None:
        functions = [address] if dispatch else closure(title, sizes, address, limit)
    codes = [(a, title.code(a, sizes[a])) for a in functions]
    codes = [(a, c) for a, c in codes if c]
    referenced = {}
    for a, c in codes:
        for target, size in references(c, a).items():
            referenced[target] = max(referenced.get(target, 1), size)
    image, contracts = build_synthetic(codes, referenced, uniform, dispatch, guest_base, guest_data, external,
                                       specs, target_sets)
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


def reference_regions(title, sizes, functions):
    """The data regions a function set references, page-expanded and merged, as contract data specs.

    With the real eboot as the image the compiler reads each region's real bytes into a global, so
    a title data reference resolves without mapping the whole title image."""
    referenced = {}
    for address in functions:
        code = title.code(address, sizes.get(address) or 0)
        if code is None:
            continue
        for target, size in references(code, address).items():
            referenced[target] = max(referenced.get(target, 1), size)
    regions = {}
    for target, size in referenced.items():
        start, length = page_region(target, size)
        regions[start] = max(regions.get(start, 0), length)
    merged = []
    for start, length in sorted(regions.items()):
        if merged and start <= merged[-1][0] + merged[-1][1]:
            previous_start, previous_length = merged[-1]
            merged[-1] = (previous_start, max(previous_length, start + length - previous_start))
        else:
            merged.append((start, length))
    return [{"address": start, "size": length} for start, length in merged]


def real_contracts(title, profile, root, limit, sha, base, entry):
    """Contracts for the real module image: the root's direct closure as uniform bodies, the ELF
    entry and the DT_INIT/DT_FINI lifecycle functions as stubs (the compiler only requires their
    signatures to exist), and the real module profile's remaining metadata.

    With `guest_data` + `dispatch` the compiler references title data at `base + vaddr` and lowers
    an indirect call the analysis cannot resolve to `NativeAotDispatch(value)`, so a target outside
    the closure no longer rejects the function. `imports` and `pointer_relocations` are dropped:
    the harness applies the relocations into the mapped image itself, and it has no HLE symbols to
    bind the imports to."""
    closure = real_closure(title, profile.sizes, root, profile, limit)
    keep = list(closure)
    init, fini = profile.lifecycle
    for extra in (entry, init, fini):
        if extra is not None and profile.has(extra) and extra not in keep:
            keep.append(extra)
    lifecycle = {init, fini} - {None}
    specs = []
    for address in keep:
        if address in lifecycle or address == entry:
            specs.append({"name": f"entry_{address:x}", "address": address, "size": profile.sizes[address],
                          "result": "void", "parameters": [], "stub": True})
        else:
            specs.append(profile.spec(address, f"sub_{address:x}"))
    contracts = {key: value for key, value in profile.raw.items()
                 if key not in ("sizes", "indirect", "functions", "pointer_relocations", "lifecycle")}
    contracts.update({"schema": 1, "sha256": sha, "functions": specs,
                      "imports": {key: dict(value, stub=True)
                                  for key, value in (profile.raw.get("imports") or {}).items()},
                      "pointer_relocations": [list(pair) for pair in profile.relocations],
                      "data": [], "guest_data": True,
                      "guest_base": base, "allow_unimplemented": True, "dispatch": True,
                      "lifecycle": {"owner": "entry", "init": init, "fini": fini}})
    return closure, contracts


def compile_real(elf_path, contracts):
    """Compile a contract set against the real eboot instead of a synthetic image."""
    try:
        ir, report = compile_image(Image(elf_path, contracts))
    except (Rejected, KeyError, ValueError) as error:
        return {"status": "rejected", "reason": str(error)[:400]}
    return {"status": "compiled", "ir": ir, "ir_lines": ir.count("\n"), "functions": report["functions"],
            "unimplemented": report.get("unimplemented_functions")}


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

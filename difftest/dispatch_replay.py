#!/usr/bin/env python3
"""Dispatch-mode two-sided replay with recorded memory pages.

Compiles the selected functions in dispatch mode (a synthetic image with `dispatch:
true`), links `NativeAotDispatch.cpp`, and registers a combined table (image
functions + per-target recording stubs). The recorded entry registers and the pages
snapshotted by the runtime entry recorder are mapped at the guest layout in both the
AOT and the x86 runner, so pointer arguments resolve instead of faulting.

usage: PYTHONPATH=core/aot:<work>/tools-py dispatch_replay.py <eboot.elf> <contracts.json> <compile-results.json> <out-dir> <fde-ranges.json> [entries] [pages]
"""
import ctypes
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

AOT = Path(__file__).resolve().parent.parent / "core" / "aot"
sys.path.insert(0, str(AOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import difftest  # noqa: E402
import replay  # noqa: E402

BASE = replay.BASE
DELTA = 0x10000  # unused; the recorder stores host addresses
RECORD_BASE = 0x140010000
PAGE = 0x4000

GENERIC_STUB = r"""
#include <stdint.h>
uint64_t aps5_calls[400000][2];
int aps5_call_count;
void aps5_stub(void* rf, uint64_t target);
void aps5_stub(void* rf, uint64_t target) {
    if (aps5_call_count < 400000) {
        aps5_calls[aps5_call_count][0] = target;
        aps5_calls[aps5_call_count][1] = (uint64_t)rf;
        aps5_call_count++;
    }
    ((uint64_t*)rf)[0] = 0;
}
"""


def load_entries(path):
    data = Path(path).read_bytes()
    result = {}
    for offset in range(0, len(data), 8 + 16 * 8):
        entry, = struct.unpack_from("<Q", data, offset)
        result[entry] = list(struct.unpack_from("<16Q", data, offset + 8))
    return result


def load_snapshot(path):
    data = Path(path).read_bytes()
    if len(data) < 4:
        return []
    offset = 4
    regions = []
    while offset + 16 <= len(data):
        base, size = struct.unpack_from("<QQ", data, offset)
        offset += 16
        if offset + size > len(data):
            break
        regions.append((base, data[offset:offset + size]))
        offset += size
    return regions


def load_pages(path):
    data = Path(path).read_bytes()
    result = {}
    record = 8 + 8 + PAGE
    for offset in range(0, len(data) - record + 1, record):
        entry, page = struct.unpack_from("<QQ", data, offset)
        result.setdefault(entry, []).append((page, data[offset + 16:offset + 16 + PAGE]))
    return result


def main():
    if len(sys.argv) < 6:
        raise SystemExit(__doc__)
    elf, contracts_path, compile_path, out_dir, ranges_path = (Path(sys.argv[1]), Path(sys.argv[2]),
                                                               Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5]))
    entries_path = Path(sys.argv[6]) if len(sys.argv) > 6 else None
    pages_path = Path(sys.argv[7]) if len(sys.argv) > 7 else None
    snapshot_path = Path(sys.argv[8]) if len(sys.argv) > 8 else None
    out_dir.mkdir(parents=True, exist_ok=True)
    contracts = json.loads(contracts_path.read_text())
    results = json.loads(compile_path.read_text())
    compiled = [int(k, 16) for k, v in results.items() if v["status"] == "compiled"]
    by_address = {spec["address"]: spec for spec in contracts["functions"]}
    target_sets = contracts["target_sets"]
    sizes = difftest.fde_sizes(ranges_path)
    title = difftest.Title(elf)
    PAD = {0x00, 0x90, 0xCC}

    def body(address):
        code = title.code(address, sizes[address]) if sizes.get(address) else None
        if not code:
            return None
        end = len(code)
        while end > 0 and code[end - 1] in PAD:
            end -= 1
        return code[:end] if end else None

    codes = [(a, body(a)) for a in compiled if body(a)]
    internal = {a for a, _ in codes}
    targets = set()
    for address in compiled:
        spec = by_address.get(address, {})
        for record in spec.get("indirect_calls", []) + spec.get("indirect_jumps", []):
            listed = record.get("targets")
            targets.update(listed if listed is not None else target_sets[record["target_set"]])
        code = body(address)
        if code:
            for target in difftest.direct_targets(code, address):
                if target not in internal:
                    targets.add(target)
    print(f"compiled {len(compiled)}, image {len(codes)}, dispatch targets {len(targets)}", flush=True)

    work = out_dir / "image"
    work.mkdir(parents=True, exist_ok=True)
    from compiler import Image, compile_image
    from toolchain import build_native_object
    excluded = []
    while True:
        referenced = {}
        for a, code in codes:
            for target, size in difftest.references(code, a).items():
                referenced[target] = max(referenced.get(target, 1), size)
        image, reduced = difftest.build_synthetic(codes, referenced, uniform=True, dispatch=True, guest_base=BASE)
        source = work / "input.elf"
        source.write_bytes(image)
        try:
            ir, _report = compile_image(Image(source, reduced))
            break
        except Exception as error:
            match = re.search(r"(?:cannot decode|ambiguous or unmapped address) 0x([0-9a-f]+)", str(error))
            if not match or len(excluded) > 60:
                raise
            bad = int(match.group(1), 16)
            removed = [a for a, c in codes if a <= bad < a + len(c)]
            if not removed:
                referenced[bad & ~0xFFF] = PAGE
                continue
            excluded.extend(removed)
            codes = [(a, c) for a, c in codes if a not in set(removed)]
            print(f"excluding {[hex(x) for x in removed]} for {hex(bad)}", flush=True)
    print(f"batch compiled, excluded {len(excluded)}", flush=True)
    ir_path = work / "image.ll"
    ir_path.write_text(ir)
    object_file = work / "image.o"
    build_native_object(ir, object_file)
    dispatch_source = Path(__file__).resolve().parent.parent / "core" / "libs" / "native" / "NativeAotDispatch.cpp"
    dispatch_object = work / "dispatch.o"
    subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-O2", "-c", str(dispatch_source), "-o", str(dispatch_object)],
                   check=True, capture_output=True)
    dylib = work / "image.dylib"
    subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-dynamiclib", str(object_file), str(dispatch_object), "-o", str(dylib)],
                   check=True, capture_output=True)

    assembly = work / "stubs.s"
    with assembly.open("w") as stream:
        stream.write(".text\n")
        for target in sorted(targets):
            stream.write(f".globl _aps5_stub_{target:x}\n_aps5_stub_{target:x}:\n")
            stream.write(f"  movz x1, #{target & 0xffff}\n")
            for shift in (16, 32, 48):
                chunk = (target >> shift) & 0xffff
                if chunk:
                    stream.write(f"  movk x1, #{chunk}, lsl #{shift}\n")
            stream.write("  b _aps5_stub\n")
    stub_source = work / "stubs.c"
    stub_source.write_text(GENERIC_STUB)
    stubs = work / "stubs.dylib"
    subprocess.run(["xcrun", "clang", "-arch", "arm64", "-O2", "-dynamiclib", str(stub_source), str(assembly), "-o", str(stubs)],
                   check=True, capture_output=True)

    library = ctypes.CDLL(str(dylib))
    stub_library = ctypes.CDLL(str(stubs))
    entries = []
    for address, _code in codes:
        try:
            native = ctypes.cast(getattr(library, f"sub_{address:x}"), ctypes.c_void_p).value
        except AttributeError:
            continue
        entries.append((BASE + address, native))
    for target in sorted(targets):
        try:
            native = ctypes.cast(getattr(stub_library, f"aps5_stub_{target:x}"), ctypes.c_void_p).value
        except AttributeError:
            continue
        entries.append((BASE + target, native))
    entries.sort()
    table = (ctypes.c_uint64 * (2 * len(entries)))()
    for index, (guest, native) in enumerate(entries):
        table[2 * index] = guest
        table[2 * index + 1] = native
    register = library.NativeAotRegisterDispatch_nid_no_patch
    register.restype = None
    register.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    register(ctypes.byref(table), ctypes.c_size_t(len(entries)))

    libc = ctypes.CDLL(None)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    for region in (0x60000000, 0x70000000):
        libc.mmap(ctypes.c_void_p(BASE + region), 0x100000, 1 | 2, 0x02 | 0x1000 | 0x10, -1, 0)

    recorded_entries = load_entries(entries_path) if entries_path and entries_path.exists() else {}
    recorded_pages = load_pages(pages_path) if pages_path and pages_path.exists() else {}
    snapshot = load_snapshot(snapshot_path) if snapshot_path and snapshot_path.exists() else []
    print(f"recorded entries {len(recorded_entries)}, page sets {len(recorded_pages)}, snapshot regions {len(snapshot)}", flush=True)

    runner = replay.build_x86_runner(work)
    matched = mismatched = x86_fault = arm_fault = executed = 0
    details = []
    for address, _code in codes:
        recorded = recorded_entries.get(address)
        pages = snapshot if snapshot else recorded_pages.get(address)
        if recorded is not None:
            registers = {name: recorded[index] for index, name in enumerate(replay.UNIFORM_GPRS)}
        else:
            registers = {item: BASE + 0x60000000 for item in replay.UNIFORM_GPRS if item != "rsp"}
            registers["rsp"] = BASE + 0x700FFFF8
        host_pages = [(page + RECORD_BASE, data) for page, data in (pages or [])]
        for vaddr, data in host_pages:
            mapped = libc.mmap(ctypes.c_void_p(vaddr), len(data), 1 | 2, 0x02 | 0x1000 | 0x10, -1, 0)
            if mapped:
                ctypes.memmove(mapped, data, len(data))
        result_path = work / f"arm_{address:x}.bin"
        pid = os.fork()
        if pid == 0:
            try:
                regfile = (ctypes.c_uint64 * 123)()
                for index, name in enumerate(replay.UNIFORM_GPRS):
                    regfile[index] = registers.get(name, 0)
                function = getattr(library, f"sub_{address:x}")
                function.restype = None
                function.argtypes = [ctypes.c_void_p]
                function(ctypes.byref(regfile))
                result_path.write_bytes(regfile[0].to_bytes(8, "little"))
                os._exit(0)
            except BaseException:
                os._exit(1)
        _, status = os.waitpid(pid, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            arm_fault += 1
            continue
        executed += 1
        arm_rax = int.from_bytes(result_path.read_bytes(), "little")
        x86, code = replay.run_x86(work, runner, image, address, registers, bytes(1 << 16), host_pages)
        if x86 is None:
            x86_fault += 1
            continue
        if arm_rax == x86["rax"]:
            matched += 1
        else:
            mismatched += 1
            details.append({"function": hex(address), "arm64_rax": arm_rax, "x86_rax": x86["rax"]})
    report = {"compiled": len(compiled), "image": len(codes), "excluded": len(excluded),
              "executed": executed, "matched": matched, "mismatched": mismatched,
              "x86_fault": x86_fault, "arm64_fault": arm_fault, "mismatches": details[:100]}
    (out_dir / "dispatch-replay.json").write_text(json.dumps(report, indent=1))
    print(f"executed={executed} matched={matched} mismatched={mismatched} x86_fault={x86_fault} arm64_fault={arm_fault}")


if __name__ == "__main__":
    sys.exit(main())

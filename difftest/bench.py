#!/usr/bin/env python3
"""Microbenchmark: the AOT-compiled ARM64 body of a guest function against the original x86-64
body executed by Rosetta, with identical inputs.

Both sides call the function through the same memory register file (the uniform ABI the
differential harness uses) with the same data image, so the only difference is the machine code
that runs. Every callee the function reaches is neutralised on both sides: a direct callee is
declared `external` and linked as a stub that returns immediately, while on the x86 side its entry
byte becomes `ret`; an indirect call is lowered to `NativeAotDispatch` and resolves to the same
no-op stub, while on the x86 side every declared indirect target entry becomes `ret`. The
measurement is therefore the cost of the function's own generated code.

The entry state is a real one: the runtime's entry trace records the 16 GPRs and the memory pages
reachable from them at each hot-function entry, so a function runs on the data a real run had.

usage: bench.py <elf> <profile.json> <selection.json> <out-dir> <out.json>
                [--iterations N] [--seeds N] [--entries FILE] [--pages FILE]
"""
import json
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "core" / "aot"))
sys.path.insert(0, str(REPO / "difftest"))

import call_record  # noqa: E402
import difftest as harness  # noqa: E402
import full_state  # noqa: E402
import real_image  # noqa: E402
import replay  # noqa: E402
import title_profile  # noqa: E402

BASE = replay.BASE
SCRATCH_SIZE = 0x10000
PAGE = 0x1000
ENTRY_RECORD = 136  # entry address + 16 GPRs, in replay.REGISTERS order
ENTRY_PAGE_RECORD = 16 + 0x4000  # (entry, guest page) + 16 KiB of memory
DRIVER = Path(__file__).resolve().parent / "bench_driver.c"
DRIVER_TIMEOUT = 90

STUB_SOURCE = '''#include <stdint.h>
extern "C" void aps5_bench_noop(uint64_t* rf) { (void)rf; }
extern "C" void* NativeAotDispatch_nid_no_patch(uint64_t value) { (void)value; return (void*)&aps5_bench_noop; }
extern "C" void NativeAotReportDispatchFailure_nid_no_patch(uint64_t site, uint64_t value) {
    (void)site; (void)value;
}
extern "C" void* NativeAotTlsBase_nid_no_patch(void) { return 0; }
extern "C" void NativeAotRegisterDispatch_nid_no_patch(const void* entries, unsigned long count) {
    (void)entries; (void)count;
}
extern "C" void NativeAotMapImage_nid_no_patch(void*, unsigned long) {}
extern "C" void NativeAotApplyRelocations_nid_no_patch(void* const*, unsigned long) {}
extern "C" void Aps5GuestTlsRegister_nid_no_patch(void*) {}
'''


def stub_source(externals):
    lines = ['#include <stdint.h>', 'extern "C" {']
    for address in externals:
        lines.append(f'void sub_{address:x}(uint64_t* rf) {{ (void)rf; }}')
    lines.append('}')
    return "\n".join(lines) + "\n" + STUB_SOURCE


def merge_regions(pieces):
    """Page-aligned, non-overlapping regions from (vaddr, bytes) pieces; a later piece wins."""
    ordered = sorted(((vaddr, vaddr + len(data), bytearray(data)) for vaddr, data in pieces),
                     key=lambda item: item[0])
    merged = []
    for start, end, data in ordered:
        if merged and start <= merged[-1][1]:
            previous_start, previous_end, previous_data = merged[-1]
            end = max(end, previous_end)
            buffer = previous_data + bytearray(max(0, end - previous_start - len(previous_data)))
            offset = start - previous_start
            buffer[offset:offset + len(data)] = data
            merged[-1] = (previous_start, end, buffer)
        else:
            merged.append((start, end, data))
    regions = []
    for start, end, data in merged:
        aligned_start = start & ~(PAGE - 1)
        aligned_end = (end + PAGE - 1) & ~(PAGE - 1)
        buffer = bytearray(aligned_start & (PAGE - 1)) + data + bytearray((-aligned_end) & (PAGE - 1))
        regions.append((aligned_start, bytes(buffer)))
    return regions


def segment_blob(regions):
    stream = bytearray(struct.pack("<I", len(regions)))
    for vaddr, data in regions:
        stream += struct.pack("<QQQ", vaddr, len(data), len(data))
        stream += data
    return bytes(stream)


def image_regions(elf, profile):
    segments = real_image.segments(elf)
    segments = real_image.patch(segments, profile.relocations)
    segments = real_image.saturate(segments, random.Random(0x5EED))
    pieces = [(vaddr, data.ljust(memsz, b"\0")) for vaddr, _filesz, memsz, data, _flags in segments]
    return merge_regions(pieces)


IMAGE_END = 0x9c2ba50


def covered(value, pages):
    """True when a recorded register value is a small integer, inside the image, or on a captured
    page: the three cases where the replay can dereference it."""
    if value < 0x10000 or BASE <= value < BASE + IMAGE_END:
        return True
    page = (value & ~0x3fff) - BASE
    return page in pages or (page - 0x4000) in pages


def load_entry_states(path, pages, limit=8):
    """{entry address: [{register: value}, ...]} from the runtime's entry trace, preferring the
    records whose pointer registers the captured pages actually cover (a record that dereferences
    an uncaptured page faults on both sides and measures nothing)."""
    data = Path(path).read_bytes()
    states = {}
    for offset in range(0, len(data) - ENTRY_RECORD + 1, ENTRY_RECORD):
        entry = struct.unpack_from("<Q", data, offset)[0]
        bucket = states.setdefault(entry, {"good": [], "first": []})
        if len(bucket["good"]) >= limit:
            continue
        values = dict(zip(replay.REGISTERS, struct.unpack_from("<16Q", data, offset + 8)))
        entry_pages = pages.get(entry, {})
        if all(covered(value, entry_pages) for name, value in values.items() if name != "rsp"):
            bucket["good"].append(values)
        elif len(bucket["first"]) < limit:
            bucket["first"].append(values)
    return {entry: (bucket["good"] or bucket["first"]) for entry, bucket in states.items()}


def load_entry_pages(path):
    """{entry address: {guest page vaddr: bytes}} from the runtime's page capture."""
    data = Path(path).read_bytes()
    pages = {}
    for offset in range(0, len(data) - ENTRY_PAGE_RECORD + 1, ENTRY_PAGE_RECORD):
        entry, page = struct.unpack_from("<QQ", data, offset)
        pages.setdefault(entry, {})[page] = data[offset + 16:offset + ENTRY_PAGE_RECORD]
    return pages


def overlay_pages(regions, pages):
    """The captured pages on top of the image regions, plus any page outside them."""
    result = list(regions)
    extra = []
    for page, data in sorted(pages.items()):
        placed = False
        for index, (start, buffer) in enumerate(result):
            if start <= page and page + len(data) <= start + len(buffer):
                patched = bytearray(buffer)
                offset = page - start
                patched[offset:offset + len(data)] = data
                result[index] = (start, bytes(patched))
                placed = True
                break
        if not placed and not any(start < page + len(data) and page < start + len(buffer)
                                 for start, buffer in result):
            extra.append((page, data))
    return result + extra


def build_drivers(directory):
    arm = directory / "bench_arm"
    x86 = directory / "bench_x86"
    if not arm.exists():
        subprocess.run(["xcrun", "clang", "-arch", "arm64", "-O1", str(DRIVER), "-o", str(arm)],
                       check=True, capture_output=True)
    if not x86.exists():
        subprocess.run(["xcrun", "clang", "-arch", "x86_64", "-O1", "-DBENCH_X86", str(DRIVER), "-o", str(x86)],
                       check=True, capture_output=True)
    return arm, x86


def build_arm_dylib(directory, ir, externals):
    from toolchain import build_native_object
    build_native_object(ir, directory / "native.o")
    (directory / "stubs.cc").write_text(stub_source(externals))
    subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-O2", "-c", str(directory / "stubs.cc"),
                    "-o", str(directory / "stubs.o")], check=True, capture_output=True)
    subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-dynamiclib", str(directory / "native.o"),
                    str(directory / "stubs.o"), "-o", str(directory / "native.dylib")],
                   check=True, capture_output=True)
    return directory / "native.dylib"


def parse_timing(text):
    values = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            values[parts[0]] = float(parts[1])
    return values


def write_regfile(path, registers, order):
    path.write_bytes(b"".join(int(registers.get(name, 0)).to_bytes(8, "little") for name in order))


def compare_states(arm, x86):
    """GPRs (each side's own order), flags the ABI defines, and the scratch window."""
    arm_gprs = struct.unpack_from("<16Q", arm, 0)
    x86_gprs = struct.unpack_from("<16Q", x86, 0)
    differences = []
    arm_flags = struct.unpack_from("<Q", arm, 128)[0]
    x86_flags = struct.unpack_from("<Q", x86, 128)[0]
    arm_mask = struct.unpack_from("<Q", arm, 136)[0]
    defined = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11)
    if (arm_flags ^ x86_flags) & arm_mask & defined:
        differences.append(f"flags: arm={arm_flags & arm_mask & defined:#x} x86={x86_flags & arm_mask & defined:#x}")
    for index, name in enumerate(replay.UNIFORM_GPRS):
        if name == "rsp":
            continue
        arm_value = arm_gprs[index]
        x86_value = x86_gprs[replay.REGISTERS.index(name)]
        if arm_value == x86_value:
            continue
        if arm_value in ((x86_value - BASE) & 0xffffffffffffffff, x86_value):
            continue
        differences.append(f"{name}: arm={arm_value:#x} x86={x86_value:#x}")
    arm_scratch = arm[144:144 + SCRATCH_SIZE]
    x86_scratch = x86[144:144 + SCRATCH_SIZE]
    for index in range(SCRATCH_SIZE):
        if arm_scratch[index] != x86_scratch[index]:
            differences.append(f"memory@{index:#x}: arm={arm_scratch[index]:#x} x86={x86_scratch[index]:#x}")
            break
    return differences


def bench_one(address, seed, profile, elf, directory, iterations, base_regions, entry_states, entry_pages):
    title = harness.Title(elf)
    sizes = profile.sizes
    if not profile.has(address):
        return {"status": "not-in-profile"}
    size = sizes[address]
    sites = [site for site in call_record.find_sites(title, sizes, address)
             if site["target"] in sizes and sizes[site["target"]]
             and not (address <= site["target"] < address + size)]
    callees = sorted({site["target"] for site in sites})
    external = set(callees)
    result = harness.compile_one(title, sizes, address, 0, directory, uniform=True,
                                 functions=[address] + callees, external=external, profile=profile,
                                 dispatch=True, guest_data=True, guest_base=BASE,
                                 declare_target_sets=False)
    if result["status"] != "compiled":
        return {"status": "rejected", "reason": result.get("reason", "")[:120]}
    try:
        dylib = build_arm_dylib(directory, result["ir"], external)
    except subprocess.CalledProcessError as error:
        return {"status": "link-failed",
                "reason": (error.stderr or b"").decode(errors="replace")[-300:]}
    # The x86 side neutralises the same callees: their entry byte becomes `ret`. Every declared
    # indirect target of the function is included, because the ARM side resolves all of them to
    # the no-op dispatch stub.
    patched = set(external)
    for _site, index, _kind in profile.indirect_records(address):
        patched.update(target for target in profile.targets_of(index)
                       if profile.has(target) and not (address <= target < address + size))
    patched -= {address}
    states = entry_states.get(address) or [None]
    recorded = states[seed % len(states)]
    regions = overlay_pages(base_regions, entry_pages.get(address, {})) if recorded else base_regions
    rng = random.Random(seed)
    registers, memory = full_state.realistic_state(rng, (), recorded)
    registers["rsp"] = full_state.RUNNER_ENTRY_RSP
    arm_driver, x86_driver = build_drivers(directory)
    (directory / "segments.bin").write_bytes(segment_blob(regions))
    (directory / "scratch.bin").write_bytes(memory)
    (directory / "stubs.txt").write_text("\n".join(f"{target:x}" for target in sorted(patched)))
    write_regfile(directory / "rf_arm.bin", registers, replay.UNIFORM_GPRS)
    write_regfile(directory / "rf_x86.bin", registers, replay.REGISTERS)
    try:
        arm = subprocess.run([str(arm_driver), str(dylib), f"sub_{address:x}", str(iterations),
                              str(directory / "rf_arm.bin"), str(directory / "scratch.bin"),
                              str(directory / "out_arm.bin"), str(directory / "segments.bin")],
                             capture_output=True, timeout=DRIVER_TIMEOUT)
        x86 = subprocess.run([str(x86_driver), str(directory / "segments.bin"), hex(address),
                              str(directory / "stubs.txt"), str(iterations),
                              str(directory / "rf_x86.bin"), str(directory / "scratch.bin"),
                              str(directory / "out_x86.bin"), hex(size)],
                             capture_output=True, timeout=DRIVER_TIMEOUT)
    except subprocess.TimeoutExpired as expired:
        # A function whose entry state sends it into a loop never returns; report it instead of
        # failing the whole selection.
        return {"status": "timeout", "driver": Path(expired.cmd[0]).name}
    if arm.returncode != 0 and x86.returncode != 0:
        return {"status": "both-fault", "arm_code": arm.returncode, "x86_code": x86.returncode}
    if arm.returncode != 0:
        return {"status": "arm-fault", "code": arm.returncode,
                "stderr": arm.stderr.decode(errors="replace")[-200:]}
    if x86.returncode != 0:
        return {"status": "x86-fault", "code": x86.returncode,
                "stderr": x86.stderr.decode(errors="replace")[-200:]}
    arm_timing = parse_timing(arm.stdout.decode())
    x86_timing = parse_timing(x86.stdout.decode())
    differences = compare_states((directory / "out_arm.bin").read_bytes(),
                                 (directory / "out_x86.bin").read_bytes())
    arm_ns = arm_timing["ns_per_call"]
    x86_ns = x86_timing["ns_per_call"]
    return {"status": "ok" if not differences else "divergent",
            "arm_ns": round(arm_ns, 2), "x86_ns": round(x86_ns, 2),
            "ratio": round(x86_ns / arm_ns, 3) if arm_ns else None,
            "iterations": int(arm_timing["iterations"]),
            "callees": len(callees), "patched": len(patched),
            "differences": differences[:4]}


def main():
    elf, profile_path, selection_path, out_dir, out_path = sys.argv[1:6]
    rest = sys.argv[6:]
    iterations = 0
    seeds = 1
    entries_path = None
    pages_path = None
    if "--iterations" in rest:
        iterations = int(rest[rest.index("--iterations") + 1])
    if "--seeds" in rest:
        seeds = int(rest[rest.index("--seeds") + 1])
    if "--entries" in rest:
        entries_path = rest[rest.index("--entries") + 1]
    if "--pages" in rest:
        pages_path = rest[rest.index("--pages") + 1]
    profile = title_profile.Profile.load(profile_path)
    selection = json.loads(Path(selection_path).read_text())
    entry_states = load_entry_states(entries_path, load_entry_pages(pages_path)) if entries_path else {}
    entry_pages = load_entry_pages(pages_path) if pages_path else {}
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    base_regions = image_regions(elf, profile)
    results = {}
    for item in selection:
        address = int(item["function"], 16)
        entry = {"hits": item.get("hits")}
        for seed in range(seeds):
            directory = Path(tempfile.mkdtemp(prefix=f"bench-{address:x}-", dir=out_dir))
            try:
                entry[f"seed{seed}"] = bench_one(address, seed, profile, elf, directory, iterations,
                                                 base_regions, entry_states, entry_pages)
            finally:
                shutil.rmtree(directory, ignore_errors=True)
        results[item["function"]] = entry
        print(json.dumps({item["function"]: entry}), flush=True)
    Path(out_path).write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""The real module image, mapped for the differential harness.

The synthetic contract only maps the closure's own code and the data regions it references; with
``guest_data`` the compiler instead references title data at ``guest_base + vaddr``. Both runners
must therefore map the real eboot's PT_LOAD segments at ``BASE + vaddr`` and have the profile's
pointer relocations already applied, so a relocated function pointer is the guest address the
native dispatch table is keyed by (``guest_base + target``).

Nothing here is title-specific: the ELF path comes from the caller.
"""
import ctypes
import hashlib
import io
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile

BASE = 0x140000000
PAGE = 0x1000


def sha256(elf_path):
    return hashlib.sha256(Path(elf_path).read_bytes()).hexdigest()


def segments(elf_path):
    """[(vaddr, filesz, memsz, data, flags)] for every PT_LOAD with a nonzero memory size."""
    raw = Path(elf_path).read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    found = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or segment["p_memsz"] == 0:
            continue
        offset = segment["p_offset"]
        found.append((segment["p_vaddr"], segment["p_filesz"], segment["p_memsz"],
                      raw[offset:offset + segment["p_filesz"]], segment["p_flags"]))
    return found


def patch(segments_list, relocations, base=BASE):
    """Apply (slot, target) pointer relocations: the slot holds the guest address of the target."""
    import bisect
    starts = [segment[0] for segment in segments_list]
    data = [bytearray(segment[3]) for segment in segments_list]
    for slot, target in relocations:
        index = bisect.bisect_right(starts, slot) - 1
        if index < 0:
            continue
        offset = slot - starts[index]
        if offset + 8 > segments_list[index][1]:
            continue
        data[index][offset:offset + 8] = (base + target).to_bytes(8, "little")
    return [(segment[0], segment[1], segment[2], bytes(data[index]), segment[4])
            for index, segment in enumerate(segments_list)]


def blob(segments_list):
    """The x86 runner's segment stream (BASE-relative vaddr, as the synthetic path writes it)."""
    stream = io.BytesIO()
    stream.write(struct.pack("<I", len(segments_list)))
    for vaddr, filesz, memsz, data, _flags in sorted(segments_list):
        stream.write(struct.pack("<QQQ", vaddr, filesz, memsz))
        stream.write(data)
    return stream.getvalue()


def saturate(segments_list, rng, base=BASE, extra=()):
    """Seed the zero 8-byte slots of the writable segments with pointers into mapped memory.

    The title initialises its own globals at run time, which the harness never does, so a global
    pointer is zero and the first `mov reg, [rip+disp]; mov reg, [reg]` faults in both runners.
    A real process does not look like that: an initialised global pointer names a mapped object.
    Giving those slots plausible pointers lets the guest follow them instead of stopping at null.
    The writable data is extended to its full memory size so an uninitialised global is covered.
    """
    spans = [(base + vaddr, memsz) for vaddr, _filesz, memsz, _data, flags in segments_list
             if flags & 2 and memsz >= 16]
    spans.extend(extra)
    if not spans:
        return segments_list
    out = []
    for vaddr, filesz, memsz, data, flags in segments_list:
        if not flags & 2 or memsz < 8:
            out.append((vaddr, filesz, memsz, data, flags))
            continue
        buffer = bytearray(memsz)
        buffer[:filesz] = data
        for offset in range(0, memsz - 7, 8):
            if int.from_bytes(buffer[offset:offset + 8], "little"):
                continue
            start, size = spans[rng.randrange(len(spans))]
            buffer[offset:offset + 8] = (start + 8 * rng.randrange(size // 8)).to_bytes(8, "little")
        out.append((vaddr, memsz, memsz, bytes(buffer), flags))
    return out


def map_range(libc, start, end):
    """Map [start, end) (BASE-relative) in this process.

    A small run (a recorded heap page) may already be mapped by the process's own layout, and
    `MAP_FIXED` would replace it, so each page is checked with `mincore` first; a large run is the
    image and is always free. `mincore` fails with ENOMEM on an unmapped page.
    """
    if end - start > 0x10000:
        pointer = libc.mmap(ctypes.c_void_p(start), end - start, 3, 0x02 | 0x1000 | 0x10, -1, 0)
        if pointer in (None, ctypes.c_void_p(-1).value, (1 << 64) - 1):
            raise RuntimeError(f"cannot map the image at {start:#x}")
        return
    vector = ctypes.create_string_buffer(1)
    for address in range(start, end, PAGE):
        if libc.mincore(ctypes.c_void_p(address), ctypes.c_size_t(PAGE), vector) == 0:
            continue
        pointer = libc.mmap(ctypes.c_void_p(address), PAGE, 3, 0x02 | 0x1000 | 0x10, -1, 0)
        if pointer in (None, ctypes.c_void_p(-1).value, (1 << 64) - 1):
            raise RuntimeError(f"cannot map the image at {address:#x}")


def map_segments(segments_list, base=BASE):
    """Map the union of the segments at BASE + vaddr and copy the bytes in (child process only).

    Sorted by vaddr and mapped as contiguous runs, because the recorded heap puts pages tens of GB
    from the image and one union mapping would reserve the whole span.
    """
    if not segments_list:
        return
    libc = ctypes.CDLL(None)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                          ctypes.c_int, ctypes.c_long]
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]
    pages = set()
    for vaddr, _filesz, memsz, _data, _flags in segments_list:
        start = vaddr & ~(PAGE - 1)
        for address in range(start, start + (vaddr & (PAGE - 1)) + memsz, PAGE):
            pages.add(address)
    run_start = run_end = None
    for address in sorted(pages) + [None]:
        if address is not None and run_end is not None and address == run_end:
            run_end = address + PAGE
            continue
        if run_start is not None:
            map_range(libc, base + run_start, base + run_end)
        if address is None:
            break
        run_start, run_end = address, address + PAGE
    for vaddr, filesz, _memsz, data, _flags in segments_list:
        if filesz:
            ctypes.memmove(base + vaddr, data, filesz)

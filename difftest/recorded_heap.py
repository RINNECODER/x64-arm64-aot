#!/usr/bin/env python3
"""The real run's heap pages, so a pointer into the title's heap resolves in the harness.

The trace build snapshots 16 KB pages reachable from the entry pointer registers to `<trace>.pages`
as `(entry, guest page, data)` records, where `guest page = host page - BASE`. Those pages hold the
title's real heap objects, including vtables whose slots are image pointers the dispatch table can
resolve; a synthetic entry state can only invent garbage there. `build` compacts the stream
(deduplicated by page, first snapshot wins) into `ANYPS5_AOT_HEAP`; `load` returns
`{guest page: data}`. Everything here is title-derived and lives under the work directory.
"""
import os
import struct
from pathlib import Path

PAGE = 0x4000
RECORD = 16 + PAGE


def build(raw_path, out_path):
    """Compact a raw `<trace>.pages` stream into `{page: data}` and write it out."""
    data = Path(raw_path).read_bytes()
    pages = {}
    for offset in range(0, len(data) - RECORD + 1, RECORD):
        _entry, page = struct.unpack_from("<QQ", data, offset)
        pages.setdefault(page, data[offset + 16:offset + 16 + PAGE])
    payload = bytearray(struct.pack("<I", len(pages)))
    for page in sorted(pages):
        payload += struct.pack("<Q", page) + pages[page]
    Path(out_path).write_bytes(bytes(payload))
    return len(pages)


def load(path=None):
    """{guest page: 16 KB of data} from a compacted store, empty when the store is absent."""
    value = path or os.environ.get("ANYPS5_AOT_HEAP") or ""
    path = Path(value)
    if not value or not path.exists():
        return {}
    data = path.read_bytes()
    count, = struct.unpack_from("<I", data, 0)
    pages, offset = {}, 4
    for _ in range(count):
        page, = struct.unpack_from("<Q", data, offset)
        pages[page] = data[offset + 8:offset + 8 + PAGE]
        offset += 8 + PAGE
    return pages


def segments(pages, image_segments, base):
    """[(guest vaddr, filesz, memsz, data)] for heap pages that the image does not already map."""
    spans = [(base + vaddr, memsz) for vaddr, _filesz, memsz, _data, _flags in image_segments]
    found = []
    for page in sorted(pages):
        address = base + page
        if any(low <= address < low + size for low, size in spans):
            continue
        found.append((page, PAGE, PAGE, pages[page], 3))
    return found


def pointer_slots(pages, image_segments, base):
    """Guest addresses of heap 8-byte slots that hold a mapped pointer.

    A guest that loads one of these as a field gets a pointer into mapped, real memory, so a
    load-then-dereference chain stays valid and an indirect call through it reaches a real image
    address the dispatch table resolves.
    """
    spans = [(base + vaddr, memsz) for vaddr, _filesz, memsz, _data, _flags in image_segments]
    spans.extend((base + page, PAGE) for page in pages)
    found = []
    for page in sorted(pages):
        data = pages[page]
        for offset in range(0, PAGE - 7, 8):
            value = int.from_bytes(data[offset:offset + 8], "little")
            if value and any(low <= value < low + size for low, size in spans):
                found.append(base + page + offset)
    return found


def saturate(segments_list, pages, rng, base):
    """Seed the zero 8-byte slots of the writable segments with addresses of heap pointer slots.

    The title initialises its own globals at run time, which the harness never does, so a global
    pointer is zero and the first `mov reg, [global]; mov reg, [reg]` faults in both runners. A real
    process does not look like that. Seeding with a *heap* pointer slot rather than an address in
    the image's own bytes is what keeps the chain coherent: the heap slot holds a real image pointer.
    """
    slots = pointer_slots(pages, segments_list, base)
    if not slots:
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
            buffer[offset:offset + 8] = slots[rng.randrange(len(slots))].to_bytes(8, "little")
        out.append((vaddr, memsz, memsz, bytes(buffer), flags))
    return out

"""Contract: the x86 reference runner maps the synthetic image faithfully.

The synthetic image builder emits one segment per function, and adjacent functions land in the
same 4 KiB page.  The runner must execute every segment's bytes, not only the last one mapped.

Regression: the runner mapped each segment with a page-granular ``MAP_FIXED`` mmap.  When two
segments shared a page, the second mmap replaced the page the first segment had been copied
into, so the x86 side executed zeroed memory and reported false mismatches -- for example a
data segment at ``0x1000`` and the routine that reads it at ``0x1080`` both live in page
``0x1000``.

Existing coverage missed it because the campaign's synthetic images usually place one function
per page, and the one that shared a page was read as a compiler miscompile rather than a runner
fault.

Run explicitly (the lane gate only runs ``core/aot/tests``)::

    ANYPS5_NATIVE_WORK=<work> python3.13 -m pytest difftest/test_runner_segments.py
"""
import os
import struct
import subprocess
import sys
from pathlib import Path

import pytest

# full_state resolves the title work directory at import; this test needs none of it.
os.environ.setdefault("ANYPS5_ELF", __file__)
os.environ.setdefault("ANYPS5_FDE_STARTS", __file__)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import full_state  # noqa: E402

# mov al, byte ptr [BASE + 0x1000] ; mov byte ptr [SCRATCH], al ; ret
CODE = bytes.fromhex("a00010004001000000" "a2000000a001000000" "c3")


def segments(entries):
    """Serialize the runner's segment table: count, then (vaddr, filesz, memsz, bytes) each."""
    stream = bytearray(struct.pack("<I", len(entries)))
    for vaddr, data in entries:
        stream += struct.pack("<QQQ", vaddr, len(data), len(data))
        stream += data
    return bytes(stream)


def test_runner_keeps_a_segment_in_a_shared_page(tmp_path):
    if not Path("/usr/bin/xcrun").exists():
        pytest.skip("xcrun is required to build the x86 reference runner")
    runner = full_state.build_runner(tmp_path)
    # Two segments in page 0x1000: the data first, the code that reads it second.
    (tmp_path / "segments.bin").write_bytes(
        segments([(0x1000, b"\x5a" + bytes(7)), (0x1080, CODE)]))
    (tmp_path / "case.bin").write_bytes(bytes(128))
    (tmp_path / "pages.bin").write_bytes(bytes(full_state.SCRATCH_SIZE))
    completed = subprocess.run([str(runner), str(tmp_path / "segments.bin"), "0x1080",
                                str(tmp_path / "case.bin"), str(tmp_path / "out.bin"),
                                str(tmp_path / "pages.bin")], capture_output=True)
    assert completed.returncode == 0, completed.stderr
    scratch = (tmp_path / "out.bin").read_bytes()[136 + 512 + 256:]
    assert scratch[0] == 0x5a

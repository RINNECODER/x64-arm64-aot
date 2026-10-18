import hashlib
import re
import struct
import unittest
from pathlib import Path

import guest_layout
import test_compiler
import test_uniform
from compiler import Image, compile_image

HEADER = (Path(__file__).resolve().parents[2] / "libs" / "prx" / "libc" / "include" /
          "GuestLayout.hpp")

# The C++ names that must match the Python mirror in guest_layout.py.
CONSTANTS = {
    'ApplicationAreaStart': guest_layout.APPLICATION_AREA_START,
    'SystemReservedStart': guest_layout.SYSTEM_RESERVED_START,
    'SystemReservedEnd': guest_layout.SYSTEM_RESERVED_END,
    'ApplicationAreaEnd': guest_layout.APPLICATION_AREA_END,
    'MacOsRefusedStart': guest_layout.MACOS_REFUSED_START,
    'MacOsRefusedEnd': guest_layout.MACOS_REFUSED_END,
    'NativeSlide': guest_layout.NATIVE_GUEST_BASE,
}


def header_constants():
    text = HEADER.read_text()
    found = {}
    for name in CONSTANTS:
        match = re.search(rf'\b{name}\s*=\s*(0x[0-9A-Fa-f]+)ull', text)
        assert match, f'{name} is not a hexadecimal constant in {HEADER}'
        found[name] = int(match.group(1), 16)
    return found


class GuestLayoutTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp

    def test_header_and_python_mirror_agree(self):
        # The compiler (guest_layout.py) and the HLE libs (GuestLayout.hpp) must use one slide;
        # a drift silently puts the guest heap outside the mapped image.
        self.assertEqual(header_constants(), CONSTANTS)

    def test_native_slide_clears_the_macos_refused_range(self):
        # macOS refuses fixed mappings in [64 GiB, 512 GiB); the whole guest address space must
        # land above it, or the arena commits with MAP_FIXED into an unmappable range.
        arena_start, arena_end = guest_layout.arena_range()
        self.assertGreaterEqual(arena_start, guest_layout.MACOS_REFUSED_END)
        self.assertGreater(arena_end, arena_start)
        self.assertEqual(arena_start, guest_layout.NATIVE_GUEST_BASE + guest_layout.APPLICATION_AREA_START)
        self.assertEqual(arena_end, guest_layout.NATIVE_GUEST_BASE + guest_layout.APPLICATION_AREA_END)

    def test_guest_data_image_translates_to_the_native_slide(self):
        # `mov byte ptr [0x5ff8], 0x58 ; ret` addresses a segment tail absolutely. With guest_data
        # the compiler references it at guest_base + vaddr, so the runtime maps the title image and
        # the HLE arena at the same slide.
        code = bytes.fromhex('c60425f85f000058c3')
        raw, contracts = test_uniform.fixture(code, [test_uniform.uniform_function('sub_1000', 0x1000, len(code))])
        image = bytearray(raw)
        struct.pack_into('<Q', image, 120 + 40, 0x6000)  # data segment p_memsz > p_filesz
        image = bytes(image)
        contracts = dict(contracts, data=[], guest_data=True, guest_base=guest_layout.NATIVE_GUEST_BASE,
                         sha256=hashlib.sha256(image).hexdigest())
        source = self.directory / 'input.elf'
        source.write_bytes(image)
        ir, report = compile_image(Image(source, contracts))
        self.assertEqual(report['unimplemented_functions'], 0)
        self.assertIn(f'inttoptr (i64 {guest_layout.NATIVE_GUEST_BASE + 0x5ff8} to ptr)', ir)
        # The runtime maps the data segment at the slid vaddr, not the raw one.
        self.assertIn(str(guest_layout.NATIVE_GUEST_BASE + 0x2000), ir)


if __name__ == '__main__':
    unittest.main()

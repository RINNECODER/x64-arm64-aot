import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path

MODULE = (Path(__file__).resolve().parents[3] / 'tools' / 'native' / 'contracts'
          / 'generate_contracts.py')
if not MODULE.exists():
    raise unittest.SkipTest(f'{MODULE} is not exported to this checkout')
_spec = importlib.util.spec_from_file_location('generate_contracts', MODULE)
generate_contracts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_contracts)

BASE = 0x400000
PHOFF = 64
PHENTSIZE = 56


def build_elf(phdrs, size, entry=0):
    raw = bytearray(size)
    struct.pack_into('<16sHHIQQQIHHHHHH', raw, 0, b'\x7fELF\x02\x01\x01' + bytes(9),
                     3, 62, 1, entry, PHOFF, 0, 0, 64, PHENTSIZE, len(phdrs), 64, 0, 0)
    for index, (kind, flags, offset, vaddr, filesz, memsz, align) in enumerate(phdrs):
        struct.pack_into('<IIQQQQQQ', raw, PHOFF + index * PHENTSIZE,
                         kind, flags, offset, vaddr, vaddr, filesz, memsz, align)
    return raw


def load(raw):
    with tempfile.NamedTemporaryFile(suffix='.elf') as handle:
        handle.write(raw)
        handle.flush()
        return generate_contracts.load_elf(handle.name)


class DynamicLessElf(unittest.TestCase):
    def test_executable_elf_without_dynamic_table_is_not_an_error(self):
        raw = build_elf([(1, 5, 0x1000, BASE + 0x1000, 0x100, 0x100, 0x1000)], 0x1200, BASE + 0x1000)
        _raw, phdrs, _entry = load(raw)
        pointer_relocations, imports, data = generate_contracts.parse_dynamic(_raw, phdrs)
        self.assertEqual((pointer_relocations, imports), ([], {}))
        self.assertEqual(data, [])

    def test_dynamic_table_without_relocations_is_not_an_error(self):
        size = 0x1000
        strings = b'\0abc\0'
        raw = build_elf([(1, 6, 0, BASE, size, size, 0x1000),
                         (2, 6, 0x180, BASE + 0x180, 0x60, 0x60, 8)], size)
        raw[0x200:0x200 + len(strings)] = strings
        raw[0x300] = 0x01
        tags = [(5, BASE + 0x200), (11, 24), (6, BASE + 0x300), (10, len(strings)), (0, 0)]
        for index, (tag, value) in enumerate(tags):
            struct.pack_into('<qQ', raw, 0x180 + index * 16, tag, value)
        _raw, phdrs, _entry = load(raw)
        pointer_relocations, imports, data = generate_contracts.parse_dynamic(_raw, phdrs)
        self.assertEqual((pointer_relocations, imports), ([], {}))
        self.assertEqual(data, [{'address': BASE, 'size': size}])


if __name__ == '__main__':
    unittest.main()

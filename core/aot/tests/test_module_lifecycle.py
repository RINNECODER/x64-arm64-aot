import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from compiler import Image, Rejected, compile_image
from test_compiler import fixture


def lifecycle_fixture():
    functions = [{'name': 'callback_' + str(index), 'address': 0x1000 + index * 16, 'size': 1,
                  'parameters': [], 'result': 'void'} for index in range(5)]
    code = b'\xc3' + (b'\x90' * 15 + b'\xc3') * 4
    pointers = [(0x2800, 0x1010), (0x2808, 0x1020), (0x2810, 0x1010), (0x2818, 0x1020), (0x2820, 0x1040)]
    raw, contracts = fixture(code, functions=functions, relocations=pointers)
    raw = bytearray(raw)
    tags = []
    for offset in range(0x2400, 0x2500, 16):
        tag, value = struct.unpack_from('<qQ', raw, offset)
        if not tag:
            break
        tags.append((tag, value))
    tags += [(12, 0x1000), (13, 0x1030), (25, 0x2800), (27, 16), (26, 0x2810), (28, 16), (32, 0x2820), (33, 8), (0, 0)]
    for index, pair in enumerate(tags):
        struct.pack_into('<qQ', raw, 0x3000 + index * 16, *pair)
    struct.pack_into('<IIQQQQQQ', raw, 176, 2, 6, 0x3000, 0x3000, 0, len(tags) * 16, len(tags) * 16, 8)
    contracts.update(sha256=hashlib.sha256(raw).hexdigest(), module_image=True, bundle_main=True, lifecycle={'owner': 'bundle'})
    return raw, contracts


class ModuleLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'input.elf'

    def image(self, raw, contracts):
        self.path.write_bytes(raw)
        return Image(self.path, dict(contracts, sha256=hashlib.sha256(raw).hexdigest()))

    def test_preinit_init_fini_order_comes_from_validated_elf(self):
        image = self.image(*lifecycle_fixture())
        _, report = compile_image(image)
        self.assertEqual(report['module_lifecycle'], {'preinit': ['callback_4'],
                         'init': ['callback_0', 'callback_1', 'callback_2'],
                         'fini': ['callback_2', 'callback_1', 'callback_3']})

    def test_shared_module_cannot_take_main_preinit_role(self):
        raw, contracts = lifecycle_fixture()
        contracts['bundle_main'] = False
        with self.assertRaisesRegex(Rejected, 'only the main'):
            self.image(raw, contracts)

    def test_callback_signature_and_noreturn_must_be_qualified(self):
        for change in ({'parameters': ['ptr']}, {'result': 'i32'}, {'noreturn': True}):
            raw, contracts = lifecycle_fixture()
            contracts['functions'][1].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(Rejected, 'lifecycle callback'):
                self.image(raw, contracts)

    def test_initializer_pointer_must_be_relocated_to_known_native_code(self):
        raw, contracts = lifecycle_fixture()
        struct.pack_into('<q', raw, 0x2380 + 16, 0x2900)
        contracts['pointer_relocations'][0] = (0x2800, 0x2900)
        with self.assertRaisesRegex(Rejected, 'lifecycle callback'):
            self.image(raw, contracts)

    def test_array_extent_must_be_pointer_sized_and_mapped(self):
        for tag, value, error in ((27, 15, 'array extent'), (25, 0x4ff8, 'pointer contract'), (25, 0, 'no address')):
            raw, contracts = lifecycle_fixture()
            for offset in range(0x3000, 0x3200, 16):
                if struct.unpack_from('<q', raw, offset)[0] == tag:
                    struct.pack_into('<Q', raw, offset + 8, value)
                    break
            with self.subTest(tag=tag, value=value), self.assertRaisesRegex(Rejected, error):
                self.image(raw, contracts)

    def test_old_entry_owned_profile_still_rejects_arrays(self):
        raw, contracts = lifecycle_fixture()
        contracts['lifecycle'] = {'owner': 'entry', 'init': 0x1000, 'fini': 0x1030}
        with self.assertRaisesRegex(Rejected, 'initializer arrays'):
            self.image(raw, contracts)


if __name__ == '__main__':
    unittest.main()

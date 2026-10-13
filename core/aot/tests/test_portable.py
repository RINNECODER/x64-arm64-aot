import hashlib
import struct
import unittest

import test_compiler
from compiler import Image, Rejected, compile_image
from toolchain import build_native_object


class PortableTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp

    def lower(self, raw, contracts):
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        return compile_image(Image(source, contracts))

    def test_cross_compilation_produces_apple_arm64_machine_code(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('4889f84801f0c3'), ['u64', 'u64'], result='u64')
        ir, report = self.lower(raw, contracts)
        output = self.directory / 'native.o'
        result = build_native_object(ir, output)
        self.assertEqual(struct.unpack_from('<III', output.read_bytes())[:2], (0xfeedfacf, 0x100000c))
        self.assertEqual(result['machine_state_allocas'], 0)
        optimized = output.with_suffix('.optimized.ll').read_text()
        self.assertIn('add i64', optimized)
        self.assertNotIn('alloca', optimized)
        self.assertEqual(report['input_sha256'], hashlib.sha256(raw).hexdigest())

    def test_linux_validation_target_produces_arm64_elf(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('4889f84801f0c3'), ['u64', 'u64'], result='u64')
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, report = compile_image(Image(source, contracts, 'linux-arm64'))
        self.assertEqual(report['target'], 'linux-arm64')
        output = self.directory / 'native.o'
        result = build_native_object(ir, output, 'linux-arm64')
        self.assertEqual(output.read_bytes()[:6], b'\x7fELF\x02\x01')
        self.assertEqual(struct.unpack_from('<HH', output.read_bytes(), 16), (1, 183))
        self.assertEqual(result['machine_state_allocas'], 0)

    def test_unknown_native_target_rejects(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('31c0c3'))
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        with self.assertRaises(ValueError):
            compile_image(Image(source, contracts, 'x86-runtime-fallback'))

    def test_changed_binary_rejects_before_codegen(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('31c0c3'))
        altered = bytearray(raw)
        altered[0x1001] ^= 1
        with self.assertRaises(Rejected):
            self.lower(bytes(altered), contracts)

    def test_unproved_native_pointer_rejects(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('b800200000488b00c3'))
        with self.assertRaises(Rejected):
            self.lower(raw, contracts)

    def test_unimplemented_instruction_rejects(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('0fa2c3'))
        with self.assertRaises(Rejected):
            self.lower(raw, contracts)


    def test_defined_ssa_freeze_is_not_virtual_machine_state(self):
        ir = 'target triple = "arm64-apple-macosx13.0.0"\ndefine i64 @test_entry(i64 %input) {\n%stable = freeze i64 %input\nret i64 %stable\n}\n'
        output = self.directory / 'freeze.o'
        result = build_native_object(ir, output)
        self.assertEqual(result['machine_state_allocas'], 0)
        self.assertGreater(result['object_bytes'], 0)


if __name__ == '__main__':
    unittest.main()

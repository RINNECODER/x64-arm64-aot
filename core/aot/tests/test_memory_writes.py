import ctypes
import unittest

import test_effects
from compiler import Rejected


def stores():
    for opcode in ('movups', 'movaps', 'movupd', 'movapd', 'movdqu', 'movdqa'):
        yield opcode, 'pxor xmm0, xmm0', 'xmm0', 16
    for opcode, size in (('movd', 4), ('movq', 8), ('movss', 4), ('movsd', 8), ('movlps', 8), ('movlpd', 8)):
        yield opcode, 'pxor xmm0, xmm0', 'xmm0', size
    for opcode in ('vmovups', 'vmovaps', 'vmovdqu', 'vmovdqa'):
        for register, size in (('xmm0', 16), ('ymm0', 32)):
            yield opcode, f'vpxor {register}, {register}, {register}', register, size
    for opcode, size in (('vmovd', 4), ('vmovq', 8)):
        yield opcode, 'vpxor xmm0, xmm0, xmm0', 'xmm0', size


class MemoryWriteTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def test_simd_stores_invalidate_overlapping_stack_pointers(self):
        for opcode, initialize, register, size in stores():
            with self.subTest(opcode=opcode, register=register):
                displacement = min(0, 8 - size)
                raw, contracts = self.fixture([
                    ('test_entry', f'push rdi\n{initialize}\n{opcode} [rsp{displacement:+d}], {register}\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')])
                with self.assertRaisesRegex(Rejected, 'pointer origin'):
                    self.compile_ir(raw, contracts)

    def test_simd_stores_invalidate_import_pointer_cells(self):
        for opcode, initialize, register, _ in stores():
            with self.subTest(opcode=opcode, register=register):
                raw, contracts = self.fixture([
                    ('test_entry', f'{initialize}\n{opcode} [rip+image_cell], {register}\ncall [rip+image_cell]\nret', [], 'void')],
                    imports={'nativeNid': {'name': 'native_probe', 'parameters': [], 'result': 'void'}})
                with self.assertRaisesRegex(Rejected, 'import target has no proven native pointer origin'):
                    self.compile_ir(raw, contracts)

    def test_callee_simd_write_invalidates_callers_pointer(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 16\nlea rdi, [rsp+8]\ncall writer\nadd rsp, 16\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('writer', 'pxor xmm0, xmm0\nmovups [rdi], xmm0\nret', ['ptr'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_callee_simd_image_write_invalidates_relocation_cell(self):
        raw, contracts = self.fixture([
            ('test_entry', 'call writer\nmov rax, [rip+image_other]\nmov rax, [rax]\nret', [], 'i64'),
            ('writer', 'pxor xmm0, xmm0\nmovups [rip+image_other], xmm0\nret', [], 'void')], relocations=[[0x2010, 0x2020]])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_vector_read_preserves_memory_proofs(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\ncall reader\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('reader', 'movups xmm0, [rdi]\nret', ['ptr'], 'void')])
        function, report, _ = self.compile(raw, contracts)
        values = (ctypes.c_uint64 * 2)(123, 456)
        self.assertEqual(function(ctypes.addressof(values)), 123)
        self.assertEqual(report['functions'][1]['memory_effects'], {'status': 'inferred', 'image_writes': []})


    def test_nonpointer_vector_contents_cannot_inherit_spilled_pointer_origin(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nmov eax, 0x2000\nmovq xmm0, rax\npunpcklqdq xmm0, xmm0\nmovups [rsp-8], xmm0\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_vector_read_preserves_spilled_pointer_origin(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nmovups xmm0, [rdi]\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')])
        function, _, _ = self.compile(raw, contracts)
        values = (ctypes.c_uint64 * 2)(123, 456)
        self.assertEqual(function(ctypes.addressof(values)), 123)


if __name__ == '__main__':
    unittest.main()

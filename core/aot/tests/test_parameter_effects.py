import ctypes
import io
import subprocess
import unittest

from elftools.elf.elffile import ELFFile

import test_compiler

import test_effects
from compiler import Rejected


class ParameterEffectTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def test_private_buffer_write_preserves_disjoint_pointer(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 16\nmov rdi, rsp\ncall writer\nmov rcx, [rsp]\nadd rsp, 16\npop rax\nmov rax, [rax]\nadd rax, rcx\nret', ['ptr'], 'i64'),
            ('writer', 'mov QWORD PTR [rdi], 42\nret', ['ptr'], 'void')])
        function, report, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 165)
        self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'], [{'parameter': 0, 'offset': 0, 'size': 8}])
        self.assertNotIn('parameter_writes', report['functions'][0]['memory_effects'])

    def test_image_buffer_write_preserves_relocated_pointer(self):
        raw, contracts = self.fixture([
            ('test_entry', 'lea rdi, [rip+image_other+8]\ncall writer\nmov rax, [rip+image_other]\nmov rax, [rax]\nret', [], 'i64'),
            ('writer', 'mov QWORD PTR [rdi], 42\nret', ['ptr'], 'void')], relocations=[[0x2010, 0x2018]])
        function, report, _ = self.compile(raw, contracts)
        self.assertEqual(function(), 42)
        self.assertEqual(report['functions'][0]['memory_effects']['image_writes'], [{'address': 0x2018, 'size': 8}])

    def test_signed_offsets_and_derived_parameter_origins(self):
        for offset in (-8, 3, 8):
            with self.subTest(offset=offset):
                raw, contracts = self.fixture([
                    ('test_entry', f'push rdi\nsub rsp, 64\nlea rdi, [rsp+16]\ncall writer\nmov rcx, [rsp+{16 + offset}]\nadd rsp, 64\npop rax\nmov rax, [rax]\nadd rax, rcx\nret', ['ptr'], 'i64'),
                    ('writer', f'mov rax, rdi\nadd rax, {offset}\nmov QWORD PTR [rax], 42\nret', ['ptr'], 'void')])
                function, report, _ = self.compile(raw, contracts)
                value = ctypes.c_uint64(123)
                self.assertEqual(function(ctypes.addressof(value)), 165)
                self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'], [{'parameter': 0, 'offset': offset, 'size': 8}])

    def test_nested_calls_and_tail_calls_compose_parameter_offsets(self):
        for call in ('call leaf\nret', 'jmp leaf'):
            with self.subTest(call=call):
                raw, contracts = self.fixture([
                    ('test_entry', 'push rdi\nsub rsp, 16\nmov rdi, rsp\ncall writer\nmovzx ecx, BYTE PTR [rsp+12]\nadd rsp, 16\npop rax\nmov rax, [rax]\nadd rax, rcx\nret', ['ptr'], 'i64'),
                    ('writer', 'lea rdi, [rdi+8]\n' + call, ['ptr'], 'void'),
                    ('leaf', 'mov BYTE PTR [rdi+4], 7\nret', ['ptr'], 'void')])
                function, report, _ = self.compile(raw, contracts)
                value = ctypes.c_uint64(123)
                self.assertEqual(function(ctypes.addressof(value)), 130)
                self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'], [{'parameter': 0, 'offset': 12, 'size': 1}])

    def test_mixed_fp_abi_keeps_parameter_indices(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 16\nxorpd xmm0, xmm0\nmov rdi, rsp\ncall writer\nmov rcx, [rsp]\nadd rsp, 16\npop rax\nmov rax, [rax]\nadd rax, rcx\nret', ['ptr'], 'i64'),
            ('writer', 'mov QWORD PTR [rdi], 42\nret', ['f64', 'ptr'], 'void')])
        function, report, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 165)
        self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'][0]['parameter'], 1)

    def test_two_destinations_preserve_only_disjoint_cells(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 16\nmov rdi, rsp\nlea rsi, [rsp+8]\ncall writer\nmov rcx, [rsp]\nadd rcx, [rsp+8]\nadd rsp, 16\npop rax\nmov rax, [rax]\nadd rax, rcx\nret', ['ptr'], 'i64'),
            ('writer', 'mov QWORD PTR [rdi], 17\nmov QWORD PTR [rsi], 25\nret', ['ptr', 'ptr'], 'void')])
        function, _, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 165)

    def test_aliasing_parameters_invalidate_overlapping_pointer(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nmov rdi, rsp\nmov rsi, rsp\ncall writer\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('writer', 'mov BYTE PTR [rdi+7], 0\nmov BYTE PTR [rsi], 0\nret', ['ptr', 'ptr'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_branch_union_does_not_assume_a_nonwriting_path(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 8\nmov rdi, rsp\nxor esi, esi\ncall writer\nadd rsp, 8\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('writer', 'test esi, esi\njz other\nmov QWORD PTR [rdi], 17\nret\nother:\nmov QWORD PTR [rdi+8], 25\nret', ['ptr', 'i32'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_dynamic_parameter_index_remains_unknown(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 16\nmov rdi, rsp\nxor esi, esi\ncall writer\nadd rsp, 16\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('writer', 'mov BYTE PTR [rdi+rsi], 0\nret', ['ptr', 'i64'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_unresolved_external_alias_still_invalidates_caller_memory(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\ncall writer\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('writer', 'mov QWORD PTR [rdi], 42\nret', ['ptr'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_stack_passed_pointer_preserves_disjoint_caller_memory(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 24\nlea rax, [rsp+8]\nmov [rsp], rax\nxor edi, edi\nxor esi, esi\nxor edx, edx\nxor ecx, ecx\nxor r8d, r8d\nxor r9d, r9d\ncall writer\nadd rsp, 24\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('writer', 'mov rax, [rsp+8]\nmov QWORD PTR [rax], 42\nret', ['i64'] * 6 + ['ptr'], 'void')])
        function, report, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 123)
        self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'], [{'parameter': 6, 'offset': 0, 'size': 8}])

    def test_parameter_write_invalidates_import_binding(self):
        imports = {'nativeNid': {'name': 'native_probe', 'parameters': [], 'result': 'void',
                               'memory_effects': {'writes': [], 'callbacks': False, 'evidence': 'Fixture provider'}}}
        raw, contracts = self.fixture([
            ('test_entry', 'lea rdi, [rip+image_cell]\ncall writer\ncall [rip+image_cell]\nret', [], 'void'),
            ('writer', 'mov BYTE PTR [rdi+7], 0\nret', ['ptr'], 'void')], imports=imports)
        with self.assertRaisesRegex(Rejected, 'import target has no proven native pointer origin'):
            self.compile_ir(raw, contracts)

    def test_clang_compiled_struct_writer_matches_integer_reference(self):
        source, obj = self.directory / 'writer.c', self.directory / 'writer.o'
        source.write_text('typedef unsigned long long U64; struct Pair { U64 first, second; }; void writer(struct Pair* out, U64 value) { out->first = value; out->second = value + 1; }\n')
        subprocess.run(['xcrun', 'clang', '--target=x86_64-unknown-freebsd', '-O2', '-fno-vectorize', '-fno-slp-vectorize',
                        '-c', str(source), '-o', str(obj)], check=True, capture_output=True)
        elf = ELFFile(io.BytesIO(obj.read_bytes()))
        self.assertFalse(any(section['sh_type'] in ('SHT_REL', 'SHT_RELA') and section['sh_info'] == elf.get_section_index('.text') for section in elf.iter_sections()))
        symbol = next(symbol for symbol in elf.get_section_by_name('.symtab').iter_symbols() if symbol.name == 'writer')
        code = elf.get_section_by_name('.text').data()[symbol['st_value']:symbol['st_value'] + symbol['st_size']]
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 16\nmov rdi, rsp\ncall writer\nmov rcx, [rsp]\nxor rcx, [rsp+8]\nadd rsp, 16\npop rax\nmov rax, [rax]\nxor rax, rcx\nret', ['ptr', 'u64'], 'u64'),
            ('writer', 'ret', ['ptr', 'u64'], 'void')])
        writer = contracts['functions'][1]
        writer['size'] = len(code)
        raw, contracts = test_compiler.fixture(raw[0x1000:writer['address']] + code, functions=contracts['functions'])
        function, report, _ = self.compile(raw, contracts)
        guard = ctypes.c_uint64(123)
        for value in (0, 1, 17, 1 << 63, (1 << 64) - 1):
            self.assertEqual(function(ctypes.addressof(guard), value), 123 ^ value ^ ((value + 1) & ((1 << 64) - 1)))
            self.assertEqual(guard.value, 123)
        self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'], [{'parameter': 0, 'offset': 0, 'size': 16}])

    def test_out_of_frame_parameter_write_is_not_a_private_effect(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nmov rdi, rsp\ncall writer\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('writer', 'mov QWORD PTR [rdi+16], 42\nret', ['ptr'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)


if __name__ == '__main__':
    unittest.main()

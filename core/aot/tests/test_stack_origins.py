import ctypes
import io
import subprocess
import unittest

from elftools.elf.elffile import ELFFile

import test_compiler
import test_effects
import test_provider_effects
from compiler import Rejected


class StackOriginTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir
    provider = test_provider_effects.ProviderEffectsTests.provider

    def caller(self, target='writer'):
        return f'push rdi\nsub rsp, 40\nlea rax, [rsp+24]\nmov [rsp+16], rax\nmov QWORD PTR [rsp], 7\nmov QWORD PTR [rsp+8], 8\nmov edi, 1\nmov esi, 2\nmov edx, 3\nmov ecx, 4\nmov r8d, 5\nmov r9d, 6\ncall {target}\nmov rcx, [rsp+24]\nadd rsp, 40\npop rax\nmov rax, [rax]\nadd rax, rcx\nret'

    def test_ninth_argument_pointer_reaches_native_provider(self):
        parameters = ['u64'] * 8 + ['ptr']
        raw, contracts = self.fixture([('test_entry', self.caller('[rip+image_cell]'), ['ptr'], 'u64')],
            imports=self.provider(parameters, [{'parameter': 8, 'size': 8}]))
        provider = 'void native_probe(unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d, unsigned long long e, unsigned long long f, unsigned long long g, unsigned long long h, unsigned long long* out) { *out = a+b+c+d+e+f+g+h; }'
        function, _, _ = self.compile(raw, contracts, extra=provider)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 159)

    def test_clang_compiled_stack_argument_writer(self):
        source, obj = self.directory / 'writer.c', self.directory / 'writer.o'
        source.write_text('void writer(unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d, unsigned long long e, unsigned long long f, unsigned long long g, unsigned long long h, unsigned long long* out) { *out = a+b+c+d+e+f+g+h; }\n')
        subprocess.run(['xcrun', 'clang', '--target=x86_64-unknown-freebsd', '-O2', '-fno-vectorize', '-fno-slp-vectorize', '-c', str(source), '-o', str(obj)], check=True, capture_output=True)
        elf = ELFFile(io.BytesIO(obj.read_bytes()))
        self.assertFalse(any(section['sh_type'] in ('SHT_REL', 'SHT_RELA') and section['sh_info'] == elf.get_section_index('.text') for section in elf.iter_sections()))
        symbol = next(symbol for symbol in elf.get_section_by_name('.symtab').iter_symbols() if symbol.name == 'writer')
        code = elf.get_section_by_name('.text').data()[symbol['st_value']:symbol['st_value'] + symbol['st_size']]
        raw, contracts = self.fixture([('test_entry', self.caller(), ['ptr'], 'u64'),
                                      ('writer', 'ret', ['u64'] * 8 + ['ptr'], 'void')])
        writer = contracts['functions'][1]
        writer['size'] = len(code)
        raw, contracts = test_compiler.fixture(raw[0x1000:writer['address']] + code, functions=contracts['functions'])
        function, report, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 159)
        self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'], [{'parameter': 8, 'offset': 0, 'size': 8}])

    def test_mixed_float_spills_and_tail_call_keep_parameter_identity(self):
        zero_fp = '\n'.join(f'xorpd xmm{i}, xmm{i}' for i in range(8))
        zero_gp = '\n'.join(f'xor {name}, {name}' for name in ('edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d'))
        parameters = ['f64'] * 9 + ['u64'] * 6 + ['ptr']
        raw, contracts = self.fixture([
            ('test_entry', f'push rdi\nsub rsp, 32\nlea rax, [rsp+16]\nmov [rsp+8], rax\nmov QWORD PTR [rsp], 0\n{zero_fp}\n{zero_gp}\ncall wrapper\nmov rcx, [rsp+16]\nadd rsp, 32\npop rax\nmov rax, [rax]\nadd rax, rcx\nret', ['ptr'], 'u64'),
            ('wrapper', 'jmp writer', parameters, 'void'),
            ('writer', 'mov rax, [rsp+16]\nmov QWORD PTR [rax], 42\nret', parameters, 'void')])
        function, report, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 165)
        self.assertEqual(report['functions'][1]['memory_effects']['parameter_writes'], [{'parameter': 15, 'offset': 0, 'size': 8}])

    def spill_fixture(self, rewrite='', reload='mov rdi, [rsp]', before=''):
        return self.fixture([
            ('test_entry', f'push rdi\nsub rsp, 32\nlea rax, [rsp+16]\nmov [rsp], rax\n{rewrite}\n{reload}\n{before}\ncall writer\nmov rcx, [rsp+16]\nadd rsp, 32\npop rax\nmov rax, [rax]\nadd rax, rcx\nret', ['ptr', 'i64'], 'i64'),
            ('writer', 'mov QWORD PTR [rdi], 42\nret', ['ptr'], 'void')])

    def test_spilled_pointer_reload_preserves_output_region(self):
        function, _, _ = self.compile(*self.spill_fixture())
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value), 0), 165)

    def test_push_from_pointer_cell_and_pop_preserve_origin(self):
        function, _, _ = self.compile(*self.spill_fixture(reload='push [rsp]\npop rdi'))
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value), 0), 165)

    def test_partial_overwrite_and_narrow_reload_destroy_origin(self):
        for rewrite, reload in [('mov BYTE PTR [rsp+7], 0', 'mov rdi, [rsp]'), ('', 'mov edi, [rsp]')]:
            with self.subTest(rewrite=rewrite, reload=reload):
                with self.assertRaisesRegex(Rejected, 'pointer origin'):
                    self.compile_ir(*self.spill_fixture(rewrite, reload))

    def test_full_pointer_overwrite_tracks_new_destination(self):
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(*self.spill_fixture(rewrite='lea rax, [rsp+32]\nmov [rsp], rax'))

    def test_control_flow_join_does_not_choose_one_of_two_origins(self):
        rewrite = 'test esi, esi\njz join\nlea rax, [rsp+32]\nmov [rsp], rax\njoin:'
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(*self.spill_fixture(rewrite=rewrite))

    def test_control_flow_join_preserves_identical_origins(self):
        rewrite = 'test esi, esi\njz join\nlea rax, [rsp+16]\nmov [rsp], rax\njoin:'
        function, _, _ = self.compile(*self.spill_fixture(rewrite=rewrite))
        value = ctypes.c_uint64(123)
        for path in (0, 1):
            self.assertEqual(function(ctypes.addressof(value), path), 165)

    def test_unknown_call_invalidates_spilled_origins(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\ncall [rip+image_cell]\nmov rdi, [rsp]\ncall writer\npop rax\nret', ['ptr'], 'void'),
            ('writer', 'mov QWORD PTR [rdi], 42\nret', ['ptr'], 'void')],
            imports={'nativeNid': {'name': 'native_unknown', 'parameters': [], 'result': 'void'}})
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_overlapping_callee_write_invalidates_spilled_origins(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 32\nlea rax, [rsp+16]\nmov [rsp], rax\nmov rdi, rsp\ncall writer\nmov rdi, [rsp]\ncall writer\nadd rsp, 32\npop rax\nret', ['ptr'], 'void'),
            ('writer', 'mov QWORD PTR [rdi], 42\nret', ['ptr'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_wide_overwrite_invalidates_every_overlapped_pointer_origin(self):
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(*self.spill_fixture(rewrite='pxor xmm0, xmm0\nmovups [rsp], xmm0'))

    def test_stack_passed_effect_size_resolves_write_region(self):
        parameters = ['ptr'] + ['u64'] * 8
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 40\nlea rdi, [rsp+24]\nmov QWORD PTR [rsp], 0\nmov QWORD PTR [rsp+8], 0\nmov QWORD PTR [rsp+16], 8\nxor esi, esi\nxor edx, edx\nxor ecx, ecx\nxor r8d, r8d\nxor r9d, r9d\ncall [rip+image_cell]\nadd rsp, 40\npop rax\nmov rax, [rax]\nret', ['ptr'], 'u64')],
            imports=self.provider(parameters, [{'parameter': 0, 'size_parameter': 8}]))
        provider = '#include <string.h>\nvoid native_probe(void* p, unsigned long long a, unsigned long long b, unsigned long long c, unsigned long long d, unsigned long long e, unsigned long long f, unsigned long long g, unsigned long long size) { memset(p,0,size); }'
        function, _, _ = self.compile(raw, contracts, extra=provider)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 123)

    def test_disjoint_callee_write_keeps_spilled_origin(self):
        function, _, _ = self.compile(*self.spill_fixture(rewrite='lea rdi, [rsp+16]\ncall writer'))
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value), 0), 165)


if __name__ == '__main__':
    unittest.main()

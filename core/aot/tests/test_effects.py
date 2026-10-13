import ctypes
import io
import subprocess
import unittest

from elftools.elf.elffile import ELFFile

import test_compiler
from compiler import Image, Rejected, compile_image


class CallEffectsTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp
    compile = test_compiler.CompilerTests.compile

    def fixture(self, bodies, imports=None, relocations=None):
        assembly = ['.intel_syntax noprefix', '.text', '.set image_cell, test_entry + 0x1000',
                    '.set image_other, test_entry + 0x1010']
        for name, body, _, _ in bodies:
            assembly.extend(['.balign 256, 0x90', name + ':', body, 'end_' + name + ':'])
        source, obj = self.directory / 'input.S', self.directory / 'input.o'
        source.write_text('\n'.join(assembly) + '\n')
        subprocess.run(['xcrun', 'clang', '--target=x86_64-unknown-freebsd', '-c', str(source), '-o', str(obj)],
                       check=True, capture_output=True)
        elf = ELFFile(io.BytesIO(obj.read_bytes()))
        symbols = {symbol.name: symbol['st_value'] for symbol in elf.get_section_by_name('.symtab').iter_symbols()}
        functions = [{'name': name, 'address': 0x1000 + symbols[name], 'size': symbols['end_' + name] - symbols[name],
                      'parameters': parameters, 'result': result} for name, _, parameters, result in bodies]
        return test_compiler.fixture(elf.get_section_by_name('.text').data(), functions=functions,
                                     imports=imports, relocations=relocations)

    def compile_ir(self, raw, contracts):
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        return compile_image(Image(source, contracts))

    def spill_caller(self, call='call helper'):
        return ('test_entry', 'push rdi\n' + call + '\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')

    def test_local_frame_writes_preserve_caller_pointer_spill(self):
        for body in ['ret', 'sub rsp, 8\nmov QWORD PTR [rsp], 7\nadd rsp, 8\nret',
                     'push rbp\nmov rbp, rsp\nsub rsp, 8\nlea rax, [rbp-8]\nmov QWORD PTR [rax], 7\nadd rsp, 8\npop rbp\nret']:
            with self.subTest(body=body):
                raw, contracts = self.fixture([self.spill_caller(), ('helper', body, [], 'void')])
                function, report, _ = self.compile(raw, contracts)
                value = ctypes.c_uint64(42)
                self.assertEqual(function(ctypes.addressof(value)), 42)
                self.assertEqual(report['functions'][1]['memory_effects'], {'status': 'inferred', 'image_writes': []})

    def test_transitive_tail_call_effects_preserve_image_pointer(self):
        bodies = [('test_entry', 'call helper\nmov rax, [rip+image_cell]\nmov rax, [rax]\nret', [], 'i64'),
                  ('helper', 'jmp leaf', [], 'void'), ('leaf', 'ret', [], 'void')]
        raw, contracts = self.fixture(bodies, relocations=[[0x2000, 0x2010]])
        function, report, _ = self.compile(raw, contracts)
        self.assertEqual(function(), 0)
        self.assertTrue(all(item['memory_effects']['status'] == 'inferred' for item in report['functions']))
        reversed_contracts = dict(contracts, functions=list(reversed(contracts['functions'])))
        _, reversed_report = self.compile_ir(raw, reversed_contracts)
        self.assertEqual({item['name']: item['memory_effects'] for item in report['functions']},
                         {item['name']: item['memory_effects'] for item in reversed_report['functions']})

    def test_disjoint_image_write_preserves_pointer_and_has_native_effect(self):
        raw, contracts = self.fixture([
            ('test_entry', 'call helper\nmov rax, [rip+image_cell]\nmov rax, [rax]\nret', [], 'i64'),
            ('helper', 'mov QWORD PTR [rip+image_other], 42\nret', [], 'void')], relocations=[[0x2000, 0x2010]])
        function, report, _ = self.compile(raw, contracts)
        self.assertEqual(function(), 42)
        self.assertEqual(report['functions'][1]['memory_effects']['image_writes'], [{'address': 0x2010, 'size': 8}])

    def test_partial_image_write_invalidates_pointer_cell(self):
        raw, contracts = self.fixture([
            ('test_entry', 'call helper\nmov rax, [rip+image_cell]\nmov rax, [rax]\nret', [], 'i64'),
            ('helper', 'mov BYTE PTR [rip+image_cell+7], 0\nret', [], 'void')], relocations=[[0x2000, 0x2010]])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_pointer_parameter_write_invalidates_overlapping_cell(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nmov rdi, rsp\ncall helper\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('helper', 'mov BYTE PTR [rdi], 0\nret', ['ptr'], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_import_in_nested_callee_remains_unknown(self):
        raw, contracts = self.fixture([
            self.spill_caller(), ('helper', 'call [rip+image_cell]\nret', [], 'void')],
            imports={'nativeNid': {'name': 'native_unknown', 'parameters': [], 'result': 'void'}})
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_transitive_import_tail_call_remains_unknown(self):
        raw, contracts = self.fixture([
            self.spill_caller(), ('helper', 'jmp [rip+image_cell]', [], 'void')],
            imports={'nativeNid': {'name': 'native_unknown', 'parameters': [], 'result': 'void'}})
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_recursive_call_graph_remains_unknown_and_order_independent(self):
        raw, contracts = self.fixture([self.spill_caller(), ('helper', 'call other\nret', [], 'void'),
                                      ('other', 'call helper\nret', [], 'void')])
        for functions in [contracts['functions'], list(reversed(contracts['functions']))]:
            with self.subTest(order=[item['name'] for item in functions]):
                with self.assertRaisesRegex(Rejected, 'pointer origin'):
                    self.compile_ir(raw, dict(contracts, functions=functions))

    def test_indexed_frame_write_cannot_claim_private_memory(self):
        raw, contracts = self.fixture([self.spill_caller(),
                                      ('helper', 'xor eax, eax\nmov BYTE PTR [rsp+rax-8], 0\nret', [], 'void')])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_callee_parameter_reads_preserve_pointer_spill(self):
        raw, contracts = self.fixture([self.spill_caller(), ('helper', 'mov rax, [rdi]\nret', ['ptr'], 'i64')])
        function, _, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 123)

    def test_unknown_import_before_internal_call_cannot_restore_proof(self):
        raw, contracts = self.fixture([
            self.spill_caller('call [rip+image_cell]\ncall helper'), ('helper', 'ret', [], 'void')],
            imports={'nativeNid': {'name': 'native_unknown', 'parameters': [], 'result': 'void'}})
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_branch_write_union_invalidates_even_when_one_path_is_pure(self):
        raw, contracts = self.fixture([
            ('test_entry', 'call helper\nmov rax, [rip+image_cell]\nmov rax, [rax]\nret', ['i32'], 'i64'),
            ('helper', 'test edi, edi\njz clean\nmov BYTE PTR [rip+image_cell], 0\nclean:\nret', ['i32'], 'void')],
            relocations=[[0x2000, 0x2010]])
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_supported_scalar_recursion_executes_with_unknown_effects(self):
        raw, contracts = self.fixture([
            ('test_entry', 'call helper\nmov eax, 42\nret', ['i32'], 'i64'),
            ('helper', 'test edi, edi\njz done\ndec edi\ncall helper\ndone:\nret', ['i32'], 'void')])
        function, report, _ = self.compile(raw, contracts)
        for count in (0, 1, 10):
            self.assertEqual(function(count), 42)
        self.assertTrue(all(item['memory_effects'] == {'status': 'unknown'} for item in report['functions']))

    def test_saved_frame_origin_survives_nonwriting_call(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rbp\nmov rbp, rsp\npush rbp\ncall helper\npop rbp\nlea rax, [rbp-8]\nmov QWORD PTR [rax], 42\nmov rax, [rax]\npop rbp\nret', [], 'i64'),
            ('helper', 'ret', [], 'void')])
        function, _, _ = self.compile(raw, contracts)
        self.assertEqual(function(), 42)

    def test_image_write_preserves_disjoint_caller_frame(self):
        raw, contracts = self.fixture([self.spill_caller(),
                                      ('helper', 'mov QWORD PTR [rip+image_other], 42\nret', [], 'void')])
        function, _, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 123)


if __name__ == '__main__':
    unittest.main()

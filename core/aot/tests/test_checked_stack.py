import ctypes
import subprocess
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM

import test_effects
from compiler import Rejected
from toolchain import build_native_object


class CheckedStackTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def annotate(self, raw, contracts, offset, size, pointer):
        function = contracts['functions'][0]
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        sites = [(ins, index) for ins in decoder.disasm(raw[0x1000:0x1000+function['size']], 0x1000)
                 for index, operand in enumerate(ins.operands) if operand.type == X86_OP_MEM and operand.mem.index]
        self.assertEqual(len(sites), 1)
        ins, index = sites[0]
        function['stack_objects'] = [{'offset': offset, 'size': size, 'alignment': 8}]
        function['checked_stack_accesses'] = [{'address': ins.address, 'operand': index, 'object_offset': offset, 'pointer': pointer}]
        return raw, contracts

    def pointer_fixture(self, scale=8, corrupt=''):
        return self.annotate(*self.fixture([
            ('test_entry', f'sub rsp, 24\nmov [rsp], rdi\nmov [rsp+8], rsi\n{corrupt}\nmov rax, [rsp+rdx*{scale}]\nadd rsp, 24\nmov rax, [rax]\nret', ['ptr', 'ptr', 'u64'], 'u64')]),
            offset=-24, size=16, pointer=True)

    def test_checked_indexed_store_preserves_unrelated_pointer(self):
        raw, contracts = self.annotate(*self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 32\nmov BYTE PTR [rsp+rsi], 7\nadd rsp, 32\npop rax\nmov rax, [rax]\nret', ['ptr', 'u64'], 'u64')]), offset=-40, size=16, pointer=False)
        function, report, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(42)
        for index in (0, 7, 15):
            self.assertEqual(function(ctypes.addressof(value), index), 42)
        self.assertEqual(len(report['functions'][0]['checked_stack_accesses']), 1)
        ir, _ = self.compile_ir(raw, contracts)
        self.assertIn('_checked_stack_invalid', ir)

    def test_checked_pointer_table_load_uses_proven_cells(self):
        function, _, _ = self.compile(*self.pointer_fixture())
        left, right = ctypes.c_uint64(17), ctypes.c_uint64(42)
        for index, expected in ((0, 17), (1, 42)):
            self.assertEqual(function(ctypes.addressof(left), ctypes.addressof(right), index), expected)

    def test_unproven_or_partially_rewritten_pointer_cell_rejects(self):
        for corrupt in ('mov QWORD PTR [rsp], 0x1000', 'mov BYTE PTR [rsp+3], 0'):
            with self.subTest(corrupt=corrupt):
                with self.assertRaisesRegex(Rejected, 'unproved pointer cells'):
                    self.compile_ir(*self.pointer_fixture(corrupt=corrupt))

    def test_out_of_range_and_misaligned_indices_trap_natively(self):
        raw, contracts = self.pointer_fixture(scale=1)
        ir, _ = self.compile_ir(raw, contracts)
        obj = self.directory / 'checked.o'
        build_native_object(ir, obj)
        main = self.directory / 'main.cpp'
        main.write_text('#include <csignal>\n#include <cstdlib>\nextern "C" unsigned long long test_entry(unsigned long long*,unsigned long long*,unsigned long long);\nstatic void trapped(int) { std::_Exit(77); }\nint main(int argc,char** argv) { std::signal(SIGILL,trapped); std::signal(SIGTRAP,trapped); unsigned long long a=17,b=42; auto index=std::strtoull(argv[1],nullptr,0); auto value=test_entry(&a,&b,index); return value==(index==0?17:42)?0:1; }\n')
        binary = self.directory / 'checked'
        subprocess.run(['xcrun', 'clang++', '-arch', 'arm64', '-O2', str(main), str(obj), '-o', str(binary)], check=True, capture_output=True)
        self.assertEqual(subprocess.check_output(['xcrun', 'lipo', '-archs', str(binary)], text=True).strip(), 'arm64')
        for index, expected in ((0, 0), (8, 0), (1, 77), (16, 77), ((1 << 64)-1, 77)):
            with self.subTest(index=index):
                result = subprocess.run([str(binary), str(index)], capture_output=True, timeout=5)
                self.assertEqual(result.returncode, expected)

    def test_contract_cannot_claim_nonframe_memory(self):
        raw, contracts = self.annotate(*self.fixture([
            ('test_entry', 'mov BYTE PTR [rdi+rsi], 7\nret', ['ptr','u64'], 'void')]), offset=-16, size=16, pointer=False)
        with self.assertRaisesRegex(Rejected, 'not a native frame address'):
            self.compile_ir(raw, contracts)

    def test_missing_object_duplicate_site_and_bad_operand_reject(self):
        for field, value in [('object_offset', -128), ('operand', 0), ('pointer', 1), ('address', 0x1000)]:
            with self.subTest(field=field):
                raw, contracts = self.pointer_fixture()
                contracts['functions'][0]['checked_stack_accesses'][0][field] = value
                with self.assertRaises(Rejected):
                    self.compile_ir(raw, contracts)
        raw, contracts = self.pointer_fixture()
        sites = contracts['functions'][0]['checked_stack_accesses']
        sites.append(dict(sites[0]))
        with self.assertRaisesRegex(Rejected, 'unique decoded instruction'):
            self.compile_ir(raw, contracts)

    def test_unannotated_indexed_store_keeps_conservative_behavior(self):
        raw, contracts = self.annotate(*self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 32\nmov BYTE PTR [rsp+rsi], 7\nadd rsp, 32\npop rax\nmov rax, [rax]\nret', ['ptr','u64'], 'u64')]), offset=-40, size=16, pointer=False)
        del contracts['functions'][0]['checked_stack_accesses']
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)


if __name__ == '__main__':
    unittest.main()

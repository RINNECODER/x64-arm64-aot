import ctypes
import subprocess
import unittest

import test_effects
from compiler import Rejected


class StackValueTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def null_argument(self, initialize, parameters=None):
        zero = '\n'.join(f'xor {name}, {name}' for name in ('edi','esi','edx','ecx','r8d','r9d'))
        return self.fixture([('test_entry', f'sub rsp, 8\n{initialize}\n{zero}\ncall [rip+image_cell]\nadd rsp, 8\nret',parameters or [],'u64')],
                            imports={'nativeNid': {'name':'native_probe','parameters':['u64']*6+['ptr'],'result':'u64'}})

    def test_null_stack_pointer_argument_is_a_valid_native_null(self):
        provider='unsigned long long native_probe(unsigned long long a,unsigned long long b,unsigned long long c,unsigned long long d,unsigned long long e,unsigned long long f,void* p){return p==0?42:1;}'
        for initialize in ('mov QWORD PTR [rsp], 0','mov DWORD PTR [rsp], 0\nmov DWORD PTR [rsp+4], 0'):
            with self.subTest(initialize=initialize):
                function,_,_=self.compile(*self.null_argument(initialize),extra=provider)
                self.assertEqual(function(),42)

    def test_pushed_null_is_valid_but_not_an_indirect_call_target(self):
        raw,contracts=self.fixture([('test_entry','push 0\nxor edi,edi\nxor esi,esi\nxor edx,edx\nxor ecx,ecx\nxor r8d,r8d\nxor r9d,r9d\ncall [rip+image_cell]\nadd rsp,8\nret',[],'u64')],
            imports={'nativeNid':{'name':'native_probe','parameters':['u64']*6+['ptr'],'result':'u64'}})
        function,_,_=self.compile(raw,contracts,extra='unsigned long long native_probe(unsigned long long a,unsigned long long b,unsigned long long c,unsigned long long d,unsigned long long e,unsigned long long f,void* p){return p==0?42:1;}')
        self.assertEqual(function(),42)
        raw,contracts=self.fixture([('test_entry','push 0\ncall [rsp]\nadd rsp,8\nret',[],'void'),('target','ret',[],'void')])
        contracts['functions'][0]['indirect_calls']=[{'address':0x1002,'parameters':[],'result':'void','targets':[0x1100]}]
        with self.assertRaisesRegex(Rejected,'indirect call target has no proven native pointer origin'):
            self.compile_ir(raw,contracts)

    def test_partial_unknown_or_nonzero_stack_values_are_not_pointers(self):
        for initialize in ('mov DWORD PTR [rsp],0','mov QWORD PTR [rsp],0x2000','mov QWORD PTR [rsp],0\nmov BYTE PTR [rsp+7],1'):
            with self.subTest(initialize=initialize):
                with self.assertRaisesRegex(Rejected,'stack pointer argument'):
                    self.compile_ir(*self.null_argument(initialize))

    def test_join_of_different_constants_does_not_prove_null(self):
        initialize='test rdi,rdi\njz zero\nmov QWORD PTR [rsp],1\njmp join\nzero:\nmov QWORD PTR [rsp],0\njoin:'
        with self.assertRaisesRegex(Rejected,'stack pointer argument'):
            self.compile_ir(*self.null_argument(initialize,['u64']))

    def test_loaded_zero_does_not_launder_a_guest_integer_address(self):
        for load in ('mov rax, [rsp]', 'pop rax\nsub rsp,8'):
            with self.subTest(load=load):
                raw,contracts=self.fixture([('test_entry',f'push 0\n{load}\nadd rsp,8\nadd rax,0x2000\nmov rax,[rax]\nret',[],'u64')])
                with self.assertRaisesRegex(Rejected,'literal-derived|pointer origin'):
                    self.compile_ir(raw,contracts)

    def test_subword_signed_and_unsigned_loads_keep_exact_bits(self):
        for instruction,expected in [('movzx eax,BYTE PTR [rsp]',255),('movsx rax,BYTE PTR [rsp]',(1<<64)-1),('mov eax,DWORD PTR [rsp]',0xffffffff)]:
            with self.subTest(instruction=instruction):
                raw,contracts=self.fixture([('test_entry',f'push -1\n{instruction}\nadd rsp,8\nret',[],'u64')])
                function,_,_=self.compile(raw,contracts)
                self.assertEqual(function(),expected)

    def test_unknown_call_invalidates_cached_null(self):
        zero='\n'.join(f'xor {name},{name}' for name in ('edi','esi','edx','ecx','r8d','r9d'))
        raw,contracts=self.fixture([('test_entry',f'push 0\ncall [rip+image_cell]\n{zero}\ncall [rip+image_cell+8]\nadd rsp,8\nret',[],'u64')],
            imports={'first':{'name':'unknown','parameters':[],'result':'void'},'second':{'name':'nullable','parameters':['u64']*6+['ptr'],'result':'u64'}})
        contracts['immutable_data']=[{'address':0x2000,'evidence':'Fixture import table is immutable'}]
        with self.assertRaisesRegex(Rejected,'stack pointer argument'):
            self.compile_ir(raw,contracts)


if __name__ == '__main__':
    unittest.main()


class MovbeStoreTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture

    null_argument = StackValueTests.null_argument
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def test_movbe_store_invalidates_a_stale_null_stack_value(self):
        # [rsp] held a known 0; movbe overwrites it with a nonzero value, so it is no longer a valid null.
        initialize = 'mov QWORD PTR [rsp], 0\nmov rax, 0x2000\nmovbe [rsp], rax'
        with self.assertRaisesRegex(Rejected, 'stack pointer argument'):
            self.compile_ir(*self.null_argument(initialize))

    def test_movbe_store_is_a_recorded_memory_write(self):
        body = ('sub rsp, 24\nmov rax, 0x1122334455667788\nmov [rsp+8], rax\n'
                'mov rcx, 0x0102030405060708\nmovbe [rsp+8], rcx\nmov rdx, [rsp+8]\nmov rax, rdx\nadd rsp, 24\nret')
        function, _, _ = self.compile(*self.fixture([('test_entry', body, [], 'u64')]))
        # The x86 reference: the same sequence assembled for x86_64 and run under the translator.
        source = self.directory / 'reference.S'
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n' + body + '\n')
        runner = self.directory / 'reference.c'
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\nextern uint64_t run(void);\n'
                          'int main(void){printf("%llu\\n",(unsigned long long)run());return 0;}\n')
        binary = self.directory / 'reference.x86'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', str(source), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        expected = int(subprocess.run([str(binary)], check=True, capture_output=True, text=True).stdout)
        self.assertEqual(expected, 0x0807060504030201)
        self.assertEqual(function(), expected)

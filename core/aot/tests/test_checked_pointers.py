import ctypes
import os
from pathlib import Path
import resource
import signal
import unittest

import test_compiler
import test_effects
from compiler import Rejected


HELPER = Path(__file__).resolve().parents[2] / 'libs/native/NativeAotPointer.cpp'


class CheckedPointerTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def compile(self, raw, contracts, extra=''):
        return test_compiler.CompilerTests.compile(self, raw, contracts, extra, extra_sources=[HELPER])

    def assert_traps(self, function, *arguments):
        child = os.fork()
        if child == 0:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            function(*arguments)
            os._exit(0)
        _, status = os.waitpid(child, 0)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertIn(os.WTERMSIG(status), (signal.SIGILL, signal.SIGTRAP))

    def pointer_load(self, nullable=False, dereference=True):
        raw, contracts = self.fixture([('test_entry', 'mov rax, [rdi]\n'+('mov rax, [rax]\n' if dereference else '')+'ret', ['ptr'], 'i64')])
        contracts['functions'][0]['checked_pointer_loads'] = [{'address':0x1000,'bytes':8,'nullable':nullable,'evidence':'The input contains a source-declared pointer field; native mapping check is mandatory.'}]
        return raw, contracts

    def test_readable_pointer_field_executes(self):
        function, _, _ = self.compile(*self.pointer_load())
        value = ctypes.c_uint64(87)
        cell = ctypes.c_void_p(ctypes.addressof(value))
        self.assertEqual(function(ctypes.addressof(cell)), 87)

    def test_unmapped_pointer_traps_before_dereference(self):
        function, _, _ = self.compile(*self.pointer_load())
        cell = ctypes.c_void_p(8192)
        self.assert_traps(function, ctypes.addressof(cell))

    def test_nullability_is_enforced(self):
        null = ctypes.c_void_p()
        function, _, _ = self.compile(*self.pointer_load(nullable=True, dereference=False))
        self.assertEqual(function(ctypes.addressof(null)), 0)
        function, _, _ = self.compile(*self.pointer_load(nullable=False, dereference=False))
        self.assert_traps(function, ctypes.addressof(null))

    def test_checked_load_proof_does_not_survive_partial_overwrite(self):
        raw, contracts = self.fixture([('test_entry', 'push rdi\nmov rax, [rsp]\nmov byte ptr [rsp], 7\nmov rax, [rsp]\nmov rax, [rax]\npop rdi\nret', ['ptr'], 'i64')])
        contracts['functions'][0]['checked_pointer_loads']=[{'address':0x1001,'bytes':8,'nullable':False,'evidence':'Guarded pointer cell before a conflicting write.'}]
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw,contracts)

    def argument_case(self, partial=False):
        body='push rbx\nmov rbx, rdi\nmov rax, rdi\n'+('mov ax, 16384\n' if partial else '')+'mov rdi, rax\ncall [rip+image_cell]\nmov rax, [rbx]\npop rbx\nret'
        raw, contracts=self.fixture([('test_entry',body,['i64'],'i64')],imports={'nativeNid':{'name':'native_accept','parameters':['ptr'],'result':'void'}})
        from compiler import Image
        source=self.directory/'source.elf';source.write_bytes(raw);image=Image(source,contracts)
        owner=contracts['functions'][0]
        call=next(i for i in image.decoder.disasm(image.read(owner['address'],owner['size']),owner['address']) if i.mnemonic=='call')
        owner['checked_pointer_arguments']=[{'address':call.address,'parameter':0,'bytes':8,'nullable':False,'evidence':'A native boundary validates this pointer value; only unchanged register copies share the proof.'}]
        return raw,contracts

    def test_guarded_argument_qualifies_unchanged_callee_saved_copy(self):
        function,_,_=self.compile(*self.argument_case(),extra='void native_accept(void *p) { (void)p; }')
        value=ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)),123)
        self.assert_traps(function,8192)

    def test_partial_register_write_breaks_value_identity(self):
        with self.assertRaisesRegex(Rejected,'pointer origin'):
            self.compile_ir(*self.argument_case(partial=True))

    def test_pointer_and_null_join_executes_both_paths(self):
        raw,contracts=self.fixture([('test_entry','mov rax, rsi\ntest edi, edi\njne done\nxor eax, eax\ndone:\nret',['i32','ptr'],'ptr')])
        function,_,_=self.compile(raw,contracts)
        value=ctypes.c_uint64(29)
        self.assertEqual(function(1,ctypes.addressof(value)),ctypes.addressof(value))
        self.assertEqual(function(0,ctypes.addressof(value)),0)

    def test_nonzero_integer_join_still_rejects(self):
        raw,contracts=self.fixture([('test_entry','mov rax, rsi\ntest edi, edi\njne done\nmov eax, 8192\ndone:\nret',['i32','ptr'],'ptr')])
        with self.assertRaisesRegex(Rejected,'pointer return'):
            self.compile_ir(raw,contracts)


if __name__ == '__main__':
    unittest.main()

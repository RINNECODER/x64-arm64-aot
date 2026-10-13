import ctypes
import os
import resource
import signal
import unittest

from compiler import Image, Rejected
import test_effects


class GraphicsInvariantTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    fixture = test_effects.CallEffectsTests.fixture
    compile = test_effects.CallEffectsTests.compile
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def annotate_store(self, raw, contracts):
        source=self.directory/'input.elf';source.write_bytes(raw);image=Image(source,contracts)
        owner=contracts['functions'][0]
        ins=next(i for i in image.decoder.disasm(image.read(owner['address'],owner['size']),owner['address']) if i.mnemonic=='mov' and i.op_str.startswith('qword ptr [rax]'))
        owner['checked_frame_exclusion']=[{'address':ins.address,'evidence':'The emitted interval guard must reject writes into any part of this function frame.'}]

    def assert_traps(self, function, *args):
        child=os.fork()
        if child==0:
            resource.setrlimit(resource.RLIMIT_CORE,(0,0));function(*args);os._exit(0)
        _,status=os.waitpid(child,0)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertIn(os.WTERMSIG(status),(signal.SIGILL,signal.SIGTRAP))

    def identity(self):
        return {'nativeNid':{'name':'native_identity','parameters':['ptr'],'result':'ptr','memory_effects':{'writes':[],'callbacks':False,'evidence':'Test identity provider returns its argument without writes or callbacks.'}}}

    def test_external_write_keeps_private_pointer_spill(self):
        raw,contracts=self.fixture([('test_entry','push rdi\nmov rdi, rsi\ncall [rip+image_cell]\nmov qword ptr [rax], 77\npop rax\nmov rax, [rax]\nret',['ptr','ptr'],'i64')],imports=self.identity())
        self.annotate_store(raw,contracts)
        function,_,_=self.compile(raw,contracts,'void *native_identity(void *p) { return p; }')
        source,destination=ctypes.c_uint64(123),ctypes.c_uint64(0)
        self.assertEqual(function(ctypes.addressof(source),ctypes.addressof(destination)),123)
        self.assertEqual(destination.value,77)

    def test_private_frame_alias_traps_before_overwrite(self):
        raw,contracts=self.fixture([('test_entry','push rdi\nmov rdi, rsp\ncall [rip+image_cell]\nmov qword ptr [rax], 8192\npop rax\nmov rax, [rax]\nret',['ptr'],'i64')],imports=self.identity())
        self.annotate_store(raw,contracts)
        function,_,_=self.compile(raw,contracts,'void *native_identity(void *p) { return p; }')
        value=ctypes.c_uint64(123);self.assert_traps(function,ctypes.addressof(value))

    def test_copied_incoming_stack_arguments_are_protected(self):
        raw,contracts=self.fixture([('test_entry','lea rdi, [rsp+8]\ncall [rip+image_cell]\nmov qword ptr [rax], 8192\nmov rax, [rsp+8]\nmov rax, [rax]\nret',['i64']*6+['ptr'],'i64')],imports=self.identity())
        self.annotate_store(raw,contracts)
        function,_,_=self.compile(raw,contracts,'void *native_identity(void *p) { return p; }')
        value=ctypes.c_uint64(123);self.assert_traps(function,0,0,0,0,0,0,ctypes.addressof(value))

    def output_case(self, helper):
        return self.fixture([('test_entry','sub rsp, 32\nmov edx, esi\nmov rsi, rdi\nmov rdi, rsp\ncall helper\nmov rax, [rsp]\nadd rsp, 32\nret',['ptr','i32'],'ptr'),('helper',helper,['ptr','ptr','i32'],'void')])

    def test_inferred_output_can_be_native_pointer_or_null(self):
        raw,contracts=self.output_case('pxor xmm0, xmm0\nmovups [rdi], xmm0\ntest edx, edx\nje done\nmov [rdi], rsi\ndone:\nret')
        function,report,_=self.compile(raw,contracts)
        value=ctypes.c_uint64(41)
        self.assertEqual(function(ctypes.addressof(value),1),ctypes.addressof(value))
        self.assertEqual(function(ctypes.addressof(value),0),0)
        self.assertEqual(report['inferred_pointer_outputs']['helper'],[(0,0)])

    def test_uninitialized_output_path_does_not_gain_type(self):
        with self.assertRaisesRegex(Rejected,'pointer return'):
            self.compile_ir(*self.output_case('test edx, edx\nje done\nmov [rdi], rsi\ndone:\nret'))

    def test_zero_only_output_is_not_invented_as_pointer_origin(self):
        with self.assertRaisesRegex(Rejected,'pointer return'):
            self.compile_ir(*self.output_case('pxor xmm0, xmm0\nmovups [rdi], xmm0\nret'))

    def test_xmm_overwrite_invalidates_zero_ymm_summary(self):
        body='test edx, edx\nje native\nvpxor ymm0, ymm0, ymm0\nmov eax, 8192\nmovq xmm0, rax\nvmovdqu [rdi], ymm0\nret\nnative:\nmov [rdi], rsi\nret'
        with self.assertRaisesRegex(Rejected,'pointer return'):
            self.compile_ir(*self.output_case(body))


if __name__=='__main__':
    unittest.main()

"""Differential tests for the block-local register SSA (REPORT15 section 3, cut 1).

The optimization keeps each guest register as an SSA value inside a basic block and spills it to
its register-file alloca only at a block boundary. The contract is exactness: the whole register
file must be left in exactly the state the plain per-instruction load/store build leaves it in,
for any initial state. Each test compiles the same function twice -- once with the SSA and once
without -- and compares every byte of the register file after running both. The two IRs are
asserted different, so a test that silently stopped exercising the optimization fails.
"""
import ctypes
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import compiler
from compiler import Image, compile_image
from test_uniform import GPR, RegisterFile, fixture, uniform_function


def assemble(parts, size):
    """A byte array with the given (offset, hex) pieces placed at their addresses."""
    code = bytearray(size)
    for offset, text in parts:
        raw = bytes.fromhex(text)
        code[offset:offset + len(raw)] = raw
    return code


class RegisterSSATests(unittest.TestCase):
    serial = 0

    def setUp(self):
        RegisterSSATests.serial += 1
        self.temporary = tempfile.TemporaryDirectory(prefix='anyps5-register-ssa-')
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def build(self, raw, contracts, entry, ssa):
        suffix = f'-ssa{int(ssa)}-{RegisterSSATests.serial}'
        source = self.directory / f'input{suffix}.elf'
        source.write_bytes(raw)
        with mock.patch.object(compiler, 'REGISTER_SSA', ssa):
            ir, _ = compile_image(Image(source, contracts))
        ll = self.directory / f'output{suffix}.ll'
        ll.write_text(ir)
        binary = self.directory / f'output{suffix}.dylib'
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ll),
                        '-o', str(binary)], check=True, capture_output=True)
        library = ctypes.CDLL(str(binary))
        function = getattr(library, entry)
        function.restype = None
        function.argtypes = [ctypes.POINTER(RegisterFile)]
        return function, ir

    def initial(self):
        state = RegisterFile()
        state.gpr[GPR['rax']] = 0x00000000deadbeef
        state.gpr[GPR['rbx']] = 0x1111222233334444
        state.gpr[GPR['rcx']] = 0x00000000000000ff
        state.gpr[GPR['rdx']] = 0x9988776655443322
        state.gpr[GPR['rdi']] = 0
        state.gpr[GPR['rsi']] = 21
        state.gpr[GPR['rbp']] = 0x5555555555555555
        for index, name in enumerate(('r12', 'r13', 'r14', 'r15')):
            state.gpr[GPR[name]] = 0x1234000000000000 | index
        for lane in range(16):
            state.xmm[lane][0] = 0x0102030405060708 + lane
            state.xmm[lane][1] = 0x1112131415161718 + lane
            state.ymm_hi[lane][0] = 0x2122232425262728 + lane
            state.ymm_hi[lane][1] = 0x3132333435363738 + lane
        state.flags = 0x212
        state.flags_mask = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11)
        return state

    def compare(self, raw, contracts, entry):
        summary_function, summary_ir = self.build(raw, contracts, entry, True)
        plain_function, plain_ir = self.build(raw, contracts, entry, False)
        self.assertNotEqual(summary_ir, plain_ir)
        for taken in (False, True):
            def run(function):
                state = self.initial()
                state.gpr[GPR['rdi']] = 1 if taken else 0
                function(ctypes.byref(state))
                return bytes(state)
            self.assertEqual(run(summary_function), run(plain_function),
                             f'register file diverged with the branch {"taken" if taken else "not taken"}')
        return summary_ir, plain_ir

    def test_branching_body_matches_the_plain_build(self):
        # A partial write of `al` in the taken block and a 32-bit write of `eax` in the
        # fall-through block both have to reach the join block: the spill at each block boundary
        # carries them.
        #   test rdi,rdi ; je 0x1012 ; mov eax,0x11223344 ; add rbx,rax ; jmp 0x1017
        #   0x1012: mov al,0x7f ; inc rcx ; 0x1017: add rax,rcx ; ret
        code = assemble([(0x00, '4885ff'), (0x03, '740d'), (0x05, 'b844332211'),
                         (0x0a, '4801c3'), (0x0d, 'eb08'), (0x0f, '90'), (0x10, '90'),
                         (0x11, '90'), (0x12, 'b07f'), (0x14, '48ffc1'),
                         (0x17, '4801c8'), (0x1a, 'c3')], 0x1b)
        functions = [uniform_function('sub_1000', 0x1000, len(code))]
        raw, contracts = fixture(bytes(code), functions)
        self.compare(raw, contracts, 'sub_1000')

    def test_call_and_branch_match_the_plain_build(self):
        # The caller writes the callee's read set into the outgoing register file and reads its
        # write set back, with a branch on each side of the call.
        code = assemble([(0x00, '4885ff'), (0x03, '740a'), (0x05, 'e836000000'),
                         (0x0a, '4801c3'), (0x0d, 'eb06'), (0x0f, '909090'),
                         (0x12, '48ffc9'), (0x15, '4889d8'), (0x18, 'c3'),
                         (0x40, '4889f8'), (0x43, '4801f0'), (0x46, 'c3')], 0x47)
        functions = [uniform_function('sub_1000', 0x1000, 0x19),
                     uniform_function('sub_1040', 0x1040, 0x7)]
        raw, contracts = fixture(bytes(code), functions)
        summary_ir, plain_ir = self.compare(raw, contracts, 'sub_1000')
        # The callee is reached through the uniform call path, not a plain load/store sequence.
        self.assertIn('call void @sub_1040(ptr %rf_out)', summary_ir)
        self.assertIn('call void @sub_1040(ptr %rf_out)', plain_ir)

    def test_loop_carried_register_matches_the_plain_build(self):
        # A loop back edge is the hard case for block-local SSA: the value written at the bottom
        # of the body has to be spilled before the branch and reloaded at the header.
        #   0x1000: mov eax,0 ; 0x1005: add rax,rdi ; 0x1008: dec rsi ; 0x100b: jne 0x1005 ; ret
        code = assemble([(0x00, 'b800000000'), (0x05, '4801f8'), (0x08, '48ffce'),
                         (0x0b, '75f8'), (0x0d, 'c3')], 0xe)
        functions = [uniform_function('sub_1000', 0x1000, 0xe)]
        raw, contracts = fixture(bytes(code), functions)
        summary_function, summary_ir = self.build(raw, contracts, 'sub_1000', True)
        plain_function, plain_ir = self.build(raw, contracts, 'sub_1000', False)
        self.assertNotEqual(summary_ir, plain_ir)
        def run(function):
            state = self.initial()
            state.gpr[GPR['rdi']] = 3
            state.gpr[GPR['rsi']] = 5
            function(ctypes.byref(state))
            return bytes(state)
        self.assertEqual(run(summary_function), run(plain_function))
        state = self.initial()
        state.gpr[GPR['rdi']] = 3
        state.gpr[GPR['rsi']] = 5
        summary_function(ctypes.byref(state))
        self.assertEqual(state.gpr[GPR['rax']], 15)
        self.assertEqual(state.gpr[GPR['rsi']], 0)

    def test_tail_call_matches_the_plain_build(self):
        # A tail jmp goes through `repair_frame` and the tail-call uniform_call, which reads the
        # SSA values rather than the allocas.
        #   0x1000: mov rax,rdi ; jmp 0x1010 ; 0x1010: add rax,rsi ; ret
        code = assemble([(0x00, '4889f8'), (0x03, 'e908000000'),
                         (0x10, '4801f0'), (0x13, 'c3')], 0x14)
        functions = [uniform_function('sub_1000', 0x1000, 0x8),
                     uniform_function('sub_1010', 0x1010, 0x4)]
        raw, contracts = fixture(bytes(code), functions)
        summary_function, summary_ir = self.build(raw, contracts, 'sub_1000', True)
        plain_function, plain_ir = self.build(raw, contracts, 'sub_1000', False)
        self.assertNotEqual(summary_ir, plain_ir)
        def run(function):
            state = self.initial()
            state.gpr[GPR['rdi']] = 0x1234
            function(ctypes.byref(state))
            return bytes(state)
        self.assertEqual(run(summary_function), run(plain_function))
        state = self.initial()
        state.gpr[GPR['rdi']] = 0x1234
        summary_function(ctypes.byref(state))
        self.assertEqual(state.gpr[GPR['rax']], 0x1234 + 21)

    def test_straight_line_block_stays_in_ssa(self):
        # A straight-line body must lower to one block: no per-instruction label and no
        # per-instruction branch, so the register traffic collapses to the prologue spill.
        code = assemble([(0x00, '4889f8'), (0x03, '4801f0'), (0x06, 'c3')], 0x7)
        functions = [uniform_function('sub_1000', 0x1000, 0x7)]
        raw, contracts = fixture(bytes(code), functions)
        summary_function, summary_ir = self.build(raw, contracts, 'sub_1000', True)
        _, plain_ir = self.build(raw, contracts, 'sub_1000', False)
        # The SSA build never reloads rax from its alloca inside the block: the value written by
        # `mov rax,rdi` flows straight into `add rax,rsi`. The plain build reloads it twice (once
        # for the add, once for the return write-back).
        self.assertEqual(summary_ir.count('load i64, ptr %rax'), 0)
        self.assertGreater(plain_ir.count('load i64, ptr %rax'), 0)
        self.assertLess(len(summary_ir), len(plain_ir))
        state = self.initial()
        state.gpr[GPR['rdi']] = 0x1234
        summary_function(ctypes.byref(state))
        self.assertEqual(state.gpr[GPR['rax']], 0x1234 + 21)

    def test_ssa_is_actually_on(self):
        # Guard against the switch silently defaulting off, which would make every comparison above
        # a comparison of the plain build with itself.
        self.assertTrue(compiler.REGISTER_SSA)


if __name__ == '__main__':
    unittest.main()

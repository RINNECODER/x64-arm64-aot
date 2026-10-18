"""Restoring rsp from a register that holds a known frame-relative value.

`mov rsp, r12` after `lea r12, [rsp + n]` or `mov r12, rsp` appears in the title's frame
trampolines. The analysis records a frame pointer for those destinations, so the restore is
supported; a register whose value is not provably frame-relative must still be rejected. Both
positive cases move rsp to a different slot than the one the epilogue would read, so a restore that
did not actually happen reads the wrong value instead of passing silently.
"""
import unittest

import test_effects
from compiler import Rejected


class FrameRestoreTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def body(self, middle):
        return ('push rbp\nmov rbp, rsp\nsub rsp, 32\n'
                'mov qword ptr [rsp], 4660\nmov qword ptr [rsp + 16], 8192\n'
                f'{middle}\n'
                'mov rsp, rbp\npop rbp\nret')

    def value(self, middle, expected):
        raw, contracts = self.fixture([('test_entry', self.body(middle), [], 'i64')])
        function, _, _ = self.compile(raw, contracts)
        self.assertEqual(function(), expected)

    def test_restores_rsp_from_a_register_holding_a_frame_slot(self):
        # lea records the slot; the restore moves rsp onto the +16 slot, so [rsp] is 8192.
        self.value('lea r12, [rsp + 16]\nmov rsp, r12\nmov rax, [rsp]', 8192)

    def test_restores_rsp_from_a_register_holding_the_frame_pointer(self):
        # mov records the frame pointer; add rsp moves the frame on, and the restore undoes it.
        self.value('mov r12, rsp\nadd rsp, 16\nmov rsp, r12\nmov rax, [rsp]', 4660)

    def test_a_source_that_is_not_frame_relative_is_still_rejected(self):
        raw, contracts = self.fixture([('test_entry', self.body('xor r12, r12\nmov rsp, r12'), [], 'i64')])
        with self.assertRaises(Rejected) as raised:
            self.compile_ir(raw, contracts)
        self.assertIn('unsupported frame manipulation', str(raised.exception))

    def test_leave_reads_the_frame_and_restores_rsp(self):
        # leave = mov rsp, rbp ; pop rbp. The local slot is read before the frame is released.
        body = ('push rbp\nmov rbp, rsp\nsub rsp, 16\n'
                'mov qword ptr [rbp - 8], rdi\n'
                'mov rax, qword ptr [rbp - 8]\n'
                'leave\nret')
        raw, contracts = self.fixture([('test_entry', body, ['i64'], 'i64')])
        function, _, _ = self.compile(raw, contracts)
        self.assertEqual(function(0x2a), 0x2a)


if __name__ == '__main__':
    unittest.main()

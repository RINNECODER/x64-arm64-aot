"""VEX.128 scalar move zero-upper semantics, lifted IR vs native x86_64."""
from avx_reference import NativeAvxHarness


class ScalarMoveTests(NativeAvxHarness):
    def test_two_operand_move_zeroes_upper(self):
        # The two-operand VEX.128 load zeroes bits 127:lane and 255:128, so a following
        # full-width store must compile and match native (which zeroes the same bits).
        for mnemonic, operand in (('vmovss', 'dword ptr [rdx]'), ('vmovsd', 'qword ptr [rdx]')):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm3, {operand}\nvmovaps xmmword ptr [rdx], xmm3',
                                    self.samples())

    def test_three_operand_move_merges_upper(self):
        for mnemonic in ('vmovss', 'vmovsd'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1, xmm2', self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

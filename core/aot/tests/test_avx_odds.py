"""Remaining AVX odds: dup moves, 128-bit broadcast, the compare-predicate family,
vpblendd and vpermpd/vpermps, vs native x86_64."""
from avx_reference import NativeAvxHarness


class AvxOddsTests(NativeAvxHarness):
    def test_dups(self):
        for instruction in ('vmovshdup xmm0, xmm1', 'vmovshdup ymm0, ymm1',
                            'vmovsldup xmm0, xmm1', 'vmovsldup ymm0, ymm1',
                            'vmovddup xmm0, xmm1', 'vmovddup ymm0, ymm1',
                            'vmovddup xmm0, QWORD PTR [rsi]'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_broadcast128(self):
        for instruction in ('vbroadcastf128 ymm0, XMMWORD PTR [rsi]',
                            'vbroadcasti128 ymm0, XMMWORD PTR [rsi]'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_compare_predicates(self):
        for mnemonic in ('vcmpps', 'vcmppd'):
            for width in ('xmm', 'ymm'):
                for predicate in range(32):
                    with self.subTest(mnemonic=mnemonic, width=width, predicate=predicate):
                        self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2, {predicate}', self.samples())
        for mnemonic in ('vcmpss', 'vcmpsd'):
            for predicate in range(32):
                with self.subTest(mnemonic=mnemonic, predicate=predicate):
                    self.compare_native(f'{mnemonic} xmm0, xmm1, xmm2, {predicate}', self.samples())

    def test_vpblendd(self):
        for width in ('xmm', 'ymm'):
            for control in (0x00, 0x0f, 0x55, 0xaa, 0xff):
                with self.subTest(width=width, control=control):
                    self.compare_native(f'vpblendd {width}0, {width}1, {width}2, {control}', self.samples())

    def test_permpd_permps(self):
        for control in (0x00, 0x1b, 0x4e, 0x93, 0xff):
            with self.subTest(control=control):
                self.compare_native(f'vpermpd ymm0, ymm1, {control}', self.samples())
        self.compare_native('vpermps ymm0, ymm1, ymm2', self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

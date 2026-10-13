"""AVX/AVX2 unpack, shuffle, blend and permute instructions vs native x86_64."""
from avx_reference import NativeAvxHarness


class AvxShuffleTests(NativeAvxHarness):
    def test_unpacks(self):
        for mnemonic in ('vpunpcklbw', 'vpunpckhbw', 'vpunpcklwd', 'vpunpckhwd',
                         'vpunpckldq', 'vpunpckhdq', 'vpunpcklqdq', 'vpunpckhqdq',
                         'vunpcklps', 'vunpckhps', 'vunpcklpd', 'vunpckhpd'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_shuffles_and_moves(self):
        for mnemonic in ('vshufps', 'vshufpd'):
            for width in ('xmm', 'ymm'):
                for control in (0x00, 0x1b, 0x4e, 0xe4, 0xff):
                    with self.subTest(mnemonic=mnemonic, width=width, control=control):
                        self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2, {control}', self.samples())
        for mnemonic in ('vmovlhps', 'vmovhlps'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1, xmm2', self.samples())

    def test_blends_immediate(self):
        for mnemonic in ('vblendps', 'vblendpd', 'vpblendw'):
            for width in ('xmm', 'ymm'):
                for control in (0x00, 0x0f, 0x55, 0xaa, 0xff):
                    with self.subTest(mnemonic=mnemonic, width=width, control=control):
                        self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2, {control}', self.samples())

    def test_blends_variable(self):
        for mnemonic in ('vblendvps', 'vblendvpd', 'vpblendvb'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2, {width}3', self.samples())

    def test_permil(self):
        for mnemonic in ('vpermilps', 'vpermilpd'):
            for width in ('xmm', 'ymm'):
                for control in (0x00, 0x1b, 0x4e, 0xff):
                    with self.subTest(mnemonic=mnemonic, width=width, control=control):
                        self.compare_native(f'{mnemonic} {width}0, {width}1, {control}', self.samples())
                with self.subTest(mnemonic=mnemonic, width=width, variable=True):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_permutations(self):
        for control in (0x00, 0x20, 0x31, 0x80, 0xff):
            with self.subTest(control=control):
                self.compare_native(f'vperm2f128 ymm0, ymm1, ymm2, {control}', self.samples())
        self.compare_native('vinsertf128 ymm0, ymm1, xmm2, 1', self.samples())
        self.compare_native('vextractf128 xmm0, ymm1, 1', self.samples())
        for control in (0x00, 0x1b, 0x4e, 0x93, 0xff):
            with self.subTest(control=control):
                self.compare_native(f'vpermq ymm0, ymm1, {control}', self.samples())
        self.compare_native('vpermd ymm0, ymm1, ymm2', self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

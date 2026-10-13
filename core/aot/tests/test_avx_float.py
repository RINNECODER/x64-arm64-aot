"""AVX packed/scalar floating-point arithmetic, min/max, bitwise and vptest."""
from avx_reference import NativeAvxHarness


class AvxFloatTests(NativeAvxHarness):
    def test_packed_arithmetic(self):
        for mnemonic in ('vaddps', 'vsubps', 'vmulps', 'vdivps', 'vminps', 'vmaxps',
                         'vaddpd', 'vsubpd', 'vmulpd', 'vdivpd', 'vminpd', 'vmaxpd'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())
        self.compare_native('vaddps ymm0, ymm1, [rsi]', self.samples())
        self.compare_native('vaddpd ymm0, ymm1, [rsi]', self.samples())

    def test_scalar_arithmetic(self):
        for mnemonic in ('vaddss', 'vsubss', 'vmulss', 'vdivss', 'vminss', 'vmaxss',
                         'vaddsd', 'vsubsd', 'vmulsd', 'vdivsd', 'vminsd', 'vmaxsd'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1, xmm2', self.samples())
        self.compare_native('vaddss xmm0, xmm1, [rsi]', self.samples())
        self.compare_native('vaddsd xmm0, xmm1, [rsi]', self.samples())

    def test_bitwise(self):
        for mnemonic in ('vandps', 'vandpd', 'vandnps', 'vandnpd', 'vorps', 'vorpd', 'vxorpd'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_ptest_flags(self):
        for mnemonic in ('vptest',):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1', self.samples(), flag_mask=0x41)


if __name__ == '__main__':
    import unittest
    unittest.main()

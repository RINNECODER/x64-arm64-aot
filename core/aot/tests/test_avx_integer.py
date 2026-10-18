"""AVX2 integer core: element-wise add/sub/mul, compares, min/max, shifts, extends,
abs, packs and bitwise, compared against native x86_64."""
from avx_reference import NativeAvxHarness


class AvxIntegerTests(NativeAvxHarness):
    def test_elementwise_add_sub_mul(self):
        for mnemonic in ('vpaddb', 'vpaddw', 'vpaddd', 'vpaddq', 'vpsubb', 'vpsubw', 'vpsubd', 'vpsubq',
                         'vpmullw', 'vpmulld'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())
        self.compare_native('vpaddd ymm0, ymm1, [rsi]', self.samples())

    def test_saturating_add_sub(self):
        for mnemonic in ('vpaddsb', 'vpaddsw', 'vpaddusb', 'vpaddusw',
                         'vpsubsb', 'vpsubsw', 'vpsubusb', 'vpsubusw'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())
        self.compare_native('vpsubusw ymm0, ymm1, [rsi]', self.samples())

    def test_unsigned_word_multiply_high(self):
        for width in ('xmm', 'ymm'):
            with self.subTest(width=width):
                self.compare_native(f'vpmulhuw {width}0, {width}1, {width}2', self.samples())

    def test_compares(self):
        for mnemonic in ('vpcmpeqb', 'vpcmpeqw', 'vpcmpeqd', 'vpcmpeqq',
                         'vpcmpgtb', 'vpcmpgtw', 'vpcmpgtd', 'vpcmpgtq'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_min_max(self):
        for mnemonic in ('vpminsb', 'vpminsw', 'vpminsd', 'vpminub', 'vpminuw', 'vpminud',
                         'vpmaxsb', 'vpmaxsw', 'vpmaxsd', 'vpmaxub', 'vpmaxuw', 'vpmaxud'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_shifts_immediate(self):
        for mnemonic in ('vpsllw', 'vpslld', 'vpsllq', 'vpsrlw', 'vpsrld', 'vpsrlq',
                         'vpsraw', 'vpsrad'):
            for width in ('xmm', 'ymm'):
                for amount in (0, 1, 5, 31):
                    with self.subTest(mnemonic=mnemonic, width=width, amount=amount):
                        self.compare_native(f'{mnemonic} {width}0, {width}1, {amount}', self.samples())

    def test_shifts_variable(self):
        for mnemonic in ('vpsllvd', 'vpsllvq', 'vpsrlvd', 'vpsrlvq', 'vpsravd'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())
        for mnemonic in ('vpslldq', 'vpsrldq'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, 4', self.samples())

    def test_abs_and_extends(self):
        for mnemonic in ('vpabsb', 'vpabsw', 'vpabsd'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1', self.samples())
        for instruction in ('vpmovsxbw ymm0, xmm1', 'vpmovzxbw ymm0, xmm1',
                            'vpmovsxwd ymm0, xmm1', 'vpmovzxwd ymm0, xmm1',
                            'vpmovsxdq ymm0, xmm1', 'vpmovzxdq ymm0, xmm1',
                            'vpmovsxwd xmm0, xmm1', 'vpmovzxwd xmm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_packs_and_bitwise(self):
        for mnemonic in ('vpackuswb', 'vpacksswb'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())
        for mnemonic in ('vpandn',):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

"""AVX2 odds: byte/word broadcast, all-width extends, dword packs, word shuffles,
even-lane 32x32 multiplies and vperm2i128, vs native x86_64."""
from avx_reference import NativeAvxHarness


class Avx2OddsTests(NativeAvxHarness):
    def test_byte_word_broadcast(self):
        for instruction in ('vpbroadcastb xmm0, xmm1', 'vpbroadcastb ymm0, xmm1',
                            'vpbroadcastw xmm0, xmm1', 'vpbroadcastw ymm0, xmm1',
                            'vpbroadcastb xmm0, BYTE PTR [rsi]', 'vpbroadcastw ymm0, WORD PTR [rsi]'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_all_width_extends(self):
        for instruction in ('vpmovsxbd xmm0, xmm1', 'vpmovzxbd xmm0, xmm1',
                            'vpmovsxbd ymm0, xmm1', 'vpmovzxbd ymm0, xmm1',
                            'vpmovsxwq xmm0, xmm1', 'vpmovzxwq xmm0, xmm1',
                            'vpmovsxwq ymm0, xmm1', 'vpmovzxwq ymm0, xmm1',
                            'vpmovsxbq xmm0, xmm1', 'vpmovzxbq xmm0, xmm1',
                            'vpmovsxbw ymm0, xmm1', 'vpmovzxbw ymm0, xmm1',
                            'vpmovsxwd ymm0, xmm1', 'vpmovzxwd ymm0, xmm1',
                            'vpmovsxdq ymm0, xmm1', 'vpmovzxdq ymm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_dword_packs(self):
        for mnemonic in ('vpackssdw', 'vpackusdw'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_word_shuffles(self):
        for mnemonic in ('vpshuflw', 'vpshufhw'):
            for width in ('xmm', 'ymm'):
                for control in (0x00, 0x1b, 0x4e, 0x93, 0xff):
                    with self.subTest(mnemonic=mnemonic, width=width, control=control):
                        self.compare_native(f'{mnemonic} {width}0, {width}1, {control}', self.samples())

    def test_even_lane_multiply(self):
        for mnemonic in ('vpmuludq', 'vpmuldq'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_horizontal_adds(self):
        for mnemonic in ('vphaddw', 'vphaddd', 'vhaddps', 'vhaddpd'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2',
                                        self.samples(), nan_normalize=True)

    def test_vpmovmskb(self):
        for instruction in ('vpmovmskb eax, xmm0', 'vpmovmskb eax, ymm0'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_vpmaddwd(self):
        for width in ('xmm', 'ymm'):
            with self.subTest(width=width):
                self.compare_native(f'vpmaddwd {width}0, {width}1, {width}2', self.samples())

    def test_vaddsub(self):
        for instruction in ('vaddsubps xmm0, xmm1, xmm2', 'vaddsubps ymm0, ymm1, ymm2',
                            'vaddsubpd ymm0, ymm1, ymm2'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples(), nan_normalize=True)

    def test_vcvtdq2pd(self):
        for instruction in ('vcvtdq2pd xmm0, xmm1', 'vcvtdq2pd ymm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_word_multiply_high_and_sum_of_absolute_differences(self):
        for mnemonic in ('vpmulhw', 'vpsadbw'):
            for width in ('xmm', 'ymm'):
                with self.subTest(mnemonic=mnemonic, width=width):
                    self.compare_native(f'{mnemonic} {width}0, {width}1, {width}2', self.samples())

    def test_horizontal_minimum_position(self):
        self.compare_native('vphminposuw xmm0, xmm1', self.samples())

    def test_masked_moves(self):
        for instruction in ('vmaskmovps ymm0, ymm1, ymmword ptr [rsi]',
                            'vmaskmovps xmm0, xmm1, xmmword ptr [rsi]',
                            'vpmaskmovd ymm0, ymm1, ymmword ptr [rsi]',
                            'vpmaskmovd xmm0, xmm1, xmmword ptr [rsi]',
                            'vmaskmovps ymmword ptr [rdx], ymm1, ymm2',
                            'vpmaskmovd xmmword ptr [rdx], xmm1, xmm2'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_perm2i128(self):
        for control in (0x00, 0x20, 0x31, 0x80, 0xff):
            with self.subTest(control=control):
                self.compare_native(f'vperm2i128 ymm0, ymm1, ymm2, {control}', self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

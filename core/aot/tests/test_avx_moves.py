"""AVX moves, broadcasts and scalar conversions, compared against native x86_64."""
from avx_reference import NativeAvxHarness


class AvxMoveTests(NativeAvxHarness):
    def test_scalar_moves(self):
        for instruction in ('vmovss xmm0, xmm1, xmm2', 'vmovss xmm0, [rsi]', 'vmovss [rdx], xmm0',
                            'vmovsd xmm0, xmm1, xmm2', 'vmovsd xmm0, [rsi]', 'vmovsd [rdx], xmm0'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_packed_moves(self):
        for mnemonic in ('vmovupd', 'vmovapd'):
            for width in ('xmm', 'ymm'):
                for operands in (f'{width}0, {width}1', f'{width}0, [rsi]', f'[rdx], {width}0'):
                    with self.subTest(mnemonic=mnemonic, operands=operands):
                        self.compare_native(f'{mnemonic} {operands}', self.samples())

    def test_broadcasts(self):
        for instruction in ('vbroadcastss xmm0, xmm1', 'vbroadcastss ymm0, xmm1',
                            'vbroadcastss xmm0, [rsi]', 'vbroadcastss ymm0, [rsi]',
                            'vbroadcastsd ymm0, xmm1', 'vbroadcastsd ymm0, [rsi]',
                            'vpbroadcastq xmm0, xmm1', 'vpbroadcastq ymm0, xmm1',
                            'vpbroadcastq ymm0, [rsi]'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_integer_conversions(self):
        for instruction in ('vcvtsi2ss xmm0, xmm1, ecx', 'vcvtsi2ss xmm0, xmm1, rcx',
                            'vcvtsi2ss xmm0, xmm1, DWORD PTR [rsi]',
                            'vcvtsi2sd xmm0, xmm1, ecx', 'vcvtsi2sd xmm0, xmm1, rcx',
                            'vcvtsi2sd xmm0, xmm1, QWORD PTR [rsi]'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_scalar_conversions(self):
        for instruction in ('vcvtsd2ss xmm0, xmm1, xmm2', 'vcvtsd2ss xmm0, xmm1, [rsi]',
                            'vcvtss2sd xmm0, xmm1, xmm2', 'vcvtss2sd xmm0, xmm1, [rsi]'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

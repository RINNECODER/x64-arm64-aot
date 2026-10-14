"""sqrt, round, cvt-with-rounding, float-to-int and F16C vs native x86_64."""
from avx_reference import NativeAvxHarness


class AvxConvertTests(NativeAvxHarness):
    def test_sqrt(self):
        for instruction in ('vsqrtps xmm0, xmm1', 'vsqrtps ymm0, ymm1', 'vsqrtps xmm0, [rsi]',
                            'vsqrtpd xmm0, xmm1', 'vsqrtpd ymm0, ymm1',
                            'vsqrtss xmm0, xmm1, xmm2', 'vsqrtsd xmm0, xmm1, xmm2'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples(), nan_normalize=True)

    def test_round(self):
        for mnemonic in ('vroundps', 'vroundpd'):
            for width in ('xmm', 'ymm'):
                for mode in (0, 1, 2, 3):
                    with self.subTest(mnemonic=mnemonic, width=width, mode=mode):
                        self.compare_native(f'{mnemonic} {width}0, {width}1, {mode}', self.samples(), nan_normalize=True)
        for mnemonic in ('vroundss', 'vroundsd'):
            for mode in (0, 1, 2, 3):
                with self.subTest(mnemonic=mnemonic, mode=mode):
                    self.compare_native(f'{mnemonic} xmm0, xmm1, xmm2, {mode}', self.samples(), nan_normalize=True)

    def test_float_to_int(self):
        for instruction in ('vcvtps2dq xmm0, xmm1', 'vcvtps2dq ymm0, ymm1',
                            'vcvttps2dq xmm0, xmm1', 'vcvttps2dq ymm0, ymm1',
                            'vcvtpd2dq xmm0, xmm1', 'vcvttpd2dq xmm0, xmm1',
                            'vcvtdq2ps xmm0, xmm1', 'vcvtdq2ps ymm0, ymm1',
                            'vcvtpd2ps xmm0, xmm1', 'vcvtps2pd xmm0, xmm1', 'vcvtps2pd ymm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_scalar_to_int(self):
        for instruction in ('vcvttss2si eax, xmm0', 'vcvttsd2si eax, xmm0',
                            'vcvtss2si eax, xmm0', 'vcvtsd2si eax, xmm0',
                            'vcvttss2si rax, xmm0', 'vcvttsd2si rax, xmm0',
                            'vcvtss2si rax, xmm0', 'vcvtsd2si rax, xmm0'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_f16c(self):
        for instruction in ('vcvtph2ps xmm0, xmm1', 'vcvtph2ps ymm0, xmm1',
                            'vcvtps2ph xmm0, xmm1, 0', 'vcvtps2ph xmm0, ymm1, 0',
                            'vcvtps2ph xmm0, xmm1, 4'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

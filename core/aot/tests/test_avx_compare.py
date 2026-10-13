"""EFLAGS compares, movmsk, vtest, extract/insert and legacy partial moves vs native x86."""
from avx_reference import NativeAvxHarness


class AvxCompareTests(NativeAvxHarness):
    def test_flags_compares(self):
        for instruction in ('vucomiss xmm0, xmm1', 'vucomiss xmm0, [rsi]',
                            'vucomisd xmm0, xmm1', 'vucomisd xmm0, [rsi]',
                            'vcomiss xmm0, xmm1', 'vcomisd xmm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples(), flag_mask=0x8c5)

    def test_movmsk(self):
        for instruction in ('vmovmskps eax, xmm0', 'vmovmskps eax, ymm0',
                            'vmovmskpd eax, xmm0', 'vmovmskpd eax, ymm0',
                            'pmovmskb eax, xmm0', 'movmskps eax, xmm0', 'movmskpd eax, xmm0'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_vtest_flags(self):
        for instruction in ('vtestps xmm0, xmm1', 'vtestps ymm0, ymm1',
                            'vtestpd xmm0, xmm1', 'vtestpd ymm0, ymm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples(), flag_mask=0x41)

    def test_extract_insert(self):
        for instruction in ('vpextrb eax, xmm0, 3', 'vpextrw eax, xmm0, 5',
                            'vpextrd eax, xmm0, 2', 'vpextrq rax, xmm0, 1',
                            'vextractps eax, xmm0, 1', 'vpextrb [rdx], xmm0, 1',
                            'vpinsrb xmm0, xmm1, ecx, 3', 'vpinsrw xmm0, xmm1, ecx, 5',
                            'vpinsrd xmm0, xmm1, ecx, 2', 'vpinsrq xmm0, xmm1, rcx, 1',
                            'vinsertps xmm0, xmm1, xmm2, 0x00', 'vinsertps xmm0, xmm1, xmm2, 0x55',
                            'vinsertps xmm0, xmm1, xmm2, 0xff', 'vinsertps xmm0, xmm1, DWORD PTR [rsi], 0x10'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_legacy_partial_moves(self):
        for instruction in ('vmovlps xmm0, xmm1, QWORD PTR [rsi]', 'vmovhps xmm0, xmm1, QWORD PTR [rsi]',
                            'vmovlpd xmm0, xmm1, QWORD PTR [rsi]', 'vmovhpd xmm0, xmm1, QWORD PTR [rsi]',
                            'vmovlps QWORD PTR [rdx], xmm0', 'vmovhps QWORD PTR [rdx], xmm0'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

"""Legacy SSE scalar arithmetic, conversions and compares vs native x86_64."""
from avx_reference import NativeAvxHarness


class SseScalarTests(NativeAvxHarness):
    def test_scalar_arithmetic(self):
        for instruction in ('addss xmm0, xmm1', 'subss xmm0, xmm1', 'mulss xmm0, xmm1',
                            'divss xmm0, xmm1', 'sqrtss xmm0, xmm1',
                            'addsd xmm0, xmm1', 'subsd xmm0, xmm1', 'mulsd xmm0, xmm1',
                            'divsd xmm0, xmm1', 'sqrtsd xmm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples(), nan_normalize=True)

    def test_conversions(self):
        for instruction in ('cvtsi2sd xmm0, ecx', 'cvtsi2sd xmm0, rcx',
                            'cvtsd2ss xmm0, xmm1', 'cvtss2sd xmm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples(), nan_normalize=True)

    def test_to_int(self):
        for instruction in ('cvttss2si eax, xmm0', 'cvttss2si rax, xmm0',
                            'cvttsd2si eax, xmm0', 'cvttsd2si rax, xmm0',
                            'cvtss2si eax, xmm0', 'cvtss2si rax, xmm0',
                            'cvtsd2si eax, xmm0', 'cvtsd2si rax, xmm0'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_compares(self):
        for instruction in ('comiss xmm0, xmm1', 'ucomiss xmm0, xmm1',
                            'comisd xmm0, xmm1', 'ucomisd xmm0, xmm1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples(), flag_mask=0x8c5)


if __name__ == '__main__':
    import unittest
    unittest.main()

"""Legacy SSE packed integer/float compares, min/max, unpacks and arithmetic."""
from avx_reference import NativeAvxHarness


class SsePackedTests(NativeAvxHarness):
    def test_integer_compares(self):
        for mnemonic in ('pcmpeqb', 'pcmpeqw', 'pcmpeqd', 'pcmpeqq',
                         'pcmpgtb', 'pcmpgtw', 'pcmpgtd', 'pcmpgtq'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples())

    def test_unpacks(self):
        for mnemonic in ('punpcklbw', 'punpckhbw', 'punpcklwd', 'punpckhwd',
                         'punpckldq', 'punpckhdq', 'punpcklqdq', 'punpckhqdq'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples())

    def test_min_max(self):
        for mnemonic in ('minps', 'maxps', 'minpd', 'maxpd', 'minss', 'maxss', 'minsd', 'maxsd'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples(), nan_normalize=True)

    def test_packed_float_arithmetic(self):
        for mnemonic in ('addpd', 'subpd', 'mulpd', 'divpd'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples(), nan_normalize=True)

    def test_packed_integer_ops(self):
        for mnemonic in ('paddq', 'psubd', 'psubq', 'pmaxub', 'pminub', 'pmaxuw', 'pminuw',
                         'pmuludq', 'pmuldq'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples())

    def test_word_shuffles(self):
        for mnemonic in ('pshuflw', 'pshufhw'):
            for control in (0x00, 0x1b, 0x39, 0xe4):
                with self.subTest(mnemonic=mnemonic, control=control):
                    self.compare_native(f'{mnemonic} xmm0, xmm1, {control}', self.samples())

    def test_word_multiply_high_and_sum_of_absolute_differences(self):
        for mnemonic in ('pmulhw', 'psadbw'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples())

    def test_extract_word(self):
        for control in (0, 1, 3, 7):
            with self.subTest(control=control):
                self.compare_native(f'pextrw eax, xmm0, {control}', self.samples())

    def test_horizontal_minimum_position(self):
        self.compare_native('phminposuw xmm0, xmm1', self.samples())

    def test_byte_shifts(self):
        for mnemonic in ('pslldq', 'psrldq'):
            for count in (0, 1, 5, 8, 15, 16, 20):
                with self.subTest(mnemonic=mnemonic, count=count):
                    self.compare_native(f'{mnemonic} xmm0, {count}', self.samples())

    def test_scalar_conversion_from_memory(self):
        # A scalar conversion may read memory and write a GPR, with no xmm operand.
        self.compare_native('cvttsd2si eax, qword ptr [rsi]', self.samples())
        self.compare_native('cvttsd2si rax, qword ptr [rsi]', self.samples())

    def test_signed_packs(self):
        for mnemonic in ('packsswb', 'packssdw'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples())

    def test_packed_shifts(self):
        for mnemonic in ('psrlw', 'psrld', 'psrlq', 'psraw', 'psrad', 'psllw', 'pslld', 'psllq'):
            for amount in (0, 1, 5, 15):
                with self.subTest(mnemonic=mnemonic, amount=amount):
                    self.compare_native(f'{mnemonic} xmm0, {amount}', self.samples())
            with self.subTest(mnemonic=mnemonic, count='xmm'):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples())

    def test_packed_conversions(self):
        for mnemonic in ('cvtdq2pd', 'cvtpd2dq', 'cvttpd2dq', 'cvtpd2ps', 'cvtps2pd',
                         'cvtdq2ps', 'cvtps2dq', 'cvttps2dq'):
            with self.subTest(mnemonic=mnemonic):
                self.compare_native(f'{mnemonic} xmm0, xmm1', self.samples(), nan_normalize=True)

    def test_compare_predicates(self):
        for kind in ('ps', 'pd'):
            for predicate in range(32):
                with self.subTest(kind=kind, predicate=predicate):
                    self.compare_native(f'cmp{kind} xmm0, xmm1, {predicate}', self.samples())
        for kind in ('ss', 'sd'):
            for predicate in range(32):
                with self.subTest(kind=kind, predicate=predicate):
                    self.compare_native(f'cmp{kind} xmm0, xmm1, {predicate}', self.samples())


if __name__ == '__main__':
    import unittest
    unittest.main()

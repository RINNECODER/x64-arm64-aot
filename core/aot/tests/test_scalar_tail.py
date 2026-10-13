"""Scalar integer tail (mul, cwde, bswap, shld/shrd, cld, prefetch) vs native x86_64."""
import random

from test_bitops import BitOpReferenceTests


class ScalarTailTests(BitOpReferenceTests):
    def test_mul(self):
        randoms = random.Random(1234)
        values = [0, 1, 2, 0xffffffff, 0x80000000, 0x7fffffff, (1 << 63), 0xdeadbeefcafebabe] + \
                 [randoms.getrandbits(64) for _ in range(30)]
        for code, name in (('f7e1', 'mul32'), ('48f7e1', 'mul64')):
            width = 64 if code.startswith('48') else 32
            mask = (1 << width) - 1
            with self.subTest(name=name):
                self.compare(code, [(value & mask, other & mask, 0) for value in values for other in values[:8]], ('cf', 'of'))

    def test_cwde(self):
        values = [0, 1, 0x7fff, 0x8000, 0xffff, 0x1234, 0xabcd]
        self.compare('98', [(value, 0, 0) for value in values], ())

    def test_bswap(self):
        randoms = random.Random(77)
        values = [0, 1, 0x12345678, 0xdeadbeef, (1 << 63)] + [randoms.getrandbits(64) for _ in range(20)]
        for code, name in (('0fc8', 'bswap32'), ('480fc8', 'bswap64')):
            width = 64 if code.startswith('48') else 32
            mask = (1 << width) - 1
            with self.subTest(name=name):
                self.compare(code, [(value & mask, 0, 0) for value in values], ())

    def test_double_shift(self):
        randoms = random.Random(99)
        values = [0, 1, 0x123456789abcdef0, (1 << 63), 0xffffffffffffffff] + [randoms.getrandbits(64) for _ in range(20)]
        for code, name in (('0fa4c804', 'shld32'), ('480fa4c804', 'shld64'),
                           ('0facc804', 'shrd32'), ('480facc804', 'shrd64')):
            width = 64 if code.startswith('48') else 32
            mask = (1 << width) - 1
            with self.subTest(name=name):
                self.compare(code, [(value & mask, other & mask, 0) for value in values for other in values[:6]], ('cf',))

    def test_noops(self):
        for code, name in (('fc', 'cld'), ('0f1800', 'prefetchnta')):
            with self.subTest(name=name):
                self.compare(code, [(0x123456789abcdef0, 0, 0)], ())


if __name__ == '__main__':
    import unittest
    unittest.main()

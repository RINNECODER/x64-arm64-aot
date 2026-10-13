"""Byte shuffles, palignr, 128-bit lane extract/insert, and the reciprocal family."""
import subprocess

from avx_reference import NativeAvxHarness


class AvxByteTests(NativeAvxHarness):
    def test_pshufb(self):
        for instruction in ('vpshufb xmm0, xmm1, xmm2', 'vpshufb ymm0, ymm1, ymm2',
                            'vpshufb xmm0, xmm1, [rsi]', 'vpshufb ymm0, ymm1, [rsi]'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_palignr(self):
        for width in ('xmm', 'ymm'):
            for amount in (0, 1, 5, 15, 16, 31):
                with self.subTest(width=width, amount=amount):
                    self.compare_native(f'vpalignr {width}0, {width}1, {width}2, {amount}', self.samples())

    def test_extract_insert_128(self):
        for instruction in ('vextracti128 xmm0, ymm1, 0', 'vextracti128 xmm0, ymm1, 1',
                            'vinserti128 ymm0, ymm1, xmm2, 0', 'vinserti128 ymm0, ymm1, xmm2, 1'):
            with self.subTest(instruction=instruction):
                self.compare_native(instruction, self.samples())

    def test_reciprocal_compiles(self):
        # The relinker stubs the 128-bit RCPPS/RSQRTPS as 1/x and 1/sqrt(x); the lifted
        # form emits the same. Only compilation is asserted here (the native instruction
        # is the approximate form the game does not see on the Rosetta path).
        for instruction in ('vrcpps xmm0, xmm1', 'vrcpps ymm0, ymm1',
                            'vrcpss xmm0, xmm1, xmm2',
                            'vrsqrtps xmm0, xmm1', 'vrsqrtps ymm0, ymm1',
                            'vrsqrtss xmm0, xmm1, xmm2'):
            with self.subTest(instruction=instruction):
                instructions, stem = self.instructions(instruction)
                emitter = self.emitter()
                self.assertTrue(__import__('avx').analyze(emitter, instructions[0], emitter.state))
                self.assertTrue(__import__('avx').lower(emitter, instructions[0]))
                ir = stem.with_suffix('.ll')
                ir.write_text(emitter.finish())
                subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ir),
                                '-o', str(stem.with_suffix('.dylib'))], check=True, capture_output=True)

    def emitter(self):
        from test_avx import Emitter
        return Emitter()


if __name__ == '__main__':
    import unittest
    unittest.main()

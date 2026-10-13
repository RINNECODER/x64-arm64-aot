"""Non-lock bit test/set/reset/complement and bit scan, lifted IR vs native x86_64."""
import ctypes
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import integer
from test_integer import FLAG_ORDER, Harness, MASK64

RFLAGS_BITS = {'cf': 0, 'pf': 2, 'zf': 6, 'sf': 7, 'of': 11}


RUNNER = (
    '#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
    'extern void run(uint64_t, uint64_t, uint64_t, uint64_t*);\n'
    'int main(void){ uint64_t in[3]; while(fread(in,1,24,stdin)==24){ uint64_t out[3]={0};\n'
    '  run(in[0],in[1],in[2],out); fwrite(out,1,24,stdout);} return ferror(stdin)?1:0; }\n')


class BitOpReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='anyps5-bitops-')
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.counter = 0

    def decode(self, code):
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        result = list(decoder.disasm(bytes.fromhex(code), 0x1000))
        self.assertEqual(len(result), 1)
        return result[0]

    def lift(self, code):
        ins = self.decode(code)
        harness = Harness(ins)
        state = harness.states[ins.address]
        self.assertTrue(integer.analyze(harness, ins, state))
        ir = harness.finish(ins)
        self.counter += 1
        source = self.directory / f'probe{self.counter}.ll'
        destination = source.with_suffix('.dylib')
        source.write_text(ir)
        result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib',
                                 str(source), '-o', str(destination)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        function = ctypes.CDLL(str(destination)).probe
        function.argtypes = [ctypes.c_uint64] * 6 + [ctypes.POINTER(ctypes.c_uint64)]
        function.restype = None

        def run(rax, rcx, rdx=0):
            output = (ctypes.c_uint64 * 3)()
            function(rax, rdx, rcx, 0, 0, 0, output)
            return output[0], output[1], output[2]
        return run

    def native(self, code):
        body = '\n'.join('  .byte 0x%02x' % byte for byte in bytes.fromhex(code))
        source = self.directory / 'oracle.S'
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          '  push rbp\n  mov rbp, rsp\n  sub rsp, 0x20\n'
                          '  mov QWORD PTR [rbp-8], rcx\n  mov rax, rdi\n  mov rcx, rsi\n'
                          + body + '\n'
                          '  mov r8, QWORD PTR [rbp-8]\n  mov QWORD PTR [r8], rax\n'
                          '  mov QWORD PTR [r8+8], rdx\n'
                          '  pushfq\n  pop r9\n  and r9, 2245\n  mov QWORD PTR [r8+16], r9\n'
                          '  mov rsp, rbp\n  pop rbp\n  ret\n')
        runner = self.directory / 'oracle.c'
        runner.write_text(RUNNER)
        binary = self.directory / 'oracle.x86'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(source), str(runner),
                        '-o', str(binary)], check=True, capture_output=True)
        return binary

    def compare(self, code, samples, flag_names):
        lifted = self.lift(code)
        binary = self.native(code)
        payload = b''.join(struct.pack('<QQQ', rax, rcx, rdx) for rax, rcx, rdx in samples)
        expected = subprocess.run([str(binary)], input=payload, check=True, capture_output=True).stdout
        self.assertEqual(len(expected), len(samples) * 24)
        for index, (rax, rcx, rdx) in enumerate(samples):
            result, _, flags = lifted(rax, rcx, rdx)
            reference = struct.unpack_from('<QQQ', expected, index * 24)
            self.assertEqual(result, reference[0], (code, index, rax, rcx))
            for name in flag_names:
                lifted_bit = (flags >> FLAG_ORDER.index(name)) & 1
                native_bit = (reference[2] >> RFLAGS_BITS[name]) & 1
                self.assertEqual(lifted_bit, native_bit, (code, name, index, rax, rcx))

    def test_register_set_reset_complement(self):
        randoms = random.Random(6649)
        values = [0, 1, 2, MASK64, 0x123456789abcdef0, 1 << 63] + [randoms.getrandbits(64) for _ in range(40)]
        for code, name in (('0fabc8', 'bts32'), ('480fabc8', 'bts64'),
                           ('0fabc8'.replace('ab', 'b3'), 'btr32'), ('480fabc8'.replace('ab', 'b3'), 'btr64'),
                           ('0fabc8'.replace('ab', 'bb'), 'btc32'), ('480fabc8'.replace('ab', 'bb'), 'btc64')):
            width = 64 if code.startswith('48') else 32
            mask = (1 << width) - 1
            samples = [(value, index, 0) for value in values for index in (0, 1, width - 1, width, width + 1, MASK64)]
            with self.subTest(name=name):
                self.compare(code, samples, ('cf',))

    def test_bit_scan(self):
        randoms = random.Random(882)
        values = [0, 1, 2, 3, 1 << 63, MASK64] + [randoms.getrandbits(64) for _ in range(60)]
        for code, name in (('0fbcc1', 'bsf32'), ('480fbcc1', 'bsf64'),
                           ('0fbdc1', 'bsr32'), ('480fbdc1', 'bsr64')):
            with self.subTest(name=name):
                self.compare(code, [(0xdeadbeef, value, 0) for value in values], ('zf',))


if __name__ == '__main__':
    unittest.main()

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
import test_effects
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

    def test_isolate_and_mask_lowest_set_bit(self):
        randoms = random.Random(7731)
        values = [0, 1, 2, 0x80, 0xff, 0x8000, 0x80000000, 0xffffffff, MASK64,
                  0x123456789abcdef0, 1 << 63] + [randoms.getrandbits(64) for _ in range(40)]
        for code, name in (('c4e278f3d9', 'blsi32'), ('c4e278f3d1', 'blsmsk32'), ('c4e278f3c9', 'blsr32'),
                           ('c4e2f8f3d9', 'blsi64'), ('c4e2f8f3d1', 'blsmsk64'), ('c4e2f8f3c9', 'blsr64')):
            width = 64 if code.startswith('c4e2f8') else 32
            mask = (1 << width) - 1
            samples = [(0, value & mask, 0) for value in values]
            with self.subTest(name=name):
                self.compare(code, samples, ('cf', 'zf', 'sf', 'of', 'pf'))

    def test_rotates_immediate_and_register_counts(self):
        randoms = random.Random(4422)
        values = [0, 1, 2, 0x80, 0xff, 0x8000, 0x80000000, 0xffffffff, MASK64,
                  0x123456789abcdef0, 1 << 63] + [randoms.getrandbits(64) for _ in range(30)]
        counts = [0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 0x7f]
        register = (('d2c0', 'rol al, cl'), ('d2c8', 'ror al, cl'), ('66d3c0', 'rol ax, cl'),
                    ('66d3c8', 'ror ax, cl'), ('d3c0', 'rol eax, cl'), ('d3c8', 'ror eax, cl'),
                    ('48d3c0', 'rol rax, cl'), ('48d3c8', 'ror rax, cl'),
                    ('d2d0', 'rcl al, cl'), ('d2d8', 'rcr al, cl'), ('d3d0', 'rcl eax, cl'),
                    ('d3d8', 'rcr eax, cl'), ('48d3d0', 'rcl rax, cl'), ('48d3d8', 'rcr rax, cl'))
        for code, name in register:
            with self.subTest(name=name):
                self.compare(code, [(value, count, 0) for value in values for count in counts], ('cf',))
        immediate = (('c0c000', 'rol al, 0'), ('c0c001', 'rol al, 1'), ('c0c81f', 'ror al, 31'),
                     ('c0c008', 'rol al, 8'), ('c0c009', 'rol al, 9'),
                     ('66c1c001', 'rol ax, 1'), ('66c1c83f', 'ror ax, 63'),
                     ('c1c001', 'rol eax, 1'), ('c1c81f', 'ror eax, 31'), ('c1c100', 'rol ecx, 0'),
                     ('48c1c001', 'rol rax, 1'), ('48c1c83f', 'ror rax, 63'),
                     ('c1d001', 'rcl eax, 1'), ('c1d83f', 'rcr eax, 63'), ('48c1d001', 'rcl rax, 1'))
        for code, name in immediate:
            with self.subTest(name=name):
                self.compare(code, [(value, 0, 0) for value in values], ('cf',))
        # OF is defined only for a count of one.
        for code, name in (('d3c0', 'rol eax, cl'), ('d3c8', 'ror eax, cl'),
                           ('48d3c0', 'rol rax, cl'), ('48d3c8', 'ror rax, cl')):
            with self.subTest(name=name + ' count 1'):
                self.compare(code, [(value, 1, 0) for value in values], ('cf', 'of'))
        for code, name in (('c0c001', 'rol al, 1'), ('c1c001', 'rol eax, 1'), ('48c1c001', 'rol rax, 1')):
            with self.subTest(name=name):
                self.compare(code, [(value, 0, 0) for value in values], ('cf', 'of'))

    def test_bit_scan(self):
        randoms = random.Random(882)
        values = [0, 1, 2, 3, 1 << 63, MASK64] + [randoms.getrandbits(64) for _ in range(60)]
        for code, name in (('0fbcc1', 'bsf32'), ('480fbcc1', 'bsf64'),
                           ('0fbdc1', 'bsr32'), ('480fbdc1', 'bsr64')):
            with self.subTest(name=name):
                self.compare(code, [(0xdeadbeef, value, 0) for value in values], ('zf',))


class MemoryBitTestTests(unittest.TestCase):
    """`bt m, r/imm` tests a bit of a bit string in memory, crossing operand boundaries."""
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture

    def test_memory_bit_test_with_a_register_index(self):
        body = ('sub rsp, 16\n'
                'mov qword ptr [rsp], rdi\n'
                'mov qword ptr [rsp + 8], rsi\n'
                'bt qword ptr [rsp], rdx\n'
                'setc al\n'
                'movzx eax, al\n'
                'add rsp, 16\n'
                'ret')
        raw, contracts = self.fixture([('test_entry', body, ['i64', 'i64', 'i64'], 'i64')])
        function, _, _ = self.compile(raw, contracts)
        for value, high, index, expected in (
                (0x20, 0, 5, 1), (0x20, 0, 4, 0), (1 << 63, 0, 63, 1), (0, 0, 0, 0),
                (0, 1, 64, 1), (0, 0, 64, 0), (0, 1, 32, 0), (0, 1, 96, 0)):
            with self.subTest(value=value, index=index):
                self.assertEqual(function(value, high, index), expected)

    def test_memory_bit_test_with_an_immediate_index(self):
        body = ('sub rsp, 16\n'
                'mov qword ptr [rsp], rdi\n'
                'mov qword ptr [rsp + 8], rsi\n'
                'bt qword ptr [rsp], 5\n'
                'setc al\n'
                'movzx eax, al\n'
                'add rsp, 16\n'
                'ret')
        raw, contracts = self.fixture([('test_entry', body, ['i64', 'i64'], 'i64')])
        function, _, _ = self.compile(raw, contracts)
        self.assertEqual(function(0x20, 0), 1)
        self.assertEqual(function(0x10, 0), 0)

    def test_memory_bit_test_crosses_a_dword_boundary(self):
        body = ('sub rsp, 16\n'
                'mov dword ptr [rsp], edi\n'
                'mov dword ptr [rsp + 4], esi\n'
                'bt dword ptr [rsp], edx\n'
                'setc al\n'
                'movzx eax, al\n'
                'add rsp, 16\n'
                'ret')
        raw, contracts = self.fixture([('test_entry', body, ['i64', 'i64', 'i64'], 'i64')])
        function, _, _ = self.compile(raw, contracts)
        for value, high, index, expected in (
                (1, 0, 0, 1), (0, 1, 32, 1), (0, 0, 32, 0), (1, 0, 32, 0)):
            with self.subTest(value=value, index=index):
                self.assertEqual(function(value, high, index), expected)


if __name__ == '__main__':
    unittest.main()

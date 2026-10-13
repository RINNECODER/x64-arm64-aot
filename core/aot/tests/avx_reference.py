"""Native x86_64 reference harness for the AVX/AVX2 lifter tests.

Builds the same snippet twice: once as the lifted ARM64 LLVM IR (via test_avx.Emitter)
and once as a native x86_64 binary run under Rosetta, then compares the two. Output
layout matches test_avx.Emitter.finish: 32 bytes ymm0, 32 ymm1, 32 ymm2, 32 scratch
([rdx]), 8 rax, 8 packed flags.
"""
import ctypes
import io
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

import atomics
import avx
import bmi
import fma
import integer
import system
import vector
import x87
from test_avx import Emitter


ORACLE_PREFIX = (
    '.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
    '  push rbp\n  mov rbp, rsp\n  sub rsp, 0x40\n'
    '  mov QWORD PTR [rbp-8], rcx\n  mov QWORD PTR [rbp-16], rdx\n'
    '  mov rcx, r8\n  xor eax, eax\n'
    '  vmovups ymm0, YMMWORD PTR [rdi]\n'
    '  vmovups ymm1, YMMWORD PTR [rsi]\n'
    '  vmovups ymm2, YMMWORD PTR [rdx]\n'
    '  mov rdx, QWORD PTR [rbp-8]\n  add rdx, 96\n')

ORACLE_SUFFIX = (
    '\n  mov r8, QWORD PTR [rbp-8]\n'
    '  vmovups YMMWORD PTR [r8], ymm0\n'
    '  vmovups YMMWORD PTR [r8+32], ymm1\n'
    '  vmovups YMMWORD PTR [r8+64], ymm2\n'
    '  mov QWORD PTR [r8+128], rax\n'
    '  pushfq\n  pop rax\n  and rax, 2245\n  mov QWORD PTR [r8+136], rax\n'
    '  mov rsp, rbp\n  pop rbp\n  ret\n')

RUNNER = (
    '#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
    'extern void run(const void*, const void*, const void*, void*, uint64_t);\n'
    'int main(void) {\n'
    '  unsigned char raw[256], outraw[256];\n'
    '  unsigned char *in = (unsigned char*)(((uintptr_t)raw + 31) & ~(uintptr_t)31);\n'
    '  unsigned char *out = (unsigned char*)(((uintptr_t)outraw + 31) & ~(uintptr_t)31);\n'
    '  while (fread(in, 1, 104, stdin) == 104) {\n'
    '    uint64_t scalar; memcpy(&scalar, in + 96, 8);\n'
    '    memset(out, 0xa5, 144);\n'
    '    run(in, in + 32, in + 64, out, scalar);\n'
    '    if (fwrite(out, 1, 144, stdout) != 144) return 2;\n'
    '  }\n'
    '  return ferror(stdin) ? 1 : 0;\n}\n')


def _normalize_nan(blob):
    value = bytearray(blob)
    for lane in range(34):
        bits = struct.unpack_from('<I', value, lane * 4)[0]
        if bits & 0x7f800000 == 0x7f800000 and bits & 0x007fffff:
            struct.pack_into('<I', value, lane * 4, 0x7fc00000)
    return bytes(value)

class NativeAvxHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='anyps5-avx-native-')
        cls.directory = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        cls.decoder.detail = True
        cls.serial = 0

    def instructions(self, assembly):
        type(self).serial += 1
        stem = self.directory / f'{type(self).__name__}-{self.serial}'
        source = stem.with_suffix('.S')
        source.write_text('.intel_syntax noprefix\n.text\n' + assembly + '\n')
        obj = stem.with_suffix('.x86.o')
        subprocess.run(['xcrun', 'clang', '--target=x86_64-unknown-freebsd', '-mavx2',
                        '-c', str(source), '-o', str(obj)], check=True, capture_output=True)
        code = ELFFile(io.BytesIO(obj.read_bytes())).get_section_by_name('.text').data()
        decoded = list(self.decoder.disasm(code, 0x1000))
        self.assertEqual(sum(ins.size for ins in decoded), len(code))
        return decoded, stem

    def samples(self, count=40, seed=681):
        randoms = random.Random(seed)
        return [(randoms.randbytes(32), randoms.randbytes(32), randoms.randbytes(32),
                 randoms.getrandbits(64)) for _ in range(count)]

    def compare_native(self, assembly, samples, flag_mask=None, nan_normalize=False):
        instructions, stem = self.instructions(assembly)
        emitter = Emitter()
        for ins in instructions:
            handled = False
            for module in (fma, avx, vector, x87, integer, bmi, system, atomics):
                if module.analyze(emitter, ins, emitter.state):
                    self.assertTrue(module.lower(emitter, ins))
                    handled = True
                    break
            self.assertTrue(handled, ins.mnemonic)
        ir = stem.with_suffix('.ll')
        ir.write_text(emitter.finish())
        native = stem.with_suffix('.dylib')
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ir),
                        '-o', str(native)], check=True, capture_output=True)
        function = ctypes.CDLL(str(native)).test_entry
        function.argtypes = [ctypes.c_void_p] * 4 + [ctypes.c_uint64]
        function.restype = None

        oracle = stem.with_suffix('.oracle.S')
        oracle.write_text(ORACLE_PREFIX + assembly + '\n' + ORACLE_SUFFIX)
        runner = stem.with_suffix('.runner.c')
        runner.write_text(RUNNER)
        binary = stem.with_suffix('.x86')
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', '-mavx2', str(oracle),
                        str(runner), '-o', str(binary)], check=True, capture_output=True)
        payload = b''.join(a + b + c + struct.pack('<Q', scalar) for a, b, c, scalar in samples)
        expected = subprocess.run([binary], input=payload, check=True, capture_output=True).stdout
        self.assertEqual(len(expected), len(samples) * 144)

        for index, (a, b, c, scalar) in enumerate(samples):
            storage = [ctypes.create_string_buffer(64) for _ in range(3)]
            addresses = [(ctypes.addressof(value) + 31) & ~31 for value in storage]
            for address, data in zip(addresses, (a, b, c)):
                ctypes.memmove(address, data, 32)
            out_storage = ctypes.create_string_buffer(176)
            out_address = (ctypes.addressof(out_storage) + 31) & ~31
            ctypes.memset(out_address, 0xa5, 144)
            function(*addresses, out_address, scalar)
            actual = ctypes.string_at(out_address, 144)
            reference = expected[index * 144:(index + 1) * 144]
            if nan_normalize:
                actual = _normalize_nan(actual)
                reference = _normalize_nan(reference)
            self.assertEqual(actual[:136], reference[:136],
                             (assembly, index, a.hex(), b.hex(), c.hex(), scalar))
            if flag_mask is not None:
                self.assertEqual(struct.unpack_from('<Q', actual, 136)[0] & flag_mask,
                                 struct.unpack_from('<Q', reference, 136)[0] & flag_mask,
                                 (assembly, index))
        return native

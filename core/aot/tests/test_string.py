"""REP STOS string stores, lifted IR vs native x86_64."""
import ctypes
import subprocess
import tempfile
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import integer
from test_integer import Harness


ORACLE = """  push rbp
  mov rbp, rsp
  sub rsp, 0x20
  mov QWORD PTR [rbp-8], rcx
  mov rax, rdi
  mov rcx, rsi
  mov rdi, rdx
  .byte {bytes}
  mov r8, QWORD PTR [rbp-8]
  mov QWORD PTR [r8], rdi
  mov rsp, rbp
  pop rbp
  ret
"""
RUNNER = (
    '#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
    'extern void run(uint64_t, uint64_t, void*, uint64_t*);\n'
    'int main(void){ uint64_t in[3]; while(fread(in,1,24,stdin)==24){ uint8_t buf[64];\n'
    '  memset(buf,0xaa,sizeof(buf)); uint64_t out=0; run(in[0],in[1],buf,&out);\n'
    '  fwrite(buf,1,64,stdout); fwrite(&out,1,8,stdout);} return ferror(stdin)?1:0; }\n')


class StringStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='anyps5-string-')
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.counter = 0

    def decode(self, code):
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        decoder.detail = True
        return list(decoder.disasm(bytes.fromhex(code), 0x1000))[0]

    def compare(self, code, samples):
        ins = self.decode(code)
        harness = Harness(ins)
        state = harness.states[ins.address]
        self.assertTrue(integer.analyze(harness, ins, state))
        self.counter += 1
        source = self.directory / f'probe{self.counter}.ll'
        source.write_text(harness.finish(ins))
        destination = source.with_suffix('.dylib')
        result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib',
                                 str(source), '-o', str(destination)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        function = ctypes.CDLL(str(destination)).probe
        function.argtypes = [ctypes.c_uint64] * 6 + [ctypes.POINTER(ctypes.c_uint64)]
        function.restype = None

        oracle = self.directory / f'oracle{self.counter}.S'
        oracle.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          + ORACLE.format(bytes=', '.join('0x%02x' % byte for byte in bytes.fromhex(code))))
        runner = self.directory / f'oracle{self.counter}.c'
        runner.write_text(RUNNER)
        binary = self.directory / f'oracle{self.counter}.x86'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(oracle), str(runner),
                        '-o', str(binary)], check=True, capture_output=True)

        import struct
        payload = b''.join(struct.pack('<QQQ', value, count, 0) for value, count in samples)
        expected = subprocess.run([str(binary)], input=payload, check=True, capture_output=True).stdout
        for index, (value, count) in enumerate(samples):
            buffer = ctypes.create_string_buffer(b'\xaa' * 64, 64)
            output = (ctypes.c_uint64 * 3)()
            function(value, 0, count, ctypes.addressof(buffer), 0, 0, output)
            reference = expected[index * 72:index * 72 + 64]
            self.assertEqual(buffer.raw[:64], reference, (code, index, value, count))

    def test_rep_stos(self):
        samples = [(0x1122334455667788, 0), (0x1122334455667788, 1), (0xdeadbeefcafebabe, 5),
                   (0xffffffffffffffff, 8), (0x0102030405060708, 4)]
        for code, name in (('f348ab', 'rep_stosq'), ('f3ab', 'rep_stosd'), ('66f3ab', 'rep_stosw')):
            with self.subTest(name=name):
                self.compare(code, samples)


if __name__ == '__main__':
    unittest.main()

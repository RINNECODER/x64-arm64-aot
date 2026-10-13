import ctypes
import io
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

import bmi
import integer
from test_integer import FLAG_ORDER, MASK64, Harness


class BmiHarness(Harness):
    def finish(self, instruction):
        if not bmi.lower(self, instruction):
            integer.lower(self, instruction)
        combined = '0'
        for index, name in enumerate(FLAG_ORDER):
            value = self.emit(f'zext i1 {integer.load_flag(self, name)} to i64')
            value = self.emit(f'shl i64 {value}, {index}')
            combined = self.emit(f'or i64 {combined}, {value}')
        for index, value in enumerate([self.load('rax'), self.load('rdx'), combined]):
            address = self.emit(f'getelementptr i64, ptr %output, i64 {index}')
            self.lines.append(f'  store i64 {value}, ptr {address}, align 8')
        self.lines.extend(['  ret void', '}'])
        return '\n'.join(self.lines)


class BMITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='anyps5-bmi-')
        cls.directory = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        cls.decoder.detail = True
        cls.serial = 0

    def assemble(self, assembly):
        type(self).serial += 1
        stem = self.directory / str(self.serial)
        source = stem.with_suffix('.S')
        source.write_text('.intel_syntax noprefix\n.text\n' + assembly + '\n')
        obj = stem.with_suffix('.o')
        subprocess.run(['xcrun', 'clang', '--target=x86_64-unknown-freebsd', '-c', str(source), '-o', str(obj)],
                       check=True, capture_output=True)
        code = ELFFile(io.BytesIO(obj.read_bytes())).get_section_by_name('.text').data()
        decoded = list(self.decoder.disasm(code, 0x1000))
        self.assertEqual(len(decoded), 1)
        return decoded[0], stem

    def oracle(self, assembly, samples):
        ins, stem = self.assemble(assembly)
        source = stem.with_suffix('.oracle.S')
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          'mov r10, rdi\nmov rax, rsi\n' + assembly +
                          '\nmov [r10], rax\nmov [r10+8], rdx\npushfq\npop rax\nand rax, 2245\nmov [r10+16], rax\nret\n')
        runner = stem.with_suffix('.c')
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
                          'extern void run(uint64_t*, uint64_t, uint64_t, uint64_t);\n'
                          'int main(void){uint64_t in[3], out[3]; while(fread(in,8,3,stdin)==3){'
                          'memset(out,0,sizeof out); run(out,in[0],in[1],in[2]); fwrite(out,8,3,stdout);} return 0;}\n')
        binary = stem.with_suffix('.x86')
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(source), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        payload = b''.join(struct.pack('<QQQ', rax, rdx, rcx) for rax, rdx, rcx in samples)
        raw = subprocess.run([str(binary)], input=payload, check=True, capture_output=True).stdout
        return [struct.unpack_from('<QQQ', raw, index * 24) for index in range(len(samples))]

    def native(self, assembly):
        ins, stem = self.assemble(assembly)
        harness = BmiHarness(ins)
        state = harness.states[ins.address]
        if not bmi.analyze(harness, ins, state):
            self.assertTrue(integer.analyze(harness, ins, state))
        defined = set() if ins.mnemonic in ('mulx', 'rorx', 'shlx', 'shrx', 'sarx', 'movbe') else set(state['flags'])
        ir = stem.with_suffix('.ll')
        ir.write_text(harness.finish(ins))
        destination = stem.with_suffix('.dylib')
        result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ir), '-o', str(destination)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        library = ctypes.CDLL(str(destination))
        function = library.probe
        function.argtypes = [ctypes.c_uint64] * 6 + [ctypes.POINTER(ctypes.c_uint64)]
        function.restype = None

        def run(rax, rdx, rcx):
            output = (ctypes.c_uint64 * 3)()
            function(rax, rdx, rcx, 0, 0, 0, output)
            return output[0], output[1], {name: output[2] >> index & 1 for index, name in enumerate(FLAG_ORDER)}
        return run, defined

    X86_BIT = {'cf': 0, 'pf': 2, 'zf': 6, 'sf': 7, 'of': 11}

    def check(self, assembly, samples):
        expected = self.oracle(assembly, samples)
        run, defined = self.native(assembly)
        for index, (rax, rdx, rcx) in enumerate(samples):
            result_rax, result_rdx, flags = run(rax, rdx, rcx)
            want_rax, want_rdx, want_flags = expected[index]
            self.assertEqual((result_rax, result_rdx), (want_rax, want_rdx), (assembly, index, hex(rax)))
            for name in defined:
                self.assertEqual(flags[name], (want_flags >> self.X86_BIT[name]) & 1, (assembly, index, name, hex(rax)))

    def test_bmi2_and_scalar_tail_against_x86(self):
        cases = ['andn rax, rdx, rcx', 'mulx rdx, rax, rcx', 'bextr rax, rdx, rcx',
                 'bzhi rax, rdx, rcx', 'shlx rax, rdx, rcx', 'shrx rax, rdx, rcx',
                 'sarx rax, rdx, rcx', 'rorx rax, rdx, 5', 'popcnt rax, rdx', 'lzcnt rax, rdx', 'tzcnt rax, rdx',
                 'rol rax, cl', 'ror rax, cl']
        values = [0, 1, 2, 0x123456789abcdef0, MASK64, 1 << 63, 0xff00ff00ff00ff00]
        controls = [0, 1, 3, 7, 8, 63, 64, 200]
        for assembly in cases:
            samples = [(value, value, control) for value in values for control in controls]
            self.check(assembly, samples)

    def test_one_operand_mul_div_against_x86(self):
        values = [0, 1, 2, 3, 0x123456789abcdef0, MASK64, 1 << 63, 0xffffffff]
        self.check('imul rcx', [(rax, 0, rcx) for rax in values for rcx in values])
        division = []
        for rax in values:
            for rcx in [1, 2, 3, 7, 0x100, 1 << 32, MASK64]:
                division.append((rax, 0, rcx))
        self.check('div rcx', division)
        signed_division = [(rax, MASK64 if rax >> 63 else 0, rcx)
                           for rax in values for rcx in [1, 2, 3, 7, 0x100, 1 << 32]]
        self.check('idiv rcx', signed_division)

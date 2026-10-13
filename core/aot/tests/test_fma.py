import ctypes
import io
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile

import fma
import vector


class FmaEmitter:
    def __init__(self):
        self.serial = 0
        self.contract = {'floating_point': dict(vector.FP_POLICY)}
        self.lines = ['target triple = "arm64-apple-macosx13.0.0"', 'declare void @llvm.trap()',
                      'define void @test_entry(ptr %left, ptr %right, ptr %third, ptr %out) {', 'entry:']
        for name, source in [('xmm0', 'left'), ('xmm1', 'right'), ('xmm2', 'third')]:
            self.lines.append(f'  %{name} = alloca i128, align 16')
            value = self.emit(f'load i128, ptr %{source}, align 1')
            self.lines.append(f'  store i128 {value}, ptr %{name}, align 16')
        for index in range(16):
            self.lines.append(f'  %ymm_hi{index} = alloca i128, align 16')
            self.lines.append(f'  store i128 0, ptr %ymm_hi{index}, align 16')
        self.state = {'known': {'xmm0': vector.MASK128, 'xmm1': vector.MASK128, 'xmm2': vector.MASK128}, 'flags': set()}

    def emit(self, expression):
        self.serial += 1
        value = f'%v{self.serial}'
        self.lines.append(f'  {value} = {expression}')
        return value

    def fail(self, ins, message):
        raise ValueError(message)

    def check_register(self, ins, state, name, bits, shift=0):
        if state['known'].get(name, 0) & (((1 << bits) - 1) << shift) != ((1 << bits) - 1) << shift:
            self.fail(ins, 'undefined register bits')

    def read_operand(self, ins, state, operand):
        if operand.type == X86_OP_MEM:
            self.address(ins, operand)
        elif operand.type == X86_OP_REG:
            self.check_register(ins, state, ins.reg_name(operand.reg), operand.size * 8)

    def define(self, ins, state, operand):
        pass

    def address(self, ins, operand):
        name = ins.reg_name(operand.mem.base)
        if operand.mem.index or operand.mem.disp or name not in ('rdi', 'rsi', 'rdx'):
            raise ValueError('unsupported test address')
        return {'rdi': '%left', 'rsi': '%right', 'rdx': '%out'}[name]

    def read(self, ins, operand, bits=None):
        bits = operand.size * 8 if bits is None else bits
        if operand.type == X86_OP_MEM:
            return self.emit(f'load i{bits}, ptr {self.address(ins, operand)}, align 1')
        name = ins.reg_name(operand.reg)
        value = self.emit(f'load i128, ptr %{name}, align 16')
        return value if bits == 128 else self.emit(f'trunc i128 {value} to i{bits}')

    def store_vector(self, name, value, bits=128, zero_upper=False):
        if bits != 128:
            value = self.emit(f'zext i{bits} {value} to i128')
            if not zero_upper:
                old = self.emit(f'load i128, ptr %{name}, align 16')
                upper = self.emit(f'and i128 {old}, {vector.MASK128 ^ ((1 << bits) - 1)}')
                value = self.emit(f'or i128 {upper}, {value}')
        self.lines.append(f'  store i128 {value}, ptr %{name}, align 16')

    def load(self, name, bits=64, shift=0):
        value = self.emit(f'load i128, ptr %{name}, align 16')
        if shift:
            value = self.emit(f'lshr i128 {value}, {shift}')
        return value if bits >= 128 else self.emit(f'trunc i128 {value} to i{bits}')

    def store(self, name, value, bits=64, shift=0):
        if bits < 128:
            value = self.emit(f'zext i{bits} {value} to i128')
        self.lines.append(f'  store i128 {value}, ptr %{name}, align 16')

    def finish(self):
        value = self.emit('load i128, ptr %xmm0, align 16')
        self.lines.append(f'  store i128 {value}, ptr %out, align 1')
        self.lines.extend(['  ret void', '}'])
        return '\n'.join(self.lines) + '\n'


class FMATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='anyps5-fma-')
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
        subprocess.run(['xcrun', 'clang', '--target=x86_64-unknown-freebsd', '-mavx2', '-mfma', '-c', str(source), '-o', str(obj)],
                       check=True, capture_output=True)
        code = ELFFile(io.BytesIO(obj.read_bytes())).get_section_by_name('.text').data()
        decoded = list(self.decoder.disasm(code, 0x1000))
        self.assertEqual(len(decoded), 1)
        return decoded[0], stem

    def compare(self, assembly, samples):
        ins, stem = self.assemble(assembly)
        emitter = FmaEmitter()
        self.assertTrue(fma.analyze(emitter, ins, emitter.state))
        self.assertTrue(fma.lower(emitter, ins))
        ir = stem.with_suffix('.ll')
        ir.write_text(emitter.finish())
        native = stem.with_suffix('.dylib')
        result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ir), '-o', str(native)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        library = ctypes.CDLL(str(native))
        function = library.test_entry
        function.restype = None
        function.argtypes = [ctypes.c_void_p] * 4
        oracle = stem.with_suffix('.oracle.S')
        oracle.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          'movdqu xmm0, XMMWORD PTR [rdi]\nmovdqu xmm1, XMMWORD PTR [rsi]\nmovdqu xmm2, XMMWORD PTR [rdx]\n'
                          + assembly + '\nmovdqu XMMWORD PTR [rcx], xmm0\nret\n')
        runner = stem.with_suffix('.c')
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
                          'extern void run(const void*, const void*, const void*, void*);\n'
                          'int main(void){unsigned char a[16],b[16],c[16],o[16];'
                          'while(fread(a,1,16,stdin)==16&&fread(b,1,16,stdin)==16&&fread(c,1,16,stdin)==16){'
                          'memset(o,0,16);run(a,b,c,o);fwrite(o,1,16,stdout);} return 0;}\n')
        binary = stem.with_suffix('.x86')
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(oracle), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        payload = b''.join(a + b + c for a, b, c in samples)
        expected = subprocess.run([str(binary)], input=payload, check=True, capture_output=True).stdout
        for index, (a, b, c) in enumerate(samples):
            left, right, third, out = (ctypes.create_string_buffer(value, 16) for value in (a, b, c, b'\0' * 16))
            function(left, right, third, out)
            actual, reference = bytearray(out.raw), bytearray(expected[index * 16:(index + 1) * 16])
            for value in (actual, reference):
                for lane in range(4):
                    bits = struct.unpack_from('<I', value, lane * 4)[0]
                    if bits & 0x7f800000 == 0x7f800000 and bits & 0x007fffff:
                        struct.pack_into('<I', value, lane * 4, 0x7fc00000)
            self.assertEqual(actual, reference, (assembly, index))

    def test_fma_against_x86(self):
        import random
        randoms = random.Random(0x5f3a)
        samples = [(randoms.randbytes(16), randoms.randbytes(16), randoms.randbytes(16)) for _ in range(60)]
        cases = ['vfmadd132ps xmm0, xmm1, xmm2', 'vfmadd213ps xmm0, xmm1, xmm2', 'vfmadd231ps xmm0, xmm1, xmm2',
                 'vfmsub132ps xmm0, xmm1, xmm2', 'vfnmadd132ps xmm0, xmm1, xmm2', 'vfnmsub213ps xmm0, xmm1, xmm2',
                 'vfmaddsub132ps xmm0, xmm1, xmm2', 'vfmsubadd231ps xmm0, xmm1, xmm2',
                 'vfmadd132pd xmm0, xmm1, xmm2', 'vfmadd213sd xmm0, xmm1, xmm2', 'vfmadd132ss xmm0, xmm1, xmm2']
        for assembly in cases:
            self.compare(assembly, samples)

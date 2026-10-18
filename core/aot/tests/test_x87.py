import ctypes
import math
import subprocess
import unittest
from pathlib import Path

from compiler import Image, compile_image
from test_uniform import RegisterFile, fixture, uniform_function


class X87Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.temporary = tempfile.TemporaryDirectory(prefix='anyps5-x87-')
        cls.directory = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.serial = 0

    def build(self, code):
        type(self).serial += 1
        raw, contracts = fixture(bytes(code), [uniform_function('sub_1000', 0x1000, len(code))])
        elf = self.directory / f'input{self.serial}.elf'
        elf.write_bytes(raw)
        ir, report = compile_image(Image(elf, contracts))
        ll = self.directory / f'x87{self.serial}.ll'
        ll.write_text(ir)
        library_path = self.directory / f'x87{self.serial}.dylib'
        result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ll), '-o', str(library_path)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        library = ctypes.CDLL(str(library_path))
        function = library.sub_1000
        function.restype = None
        function.argtypes = [ctypes.POINTER(RegisterFile)]
        return function

    def oracle(self, code):
        source = self.directory / f'oracle{self.serial}.S'
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          + '\n'.join(f'.byte 0x{byte:02x}' for byte in code) + '\nret\n')
        runner = self.directory / f'runner{self.serial}.c'
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
                          'extern void run(const void*, void*);\n'
                          'int main(void){double in, out; while(fread(&in,8,1,stdin)==1){out=0;run(&in,&out);fwrite(&out,8,1,stdout);}return 0;}\n')
        binary = self.directory / f'oracle{self.serial}.x86'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(source), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        import struct
        values = [1.5, 2.0, 3.25, 16.0, -4.5, 0.0, 100.0, 0.125]
        payload = b''.join(struct.pack('<d', value) for value in values)
        raw = subprocess.run([str(binary)], input=payload, check=True, capture_output=True).stdout
        return values, [struct.unpack_from('<d', raw, index * 8)[0] for index in range(len(values))]

    def check(self, code):
        values, expected = self.oracle(code)
        function = self.build(code)
        for value, want in zip(values, expected):
            registers = RegisterFile()
            input_buffer = ctypes.create_string_buffer(8)
            ctypes.memmove(input_buffer, ctypes.byref(ctypes.c_double(value)), 8)
            output_buffer = ctypes.create_string_buffer(8)
            registers.gpr[7] = ctypes.addressof(input_buffer)  # rdi
            registers.gpr[6] = ctypes.addressof(output_buffer)  # rsi
            function(ctypes.byref(registers))
            got = ctypes.c_double.from_buffer(output_buffer).value
            if math.isnan(want):
                self.assertTrue(math.isnan(got), (code.hex(), value))
            else:
                self.assertAlmostEqual(got, want, places=12, msg=(code.hex(), value))

    def compare_memory(self, code, samples, in_size, out_size):
        """Run `code` lifted and natively (x86_64) over `samples` and compare the output bytes."""
        import struct
        type(self).serial += 1
        source = self.directory / f'oracle{self.serial}.S'
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          + '\n'.join(f'.byte 0x{byte:02x}' for byte in code) + '\nret\n')
        runner = self.directory / f'runner{self.serial}.c'
        width = in_size * len(samples[0])
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n'
                          'extern void run(const void*, void*);\n'
                          f'int main(void){{ unsigned char in[{width}], out[{out_size}]; '
                          f'while(fread(in,1,{width},stdin)=={width}){{ '
                          f'for(unsigned i=0;i<{out_size};i++) out[i]=0; run(in,out); fwrite(out,1,{out_size},stdout);}} return 0; }}\n')
        binary = self.directory / f'oracle{self.serial}.x86'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(source), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        fmt = '<f' if in_size == 4 else '<d'
        payload = b''.join(struct.pack(fmt, value) for sample in samples for value in sample)
        raw = subprocess.run([str(binary)], input=payload, check=True, capture_output=True).stdout
        function = self.build(code)
        for index, sample in enumerate(samples):
            registers = RegisterFile()
            packed = b''.join(struct.pack(fmt, value) for value in sample)
            input_buffer = ctypes.create_string_buffer(packed, len(packed))
            output_buffer = ctypes.create_string_buffer(out_size)
            registers.gpr[7] = ctypes.addressof(input_buffer)  # rdi
            registers.gpr[6] = ctypes.addressof(output_buffer)  # rsi
            function(ctypes.byref(registers))
            got, want = output_buffer.raw[:out_size], raw[index * out_size:(index + 1) * out_size]
            if out_size == 8:
                self.assertAlmostEqual(struct.unpack('<d', got)[0], struct.unpack('<d', want)[0], places=12,
                                       msg=(code.hex(), sample))
            elif out_size == 4:
                self.assertAlmostEqual(struct.unpack('<f', got)[0], struct.unpack('<f', want)[0], places=6,
                                       msg=(code.hex(), sample))
            else:
                self.assertEqual(got, want, (code.hex(), sample))

    def test_fcmov_reads_the_stored_flags(self):
        # fld a ; fld b ; fld c ; fucomi st(2) ; fcmovb st(0), st(1) ; fstp qword [rsi] ;
        # fstp st(0) ; fstp st(0) ; ret — fcmovb must use CF from `fucomi st(0), st(2)`, not a
        # fresh st(0)/st(1) comparison, and the stack is left balanced for the next sample.
        code = bytes.fromhex('d907d94704d94708dbeadac1dd1eddd8ddd8c3')
        samples = [(10.0, 5.0, 7.0), (3.0, 5.0, 7.0), (7.0, 5.0, 10.0), (1.0, 2.0, 3.0)]
        self.compare_memory(code, samples, in_size=4, out_size=8)

    def test_fld_fst_m32_uses_float_width(self):
        # fld dword [rdi] ; fstp dword [rsi] ; ret — m32 is a 4-byte float, not a double.
        self.compare_memory(bytes.fromhex('d907d91ec3'),
                            [(1.5,), (2.0,), (-4.5,), (0.125,)], in_size=4, out_size=4)

    def test_fstp_m80_encodes_the_extended_value(self):
        # fld qword [rdi] ; fstp tbyte [rsi] ; ret — the 80-bit store needs an 80-bit value.
        self.compare_memory(bytes.fromhex('dd07db3ec3'),
                            [(1.5,), (2.0,), (-4.5,), (100.0,)], in_size=8, out_size=10)

    def test_x87_arithmetic_against_x86(self):
        cases = [
            bytes.fromhex('dd07d9e8dec1dd1ec3'),  # fld [rdi] ; fld1 ; faddp ; fstp [rsi] ; ret
            bytes.fromhex('dd07dd07dec9dd1ec3'),  # fld [rdi] ; fld [rdi] ; fmulp ; fstp [rsi] ; ret
            bytes.fromhex('dd07d9e0dd1ec3'),      # fld [rdi] ; fchs ; fstp [rsi] ; ret
            bytes.fromhex('dd07d9fadd1ec3'),      # fld [rdi] ; fsqrt ; fstp [rsi] ; ret
            bytes.fromhex('dd07d9e1dd1ec3'),      # fld [rdi] ; fabs ; fstp [rsi] ; ret
            bytes.fromhex('dd07d9e8d9c9dd1ec3'),  # fld [rdi] ; fld1 ; fxch st(1) ; fstp [rsi] ; ret
            bytes.fromhex('dd07d9e8dee9dd1ec3'),  # fld [rdi] ; fld1 ; fsubp ; fstp [rsi] ; ret
            bytes.fromhex('dd07d9e8def9dd1ec3'),  # fld [rdi] ; fld1 ; fdivp ; fstp [rsi] ; ret
        ]
        for code in cases:
            self.check(code)

    def test_fucompi_compares_sets_flags_and_pops_once(self):
        # fld [rdi] ; fld [rdi+8] ; fucompi st(1) ; fstp [rsi+8] ; fld1 ; jae +2 ; fchs ;
        # fstp [rsi] ; ret — capstone spells FUCOMIP ST(0), ST(1) as `fucompi st(1)`. The flags
        # must come from b vs a, the pop must leave a on the stack for the first store, and the
        # stack must end balanced.
        code = bytes.fromhex('dd07dd4708dfe9dd5e08d9e87302d9e0dd1ec3')
        samples = [(1.0, 2.0), (2.0, 1.0), (1.0, 1.0), (-3.0, 0.5), (0.5, -3.0)]
        self.compare_memory(code, samples, in_size=8, out_size=16)

    def test_fucompi_st0_compares_the_top_with_itself(self):
        # fld [rdi] ; fucompi st(0) ; fld1 ; jae +2 ; fchs ; fstp [rsi] ; ret — `st(0)` is an
        # explicit operand, so the comparison is ST(0) with ST(0) (always equal), not with ST(1).
        code = bytes.fromhex('dd07dfe8d9e87302d9e0dd1ec3')
        samples = [(1.5,), (2.0,), (-4.5,)]
        self.compare_memory(code, samples, in_size=8, out_size=8)

    def test_integer_arithmetic_from_memory(self):
        # fild dword [rdi] ; fild dword [rdi+4] ; fisub dword [rdi] ; fstp qword [rsi] ; ret —
        # the two int32 operands are loaded as doubles and FISUB subtracts the memory integer.
        # The harness reinterprets the float payload as two int32s on both sides.
        code = bytes.fromhex('db07db4704da27dd1ec3')
        samples = [(1.5, 2.25), (3.0, 1.0), (-2.0, 7.5), (0.125, 100.0)]
        self.compare_memory(code, samples, in_size=4, out_size=8)

import ctypes
import hashlib
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from abi import (ABIError, UNIFORM_STACK_SLOTS, uniform, uniform_locations, signature)
from compiler import Function, Image, compile_image


def fixture(code, functions, imports=None, relocations=None, data_bindings=None, bindings=None, dispatch=False, tls=None):
    """One executable segment with `code`, plus the data/dynamic scaffolding the image needs."""
    image = bytearray(0x5200)
    imports = imports or {}
    relocations = relocations or []
    bindings = bindings or []
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    phnum = 4 if tls else 3
    struct.pack_into('<16sHHIQQQIHHHHHH', image, 0, ident, 3, 62, 1, 0x1000, 64, 0x5000, 0, 64, 56, phnum, 64, 5, 4)
    span = max(function['address'] + function['size'] for function in functions) - 0x1000
    segment = max(len(code), span)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, 0x1000, 0x1000, 0, segment, segment, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, 6, 0x2000, 0x2000, 0, 0x3000, 0x3000, 0x1000)
    if tls:
        image[0x2600:0x2600 + len(tls)] = tls
        struct.pack_into('<IIQQQQQQ', image, 232, 7, 4, 0x2600, 0x3000, 0, len(tls), 0x1000, 16)
    image[0x1000:0x1000 + len(code)] = code
    strings = bytearray(b'\0')
    symbol_count = 1
    for index, name in enumerate(imports, 1):
        struct.pack_into('<IBBHQQ', image, 0x2100 + index * 24, len(strings), 0x12, 0, 0, 0, 0)
        strings.extend(name.encode() + b'\0')
        struct.pack_into('<QQq', image, 0x2300 + (index - 1) * 24, 0x2000 + (index - 1) * 8, (index << 32) | 7, 0)
        symbol_count = index + 1
    image[0x2200:0x2200 + len(strings)] = strings
    for index, (slot, target) in enumerate(relocations):
        struct.pack_into('<QQq', image, 0x2380 + index * 24, slot, 8, target)
    for index, (name, slot) in enumerate(bindings):
        symbol = symbol_count + index
        struct.pack_into('<IBBHQQ', image, 0x2100 + symbol * 24, len(strings), 0x11, 0, 0, 0, 0)
        strings.extend(name.encode() + b'\0')
        struct.pack_into('<QQq', image, 0x2380 + (len(relocations) + index) * 24, slot, (symbol << 32) | 1, 0)
    image[0x2200:0x2200 + len(strings)] = strings
    total_symbols = symbol_count + len(bindings)
    tags = [(6, 0x2100), (11, 24), (5, 0x2200), (10, len(strings)), (23, 0x2300), (2, len(imports) * 24),
            (20, 7), (7, 0x2380), (8, (len(relocations) + len(bindings)) * 24), (9, 24), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into('<qQ', image, 0x2400 + index * 16, *tag)
    struct.pack_into('<IIQQQQQQ', image, 176, 2, 6, 0x2400, 0x2400, 0, len(tags) * 16, len(tags) * 16, 8)
    names = b'\0.dynsym\0.dynstr\0.dynamic\0.shstrtab\0'
    image[0x2500:0x2500 + len(names)] = names
    for index, entry in enumerate([
            (1, 11, 2, 0x2100, 0x2100, total_symbols * 24, 2, 1, 8, 24),
            (9, 3, 2, 0x2200, 0x2200, len(strings), 0, 0, 1, 0),
            (17, 6, 3, 0x2400, 0x2400, len(tags) * 16, 2, 0, 8, 16),
            (26, 3, 0, 0, 0x2500, len(names), 0, 0, 1, 0)], 1):
        struct.pack_into('<IIQQQQIIQQ', image, 0x5000 + index * 64, *entry)
    contracts = {'schema': 1, 'sha256': hashlib.sha256(image).hexdigest(),
                 'functions': functions, 'imports': imports,
                 'data': [{'address': 0x2000, 'size': 0x3000}], 'pointer_relocations': relocations,
                 'data_bindings': data_bindings or {}, 'dispatch': dispatch, 'allow_unlowered_tls': True}
    return bytes(image), contracts


def uniform_function(name, address, size, **extra):
    return {'name': name, 'address': address, 'size': size, 'uniform': True,
            'result': 'void', 'parameters': [], **extra}


class RegisterFile(ctypes.Structure):
    _fields_ = [('gpr', ctypes.c_uint64 * 16), ('xmm', (ctypes.c_uint64 * 2) * 16),
                ('ymm_hi', (ctypes.c_uint64 * 2) * 16),
                ('flags', ctypes.c_uint64), ('flags_mask', ctypes.c_uint64),
                ('x87', ctypes.c_double * 8), ('x87_top', ctypes.c_uint64),
                ('stack', ctypes.c_uint64 * UNIFORM_STACK_SLOTS)]


GPR = {'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3, 'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
       **{f'r{i}': i - 8 + 8 for i in range(8, 16)}}


class UniformABITests(unittest.TestCase):
    serial = 0

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='anyps5-native-aot-')
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def compile(self, raw, contracts, entry):
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, report = compile_image(Image(source, contracts))
        ll = self.directory / 'output.ll'
        ll.write_text(ir)
        binary = self.directory / 'output.dylib'
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ll), '-o', str(binary)],
                       check=True, capture_output=True)
        library = ctypes.CDLL(str(binary))
        self.library = library
        function = getattr(library, entry)
        function.restype = None
        function.argtypes = [ctypes.POINTER(RegisterFile)]
        return function, ir, library

    def test_signature_accepts_uniform_and_rejects_scalar_result(self):
        self.assertTrue(uniform({'name': 'sub', 'uniform': True}))
        self.assertEqual(signature({'name': 'sub', 'uniform': True}), ('void', []))
        self.assertEqual(signature({'name': 'sub', 'guest_calling_convention': 'x86_64-uniform'}),
                         ('void', []))
        for bad in ({'name': 'sub', 'uniform': True, 'result': 'i64'},
                    {'name': 'sub', 'uniform': True, 'parameters': ['ptr']}):
            with self.subTest(bad=bad), self.assertRaises(ABIError):
                signature(bad)

    def test_uniform_locations_cover_the_guest_register_file(self):
        locations = uniform_locations()
        registers = [item['name'] for item in locations if item['kind'] == 'register']
        self.assertEqual(registers[:8], ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'])
        self.assertEqual(registers[8:16], [f'r{i}' for i in range(8, 16)])
        self.assertEqual(registers[16:32], [f'xmm{i}' for i in range(16)])
        self.assertEqual(registers[32:], [f'ymm_hi{i}' for i in range(16)])
        stack = [item['offset'] for item in locations if item['kind'] == 'stack']
        self.assertEqual(stack, list(range(8, 8 + 8 * UNIFORM_STACK_SLOTS, 8)))

    def test_uniform_leaf_reads_and_writes_the_register_file(self):
        code = bytes.fromhex('4889f84801f0c3')  # mov rax, rdi ; add rax, rsi ; ret
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('define void @sub_1000(ptr %rf)', ir)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 10
        registers.gpr[GPR['rsi']] = 5
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 15)

    def test_uniform_runtime_sized_frame_restored_through_a_register(self):
        # mov r14, rsp ; mov rbp, rsp ; mov r12, rsp ; sub r12, rax ; and r12, -32 ; mov rsp, r12 ;
        # mov r13, r12 ; lea rsp, [rbp] ; ret. The frame size is only known at runtime, so the
        # restore through the register is a dynamic frame, the same shape `and rsp, -32` already
        # takes in this ABI; r14 and r13 observe the entry rsp and the computed address.
        code = bytes.fromhex('4989e64889e54989e44929c44983e4e04c89e44d89e5488d6500c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.gpr[GPR['rax']] = 0x121
        function(ctypes.byref(registers))
        entered = registers.gpr[GPR['r14']]
        self.assertEqual(registers.gpr[GPR['r13']], (entered - 0x121) & ~0x1F)
        self.assertEqual(registers.gpr[GPR['rsp']], entered)

    def test_guest_data_resolves_a_segment_tail_address(self):
        # mov byte ptr [0x5ff8], 0x58 ; ret. A uniform function may address memory absolutely. The
        # address is past the segment's file-backed range but inside the memory the runtime maps and
        # zero-fills, so the segment fallback has to use the mapped extent, not the file extent.
        code = bytes.fromhex('c60425f85f000058c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        image = bytearray(raw)
        struct.pack_into('<Q', image, 120 + 40, 0x6000)  # data segment p_memsz > p_filesz
        source = self.directory / 'input.elf'
        source.write_bytes(bytes(image))
        ir, report = compile_image(Image(source, dict(contracts, data=[],
                                                      sha256=hashlib.sha256(bytes(image)).hexdigest(),
                                                      guest_data=True, guest_base=0x140000000)))
        self.assertIn(f'{0x140000000 + 0x5ff8}', ir)
        self.assertEqual(report['unimplemented_functions'], 0)

    def test_uniform_dynamic_frame_stack_transfer(self):
        # mov r14, rsp ; sub rsp, rax ; mov r12, rdi ; push r12 ; pop r13 ; mov rsp, r14 ; ret.
        # `sub rsp, rax` is a runtime-sized frame, so the push and the pop transfer at the guest rsp
        # value rather than at a frame offset; r13 has to see the value that was pushed.
        code = bytes.fromhex('4989e64829c44989fc4154415d4c89f4c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 0x1234
        registers.gpr[GPR['rax']] = 0x40
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['r13']], 0x1234)

    def test_uniform_bmi_destination_on_a_frame_register(self):
        # andn ebp, r15d, ebp ; mov eax, ebp ; ret. The scalar ABI cannot put an arbitrary value into a
        # frame register; the uniform ABI keeps the guest frame registers in the register file, where
        # the destination is an ordinary slot that only loses its frame meaning.
        code = bytes.fromhex('c4e200f2ed89e8c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.gpr[GPR['r15']] = 0x0f0f0f0f
        registers.gpr[GPR['rbp']] = 0x00ff00ff
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], ~0x0f0f0f0f & 0x00ff00ff)

    def test_uniform_restores_rsp_from_a_frame_slot(self):
        # mov rbp, rsp ; sub rsp, 0x20 ; mov [rsp], rbp ; mov [rbp-8], 0x1234 ;
        # mov rsp, [rsp] ; mov rax, [rbp-8] ; mov rsp, rbp ; ret. The frame pointer is loaded back out
        # of memory, so the frame is runtime-sized from there on and the load cannot be a frame offset.
        code = bytes.fromhex('4889e54883ec2048892c2448c745f834120000488b2424488b45f84889ecc3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0x1234)

    def test_uniform_pointer_argument_loads_the_register_not_an_undefined_arg(self):
        # mov rax, [rdi] ; ret -> rax = *(u64*)rdi. The uniform ABI keeps rdi in its
        # own alloca; a pointer dereference must use that value, not a typed %argN.
        code = bytes.fromhex('488b07c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertNotIn('%arg', ir)
        target = ctypes.c_uint64(0x1234)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = ctypes.addressof(target)
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0x1234)

    def test_uniform_call_passes_the_register_file(self):
        # 0x1000: call 0x1010 ; ret        0x1010: mov rax, rdi ; add rax, rsi ; ret
        code = bytearray(0x17)
        code[0x00:0x06] = bytes.fromhex('e80b000000c3')
        code[0x10:0x17] = bytes.fromhex('4889f84801f0c3')
        functions = [uniform_function('sub_1000', 0x1000, 6),
                     uniform_function('sub_1010', 0x1010, 7)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('call void @sub_1010(ptr %rf_out)', ir)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 21
        registers.gpr[GPR['rsi']] = 21
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 42)

    def test_uniform_conditional_tail_call(self):
        # 0x1000: test rdi,rdi ; jne 0x1010 ; mov rax,7 ; ret   0x1010: mov rax,rdi ; ret
        code = bytearray(0x14)
        code[0x00:0x0D] = bytes.fromhex('4885ff750b48c7c007000000c3')
        code[0x10:0x14] = bytes.fromhex('4889f8c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 4)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('br i1', ir)
        self.assertIn('call void @sub_1010(ptr %rf_out)', ir)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 0
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 7)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 42
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 42)

    def test_uniform_frame_repair_tail_call(self):
        # 0x1000: push rbx ; mov rbx,rdi ; jmp 0x1010   0x1010: mov rax,rdi ; ret
        code = bytearray(0x14)
        code[0x00:0x09] = bytes.fromhex('534889fbe907000000')
        code[0x10:0x14] = bytes.fromhex('4889f8c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 4)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('call void @sub_1010(ptr %rf_out)', ir)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 42
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 42)

    def test_streamed_image_matches_the_in_memory_image(self):
        # The sink path writes the preamble, bodies and stubs as they are produced; it must be
        # byte-identical to the assembled module, including the separators and trailing newline.
        code = bytes.fromhex('b801000000c3')  # mov eax, 1 ; ret
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, _ = compile_image(Image(source, contracts))
        pieces = []
        _, report = compile_image(Image(source, contracts), sink=pieces.append)
        self.assertEqual(''.join(pieces), ir)
        self.assertEqual(len(report['functions']), 1)

    def native_guest(self, code, rdi):
        """Run the guest bytes natively (x86_64) and return rax, as a reference."""
        UniformABITests.serial += 1
        stem = self.directory / f'guest{UniformABITests.serial}'
        source = stem.with_suffix('.S')
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n  call guest\n  ret\nguest:\n'
                          '  .byte ' + ', '.join(f'0x{byte:02x}' for byte in code) + '\n')
        runner = stem.with_suffix('.c')
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n'
                          'extern uint64_t run(uint64_t);\n'
                          'int main(void){uint64_t r;while(fread(&r,1,8,stdin)==8)printf("%llu\\n",(unsigned long long)run(r));return 0;}\n')
        binary = stem.with_suffix('.x86')
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(source), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        output = subprocess.run([str(binary)], input=struct.pack('<Q', rdi), check=True, capture_output=True).stdout
        return int(output.split()[0])

    def test_uniform_adjusted_conditional_tail_call(self):
        # 0x1000: push rbx ; mov rbx,rdi ; test rdi,rdi ; jne 0x1010 ; xor eax,eax ; pop rbx ; ret
        # 0x1010: mov rax,rdi ; ret  — the jne tail call carries an unbalanced (adjusted) frame.
        code = bytearray(0x14)
        code[0x00:0x0D] = bytes.fromhex('534889fb4885ff750731c05bc3')
        code[0x10:0x14] = bytes.fromhex('4889f8c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 4)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('call void @sub_1010(ptr %rf_out)', ir)
        for argument, expected in ((42, 42), (0, 0)):
            registers = RegisterFile()
            registers.gpr[GPR['rdi']] = argument
            function(ctypes.byref(registers))
            self.assertEqual(registers.gpr[GPR['rax']], expected)

    def test_uniform_fallthrough_tail_call_balanced_frame(self):
        # 0x1000: mov rax,rdi ; nops ; cmp rax,0 (last, falls through)   0x1010: ret
        code = bytearray(0x14)
        code[0x00:0x03] = bytes.fromhex('4889f8')
        code[0x03:0x0C] = bytes([0x90] * 9)
        code[0x0C:0x10] = bytes.fromhex('4883f800')
        code[0x10:0x11] = bytes.fromhex('c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 1)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('call void @sub_1010(ptr %rf_out)', ir)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 42
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], self.native_guest(bytes(code), 42))

    def test_uniform_fallthrough_tail_call_unbalanced_rejected(self):
        # 0x1000: push rbx ; nops ; cmp rdi,0 (last, falls through)   0x1010: ret
        code = bytearray(0x14)
        code[0x00] = 0x53
        code[0x01:0x0C] = bytes([0x90] * 11)
        code[0x0C:0x10] = bytes.fromhex('4883ff00')
        code[0x10:0x11] = bytes.fromhex('c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 1)]
        raw, contracts = fixture(bytes(code), functions)
        with self.assertRaises(Exception):
            self.compile(raw, contracts, 'sub_1000')

    def test_int3_terminates_and_traps(self):
        # 0x1000: push rbx ; nops ; int3    0x1010: ret — int3 is a trap terminator, not a
        # fall-through tail call into the next function.
        code = bytearray(0x14)
        code[0x00] = 0x53
        code[0x01:0x10] = bytes([0x90] * 15)
        code[0x0F] = 0xCC
        code[0x10:0x11] = bytes.fromhex('c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 1)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('call void @llvm.trap()', ir)
        self.assertNotIn('call void @sub_1010', ir)

    def native_ymm_run(self, code, data):
        """Run the 32-byte ymm copy code natively (x86_64) and return the output bytes."""
        source = self.directory / 'call.S'
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          + '\n'.join(f'.byte 0x{byte:02x}' for byte in code) + '\nret\n')
        runner = self.directory / 'call.c'
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n'
                          'extern void run(const void*, void*);\n'
                          'int main(void){unsigned char in[32], out[32]; '
                          'while(fread(in,1,32,stdin)==32){for(int i=0;i<32;i++)out[i]=0; run(in,out); '
                          'fwrite(out,1,32,stdout);} return 0;}\n')
        binary = self.directory / 'call.x86'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(source), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        return subprocess.run([str(binary)], input=data, check=True, capture_output=True).stdout[:32]

    def test_uniform_flags_mask_excludes_undefined_flags(self):
        # `add` defines OF; `shr eax, 8` leaves OF undefined (the hardware clears it but the
        # architecture does not define it), so the published mask must not claim it.
        for index, (code, published) in enumerate(((bytes.fromhex('83c001c3'), True),
                                                   (bytes.fromhex('c1e808c3'), False))):
            # A fresh directory per iteration: ctypes.CDLL caches by path.
            self.directory = self.directory / str(index)
            self.directory.mkdir()
            raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
            function, ir, _ = self.compile(raw, contracts, 'sub_1000')
            registers = RegisterFile()
            registers.gpr[0] = 0x80000000
            function(ctypes.byref(registers))
            self.assertEqual(bool(registers.flags_mask & 0x800), published, code.hex())
            if not published:
                self.assertEqual(registers.flags & 0x800, 0, code.hex())

    def test_uniform_x87_stack_is_published(self):
        # fld qword [rdi] ; ret — st(0) must appear at the register file's x87[0], not the ring index.
        code = bytes.fromhex('dd07c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        source = ctypes.create_string_buffer(struct.pack('<d', 1.5), 8)
        registers.gpr[7] = ctypes.addressof(source)
        function(ctypes.byref(registers))
        self.assertEqual(registers.x87[0], 1.5)

    def test_uniform_call_preserves_ymm_upper_halves(self):
        # 0x1000: vmovdqu ymm0,[rdi] ; call 0x1010 ; vmovdqu [rsi],ymm0 ; ret   0x1010: ret
        # The callee returns the register file, so the caller's ymm upper half survives the call.
        code = bytearray(0x11)
        code[0x00:0x04] = bytes.fromhex('c5fe6f07')
        code[0x04:0x09] = bytes.fromhex('e807000000')
        code[0x09:0x0D] = bytes.fromhex('c5fe7f06')
        code[0x0D] = 0xC3
        code[0x10] = 0xC3
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 1)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        randoms = random.Random(5150)
        for _ in range(16):
            data = randoms.randbytes(32)
            registers = RegisterFile()
            source = ctypes.create_string_buffer(data, 32)
            output = ctypes.create_string_buffer(32)
            registers.gpr[7] = ctypes.addressof(source)
            registers.gpr[6] = ctypes.addressof(output)
            function(ctypes.byref(registers))
            self.assertEqual(output.raw, data)
            self.assertEqual(self.native_ymm_run(bytes(code), data), data)

    def test_uniform_call_does_not_over_define_ymm_upper_halves(self):
        # The caller's upper halves are passed and returned; a partially defined one must stay
        # partially defined after the call rather than being assumed fully defined.
        code = bytearray(0x11)
        code[0x00:0x04] = bytes.fromhex('c5fe6f07')
        code[0x04:0x09] = bytes.fromhex('e807000000')
        code[0x09:0x0D] = bytes.fromhex('c5fe7f06')
        code[0x0D] = 0xC3
        code[0x10] = 0xC3
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 1)]
        raw, contracts = fixture(bytes(code), functions)
        elf = self.directory / 'input.elf'
        elf.write_bytes(raw)
        function = Function(Image(elf, contracts), Image(elf, contracts).functions[0x1000])
        function.analyze()
        instruction = function.instructions[0x1004]
        state = dict(function.states[0x1004])
        state['known'] = dict(state['known'])
        state['known']['ymm_hi0'] = 0x0000ffff
        after = function.transfer_unchecked(instruction, state)
        self.assertEqual(after['known'].get('ymm_hi0', 0), 0x0000ffff)

    def test_uniform_indirect_call_uses_the_declared_target_set(self):
        # 0x1000: call rax ; ret          0x1010: mov rax, rdi ; ret
        code = bytearray(0x14)
        code[0x00:0x03] = bytes.fromhex('ffd0c3')
        code[0x10:0x14] = bytes.fromhex('4889f8c3')
        functions = [uniform_function('sub_1000', 0x1000, 3,
                                      indirect_calls=[{'address': 0x1000, 'targets': [0x1010]}]),
                     uniform_function('sub_1010', 0x1010, 4)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, library = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('inttoptr i64', ir)
        self.assertIn('call void %v', ir)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = 7
        registers.gpr[GPR['rax']] = ctypes.cast(library.sub_1010, ctypes.c_void_p).value
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 7)

    def test_uniform_indirect_call_selects_among_the_declared_targets(self):
        # 0x1000: call rax ; ret   0x1010: lea eax,[rdi+1] ; ret   0x1020: lea eax,[rdi+2] ; ret
        # The declared set has two entries, so the shared membership table must select the one
        # the call actually targets.
        code = bytearray(0x24)
        code[0x00:0x03] = bytes.fromhex('ffd0c3')
        code[0x10:0x14] = bytes.fromhex('8d4701c3')
        code[0x20:0x24] = bytes.fromhex('8d4702c3')
        functions = [uniform_function('sub_1000', 0x1000, 3,
                                      indirect_calls=[{'address': 0x1000, 'targets': [0x1010, 0x1020]}]),
                     uniform_function('sub_1010', 0x1010, 4),
                     uniform_function('sub_1020', 0x1020, 4)]
        raw, contracts = fixture(bytes(code), functions)
        function, _, library = self.compile(raw, contracts, 'sub_1000')
        for name, expected in (('sub_1010', 7), ('sub_1020', 8)):
            registers = RegisterFile()
            registers.gpr[GPR['rdi']] = 6
            registers.gpr[GPR['rax']] = ctypes.cast(getattr(library, name), ctypes.c_void_p).value
            function(ctypes.byref(registers))
            self.assertEqual(registers.gpr[GPR['rax']], expected)

    def test_uniform_unannotated_indirect_call_dispatches(self):
        # 0x1000: call rax ; ret  — no target set, so it lowers to the runtime dispatch table
        code = bytearray(0x04)
        code[0x00:0x03] = bytes.fromhex('ffd0c3')
        raw, contracts = fixture(bytes(code), [uniform_function('sub_1000', 0x1000, 3)], dispatch=True)
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, report = compile_image(Image(source, contracts))
        self.assertIn('@NativeAotDispatch_nid_no_patch', ir)
        self.assertIn('@NativeAotReportDispatchFailure_nid_no_patch', ir)
        self.assertIn('call ptr @NativeAotDispatch_nid_no_patch', ir)

    def test_uniform_dispatch_table_is_valid_llvm(self):
        # The dispatch table initializer needs the struct type on each element; without
        # it clang rejects the module with "expected '}' at end of struct".
        code = bytearray(0x04)
        code[0x00:0x03] = bytes.fromhex('ffd0c3')
        raw, contracts = fixture(bytes(code), [uniform_function('sub_1000', 0x1000, 3)], dispatch=True)
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, _ = compile_image(Image(source, contracts))
        self.assertIn('{ i64, ptr } { i64 4096, ptr @sub_1000 }', ir)
        ll = self.directory / 'output.ll'
        ll.write_text(ir)
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-c', str(ll), '-o', str(self.directory / 'output.o')],
                       check=True, capture_output=True)

    def test_uniform_annotated_indirect_jump_is_a_switch(self):
        # 0x1000: jmp rax   0x1010: mov eax, 1 ; ret   0x1020: mov eax, 2 ; ret
        code = bytearray(0x30)
        code[0x00:0x02] = bytes.fromhex('ffe0')
        code[0x10:0x16] = bytes.fromhex('b801000000c3')
        code[0x20:0x26] = bytes.fromhex('b802000000c3')
        function = uniform_function('sub_1000', 0x1000, 0x30,
                                    indirect_jumps=[{'address': 0x1000, 'targets': [0x1010, 0x1020]}])
        raw, contracts = fixture(bytes(code), [function])
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, report = compile_image(Image(source, contracts))
        self.assertIn('switch_1000', ir)
        self.assertIn('label %b1010', ir)
        self.assertIn('label %b1020', ir)

    def test_uniform_calls_return_zero_stub_import(self):
        # 0x1000: call 0x1010 ; ret     0x1010: jmp [rip + slot]  (PLT stub for an import)
        code = bytearray(0x16)
        code[0x00:0x06] = bytes.fromhex('e80b000000c3')
        code[0x10:0x16] = bytes.fromhex('ff25ea0f0000')
        stub = {'name': 'stub_import', 'result': 'i64', 'parameters': [], 'stub': True}
        raw, contracts = fixture(bytes(code), [uniform_function('sub_1000', 0x1000, 6)],
                                 imports={'stub_import': stub})
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('define i64 @stub_import() { entry: ret i64 0 }', ir)
        registers = RegisterFile()
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0)

    def test_data_binding_emits_native_object_and_store(self):
        code = bytearray(0x04)
        code[0x00:0x04] = bytes.fromhex('4889f8c3')
        binding = {'name': 'bound_vtable', 'size': 64}
        raw, contracts = fixture(bytes(code), [uniform_function('sub_1000', 0x1000, 4)],
                                 bindings=[('data_symbol', 0x2000)],
                                 data_bindings={'data_symbol': binding})
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, report = compile_image(Image(source, contracts))
        self.assertIn('@bound_vtable = global [64 x i8] zeroinitializer', ir)
        self.assertIn('store ptr @bound_vtable', ir)

    def test_uniform_indirect_call_rejects_non_uniform_target(self):
        code = bytes.fromhex('ffd0c3')
        functions = [uniform_function('sub_1000', 0x1000, 3,
                                      indirect_calls=[{'address': 0x1000, 'targets': [0x1010]}]),
                     {'name': 'typed_1010', 'address': 0x1010, 'size': 3, 'result': 'void', 'parameters': []}]
        code = code + bytes.fromhex('c3')
        raw, contracts = fixture(code, functions)
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        with self.assertRaises(Exception):
            compile_image(Image(source, contracts))

    def test_unresolvable_annotated_indirect_target_falls_back_to_dispatch(self):
        # Contract: with dispatch enabled, an indirect call whose annotated target set names an
        # address that is neither a function nor a PLT stub dispatches through the runtime table
        # instead of rejecting the function (the whole-title behaviour).
        code = bytes.fromhex('ffd0c3')
        functions = [uniform_function('sub_1000', 0x1000, 3, indirect_calls=[{'address': 0x1000, 'targets': [0x2000]}])]
        raw, contracts = fixture(code, functions, dispatch=True)
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        ir, report = compile_image(Image(source, contracts))
        self.assertIn('NativeAotDispatch_nid_no_patch', ir)
        contracts['dispatch'] = False
        with self.assertRaises(Exception):
            compile_image(Image(source, contracts))

    def test_unimplemented_function_becomes_a_reporting_stub(self):
        # Contract: with allow_unimplemented (the whole-title build), a body the lifter rejects
        # becomes a stub that reports its guest address and traps, so one image covers the whole
        # eboot. Without the flag the image is still rejected (the SDK-sample default).
        # fxsave [rdi] has no lowering (x87 loads such as fld now do).
        functions = [uniform_function('sub_1000', 0x1000, 4)]
        raw, contracts = fixture(bytes.fromhex('0fae07c3'), functions)
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        with self.assertRaises(Exception):
            compile_image(Image(source, contracts))
        contracts['allow_unimplemented'] = True
        ir, report = compile_image(Image(source, contracts))
        self.assertIn('call void @NativeAotReportUnimplemented_nid_no_patch(i64 4096)', ir)
        self.assertEqual(report['unimplemented_functions'], 1)


if __name__ == '__main__':
    unittest.main()

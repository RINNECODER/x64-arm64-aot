import ctypes
import hashlib
import random
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from abi import (ABIError, UNIFORM_STACK_SLOTS, uniform, uniform_locations, signature)
from compiler import Function, Image, Rejected, compile_image
import registers


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

    def test_uniform_lea_of_a_function_yields_a_guest_address(self):
        # A `lea` of a function's address produces a guest-visible pointer. A relocated vtable slot
        # holds `guest_base + vaddr` and the runtime dispatch table is keyed by it, so naming the
        # native body (`@sub_...`) instead made the guest compare and dispatch on a host address
        # (REPORT24 n12). The guest_data test above covers an absolute data address, not a function.
        # 0x1000: lea rax,[rip+9] ; ret   0x1010: ret
        code = bytearray(0x11)
        code[0x00:0x08] = bytes.fromhex('488d0509000000c3')
        code[0x10] = 0xC3
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 1)]
        raw, contracts = fixture(bytes(code), functions)
        base = 0x140000000
        function, ir, _ = self.compile(bytes(raw), dict(contracts, guest_data=True, guest_base=base),
                                       'sub_1000')
        registers = RegisterFile()
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], base + 0x1010)

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

    def test_uniform_leave_restores_rsp_and_the_frame_pointer(self):
        # mov r14, rsp ; push rbp ; mov rbp, rsp ; sub rsp, 0x20 ; mov [rbp-8], rdi ;
        # mov rax, [rbp-8] ; leave ; ret. `leave` must read the local through rbp, then restore
        # both rsp (to the entry value r14 observed) and rbp (to the value pushed at entry).
        code = bytes.fromhex('4989e6554889e54883ec2048897df8488b45f8c9c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.gpr[GPR['rbp']] = 0xdeadbeef
        registers.gpr[GPR['rdi']] = 0x1234
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0x1234)
        self.assertEqual(registers.gpr[GPR['rbp']], 0xdeadbeef)
        self.assertEqual(registers.gpr[GPR['rsp']], registers.gpr[GPR['r14']])

    def test_uniform_join_merges_a_saved_register_and_a_stack_value(self):
        # test rdi,rdi ; je B ; A: push rbx ; jmp C ; B: push 1 ; C: pop rax ; ret. The two paths
        # reach C with a different source pushed at the same offset. The join must keep the slot
        # (and its known mask) rather than demanding the same source register.
        code = bytes.fromhex('4885ff740653eb059090906a0158c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        for rdi, rbx, expected in ((0, 0x99, 1), (1, 0x1234, 0x1234)):
            with self.subTest(rdi=rdi):
                registers = RegisterFile()
                registers.gpr[GPR['rdi']] = rdi
                registers.gpr[GPR['rbx']] = rbx
                function(ctypes.byref(registers))
                self.assertEqual(registers.gpr[GPR['rax']], expected)

    def test_uniform_popfq_restores_the_tracked_flags(self):
        # push <rflags> ; popfq ; set<cc> al ; movzx eax, al ; ret. Only the five tracked flag
        # bits come back, so a value with exactly one of them set must set exactly that condition.
        push = {0x0: '6a00', 0x1: '6a01', 0x2: '6a02', 0x4: '6a04', 0x40: '6a40',
                0x80: '6880000000', 0x800: '6800080000'}
        condition = {'c': '0f92c0', 'p': '0f9ac0', 'z': '0f94c0', 's': '0f98c0', 'o': '0f90c0'}
        cases = ((0x1, 'c', 1), (0x4, 'p', 1), (0x40, 'z', 1), (0x80, 's', 1), (0x800, 'o', 1),
                 (0x2, 'c', 0), (0x40, 'p', 0), (0x0, 'c', 0))
        for index, (value, flag, expected) in enumerate(cases):
            with self.subTest(value=value, flag=flag):
                # A fresh directory per case: ctypes.CDLL caches by path.
                self.directory = self.directory / str(index)
                self.directory.mkdir()
                code = bytes.fromhex(push[value] + '9d' + condition[flag] + '0fb6c0c3')
                raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
                function, ir, _ = self.compile(raw, contracts, 'sub_1000')
                registers = RegisterFile()
                function(ctypes.byref(registers))
                self.assertEqual(registers.gpr[GPR['rax']], expected)

    def test_uniform_int_immediate_traps(self):
        # 0x1000: int 0x41 ; ret — a software interrupt is a trap terminator, like int3.
        code = bytes.fromhex('cd41c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('call void @llvm.trap()', ir)

    def test_uniform_frame_restored_through_a_runtime_sized_frame_pointer(self):
        # mov r14, rsp ; lea r15, [rsp + rdi*8 + 8] ; lea rsp, [r15 + 8] ; mov rax, rsp ; ret.
        # r15 is a frame-derived pointer with a runtime index, so restoring the guest rsp through
        # it must stay representable as a runtime value rather than a known frame offset.
        code = bytes.fromhex('4989e64c8d7cfc08498d67084889e0c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        for rdi in (0, 1, 0x20):
            with self.subTest(rdi=rdi):
                registers = RegisterFile()
                registers.gpr[GPR['rdi']] = rdi
                function(ctypes.byref(registers))
                entered = registers.gpr[GPR['r14']]
                self.assertEqual((registers.gpr[GPR['rax']] - entered) & ((1 << 64) - 1), rdi * 8 + 16)
                self.assertEqual(registers.gpr[GPR['rsp']], registers.gpr[GPR['rax']])

    def test_uniform_borrows_an_interior_entry_of_the_next_function(self):
        # A false function start splits one real function into fragments, and a branch from one
        # fragment reaches the middle of another. sub_1000 tests rdi and, when it is nonzero,
        # branches to 0x1028, which is 8 bytes into sub_1020; the taken path must run the
        # interior entry's code (mov rax, 3) instead of rejecting the escape.
        body = bytes.fromhex('4885ff0f851f00000048c7c001000000c3' + '90' * 15)
        other = bytes.fromhex('48c7c002000000c348c7c003000000c3')
        raw, contracts = fixture(body + other, [uniform_function('sub_1000', 0x1000, 0x20),
                                                uniform_function('sub_1020', 0x1020, 0x10)])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        for argument, expected in ((0, 1), (1, 3)):
            with self.subTest(rdi=argument):
                registers = RegisterFile()
                registers.gpr[GPR['rdi']] = argument
                function(ctypes.byref(registers))
                self.assertEqual(registers.gpr[GPR['rax']], expected)

    def test_uniform_borrowing_needs_both_contracts_to_be_uniform(self):
        # The scalar ABI's native frame is the guest frame, so a scalar fragment cannot continue at
        # another function's interior entry; the escape must still be rejected.
        body = bytes.fromhex('4885ff0f851f00000048c7c001000000c3' + '90' * 15)
        other = bytes.fromhex('48c7c002000000c348c7c003000000c3')
        scalar = {'name': 'sub_1000', 'address': 0x1000, 'size': 0x20, 'parameters': [], 'result': 'void'}
        raw, contracts = fixture(body + other, [scalar, uniform_function('sub_1020', 0x1020, 0x10)])
        with self.assertRaisesRegex(Rejected, 'control flow escapes function contract'):
            self.compile(raw, contracts, 'sub_1000')

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

    def test_uniform_tail_call_publishes_the_callee_flags(self):
        # A tail `jmp` is a `call`+`ret` on x86, and `ret` does not restore flags, so the flags the
        # caller of the root finally sees are the *callee's*. Publishing the root's own analysis
        # flags instead made every tail-calling function disagree with the reference on the flags
        # its last flag-setting instruction before the `jmp` produced (REPORT24). The other
        # uniform tail-call tests assert a register result, so none of them observes the flags.
        # 0x1000: add edi,5 ; jmp 0x1010    0x1010: xor eax,eax ; ret
        code = bytearray(0x14)
        code[0x00:0x08] = bytes.fromhex('83c705e908000000')
        code[0x10:0x13] = bytes.fromhex('31c0c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 3)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('call void @sub_1010(ptr %rf_out)', ir)
        registers = RegisterFile()
        function(ctypes.byref(registers))
        # `add edi,5` with edi=0 yields PF only; the callee's `xor eax,eax` yields ZF|PF.
        self.assertEqual(registers.flags & 0x44, 0x44)
        self.assertEqual(registers.flags_mask & 0x44, 0x44)

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

    def test_uniform_unsaved_pop_reads_the_caller_window(self):
        # 0x1000: add rsp,8 ; pop rax ; sub rsp,16 ; ret — the popped slot was never pushed here,
        # but it is a declared caller stack slot, so the caller's first stack argument comes back.
        code = bytes.fromhex('4883c408584883ec10c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.stack[0] = 0x2A
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0x2A)

    def native_cell(self, code, initial):
        """Run the guest bytes natively (x86_64) with rdi -> a one-byte cell; return (rax, cell)."""
        UniformABITests.serial += 1
        stem = self.directory / f'cell{UniformABITests.serial}'
        source = stem.with_suffix('.S')
        source.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          '  .byte ' + ', '.join(f'0x{byte:02x}' for byte in code) + '\n')
        runner = stem.with_suffix('.c')
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n'
                          'extern uint64_t run(uint8_t*);\n'
                          'int main(void){uint8_t cell; uint64_t r;'
                          'while(fread(&r,1,8,stdin)==8){cell=(uint8_t)r;'
                          'uint64_t a=run(&cell);'
                          'printf("%llu %u\\n",(unsigned long long)a,cell);}return 0;}\n')
        binary = stem.with_suffix('.x86')
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(source), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        output = subprocess.run([str(binary)], input=struct.pack('<Q', initial), check=True, capture_output=True).stdout
        first, second = output.split()
        return int(first), int(second)

    def test_uniform_cmpxchg_loop_keeps_the_accumulator_defined(self):
        # 0x1000: mov al,[rdi] ; mov r8d,eax ; add r8d,1 ; lock cmpxchg [rdi],r8b ; jne 0x1000 ;
        # movsx eax,al ; ret. The loop header merges the entry state with the back edge, where the
        # byte `cmpxchg` defines only AL. The byte form leaves RAX's upper bits unchanged (the
        # lowering reloads and recombines them), so the merged state must keep RAX defined; a
        # narrower mask rejected the 32-bit use `add r8d, ecx` this shape stands in for.
        code = bytes.fromhex('8a074189c04183c001f0440fb00775f00fbec0c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        reference = self.native_cell(code, 0x40)
        registers = RegisterFile()
        cell = ctypes.create_string_buffer(b'\x40', 1)
        registers.gpr[GPR['rdi']] = ctypes.addressof(cell)
        function(ctypes.byref(registers))
        self.assertEqual((registers.gpr[GPR['rax']], cell.raw[0]), reference)

    def test_uniform_unsaved_pop_stays_defined_for_a_wider_use(self):
        # 0x1000: add rsp,8 ; pop r15 ; shl r15,1 ; mov rax,r15 ; sub rsp,16 ; ret. The popped slot
        # is the caller's first stack slot, which the lowering loads from the frame; the analysis
        # has to leave r15 defined, otherwise the 64-bit use `shl r15, 1` rejects the function even
        # though the emitted code reads a real value.
        code = bytes.fromhex('4883c408415f49d1e74c89f84883ec10c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.stack[0] = 0x21
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0x42)

    def test_uniform_gather_loads_selected_lanes_and_clears_the_mask(self):
        # vmovdqu xmm1,[rdi] ; vmovdqu xmm2,[rdi+0x10] ; vmovdqu xmm0,[rdi+0x20] ;
        # vgatherdps xmm0, [rsi + xmm1*4], xmm2 ; vmovdqu [rdx],xmm0 ;
        # vmovdqu [rdx+0x10],xmm2 ; ret — a lane whose mask sign bit is set is loaded from the
        # table, the other lanes keep the destination's previous value, and the mask register is
        # cleared once the gather completes.
        code = bytes.fromhex('c5fa6f0fc5fa6f5710c5fa6f4720c4e26992048ec5fa7f02c5fa7f5210c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        table = (ctypes.c_float * 8)(10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0)
        setup = ctypes.create_string_buffer(48)
        ctypes.memmove(setup, (ctypes.c_int32 * 4)(3, 0, 5, 2), 16)
        ctypes.memmove(ctypes.addressof(setup) + 16, (ctypes.c_int32 * 4)(-1, 0, -1, 0), 16)
        ctypes.memmove(ctypes.addressof(setup) + 32, (ctypes.c_float * 4)(1.0, 2.0, 3.0, 4.0), 16)
        output = ctypes.create_string_buffer(32)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = ctypes.addressof(setup)
        registers.gpr[GPR['rsi']] = ctypes.addressof(table)
        registers.gpr[GPR['rdx']] = ctypes.addressof(output)
        function(ctypes.byref(registers))
        self.assertEqual(list((ctypes.c_float * 4).from_buffer_copy(output.raw[:16])),
                         [40.0, 2.0, 60.0, 4.0])
        self.assertEqual(list((ctypes.c_int32 * 4).from_buffer_copy(output.raw[16:32])),
                         [0, 0, 0, 0])

    def test_uniform_vstmxcsr_stores_the_default_control_word(self):
        # vstmxcsr dword ptr [rdi] ; ret — no MXCSR is modelled, so the store publishes the
        # architectural default (exceptions masked, round to nearest) a save/restore pair expects;
        # x86 starts a process with exactly this value.
        code = bytes.fromhex('c5f8ae1fc3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        output = ctypes.create_string_buffer(4)
        registers = RegisterFile()
        registers.gpr[GPR['rdi']] = ctypes.addressof(output)
        function(ctypes.byref(registers))
        self.assertEqual(struct.unpack('<I', output.raw[:4])[0], 0x1F80)

    def test_uniform_unsaved_pop_of_the_return_address_slot(self):
        # 0x1000: pop r10 ; lea rsp,[rsp+rcx*8+8] ; push r10 ; ret — the popped slot is the guest
        # return-address slot, which the uniform ABI does not model. The function must lower, and
        # the value must be an arbitrary but defined one: never a load of memory nothing wrote.
        code = bytes.fromhex('415a488d64cc084152c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertIn('freeze i64 poison', ir)
        self.assertNotIn('load i64, ptr %frame', ir)
        function(ctypes.byref(RegisterFile()))

    def test_uniform_releases_a_stale_saved_slot(self):
        # 0x1000: push rbx ; lea rsp,[rsp+8] ; test rdi,rdi ; je 0x1010 ; nops ; 0x1010: mov rax,rbx ; ret
        # The lea gives the pushed slot back, so both paths into 0x1010 must agree on an empty frame.
        code = bytearray(0x14)
        code[0x00:0x0B] = bytes.fromhex('53488d6424084885ff7405')
        code[0x0B:0x10] = bytes([0x90] * 5)
        code[0x10:0x14] = bytes.fromhex('4889d8c3')
        raw, contracts = fixture(bytes(code), [uniform_function('sub_1000', 0x1000, 0x14)])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.gpr[GPR['rbx']] = 0x99
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0x99)

    def test_uniform_forwards_a_stack_argument_on_a_tail_call(self):
        # 0x1000: jmp 0x1010   0x1010: mov rax,[rsp+8] ; ret — a tail jmp leaves the return address at
        # [rsp], so the callee's first stack argument is the caller's [rsp+8], not its [rsp].
        code = bytearray(0x14)
        code[0x00:0x05] = b'\xe9' + (0x1010 - 0x1005).to_bytes(4, 'little', signed=True)
        code[0x10:0x16] = bytes.fromhex('488b442408c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 6)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        registers = RegisterFile()
        registers.stack[0] = 0x2A
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[GPR['rax']], 0x2A)

    def test_uniform_runtime_sized_frame_join(self):
        # 0x1000: mov ecx,edi ; xor edx,edx ; loop{cmp edx,ecx ; jge done ; push rdx ; inc edx ;
        # jmp loop} ; done: mov rax,[rsp] ; lea rsp,[rsp+rcx*8] ; ret — the loop pushes a runtime
        # number of values, so the join at the loop head has no static frame; the pushes and the
        # read then happen at the runtime guest rsp.
        code = bytearray(0x20)
        body = bytearray()
        body += bytes.fromhex('89f9')        # mov ecx, edi
        body += bytes.fromhex('31d2')        # xor edx, edx
        loop = 0x1000 + len(body)
        body += bytes.fromhex('39ca')        # cmp edx, ecx
        jge_at = 0x1000 + len(body)
        body += b'\x7d\x00'
        body += bytes.fromhex('52')          # push rdx
        body += bytes.fromhex('ffc2')        # inc edx
        jmp_at = 0x1000 + len(body)
        body += b'\xeb\x00'
        done = 0x1000 + len(body)
        body += bytes.fromhex('488b0424')    # mov rax, [rsp]
        body += bytes.fromhex('488d0ccc')    # lea rcx, [rsp + rcx*8]
        body += bytes.fromhex('4889cc')      # mov rsp, rcx
        body += bytes.fromhex('c3')          # ret
        body[jge_at - 0x1000 + 1] = (done - (jge_at + 2)) & 0xFF
        body[jmp_at - 0x1000 + 1] = (loop - (jmp_at + 2)) & 0xFF
        code[0:len(body)] = body
        raw, contracts = fixture(bytes(code), [uniform_function('sub_1000', 0x1000, len(body))])
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        for count in (1, 2, 3):
            registers = RegisterFile()
            registers.gpr[GPR['rdi']] = count
            function(ctypes.byref(registers))
            self.assertEqual(registers.gpr[GPR['rax']], count - 1)
            self.assertEqual(registers.gpr[GPR['rax']], self.native_guest(bytes(code), count))

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
        # Merging the fragments does not balance the frame either -- nothing pops rbx -- so the
        # widened contract still has to be rejected rather than emit a native frame that leaks.
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

    def fragment_fixture(self):
        """A real function split into a prologue fragment and an epilogue fragment.

        0x1000: push rbx ; nops ; cmp rdi,0 (last, falls through)
        0x1010: mov rax,rdi ; pop rbx ; ret
        Neither declared range balances: the prologue leaves rbx pushed at the fall-through, and
        the epilogue's ret pops a slot the contract table says is not there.
        """
        code = bytearray(0x15)
        code[0x00] = 0x53
        code[0x01:0x0C] = bytes([0x90] * 11)
        code[0x0C:0x10] = bytes.fromhex('4883ff00')
        code[0x10:0x13] = bytes.fromhex('4889f8')
        code[0x13] = 0x5B
        code[0x14] = 0xC3
        functions = [uniform_function('sub_1000', 0x1000, 0x10),
                     uniform_function('sub_1010', 0x1010, 5)]
        raw, contracts = fixture(bytes(code), functions)
        return bytes(code), raw, contracts

    def body(self, ir, name):
        """The IR of one emitted function, so a test can assert on that body alone."""
        start = ir.index(f'define void @{name}(ptr %rf)')
        return ir[start:ir.index('\n}', start)]

    def test_uniform_fallthrough_tail_call_merges_the_fragment_that_balances_it(self):
        # The contract table declares a false start at 0x1010, so the real function is split and
        # the prologue's fall-through tail call leaves rbx pushed. Merging the fragments makes the
        # fall-through an intra-function edge and the frame balances.
        code, raw, contracts = self.fragment_fixture()
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertNotIn('@sub_1010', self.body(ir, 'sub_1000'))
        for argument in (0, 42):
            with self.subTest(rdi=argument):
                registers = RegisterFile()
                registers.gpr[GPR['rdi']] = argument
                function(ctypes.byref(registers))
                self.assertEqual(registers.gpr[GPR['rax']], self.native_guest(code, argument))

    def test_uniform_unbalanced_epilogue_merges_the_fragment_that_pushed(self):
        # The same split seen from the other side: 0x1010 pops rbx and returns, which does not
        # balance against its own declared entry, but does against the prologue that pushed it.
        code, raw, contracts = self.fragment_fixture()
        function, ir, _ = self.compile(raw, contracts, 'sub_1010')
        self.assertNotIn('@sub_1000', self.body(ir, 'sub_1010'))
        for argument in (0, 42):
            with self.subTest(rdi=argument):
                registers = RegisterFile()
                registers.gpr[GPR['rdi']] = argument
                function(ctypes.byref(registers))
                self.assertEqual(registers.gpr[GPR['rax']], self.native_guest(code, argument))

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

    def test_uniform_structural_summary_is_reads_and_writes(self):
        # mov rax,rdi ; add rax,rsi ; ret — the store set is the callee's reads plus writes, so a
        # partial write or a written-but-unread slot still sees a defined value.
        code = bytes.fromhex('4889f84801f0c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        path = self.directory / 'input.elf'
        path.write_bytes(raw)
        image = Image(path, contracts)
        registers.prepare(image)
        store, load = image.register_summaries[0x1000]
        self.assertEqual(registers.names(store) - {'rsp'}, {'rax', 'rdi', 'rsi'})
        self.assertEqual(registers.names(load) - {'rsp'}, {'rax'})

    def test_uniform_partial_summary_unannotated_indirect_is_full(self):
        # An indirect call with no declared target set (the runtime dispatch fallback) must never
        # skip a register: its summary stays full.
        code = bytes.fromhex('ffd0c3')
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, 3)], dispatch=True)
        path = self.directory / 'input.elf'
        path.write_bytes(raw)
        image = Image(path, contracts)
        registers.prepare(image)
        self.assertEqual(image.register_summaries[0x1000], (registers.FULL, registers.FULL))

    def test_uniform_partial_summary_preserves_untouched_registers(self):
        # 0x1000: call 0x1010 ; ret   0x1010: mov rax,rdi ; add rax,rsi ; ret. The call site copies
        # only the callee's registers; every other register survives the call.
        code = bytearray(0x17)
        code[0x00:0x06] = bytes.fromhex('e80b000000c3')
        code[0x10:0x17] = bytes.fromhex('4889f84801f0c3')
        functions = [uniform_function('sub_1000', 0x1000, 6),
                     uniform_function('sub_1010', 0x1010, 7)]
        raw, contracts = fixture(bytes(code), functions)
        function, ir, _ = self.compile(raw, contracts, 'sub_1000')
        self.assertNotIn('ptr %rf_out, i64 0, i32 1', ir)  # no XMM copy at a GPR-only call site
        self.assertNotIn('ptr %rf_out, i64 0, i32 2', ir)  # no YMM upper copy either
        registers_file = RegisterFile()
        registers_file.gpr[GPR['rdi']] = 21
        registers_file.gpr[GPR['rsi']] = 21
        untouched = {name: 0x1234000000000000 | index
                     for index, name in enumerate(('rbx', 'r12', 'r13', 'r14', 'r15'))}
        for name, value in untouched.items():
            registers_file.gpr[GPR[name]] = value
        function(ctypes.byref(registers_file))
        self.assertEqual(registers_file.gpr[GPR['rax']], 42)
        for name, value in untouched.items():
            self.assertEqual(registers_file.gpr[GPR[name]], value, name)

    def test_uniform_partial_write_keeps_the_entry_high_bits(self):
        # 0x1000: mov rax,0x100 ; call 0x1010 ; ret   0x1010: mov al,1 ; ret. A partial write reads
        # the entry value, so the caller must copy rax into %rf_out for the callee to merge into.
        code = bytearray(0x13)
        code[0x00:0x07] = bytes.fromhex('48c7c000010000')
        code[0x07:0x0C] = bytes.fromhex('e804000000')
        code[0x0C] = 0xC3
        code[0x10:0x13] = bytes.fromhex('b001c3')
        functions = [uniform_function('sub_1000', 0x1000, 0x0D),
                     uniform_function('sub_1010', 0x1010, 3)]
        raw, contracts = fixture(bytes(code), functions)
        function, _, _ = self.compile(raw, contracts, 'sub_1000')
        registers_file = RegisterFile()
        function(ctypes.byref(registers_file))
        self.assertEqual(registers_file.gpr[GPR['rax']], 0x101)

    def test_uniform_partial_summary_is_transitive(self):
        # 0x1000: call 0x1010 ; ret   0x1010: call 0x1020 ; ret   0x1020: mov rax,rbx ; ret. The
        # middle frame never touches rbx, but the leaf reads it, so the outermost caller copies it.
        code = bytearray(0x24)
        code[0x00:0x06] = bytes.fromhex('e80b000000c3')
        code[0x10:0x16] = bytes.fromhex('e80b000000c3')
        code[0x20:0x24] = bytes.fromhex('4889d8c3')
        functions = [uniform_function('sub_1000', 0x1000, 6),
                     uniform_function('sub_1010', 0x1010, 6),
                     uniform_function('sub_1020', 0x1020, 4)]
        raw, contracts = fixture(bytes(code), functions)
        path = self.directory / 'input.elf'
        path.write_bytes(raw)
        image = Image(path, contracts)
        registers.prepare(image)
        self.assertIn('rbx', registers.names(image.register_summaries[0x1000][0]))
        function, _, _ = self.compile(raw, contracts, 'sub_1000')
        registers_file = RegisterFile()
        registers_file.gpr[GPR['rbx']] = 0x1234
        function(ctypes.byref(registers_file))
        self.assertEqual(registers_file.gpr[GPR['rax']], 0x1234)
        self.assertEqual(registers_file.gpr[GPR['rbx']], 0x1234)

    def test_uniform_partial_summary_reads_back_a_write_only_register(self):
        # 0x1000: call 0x1010 ; ret   0x1010: mov rcx,0x99 ; ret. The callee never reads rcx, but
        # the caller reads the result back, so rcx must be in the load set.
        code = bytearray(0x18)
        code[0x00:0x06] = bytes.fromhex('e80b000000c3')
        code[0x10:0x18] = bytes.fromhex('48c7c199000000c3')
        functions = [uniform_function('sub_1000', 0x1000, 6),
                     uniform_function('sub_1010', 0x1010, 8)]
        raw, contracts = fixture(bytes(code), functions)
        function, _, _ = self.compile(raw, contracts, 'sub_1000')
        registers_file = RegisterFile()
        function(ctypes.byref(registers_file))
        self.assertEqual(registers_file.gpr[GPR['rcx']], 0x99)

    def test_uniform_partial_summary_indirect_union(self):
        # 0x1000: call rax ; ret   0x1010: mov rax,rdi ; ret   0x1020: mov rdx,rsi ; ret. The store
        # set is the union over the declared target set, so both rdi and rsi are copied.
        code = bytearray(0x24)
        code[0x00:0x03] = bytes.fromhex('ffd0c3')
        code[0x10:0x14] = bytes.fromhex('4889f8c3')
        code[0x20:0x24] = bytes.fromhex('4889f2c3')
        functions = [uniform_function('sub_1000', 0x1000, 3,
                                      indirect_calls=[{'address': 0x1000, 'targets': [0x1010, 0x1020]}]),
                     uniform_function('sub_1010', 0x1010, 4),
                     uniform_function('sub_1020', 0x1020, 4)]
        raw, contracts = fixture(bytes(code), functions)
        path = self.directory / 'input.elf'
        path.write_bytes(raw)
        image = Image(path, contracts)
        registers.prepare(image)
        self.assertTrue({'rdi', 'rsi'} <= registers.names(image.register_summaries[0x1000][0]))
        function, _, library = self.compile(raw, contracts, 'sub_1000')
        for name, register, expected in (('sub_1010', 'rax', 0x11), ('sub_1020', 'rdx', 0x22)):
            registers_file = RegisterFile()
            registers_file.gpr[GPR['rdi']] = 0x11
            registers_file.gpr[GPR['rsi']] = 0x22
            registers_file.gpr[GPR['rax']] = ctypes.cast(getattr(library, name), ctypes.c_void_p).value
            function(ctypes.byref(registers_file))
            self.assertEqual(registers_file.gpr[GPR[register]], expected)
    def test_uniform_shared_target_set_is_one_group_and_grows(self):
        # Two callers dispatch through the same pool target set. The union over the set is one
        # group, and a target that calls a leaf writing rcx must still reach both callers through
        # the group (the two-hop propagation the grouping adds).
        code = bytearray(0x60)
        code[0x00:0x03] = bytes.fromhex('ffd0c3')            # 0x1000: call rax ; ret
        code[0x10:0x13] = bytes.fromhex('ffd0c3')            # 0x1010: call rax ; ret
        code[0x20:0x26] = bytes.fromhex('e81b000000c3')      # 0x1020: call 0x1040 ; ret
        code[0x30:0x34] = bytes.fromhex('4889f8c3')          # 0x1030: mov rax,rdi ; ret
        code[0x40:0x45] = bytes.fromhex('4889d1c3')          # 0x1040: mov rcx,rdx ; ret
        functions = [uniform_function('sub_1000', 0x1000, 3,
                                      indirect_calls=[{'address': 0x1000, 'target_set': 0}]),
                     uniform_function('sub_1010', 0x1010, 3,
                                      indirect_calls=[{'address': 0x1010, 'target_set': 0}]),
                     uniform_function('sub_1020', 0x1020, 6),
                     uniform_function('sub_1030', 0x1030, 4),
                     uniform_function('sub_1040', 0x1040, 4)]
        raw, contracts = fixture(bytes(code), functions)
        contracts['target_sets'] = [[0x1020, 0x1030]]
        path = self.directory / 'input.elf'
        path.write_bytes(raw)
        image = Image(path, contracts)
        registers.prepare(image)
        self.assertEqual(len(image.register_pool_masks), 1)
        group_store, _ = image.register_pool_masks[0]
        self.assertTrue({'rax', 'rdi', 'rcx', 'rdx'} <= registers.names(group_store))
        for caller in (0x1000, 0x1010):
            self.assertTrue({'rax', 'rdi', 'rcx', 'rdx'} <= registers.names(image.register_summaries[caller][0]),
                            hex(caller))
    def test_uniform_summary_matches_the_full_copy_build(self):
        # The optimization must be invisible: a caller that copies only the callee's read set and
        # reads back only its write set has to leave the whole register file in the same state as
        # the full-copy build. This compiles the same function both ways and compares every byte.
        code = bytearray(0x18)
        code[0x00:0x06] = bytes.fromhex('e80b000000c3')      # 0x1000: call 0x1010 ; ret
        code[0x10:0x18] = bytes.fromhex('4889f84801f0c3')    # 0x1010: mov rax,rdi ; add rax,rsi ; ret
        functions = [uniform_function('sub_1000', 0x1000, 6),
                     uniform_function('sub_1010', 0x1010, 8)]
        raw, contracts = fixture(bytes(code), functions)
        summary_function, summary_ir = self.build(raw, contracts, 'sub_1000', '-summary')
        with mock.patch.object(registers, 'prepare', lambda image: image.register_summaries), \
                mock.patch.object(registers, 'summary', lambda image, address: (registers.FULL, registers.FULL)), \
                mock.patch.object(registers, 'pool_mask', lambda image, index: None):
            full_function, full_ir = self.build(raw, contracts, 'sub_1000', '-full')
        self.assertNotEqual(summary_ir, full_ir)

        def initial():
            state = RegisterFile()
            state.gpr[GPR['rdi']] = 21
            state.gpr[GPR['rsi']] = 21
            state.gpr[GPR['rax']] = 0xdeadbeefcafef00d
            for index, name in enumerate(('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')):
                state.gpr[GPR[name]] = 0x1234000000000000 | index
            for lane in range(16):
                state.xmm[lane][0] = 0x0102030405060708 + lane
                state.xmm[lane][1] = 0x1112131415161718 + lane
                state.ymm_hi[lane][0] = 0x2122232425262728 + lane
                state.ymm_hi[lane][1] = 0x3132333435363738 + lane
            state.flags = 0x212
            state.flags_mask = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11)
            return state

        def run(function):
            state = initial()
            function(ctypes.byref(state))
            return bytes(state)

        self.assertEqual(run(summary_function), run(full_function))

    def build(self, raw, contracts, entry, suffix):
        source = self.directory / f'input{suffix}.elf'
        source.write_bytes(raw)
        ir, _ = compile_image(Image(source, contracts))
        ll = self.directory / f'output{suffix}.ll'
        ll.write_text(ir)
        binary = self.directory / f'output{suffix}.dylib'
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ll), '-o', str(binary)],
                       check=True, capture_output=True)
        library = ctypes.CDLL(str(binary))
        function = getattr(library, entry)
        function.restype = None
        function.argtypes = [ctypes.POINTER(RegisterFile)]
        return function, ir


if __name__ == '__main__':
    unittest.main()

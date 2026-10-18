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
import integer
from compiler import Function, REGISTERS

MASK64 = (1 << 64) - 1
# The x86 RFLAGS bit of each flag the atomics module models; also the packing the harness emits.
FLAG_BITS = {'cf': 0, 'pf': 2, 'zf': 6, 'sf': 7, 'of': 11}
MEMORY_BYTES = 64
MEMORY_WORDS = MEMORY_BYTES // 8
OUTPUT_WORDS = 4 + MEMORY_WORDS


class Harness(Function):
    """A minimal Function that executes one atomic instruction against `[rdi]` and reports state.

    Contract: `atomics.analyze`/`atomics.lower` must lower a locked instruction to an atomic
    operation that matches native x86, and `Function.read`/`write` must emit the TSO
    acquire/release forms. The differential tests compile this harness for arm64 and compare it
    with the same instruction running under Rosetta; the IR-shape tests read the emitted text.
    """

    def __init__(self, ins):
        self.serial, self.depth = 0, 256
        self.memory_writes = {}
        self.checked_accesses = {}
        # The uniform ABI added by the native/gaps lane; this probe uses the classic contract.
        self.uniform = False
        self.dispatch = False
        self.contract = {'name': 'probe'}
        self.lines = ['target triple = "arm64-apple-macosx13.0.0"', 'declare void @llvm.trap()',
                      'define void @probe(ptr %memory, ptr %output, i64 %input_rax, i64 %input_rcx, i64 %input_rdx, i64 %input_flags) {', 'entry:']
        known = {register: MASK64 for register in REGISTERS}
        self.states = {ins.address: {'known': known, 'flags': set(FLAG_BITS),
                                     'pointers': {'rdi': ('parameter', 0, 0)}, 'saved': {}, 'rsp': 0, 'rbp': None,
                                     'constants': {}, 'tail_stack_clean': frozenset(), 'native_pointers': {'rdi'},
                                     'stack_pointers': {}, 'image_pointers': {}}}
        for register in REGISTERS:
            self.lines.append(f'  %{register} = alloca i64, align 8')
            source = {'rax': '%input_rax', 'rcx': '%input_rcx', 'rdx': '%input_rdx'}.get(register, '0')
            self.lines.append(f'  store i64 {source}, ptr %{register}, align 8')
        for name, bit in FLAG_BITS.items():
            self.lines.append(f'  %{name} = alloca i1, align 1')
            shifted = self.emit(f'lshr i64 %input_flags, {bit}')
            integer.store_flag(self, name, self.emit(f'trunc i64 {shifted} to i1'))

    def address(self, ins, operand):
        mem = operand.mem
        if ins.reg_name(mem.base) != 'rdi' or mem.index or mem.disp:
            raise ValueError('unsupported test address')
        return '%memory'

    def finish(self, ins):
        atomics.lower(self, ins)
        combined = '0'
        for name, bit in FLAG_BITS.items():
            value = self.emit(f'zext i1 {integer.load_flag(self, name)} to i64')
            value = self.emit(f'shl i64 {value}, {bit}')
            combined = self.emit(f'or i64 {combined}, {value}')
        values = [self.load('rax'), self.load('rcx'), self.load('rdx'), combined]
        for index in range(MEMORY_WORDS):
            pointer = self.emit(f'getelementptr i8, ptr %memory, i64 {index * 8}')
            values.append(self.emit(f'load i64, ptr {pointer}, align 1'))
        for index, value in enumerate(values):
            address = self.emit(f'getelementptr i64, ptr %output, i64 {index}')
            self.lines.append(f'  store i64 {value}, ptr {address}, align 8')
        self.lines.extend(['  ret void', '}'])
        return '\n'.join(self.lines) + '\n'


class AtomicsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='anyps5-atomics-')
        cls.directory = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        cls.decoder.detail = True
        cls.serial = 0

    def instruction(self, assembly):
        type(self).serial += 1
        stem = self.directory / f'probe{self.serial}'
        source = stem.with_suffix('.S')
        source.write_text('.intel_syntax noprefix\n.text\n' + assembly + '\n')
        obj = stem.with_suffix('.o')
        subprocess.run(['xcrun', 'clang', '--target=x86_64-unknown-freebsd', '-c', str(source), '-o', str(obj)],
                       check=True, capture_output=True)
        code = ELFFile(io.BytesIO(obj.read_bytes())).get_section_by_name('.text').data()
        decoded = list(self.decoder.disasm(code, 0x1000))
        self.assertEqual(len(decoded), 1, assembly)
        return decoded[0], stem

    def lower(self, assembly):
        ins, stem = self.instruction(assembly)
        harness = Harness(ins)
        self.assertTrue(atomics.analyze(harness, ins, harness.states[ins.address]))
        return ins, stem, harness.finish(ins)

    def compare(self, assembly, samples):
        ins, stem, ir = self.lower(assembly)
        source = stem.with_suffix('.ll')
        source.write_text(ir)
        native = stem.with_suffix('.dylib')
        result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(source), '-o', str(native)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        library = ctypes.CDLL(str(native))
        function = library.probe
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64)] + [ctypes.c_uint64] * 4
        function.restype = None
        dump = ''.join(f'    mov r10, [rdi+{index * 8}]\n    mov [rsi+{32 + index * 8}], r10\n' for index in range(MEMORY_WORDS))
        oracle = stem.with_suffix('.oracle.S')
        oracle.write_text('.intel_syntax noprefix\n.text\n.globl _run\n_run:\n'
                          '    mov rax, rdx\n    mov rdx, r8\n'
                          '    mov r10, r9\n    and r10, 2245\n    or r10, 514\n    push r10\n    popfq\n'
                          + assembly + '\n'
                          '    mov [rsi], rax\n    mov [rsi+8], rcx\n    mov [rsi+16], rdx\n'
                          '    pushfq\n    pop r10\n    and r10, 2245\n    mov [rsi+24], r10\n'
                          + dump + '    ret\n')
        runner = stem.with_suffix('.c')
        runner.write_text('#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n'
                          'extern void run(const void*, void*, uint64_t, uint64_t, uint64_t, uint64_t);\n'
                          'int main(void) {\n'
                          '    unsigned char memory[64], output[96];\n    uint64_t inputs[4];\n'
                          '    while (fread(memory, 1, 64, stdin) == 64 && fread(inputs, 1, 32, stdin) == 32) {\n'
                          '        memset(output, 0, sizeof(output));\n'
                          '        run(memory, output, inputs[0], inputs[1], inputs[2], inputs[3]);\n'
                          '        if (fwrite(output, 1, 96, stdout) != 96) return 2;\n'
                          '    }\n    return ferror(stdin) ? 1 : 0;\n}\n')
        binary = stem.with_suffix('.x86')
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-O2', str(oracle), str(runner), '-o', str(binary)],
                       check=True, capture_output=True)
        payload = b''.join(memory + struct.pack('<4Q', rax, rcx, rdx, flags) for memory, rax, rcx, rdx, flags in samples)
        expected = subprocess.run([str(binary)], input=payload, check=True, capture_output=True).stdout
        self.assertEqual(len(expected), len(samples) * OUTPUT_WORDS * 8)
        for index, sample in enumerate(samples):
            memory, rax, rcx, rdx, flags = sample
            buffer = ctypes.create_string_buffer(memory, MEMORY_BYTES)
            output = (ctypes.c_uint64 * OUTPUT_WORDS)()
            function(buffer, output, rax, rcx, rdx, flags)
            actual = struct.pack(f'<{OUTPUT_WORDS}Q', *output)
            reference = expected[index * OUTPUT_WORDS * 8:(index + 1) * OUTPUT_WORDS * 8]
            self.assertEqual(actual, reference, (assembly, index, sample))
        return native

    def samples(self, count=48, flags=0, index_bound=None):
        randoms = random.Random(0xA70)
        result = []
        for _ in range(count):
            rcx = randoms.getrandbits(64)
            if index_bound is not None:
                rcx %= index_bound
            result.append((randoms.randbytes(MEMORY_BYTES), randoms.getrandbits(64), rcx, randoms.getrandbits(64), flags))
        return result

    # --- differential: every instruction vs native x86 under Rosetta ---------------------------
    def test_compare_exchange_64_and_32(self):
        for assembly in ['lock cmpxchg QWORD PTR [rdi], rcx', 'lock cmpxchg DWORD PTR [rdi], ecx']:
            self.compare(assembly, self.samples())

    def test_exchange_memory_and_registers(self):
        self.compare('xchg QWORD PTR [rdi], rcx', self.samples())
        self.compare('xchg rcx, rdx', self.samples())

    def test_exchange_add(self):
        self.compare('lock xadd QWORD PTR [rdi], rcx', self.samples())

    def test_step_instructions_preserve_carry(self):
        self.compare('lock inc QWORD PTR [rdi]', self.samples(flags=1))
        self.compare('lock dec QWORD PTR [rdi]', self.samples(flags=1))

    def test_locked_arithmetic_flags(self):
        for operation in ('add', 'sub', 'and', 'or', 'xor'):
            self.compare(f'lock {operation} QWORD PTR [rdi], rcx', self.samples())

    def test_locked_arithmetic_immediate_sources(self):
        # Every group-1 locked RMW with an immediate source, across widths, including the
        # sign-extended imm8 form (opcode 83) and a full-width imm32/imm64 form.
        cases = (('BYTE', '0xff'), ('WORD', '0x1234'), ('DWORD', '2'), ('DWORD', '0x80'),
                 ('DWORD', '-1'), ('QWORD', '0x7f'), ('QWORD', '-8'), ('QWORD', '0x12345678'))
        for operation in ('add', 'sub', 'and', 'or', 'xor'):
            for width, immediate in cases:
                with self.subTest(operation=operation, width=width, immediate=immediate):
                    self.compare(f'lock {operation} {width} PTR [rdi], {immediate}', self.samples())

    def test_locked_bit_operations(self):
        # rcx bounded so the bit-string word stays inside the 64-byte buffer; 70 exercises word 1.
        for operation in ('bts', 'btr', 'btc'):
            self.compare(f'lock {operation} QWORD PTR [rdi], rcx', self.samples(index_bound=256))
            self.compare(f'lock {operation} QWORD PTR [rdi], 6', self.samples())
            self.compare(f'lock {operation} QWORD PTR [rdi], 70', self.samples())

    def test_fences_compile(self):
        for assembly in ('mfence', 'lfence', 'sfence'):
            _, _, ir = self.lower(assembly)
            self.assertIn('  fence ', ir, assembly)
            source = self.directory / f'{assembly}.ll'
            source.write_text(ir)
            result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-c', str(source), '-o', str(source.with_suffix('.o'))],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    # --- the TSO policy ------------------------------------------------------------------------
    def test_ordering_policy_shapes(self):
        self.assertEqual(atomics.ordered_load(64, '%p'), 'load atomic i64, ptr %p acquire, align 8')
        self.assertEqual(atomics.ordered_store(32, '7', '%p'), 'store atomic i32 7, ptr %p release, align 4')
        self.assertEqual(atomics.ordered_load(8, '%p'), 'load atomic i8, ptr %p acquire, align 1')
        # 128-bit vector accesses stay plain: ldapr/stlr have no 128-bit form without LSE2.
        self.assertEqual(atomics.ordered_load(128, '%p'), 'load i128, ptr %p, align 1')
        self.assertEqual(atomics.ordered_store(128, '7', '%p'), 'store i128 7, ptr %p, align 1')

    def test_under_aligned_accesses_drop_the_release_atomic(self):
        # `ordered_store`/`ordered_load` may only claim an alignment the caller proved. A release
        # atomic whose address is not naturally aligned lowers to `stlr`, which faults on a
        # misaligned address, so an under-aligned access keeps its true alignment and takes the
        # fence form instead. An unknown alignment keeps the natural form (the pre-existing policy).
        self.assertEqual(atomics.ordered_store(32, '7', '%p', 2),
                         '  fence release\n  store i32 7, ptr %p, align 2')
        self.assertEqual(atomics.ordered_load(32, '%p', 2),
                         'load i32, ptr %p, align 2\n  fence acquire')
        self.assertEqual(atomics.ordered_store(32, '7', '%p', 4),
                         'store atomic i32 7, ptr %p release, align 4')
        self.assertEqual(atomics.ordered_load(64, '%p', 8),
                         'load atomic i64, ptr %p acquire, align 8')
        self.assertEqual(atomics.ordered_store(32, '7', '%p'),
                         'store atomic i32 7, ptr %p release, align 4')

    def test_guest_accesses_are_ordered(self):
        # A plain `mov rax, [rdi]` / `mov [rdi], rcx` must reach the IR as acquire/release.
        ins, _ = self.instruction('mov rax, QWORD PTR [rdi]')
        harness = Harness(ins)
        harness.read(ins, ins.operands[1])
        self.assertIn('load atomic i64, ptr %memory acquire, align 8', harness.lines[-1])
        ins, _ = self.instruction('mov QWORD PTR [rdi], rcx')
        harness = Harness(ins)
        harness.write(ins, ins.operands[0], '%input_rcx')
        self.assertIn('store atomic i64 %input_rcx, ptr %memory release, align 8', harness.lines[-1])

    def test_store_buffering_stays_storeload_reorderable(self):
        # TSO allows a load to pass an earlier store to a different address. A plain release store
        # must not add a full barrier; only locked RMW/fences carry one.
        ins, _ = self.instruction('mov QWORD PTR [rdi], rcx')
        harness = Harness(ins)
        harness.write(ins, ins.operands[0], '%input_rcx')
        self.assertNotIn('fence', '\n'.join(harness.lines))
        _, _, locked = self.lower('lock xchg QWORD PTR [rdi], rcx')
        self.assertIn('seq_cst', locked)

    # --- rejections ----------------------------------------------------------------------------
    def test_unsupported_shapes_reject(self):
        ins, _ = self.instruction('cmpxchg rcx, rdx')
        harness = Harness(ins)
        with self.assertRaisesRegex(Exception, 'compare-exchange requires a memory destination'):
            atomics.analyze(harness, ins, harness.states[ins.address])
        ins, _ = self.instruction('lock inc DWORD PTR [rdi]')
        harness = Harness(ins)
        self.assertTrue(atomics.analyze(harness, ins, harness.states[ins.address]))

    # --- litmus tests: the emitted ARM64 code must preserve x86 TSO ----------------------------
    def litmus(self, name, functions, driver, iterations):
        stem = self.directory / name
        source = stem.with_suffix('.ll')
        source.write_text('target triple = "arm64-apple-macosx13.0.0"\n\n' + '\n\n'.join(functions) + '\n')
        library = stem.with_suffix('.dylib')
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(source), '-o', str(library)],
                       check=True, capture_output=True)
        runner = stem.with_suffix('.c')
        runner.write_text(driver.replace('ITERATIONS', str(iterations)))
        binary = stem.with_suffix('.run')
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O2', str(runner), str(library), '-o', str(binary)],
                       check=True, capture_output=True)
        result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=120)
        return result.stdout

    def test_litmus_message_passing(self):
        # Writer: data = 1 (release), then flag = 1 (release). Reader: flag (acquire), then data
        # (acquire). TSO forbids observing flag = 1 with data = 0.
        functions = [
            'define void @writer(ptr %data, ptr %flag) {\n'
            '  store atomic i64 1, ptr %data release, align 8\n'
            '  store atomic i64 1, ptr %flag release, align 8\n  ret void\n}',
            'define i64 @reader(ptr %data, ptr %flag) {\n'
            '  %f = load atomic i64, ptr %flag acquire, align 8\n'
            '  %d = load atomic i64, ptr %data acquire, align 8\n'
            '  %packed = shl i64 %f, 32\n  %result = or i64 %packed, %d\n  ret i64 %result\n}',
        ]
        driver = '''#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
extern void writer(uint64_t*, uint64_t*);
extern uint64_t reader(uint64_t*, uint64_t*);
static uint64_t data, flag;
static _Atomic int start;
static uint64_t observed;
static void* writer_thread(void*) { while (!atomic_load(&start)) {} writer(&data, &flag); return 0; }
static void* reader_thread(void*) { while (!atomic_load(&start)) {} observed = reader(&data, &flag); return 0; }
int main(void) {
    long violations = 0;
    for (long i = 0; i < ITERATIONS; ++i) {
        data = 0; flag = 0; observed = 0; atomic_store(&start, 0);
        pthread_t w, r;
        pthread_create(&w, 0, writer_thread, 0);
        pthread_create(&r, 0, reader_thread, 0);
        atomic_store(&start, 1);
        pthread_join(w, 0); pthread_join(r, 0);
        uint64_t f = observed >> 32, d = observed & 0xffffffff;
        if (f == 1 && d == 0) ++violations;
    }
    printf("violations=%ld\\n", violations);
    return 0;
}
'''
        output = self.litmus('message_passing', functions, driver, 20000)
        self.assertEqual(output.strip(), 'violations=0')

    def test_litmus_load_buffering(self):
        # T1: r1 = x (acquire); y = 1 (release). T2: r2 = y (acquire); x = 1 (release).
        # TSO forbids r1 = 1 and r2 = 1 together (a load cannot pass a later store).
        functions = [
            'define i64 @first(ptr %x, ptr %y) {\n'
            '  %r = load atomic i64, ptr %x acquire, align 8\n'
            '  store atomic i64 1, ptr %y release, align 8\n  ret i64 %r\n}',
            'define i64 @second(ptr %x, ptr %y) {\n'
            '  %r = load atomic i64, ptr %y acquire, align 8\n'
            '  store atomic i64 1, ptr %x release, align 8\n  ret i64 %r\n}',
        ]
        driver = '''#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
extern uint64_t first(uint64_t*, uint64_t*);
extern uint64_t second(uint64_t*, uint64_t*);
static uint64_t x, y;
static _Atomic int start;
static uint64_t observed[2];
static void* one(void*) { while (!atomic_load(&start)) {} observed[0] = first(&x, &y); return 0; }
static void* two(void*) { while (!atomic_load(&start)) {} observed[1] = second(&x, &y); return 0; }
int main(void) {
    long violations = 0;
    for (long i = 0; i < ITERATIONS; ++i) {
        x = 0; y = 0; observed[0] = 0; observed[1] = 0; atomic_store(&start, 0);
        pthread_t a, b;
        pthread_create(&a, 0, one, 0);
        pthread_create(&b, 0, two, 0);
        atomic_store(&start, 1);
        pthread_join(a, 0); pthread_join(b, 0);
        if (observed[0] == 1 && observed[1] == 1) ++violations;
    }
    printf("violations=%ld\\n", violations);
    return 0;
}
'''
        output = self.litmus('load_buffering', functions, driver, 20000)
        self.assertEqual(output.strip(), 'violations=0')


if __name__ == '__main__':
    unittest.main()

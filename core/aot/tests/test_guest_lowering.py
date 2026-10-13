import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import guest_lab
import guest_lift

CASES = json.loads((Path(__file__).parent / 'guest_lab_cases.json').read_text())
CHUNK = 110


class GuestSemanticsTests(unittest.TestCase):
    def compare(self, cases, samples=48):
        with guest_lab.lab_directory() as directory:
            failures = guest_lab.Lab(directory).compare(cases, samples=samples, seed=11)
        self.assertEqual(failures[:3], [])

    def test_narrow_double_shifts_preserve_partial_registers(self):
        cases = []
        for operation in ('shld', 'shrd'):
            for count in (0, 1, 2, 8, 15, 16, 32, 33):
                for target in ('ax', 'word ptr [rsi]'):
                    cases.append({'asm': [f'{operation} {target}, dx, {count}'],
                                  'pointers': {'rsi': 64}, 'flags': guest_lab.ALL_FLAGS if count in (0, 32) else 0x8c5 if count & 31 == 1 else 0xc5})
        self.compare(cases, samples=32)

    def test_packed_truncation_and_extended_loads(self):
        cases = [
            {'asm': ['cvttpd2dq xmm0, xmm1']},
            {'asm': ['cvttpd2dq xmm0, xmmword ptr [rsi]']},
            {'asm': ['fld qword ptr [rsi]', 'fstp tbyte ptr [rsi + 16]']},
            {'asm': ['fld dword ptr [rsi]', 'fstp tbyte ptr [rsi + 16]']},
            {'asm': ['fnstcw word ptr [rsi + 32]']},
        ]
        for case in cases:
            case['pointers'] = {'rsi': 64}
            case['vectors'] = 'double'
        self.compare(cases, samples=128)

    def test_extended_loads_at_encoding_boundaries(self):
        cases = []
        for bits, size, register in ((32, 'dword', 'eax'), (64, 'qword', 'rax')):
            fraction = 23 if bits == 32 else 52
            exponent = 255 if bits == 32 else 2047
            patterns = [0, 1, (1 << fraction) - 1, 1 << fraction,
                        (exponent - 1) << fraction, exponent << fraction,
                        (exponent << fraction) | 1, (exponent << fraction) | (1 << (fraction - 1))]
            for raw in patterns:
                for sign in (0, 1 << (bits - 1)):
                    cases.append({'asm': [f'mov {register}, {raw | sign}', f'mov {size} ptr [rsi], {register}',
                                          f'fld {size} ptr [rsi]', 'fstp tbyte ptr [rsi + 16]'],
                                  'pointers': {'rsi': 64}})
        self.compare(cases, samples=1)

    def test_forms_0(self):
        self.compare(CASES[0 * CHUNK:1 * CHUNK])

    def test_forms_1(self):
        self.compare(CASES[1 * CHUNK:2 * CHUNK])

    def test_forms_2(self):
        self.compare(CASES[2 * CHUNK:3 * CHUNK])

    def test_forms_3(self):
        self.compare(CASES[3 * CHUNK:4 * CHUNK])

    def test_forms_4(self):
        self.compare(CASES[4 * CHUNK:5 * CHUNK])

    def test_forms_5(self):
        self.compare(CASES[5 * CHUNK:])

    def test_cmpxchg_flags_and_partial_results_against_specification(self):
        cases, layouts = [], []
        for bits, size, dst, src in ((8, 'byte', 'dl', 'cl'), (16, 'word', 'dx', 'cx'),
                                    (32, 'dword', 'edx', 'ecx'), (64, 'qword', 'rdx', 'rcx')):
            for mode in ('register', 'memory', 'unaligned', 'locked'):
                offset = 65 if mode == 'unaligned' else 64
                operand = dst if mode == 'register' else f'{size} ptr [rsi + {offset}]'
                prefix = 'lock ' if mode == 'locked' else ''
                cases.append({'asm': [f'{prefix}cmpxchg {operand}, {src}']})
                layouts.append((bits, mode))
        with guest_lab.lab_directory() as directory:
            lab = guest_lab.Lab(directory)
            binary, roots = lab.lifted_binary(cases)
            records, expected = [], []
            for root, (bits, mode) in zip(roots, layouts):
                offset = 65 if mode == 'unaligned' else 64
                mask = (1 << bits) - 1
                sign = 1 << (bits - 1)
                edges = (0, 1, 15, 16, 127, 128, sign - 1, sign, mask)
                for left in edges:
                    for right in edges:
                        gpr = [0] * 16
                        gpr[0] = (0x123456789abc0000 & ~mask) | left
                        gpr[1] = 0x23456789abcdef01
                        gpr[2] = (0x3456789abcde0000 & ~mask) | right
                        gpr[6] = guest_lab.BUFFER_MARK
                        gpr[15] = guest_lab.SCRATCH_MARK
                        memory = bytearray([0xa5] * guest_lab.BUFFER_SIZE)
                        memory[offset:offset + bits // 8] = right.to_bytes(bits // 8, 'little')
                        records.append((root - guest_lab.CODE, gpr, bytes(256), 2, bytes(memory)))
                        result = (left - right) & mask
                        flags = int(left < right) | ((int((result & 255).bit_count() % 2 == 0)) << 2)
                        flags |= (int((left ^ right ^ result) & 16 != 0) << 4)
                        flags |= (int(result == 0) << 6) | (int(result & sign != 0) << 7)
                        flags |= (int((left ^ right) & (left ^ result) & sign != 0) << 11)
                        accumulator, destination = gpr[0], gpr[2]
                        if left == right:
                            value = gpr[1] & mask
                            if mode == 'register':
                                destination = value if bits >= 32 else (destination & ~mask) | value
                            else:
                                memory[offset:offset + bits // 8] = value.to_bytes(bits // 8, 'little')
                        else:
                            accumulator = right if bits >= 32 else (accumulator & ~mask) | right
                        expected.append((accumulator, destination, flags, bytes(memory)))
            source, output = Path(directory) / 'spec-input.bin', Path(directory) / 'spec-output.bin'
            lab.write_inputs(records, source)
            guest_lab.run([str(binary), str(source), str(output)])
            for index, (actual, wanted) in enumerate(zip(lab.read_outputs(output, len(records)), expected)):
                with self.subTest(record=index):
                    self.assertEqual(actual[0][0], wanted[0])
                    self.assertEqual(actual[0][2], wanted[1])
                    self.assertEqual(actual[2] & guest_lab.ALL_FLAGS, wanted[2])
                    self.assertEqual(actual[3], wanted[3])

    def test_cases_cover_every_chunk(self):
        self.assertLessEqual(len(CASES), 6 * CHUNK + CHUNK)


PRELUDE = '''
.globl _start
_start:
    and rsp, -16
'''

EXIT = '''
    call qword ptr [rip + exit_slot]
'''


class GuestProgramTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='anyps5-guest-program-')
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def program(self, source, imports=('exit',), data_imports=(), relative=(), strict=True, unwind=(), tls=None, concurrent=False, abi="glibc", launcher=None, ordered_access=None):
        slots = ''.join(f'.p2align 3\n{name}_slot: .quad 0\n' for name in [*imports, *data_imports])
        code, labels = guest_lab.assemble_program(source + slots, self.directory)
        raw = guest_lab.program_image(code, labels, [(name, f'{name}_slot') for name in imports],
                                      [(name, f'{name}_slot') for name in data_imports], relative=relative, unwind=unwind, tls=tls)
        return guest_lab.build_program(raw, self.directory, strict=strict, concurrent=concurrent or getattr(self, "memory_epochs", False), abi=abi, launcher=launcher, ordered_access=ordered_access, memory_epochs=getattr(self, "memory_epochs", False), seal_image=getattr(self, "seal_image", False))

    def run_binary(self, binary):
        return subprocess.run([str(binary)], capture_output=True, timeout=20)

    def threaded_program(self, concurrent, ordered_access=None):
        return self.program(PRELUDE + """
    sub rsp, 64
    mov r12, rsp
    mov qword ptr [r12 + 24], 0
    mov qword ptr [r12 + 32], 41
    mov qword ptr [r12 + 48], 73
    lea rax, [r12 + 24]
    mov qword ptr [r12 + 40], rax
    mov qword ptr [r12 + 56], rax
    lea rdi, [r12]
    xor esi, esi
    lea rdx, [rip + worker]
    lea rcx, [r12 + 32]
    call qword ptr [rip + pthread_create_slot]
    test eax, eax
    jnz failed
    lea rdi, [r12 + 8]
    xor esi, esi
    lea rdx, [rip + worker]
    lea rcx, [r12 + 48]
    call qword ptr [rip + pthread_create_slot]
    test eax, eax
    jnz failed
    mov rdi, qword ptr [r12 + 0]
    lea rsi, [r12 + 16]
    call qword ptr [rip + pthread_join_slot]
    test eax, eax
    jnz failed
    cmp qword ptr [r12 + 16], 41
    jne failed
    mov rdi, qword ptr [r12 + 8]
    lea rsi, [r12 + 16]
    call qword ptr [rip + pthread_join_slot]
    test eax, eax
    jnz failed
    cmp qword ptr [r12 + 16], 73
    jne failed
    cmp qword ptr [r12 + 24], 20000
    jne failed
    mov rdi, qword ptr [r12 + 0]
    xor esi, esi
    call qword ptr [rip + pthread_join_slot]
    cmp eax, 3
    jne failed
    xor edi, edi
    jmp finish
failed:
    mov edi, 91
finish:
""" + EXIT + """
worker:
    mov rax, qword ptr [rdi]
    mov qword ptr fs:[0x80], rax
    mov rdx, qword ptr [rdi + 8]
    mov ecx, 10000
again:
    lock inc qword ptr [rdx]
    dec ecx
    jnz again
    mov rax, qword ptr fs:[0x80]
    ret
.p2align 3
first: .quad 0
second: .quad 0
result: .quad 0
counter: .quad 0
""", imports=('exit', 'pthread_create', 'pthread_join'), concurrent=concurrent, ordered_access=ordered_access)

    def test_guest_threads_join_tls_and_atomic_contention(self):
        binary, _ = self.threaded_program(True)
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_atomic_guest_threads(self):
        binary, _ = self.threaded_program(True, ordered_access='atomic')
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_atomic_unaligned_accesses(self):
        source = PRELUDE + 'sub rsp, 128\n'
        for offset in range(1, 17):
            for size, left, right in (('byte', 'al', 'cl'), ('word', 'ax', 'cx'), ('dword', 'eax', 'ecx'), ('qword', 'rax', 'rcx')):
                source += f'mov rax, 0xFEDCBA9876543210\nmov {size} ptr [rsp + {offset}], {left}\nmov {right}, {size} ptr [rsp + {offset}]\ncmp {left}, {right}\njne bad\n'
        source += 'xor edi, edi\njmp done\nbad:\nmov edi, 97\ndone:\n' + EXIT
        for implementation in ('fenced', 'atomic'):
            with self.subTest(implementation=implementation):
                binary, _ = self.program(source, concurrent=True, ordered_access=implementation)
                result = self.run_binary(binary)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_atomic_threads_and_cpuid_ordering(self):
        binary, _ = self.threaded_program(True, ordered_access='atomic')
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        workers = ["mov qword ptr [rdi], 1\nxor eax, eax\ncpuid\nmov rax, qword ptr [rdi + 8]\nmov qword ptr [rdi + 16], rax\nret",
                   "mov qword ptr [rdi + 8], 1\nxor eax, eax\ncpuid\nmov rax, qword ptr [rdi]\nmov qword ptr [rdi + 24], rax\nret"]
        self.litmus(workers, "mov rax, qword ptr [r12 + 16]\nor rax, qword ptr [r12 + 24]\njz bad", implementations=('atomic',))

    def test_guest_threads_reject_unordered_image(self):
        binary, _ = self.threaded_program(False)
        result = self.run_binary(binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'ordered memory profile', result.stderr)

    def test_ordered_shared_memory_litmus(self):
        writers = ["mov qword ptr [rdi], 1\nmov qword ptr [rdi + 8], 1\nxor eax, eax\nret",
                   "spin:\nmov rax, qword ptr [rdi + 8]\ntest rax, rax\njz spin\nmov rax, qword ptr [rdi]\nmov qword ptr [rdi + 16], rax\nret"]
        self.litmus(writers, "cmp qword ptr [r12 + 16], 1\njne bad")

    def test_ordered_store_buffering_with_fences(self):
        workers = ["mov qword ptr [rdi], 1\nmfence\nmov rax, qword ptr [rdi + 8]\nmov qword ptr [rdi + 16], rax\nret",
                   "mov qword ptr [rdi + 8], 1\nmfence\nmov rax, qword ptr [rdi]\nmov qword ptr [rdi + 24], rax\nret"]
        self.litmus(workers, "mov rax, qword ptr [r12 + 16]\nor rax, qword ptr [r12 + 24]\njz bad")

    def test_ordered_store_buffering_without_explicit_fence(self):
        workers = ["mov qword ptr [rdi], 1\nmov rax, qword ptr [rdi + 8]\nmov qword ptr [rdi + 16], rax\nret",
                   "mov qword ptr [rdi + 8], 1\nmov rax, qword ptr [rdi]\nmov qword ptr [rdi + 24], rax\nret"]
        self.litmus(workers, "mov rax, qword ptr [r12 + 16]\nor rax, qword ptr [r12 + 24]\njz bad", implementations=("fenced", "atomic"))

    def test_ordered_message_passing_with_atomic_publish(self):
        workers = ["mov qword ptr [rdi], 1\nmov eax, 1\nxchg qword ptr [rdi + 8], rax\nret",
                   "spin:\nmov rax, qword ptr [rdi + 8]\ntest rax, rax\njz spin\nmov rax, qword ptr [rdi]\nmov qword ptr [rdi + 16], rax\nret"]
        self.litmus(workers, "cmp qword ptr [r12 + 16], 1\njne bad")

    def test_ordered_independent_reads_of_independent_writes(self):
        workers = ["mov qword ptr [rdi], 1\nret", "mov qword ptr [rdi + 8], 1\nret",
                   "mov rax, qword ptr [rdi]\nmov qword ptr [rdi + 16], rax\nmov rax, qword ptr [rdi + 8]\nmov qword ptr [rdi + 24], rax\nret",
                   "mov rax, qword ptr [rdi + 8]\nmov qword ptr [rdi + 32], rax\nmov rax, qword ptr [rdi]\nmov qword ptr [rdi + 40], rax\nret"]
        check = "cmp qword ptr [r12 + 16], 1\njne good\ncmp qword ptr [r12 + 24], 0\njne good\ncmp qword ptr [r12 + 32], 1\njne good\ncmp qword ptr [r12 + 40], 0\nje bad\ngood:"
        self.litmus(workers, check)

    def litmus(self, workers, check, implementations=("fenced", "atomic")):
        source = PRELUDE + "sub rsp, 128\nmov r12, rsp\nmov r13d, 128\nround:\n"
        source += ''.join(f"mov qword ptr [r12 + {offset}], 0\n" for offset in range(0, 64, 8))
        for index in range(len(workers)):
            source += f"lea rdi, [r12 + {64 + index * 8}]\nxor esi, esi\nlea rdx, [rip + worker{index}]\nmov rcx, r12\ncall qword ptr [rip + pthread_create_slot]\ntest eax, eax\njnz bad\n"
        source += 'mov qword ptr [r12 + 48], 1\n'
        for index in range(len(workers)):
            source += f"mov rdi, qword ptr [r12 + {64 + index * 8}]\nxor esi, esi\ncall qword ptr [rip + pthread_join_slot]\ntest eax, eax\njnz bad\n"
        source += check + "\ndec r13d\njnz round\nxor edi, edi\njmp done\nbad:\nmov edi, 93\ndone:\n" + EXIT
        source += ''.join(f"worker{index}:\nwait_start{index}:\nmov rax, qword ptr [rdi + 48]\ntest rax, rax\njz wait_start{index}\n{body}\n" for index, body in enumerate(workers))
        for implementation in implementations:
            with self.subTest(implementation=implementation):
                binary, _ = self.program(source, imports=('exit', 'pthread_create', 'pthread_join'), concurrent=True, ordered_access=implementation)
                result = self.run_binary(binary)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_packed_truncation_rejects_misaligned_source(self):
        binary, _ = self.program(PRELUDE + 'sub rsp, 64\nlea rsi, [rsp + 1]\ncvttpd2dq xmm0, xmmword ptr [rsi]\nxor edi, edi\n' + EXIT)
        result = self.run_binary(binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'misaligned aligned vector access', result.stderr)

    def test_sce_startup_argument_block_and_entry_stack(self):
        launcher = """
#include "native/NativeAotGuest.hpp"
#include <cstdlib>
extern "C" const NativeAotGuestImage __aps5_guest_image;
void Exit(NativeAotGuestState& state) { std::_Exit(static_cast<int>(NativeAotGuest::Argument(state, 0))); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding bindings[] = {{"exit", Exit, nullptr}};
    NativeAotGuest::RegisterProviders(bindings, 1);
    NativeAotGuest::StartSceApplication(__aps5_guest_image, argc, argv);
}
"""
        binary, _ = self.program("""
.globl _start
_start:
    cmp qword ptr [rdi], 1
    jne bad
    cmp qword ptr [rdi + 16], 0
    jne bad
    mov rax, qword ptr [rdi + 8]
    cmp byte ptr [rax], 0
    je bad
    test rsi, rsi
    jnz bad
    mov rax, rsp
    and eax, 15
    cmp eax, 8
    jne bad
    xor edi, edi
    jmp done
bad:
    mov edi, 94
done:
""" + EXIT, abi='sce-app', launcher=launcher)
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sce_image_rejects_glibc_launcher(self):
        binary, _ = self.program(PRELUDE + 'xor edi, edi\n' + EXIT, abi='sce-app')
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 127)
        self.assertIn(b'startup ABI does not match', result.stderr)

    def test_unknown_startup_abi_rejects(self):
        with self.assertRaisesRegex(guest_lift.LiftError, 'unknown guest startup ABI'):
            self.program(PRELUDE + 'xor edi, edi\n' + EXIT, abi='unknown')

    def test_x87_stack_faults_are_rejected(self):
        for body in ('fldz\n' * 9, 'fstp tbyte ptr [rsp - 16]\n'):
            with self.subTest(body=body):
                binary, _ = self.program(PRELUDE + body + 'xor edi, edi\n' + EXIT)
                result = self.run_binary(binary)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b'unsupported guest operation', result.stderr)

    def test_ordered_access_options_require_concurrency(self):
        with self.assertRaisesRegex(guest_lift.LiftError, 'requires --concurrent'):
            self.program(PRELUDE + 'xor edi, edi\n' + EXIT, ordered_access='atomic')

    def test_unknown_memory_model_rejected_before_entry(self):
        launcher = """
#include "native/NativeAotGuest.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
int main() {
    auto image = __aps5_guest_image;
    image.Concurrent = 4;
    NativeAotGuest::Load(image);
}
"""
        binary, _ = self.program(PRELUDE + 'xor edi, edi\n' + EXIT, launcher=launcher)
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 127)
        self.assertIn(b'unsupported guest memory model', result.stderr)

    def test_variadic_provider_reads_registers_and_stack(self):
        binary, _ = self.program(PRELUDE + '''
    mov rdi, qword ptr [rip + stdout_slot]
    mov rdi, qword ptr [rdi]
    lea rsi, [rip + format]
    mov edx, 1
    mov ecx, 2
    mov r8d, 3
    mov r9d, -4
    movsd xmm0, qword ptr [rip + first]
    movsd xmm1, qword ptr [rip + second]
    lea rax, [rip + text]
    push rax
    push 0
    push 6
    push 5
    mov eax, 2
    call qword ptr [rip + fprintf_slot]
    add rsp, 32
    mov edi, 3
''' + EXIT + '''
format: .asciz "%d %u %x %d %ld %5ld %.2f %.3e %p %-6s|\\n"
text: .asciz "hello"
.p2align 3
first: .double 1.5
second: .double 2.25
''', imports=('fprintf', 'exit'), data_imports=('stdout',))
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stdout, b'1 2 3 -4 5     6 1.50 2.250e+00 (nil) hello |\n')

    def test_guest_callback_through_provider(self):
        binary, _ = self.program(PRELUDE + '''
    sub rsp, 64
    mov qword ptr [rsp], 9
    mov qword ptr [rsp + 8], -3
    mov qword ptr [rsp + 16], 7
    mov qword ptr [rsp + 24], 0
    mov qword ptr [rsp + 32], 100
    mov qword ptr [rsp + 40], -50
    mov qword ptr [rsp + 48], 7
    mov qword ptr [rsp + 56], 1
    mov rdi, rsp
    mov esi, 8
    mov edx, 8
    lea rcx, [rip + compare]
    call qword ptr [rip + qsort_slot]
    mov rdi, rsp
    mov esi, 8
    mov edx, 8
    mov rcx, qword ptr [rip + stdout_slot]
    mov rcx, qword ptr [rcx]
    call qword ptr [rip + fwrite_slot]
    xor edi, edi
''' + EXIT + '''
compare:
    mov rax, qword ptr [rdi]
    mov rcx, qword ptr [rsi]
    xor edx, edx
    cmp rax, rcx
    setg dl
    mov eax, -1
    cmovge eax, edx
    ret
''', imports=('qsort', 'fwrite', 'exit'), data_imports=('stdout',))
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 0, result.stderr)
        values = [int.from_bytes(result.stdout[i:i + 8], 'little', signed=True) for i in range(0, 64, 8)]
        self.assertEqual(values, sorted([9, -3, 7, 0, 100, -50, 7, 1]))

    def test_unknown_indirect_target_traps(self):
        binary, _ = self.program(PRELUDE + '''
    mov rax, rsp
    call rax
    xor edi, edi
''' + EXIT)
        result = self.run_binary(binary)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'control transfer to an address without converted code', result.stderr)

    def test_mismatched_return_address_is_not_followed(self):
        binary, _ = self.program(PRELUDE + '''
    call redirect
    mov edi, 1
''' + EXIT + '''
landing:
    mov edi, 7
''' + EXIT + '''
redirect:
    lea rax, [rip + landing]
    mov qword ptr [rsp], rax
    ret
''')
        result = self.run_binary(binary)
        self.assertNotEqual(result.returncode, 7)
        self.assertIn(b'guest return address does not match any converted caller', result.stderr)

    def test_missing_import_fails_at_startup(self):
        binary, _ = self.program(PRELUDE + '''
    call qword ptr [rip + definitely_missing_slot]
    xor edi, edi
''' + EXIT, imports=('definitely_missing', 'exit'))
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 127)
        self.assertIn(b'missing import providers: definitely_missing', result.stderr)

    def test_bounded_and_scanned_jump_tables(self):
        source = PRELUDE + '''
    mov eax, dword ptr [rsp]
    cmp eax, 3
    ja done
    lea rcx, [rip + table]
    movsxd rax, dword ptr [rcx + 4*rax]
    add rax, rcx
    jmp rax
case0:
    mov edi, 10
    jmp done_exit
case1:
    mov edi, 11
    jmp done_exit
case2:
    mov edi, 12
    jmp done_exit
case3:
    mov edi, 13
    jmp done_exit
done:
    mov edi, 99
done_exit:
''' + EXIT + '''
.p2align 2
table:
    .long case0 - table
    .long case1 - table
    .long case2 - table
    .long case3 - table
'''
        binary, report = self.program(source)
        self.assertEqual(report['jump_tables'], {'qualified': 1, 'candidate': 0})
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 11, result.stderr)

    def test_scanned_table_keeps_runtime_membership(self):
        source = PRELUDE + '''
    mov eax, dword ptr [rsp]
    add eax, 1
    and eax, 3
    lea rcx, [rip + table]
    movsxd rax, dword ptr [rcx + 4*rax]
    add rax, rcx
    jmp rax
case0:
    mov edi, 20
    jmp finish
case1:
    mov edi, 21
    jmp finish
case2:
    mov edi, 22
finish:
''' + EXIT + '''
.p2align 2
table:
    .long case0 - table
    .long case1 - table
    .long case2 - table
    .long case2 - table
'''
        binary, report = self.program(source)
        self.assertEqual(report['jump_tables'], {'qualified': 0, 'candidate': 0})
        self.assertIn('indirect-jump-dispatch', {item['kind'] for item in report['obligations']})
        result = self.run_binary(binary)
        self.assertNotEqual(result.returncode, 22)
        self.assertIn(b'guest return address does not match any converted caller', result.stderr)
        binary, report = self.program(source + 'end_of_start:\n', unwind=[('_start', 'table')])
        self.assertEqual(report['jump_tables'], {'qualified': 0, 'candidate': 1})
        self.assertIn('jump-table-extent-candidate', {item['kind'] for item in report['obligations']})
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 22, result.stderr)

    def test_nonlocal_jump_resumes_at_a_call_return(self):
        binary, _ = self.program(PRELUDE + '''
    sub rsp, 32
    mov rbx, rsp
    call save
    test eax, eax
    jne resumed
    call jumper
    mov edi, 1
''' + EXIT + '''
resumed:
    mov edi, eax
''' + EXIT + '''
save:
    lea rcx, [rsp + 8]
    mov qword ptr [rbx], rcx
    mov rcx, qword ptr [rsp]
    mov qword ptr [rbx + 8], rcx
    xor eax, eax
    ret
jumper:
    mov rsp, qword ptr [rbx]
    mov eax, 42
    jmp qword ptr [rbx + 8]
''')
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 42, result.stderr)

    def test_thread_pointer_and_static_tls(self):
        binary, _ = self.program(PRELUDE + '''
    mov rax, qword ptr fs:[0]
    cmp rax, qword ptr fs:[16]
    jne bad
    cmp qword ptr fs:[40], 0
    je bad
    mov rcx, qword ptr fs:[-16]
    cmp rcx, 77
    jne bad
    mov qword ptr fs:[-8], 5
    mov rcx, qword ptr [rax - 8]
    add ecx, 30
    mov edi, ecx
''' + EXIT + '''
bad:
    mov edi, 1
''' + EXIT, tls=(bytes([77] + [0] * 7), 16, 8))
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 35, result.stderr)

    def test_split_lock_traps(self):
        binary, _ = self.program(PRELUDE + '''
    lea rax, [rsp - 13]
    lock add dword ptr [rax], 1
    xor edi, edi
''' + EXIT)
        result = self.run_binary(binary)
        self.assertIn(b'locked access crosses its natural alignment', result.stderr)

    def test_implicit_atomic_alignment_is_checked(self):
        for operation in ('xchg dword ptr [rdi], ecx', 'lock cmpxchg dword ptr [rdi], ecx'):
            with self.subTest(operation=operation):
                binary, _ = self.program(PRELUDE + f'''
    lea rdi, [rsp - 13]
    xor eax, eax
    mov ecx, 1
    {operation}
    xor edi, edi
''' + EXIT)
                result = self.run_binary(binary)
                self.assertIn(b'locked access crosses its natural alignment', result.stderr)

    def test_tls_destructors_repeat_before_join_returns(self):
        binary, _ = self.program(PRELUDE + """
    sub rsp, 64
    mov r12, rsp
    mov qword ptr [r12 + 8], 0
    lea rdi, [r12 + 0]
    lea rsi, [rip + destroy]
    call qword ptr [rip + pthread_key_create_slot]
    test eax, eax
    jne fail
    lea rdi, [r12 + 16]
    xor esi, esi
    lea rdx, [rip + worker]
    mov rcx, r12
    call qword ptr [rip + pthread_create_slot]
    test eax, eax
    jne fail
    mov rdi, qword ptr [r12 + 16]
    lea rsi, [r12 + 24]
    call qword ptr [rip + pthread_join_slot]
    test eax, eax
    jne fail
    cmp qword ptr [r12 + 8], 4
    jne fail
    cmp qword ptr [r12 + 24], 73
    jne fail
    mov edi, dword ptr [r12]
    call qword ptr [rip + pthread_key_delete_slot]
    xor edi, edi
    call qword ptr [rip + exit_slot]
fail:
    mov edi, 55
    call qword ptr [rip + exit_slot]
worker:
    sub rsp, 8
    mov rsi, rdi
    mov edi, dword ptr [rdi]
    call qword ptr [rip + pthread_setspecific_slot]
    mov eax, 73
    add rsp, 8
    ret
worker_end:
destroy:
    sub rsp, 8
    add qword ptr [rdi + 8], 1
    mov rsi, rdi
    mov edi, dword ptr [rdi]
    call qword ptr [rip + pthread_setspecific_slot]
    add rsp, 8
    ret
destroy_end:
""", imports=('exit', 'pthread_key_create', 'pthread_key_delete', 'pthread_setspecific', 'pthread_create', 'pthread_join'),
            unwind=(('worker', 'worker_end'), ('destroy', 'destroy_end')), concurrent=True)
        result = self.run_binary(binary)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_narrow_double_shift_undefined_counts_trap(self):
        for operation in ('shld', 'shrd'):
            binary, _ = self.program(PRELUDE + f"mov ax, 1\nmov dx, 2\n{operation} ax, dx, 17\nxor edi, edi\n" + EXIT)
            result = self.run_binary(binary)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'unsupported guest operation', result.stderr)

    def test_memory_epochs_preserve_thread_creation_and_tls_destructors(self):
        self.memory_epochs = True
        self.test_tls_destructors_repeat_before_join_returns()

    def test_memory_epoch_promotion_resumes_without_replaying_effects(self):
        self.memory_epochs = True
        launcher = r'''#include "native/NativeAotGuest.hpp"
#include "native/NativeAotGlibc.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
extern char** environ;
void Observe(NativeAotGuestState& state) { NativeAotGuest::Return(state, NativeAotGuestSingleThreadEpoch()); }
void Foreign(NativeAotGuestState& state) { NativeAotGuest::Return(state, 0); }
int main(int argc, char** argv) {
    NativeAotGlibc::Register();
    const NativeAotGuest::ProviderBinding providers[] = {{"observe", Observe, nullptr, true}, {"foreign", Foreign, nullptr}};
    NativeAotGuest::RegisterProviders(providers, 2);
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, environ);
}
'''
        binary, _ = self.program(PRELUDE + """
    sub rsp, 16
    mov r12, rsp
    mov qword ptr [r12], 0
    call qword ptr [rip + observe_slot]
    cmp rax, 1
    jne fail
    add qword ptr [r12], 1
    call qword ptr [rip + foreign_slot]
    add qword ptr [r12], 1
    call qword ptr [rip + observe_slot]
    test rax, rax
    jne fail
    cmp qword ptr [r12], 2
    jne fail
    xor edi, edi
    call qword ptr [rip + exit_slot]
fail:
    mov edi, 55
    call qword ptr [rip + exit_slot]
""", imports=('exit', 'observe', 'foreign'), concurrent=True, launcher=launcher)
        result = self.run_binary(binary)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_memory_epochs_reject_foreign_entry_before_owner_boundary(self):
        self.memory_epochs = True
        launcher = r'''#include "native/NativeAotGuest.hpp"
#include "native/NativeAotGlibc.hpp"
#include <thread>
extern "C" const NativeAotGuestImage __aps5_guest_image;
int main() {
    NativeAotGlibc::Register();
    const auto base = NativeAotGuest::Load(__aps5_guest_image);
    std::thread other([&] { NativeAotGuestFind(base + __aps5_guest_image.EntryPoint); });
    other.join();
    return 99;
}
'''
        binary, _ = self.program(PRELUDE + 'xor edi, edi\n' + EXIT, concurrent=True, launcher=launcher)
        result = self.run_binary(binary)
        self.assertEqual(result.returncode, 127)
        self.assertIn(b'owning-thread call boundary', result.stderr)

    def test_dense_dispatch_with_overwritten_selector_and_candidate_targets(self):
        self.memory_epochs = True
        self.test_bounded_and_scanned_jump_tables()
        self.test_scanned_table_keeps_runtime_membership()

    def test_sealed_dense_dispatch_uses_verified_readonly_table(self):
        self.memory_epochs = True
        self.seal_image = True
        self.test_bounded_and_scanned_jump_tables()

    def test_sealed_image_refuses_overlapping_mapping(self):
        self.memory_epochs = True
        self.seal_image = True
        for operation in ('mmap', 'munmap'):
            body = PRELUDE + 'anchor:\nlea rdi, [rip + anchor]\nand rdi, -16384\nmov esi, 16384\n'
            if operation == 'mmap':
                body += 'mov edx, 3\nmov ecx, 50\nmov r8, -1\nxor r9d, r9d\n'
            body += f'call qword ptr [rip + {operation}_slot]\nxor edi, edi\n' + EXIT
            binary, _ = self.program(body, imports=('exit', operation))
            result = self.run_binary(binary)
            self.assertEqual(result.returncode, 127)
            self.assertIn(b'lifetime-qualified guest image', result.stderr)

    def test_provider_conversions(self):
        binary = self.directory / 'provider_checks'
        native = guest_lab.NATIVE
        sources = [str(guest_lab.ROOT / 'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp'), str(native / 'NativeAotGuest.cpp'), *map(str, sorted(native.glob('NativeAotGlibc*.cpp')))]
        guest_lab.run(['xcrun', 'clang++', '-std=c++20', '-O1', '-arch', 'arm64', f'-I{guest_lab.ROOT / "core/libs"}',
                       str(Path(__file__).parent / 'guest_provider_checks.cpp'), *sources, '-o', str(binary)])
        result = self.run_binary(binary)
        self.assertEqual((result.returncode, result.stdout), (0, b'ok\n'), result.stdout)

    def test_provider_conversions_optimized(self):
        binary = self.directory / 'provider_checks'
        native = guest_lab.NATIVE
        sources = [str(native / 'NativeAotGuest.cpp'), *map(str, sorted(native.glob('NativeAotGlibc*.cpp')))]
        guest_lab.run(['xcrun', 'clang++', '-std=c++20', '-O3', '-flto=thin', '-arch', 'arm64', f'-I{guest_lab.ROOT / "core/libs"}',
                       str(Path(__file__).parent / 'guest_provider_checks.cpp'), *sources, '-o', str(binary)])
        result = self.run_binary(binary)
        self.assertEqual((result.returncode, result.stdout), (0, b'ok\n'), result.stdout)

    def test_flags_read_after_call_are_rejected(self):
        with self.assertRaisesRegex(guest_lift.LiftError, 'read after the call'):
            self.program(PRELUDE + '''
    call helper
    je zero
    mov edi, 1
''' + EXIT + '''
zero:
    xor edi, edi
''' + EXIT + '''
helper:
    test edi, edi
    ret
''')

    def test_flags_read_at_entry_are_rejected(self):
        with self.assertRaisesRegex(guest_lift.LiftError, 'read before definition at unit entry'):
            self.program('''
.globl _start
_start:
    setb al
    movzx edi, al
''' + EXIT)

    def test_unimplemented_instruction_rejects_conversion(self):
        with self.assertRaisesRegex(guest_lift.LiftError, 'unsupported instruction'):
            self.program(PRELUDE + '''
    vaddps ymm0, ymm1, ymm2
    xor edi, edi
''' + EXIT)


if __name__ == '__main__':
    unittest.main()

import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import guest_lab


class EpochCallTests(unittest.TestCase):
    def execute(self, body, stub='jmp qword ptr [rip + strlen_slot]', writable=False, launcher=None, relative=(), concurrent=True, optimize_calls=False, seal_image=False):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = '''.globl _start
_start:
    and rsp, -16
    mov r12, rsp
''' + body + '''
    xor edi, edi
    call qword ptr [rip + exit_slot]
fail:
    mov edi, 71
    call qword ptr [rip + exit_slot]
stub:
''' + stub + '''
copy_stub:
    jmp qword ptr [rip + memcpy_slot]
free_stub:
    jmp qword ptr [rip + free_slot]
.p2align 3
strlen_slot: .quad 0
memcpy_slot: .quad 0
free_slot: .quad 0
new_target: .quad 0
exit_slot: .quad 0
text: .asciz "abcd"
'''
            code, labels = guest_lab.assemble_program(source, directory)
            raw = bytearray(guest_lab.program_image(code, labels, [('strlen', 'strlen_slot'), ('memcpy', 'memcpy_slot'), ('free', 'free_slot'), ('exit', 'exit_slot')], relative=relative))
            if writable:
                struct.pack_into('<I', raw, 68, 7)
            binary, report = guest_lab.build_program(raw, directory, concurrent=concurrent, memory_epochs=not optimize_calls, optimize_calls=optimize_calls, seal_image=seal_image, launcher=launcher)
            result = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_single_thread_qualified_calls(self):
        self.execute("""
    mov r13, 789
    lea rdi, [rip + text]
    call stub
    cmp rax, 4
    jne fail
    cmp r13, 789
    jne fail
    cmp rsp, r12
    jne fail
""", concurrent=False, optimize_calls=True)

    def test_conditional_tail_import_commits_live_state(self):
        self.execute('''
    lea rdi, [rip + text]
    call stub
    call helper
    cmp rax, 4
    jne fail
    cmp r13, 918
    jne fail
    cmp rsp, r12
    jne fail
    jmp checked
helper:
    mov r13, 918
    test rdi, rdi
    jne stub
    ret
checked:
''')

    def test_exact_thunk_preserves_caller_state_and_result(self):
        self.execute('''
    mov r13, 123
    mov r14, 456
    lea rdi, [rip + text]
    call stub
    cmp rax, 4
    jne fail
    cmp r13, 123
    jne fail
    cmp r14, 456
    jne fail
    cmp rsp, r12
    jne fail
''')

    def test_slot_is_read_after_pushing_the_return_address(self):
        self.execute('''
    mov rax, 4660
    lea rdi, [rip + text]
    lea rsp, [rip + strlen_slot + 8]
    call stub
back:
    mov rsp, r12
    cmp rax, 4660
    jne fail
    lea rax, [rip + back]
    cmp qword ptr [rip + strlen_slot], rax
    jne fail
''', writable=True)

    def test_nontrivial_thunk_keeps_its_side_effect(self):
        self.execute('''
    mov r13, 5
    lea rdi, [rip + text]
    call stub
    cmp rax, 4
    jne fail
    cmp r13, 6
    jne fail
''', stub='inc r13\njmp qword ptr [rip + strlen_slot]')
    def test_fast_provider_reads_the_post_call_return_address(self):
        self.execute(''' 
    xor eax, eax
    test eax, eax
    jne other
    lea rdi, [rsp - 8]
    lea rsi, [rip + new_target]
    mov edx, 8
    call copy_stub
    jmp fail
other:
    lea rdi, [rip + text]
    call stub
success:
''', relative=(('new_target', 'success'),))

    def test_free_preserves_unspecified_guest_return_register(self):
        self.execute('''
    mov rax, 4660
    xor edi, edi
    call free_stub
    cmp rax, 4660
    jne fail
''')

    def test_replacement_binding_invalidates_the_fast_contract(self):
        launcher = r'''#include "native/NativeAotGuest.hpp"
#include "native/NativeAotGlibc.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
extern char** environ;
void Replacement(NativeAotGuestState& state) { NativeAotGuest::Return(state, 99); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding replacement{"strlen", Replacement, nullptr};
    NativeAotGuest::RegisterProviders(&replacement, 1);
    NativeAotGlibc::Register();
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, environ);
}
'''
        self.execute('''
    lea rdi, [rip + text]
    call stub
    cmp rax, 99
    jne fail
''', launcher=launcher)
    def test_sealed_calls_reject_an_incompatible_provider(self):
        launcher = r'''#include "native/NativeAotGuest.hpp"
#include "native/NativeAotGlibc.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
extern char** environ;
void Replacement(NativeAotGuestState& state) { NativeAotGuest::Return(state, 99); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding replacement{"strlen", Replacement, nullptr, false, true};
    NativeAotGuest::RegisterProviders(&replacement, 1);
    NativeAotGlibc::Register();
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, environ);
}
'''
        self.execute("""
    lea rdi, [rip + text]
    call stub
    cmp rax, 99
    jne fail
""", launcher=launcher, seal_image=True)

    def test_changed_import_slot_rechecks_target(self):
        launcher = r'''#include "native/NativeAotGuest.hpp"
#include "native/NativeAotGlibc.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
extern char** environ;
void Replacement(NativeAotGuestState& state) { NativeAotGuest::Return(state, 99); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding replacement{"free", Replacement, nullptr};
    NativeAotGuest::RegisterProviders(&replacement, 1);
    NativeAotGlibc::Register();
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, environ);
}
'''
        self.execute("""
    lea rdi, [rip + text]
    call stub
    cmp rax, 4
    jne fail
    lea rdi, [rip + text]
    call stub
    cmp rax, 4
    jne fail
    mov rax, qword ptr [rip + free_slot]
    mov qword ptr [rip + strlen_slot], rax
    lea rdi, [rip + text]
    call stub
    cmp rax, 99
    jne fail
""", writable=True, launcher=launcher)

    def test_qualified_free_rechecks_a_rewritten_slot(self):
        self.execute('''
    mov eax, 117
    xor edi, edi
    call free_stub
    cmp rax, 117
    jne fail
    mov rax, qword ptr [rip + strlen_slot]
    mov qword ptr [rip + free_slot], rax
    lea rdi, [rip + text]
    call free_stub
    cmp rax, 4
    jne fail
''', writable=True)

    def test_qualified_free_does_not_bypass_a_replacement_provider(self):
        launcher = r'''#include "native/NativeAotGuest.hpp"
#include "native/NativeAotGlibc.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
extern char** environ;
void Replacement(NativeAotGuestState& state) { NativeAotGuest::Return(state, 73); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding replacement{"free", Replacement, nullptr};
    NativeAotGuest::RegisterProviders(&replacement, 1);
    NativeAotGlibc::Register();
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, environ);
}
'''
        self.execute('''
    xor edi, edi
    call free_stub
    cmp rax, 73
    jne fail
''', launcher=launcher)

    def dense_mutable_table(self, seal_image):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = '''.globl _start
_start:
    and rsp, -16
    lea rax, [rip + case3]
    lea rdx, [rip + table]
    sub rax, rdx
    mov dword ptr [rip + table + 4], eax
    mov eax, 1
    cmp eax, 3
    ja fail
    lea rcx, [rip + table]
    movsxd rax, dword ptr [rcx + 4*rax]
    add rax, rcx
    jmp rax
case0:
    mov edi, 10
    jmp finish
case1:
    mov edi, 11
    jmp finish
case2:
    mov edi, 12
    jmp finish
case3:
    mov edi, 13
    jmp finish
fail:
    mov edi, 99
finish:
    call qword ptr [rip + exit_slot]
.p2align 2
table:
    .long case0 - table
    .long case1 - table
    .long case2 - table
    .long case3 - table
.p2align 3
exit_slot: .quad 0
'''
            code, labels = guest_lab.assemble_program(source, directory)
            raw = bytearray(guest_lab.program_image(code, labels, [('exit', 'exit_slot')]))
            struct.pack_into('<H', raw, 56, 4)
            struct.pack_into('<IIQQQQQQ', raw, 232, 1, 6, 0x3000, 0x3000, 0x3000, 256, 256, 4096)
            binary, report = guest_lab.build_program(raw, directory, concurrent=True, memory_epochs=True, seal_image=seal_image)
            self.assertEqual(report["sealed_dispatch_tables"], 0)
            self.assertEqual(report['jump_tables']['qualified'], 1)
            result = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 13, result.stderr)
    def test_dense_dispatch_rechecks_target_when_readonly_segment_shares_writable_page(self):
        self.dense_mutable_table(False)

    def test_sealed_profile_does_not_misclassify_a_writable_page(self):
        self.dense_mutable_table(True)


if __name__ == '__main__':
    unittest.main()

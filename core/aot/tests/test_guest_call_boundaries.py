import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import guest_lab


class CallBoundaryTests(unittest.TestCase):
    def run_program(self, source, launcher=None):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            code, labels = guest_lab.assemble_program(source, folder)
            raw = bytearray(guest_lab.program_image(code, labels, [('pthread_once', 'once_slot'), ('exit', 'exit_slot')]))
            struct.pack_into('<I', raw, 68, 7)
            binary, _ = guest_lab.build_program(raw, folder, concurrent=True, memory_epochs=True, launcher=launcher)
            result = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_once_initialization_then_native_completion_preserves_live_values(self):
        self.run_program('''.globl _start
_start:
    and rsp, -16
    mov r13, 4660
    lea rdi, [rip + control]
    lea rsi, [rip + initialize]
    call qword ptr [rip + once_slot]
    test eax, eax
    jne fail
    cmp qword ptr [rip + observed], 4660
    jne fail
    cmp r10, 456
    jne fail
    mov r10, 789
    lea rdi, [rip + control]
    lea rsi, [rip + initialize]
    call qword ptr [rip + once_slot]
    test eax, eax
    jne fail
    cmp r10, 789
    jne fail
    cmp dword ptr [rip + count], 1
    jne fail
    xor edi, edi
    call qword ptr [rip + exit_slot]
fail:
    mov edi, 77
    call qword ptr [rip + exit_slot]
initialize:
    mov qword ptr [rip + observed], r13
    inc dword ptr [rip + count]
    mov r10, 456
    ret
.p2align 3
once_slot: .quad 0
exit_slot: .quad 0
observed: .quad 0
control: .long 0
count: .long 0
''')

    def test_replaced_once_does_not_read_an_unqualified_control_pointer(self):
        launcher = '''#include "native/NativeAotGuest.hpp"
#include "native/NativeAotGlibc.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
extern char** environ;
void Replacement(NativeAotGuestState& state) { NativeAotGuest::Return(state, 17); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding binding{"pthread_once", Replacement, nullptr};
    NativeAotGuest::RegisterProviders(&binding, 1);
    NativeAotGlibc::Register();
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, environ);
}
'''
        self.run_program('''.globl _start
_start:
    and rsp, -16
    xor edi, edi
    xor esi, esi
    call qword ptr [rip + once_slot]
    cmp rax, 17
    jne fail
    xor edi, edi
    call qword ptr [rip + exit_slot]
fail:
    mov edi, 78
    call qword ptr [rip + exit_slot]
.p2align 3
once_slot: .quad 0
exit_slot: .quad 0
''', launcher)


if __name__ == '__main__':
    unittest.main()

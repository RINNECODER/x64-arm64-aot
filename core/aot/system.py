"""System instruction lowering (Phase 2 lifter slice 3): cpuid, xgetbv, rdtsc.

CPUID reports the same Zen 2 feature set the Rosetta direct path ORs into the host
CPUID (`core/relinker/codegen/include/codegen/x86/RosettaCpuid.hpp`): leaf 1 ECX FMA,
MOVBE, XSAVE, OSXSAVE, AVX, F16C, RDRAND; leaf 7 EBX BMI1, AVX2, BMI2; extended leaf 1
ECX LZCNT. XGETBV(0) returns x87|SSE|AVX. RDTSC is a monotonic counter.
"""
from capstone.x86 import X86_OP_REG

OPERATIONS = {'cpuid', 'xgetbv', 'rdtsc', 'pause', 'monitorx', 'mwaitx'}

LEAF1_ECX = (1 << 12) | (1 << 22) | (1 << 26) | (1 << 27) | (1 << 28) | (1 << 29) | (1 << 30)
LEAF7_EBX = (1 << 3) | (1 << 5) | (1 << 8)
EXTENDED_LEAF1_ECX = 1 << 5
LEAF1_EDX = 0x078bfbff
LEAF1_EAX = 0x000306f2
MAX_STANDARD_LEAF = 0x10
MAX_EXTENDED_LEAF = 0x80000008
XCR0 = 0x7


def analyze(function, ins, state):
    op = ins.mnemonic
    if op not in OPERATIONS:
        return False
    if op in ('pause', 'monitorx', 'mwaitx'):
        # A spin-loop hint (and its monitored-range wait) with no architectural state effect.
        return True
    if op == 'cpuid':
        function.check_register(ins, state, 'rax', 32)
        function.check_register(ins, state, 'rcx', 32)
        for name in ('rax', 'rbx', 'rcx', 'rdx'):
            state['known'][name] = (1 << 64) - 1
            state['pointers'].pop(name, None)
    elif op == 'xgetbv':
        function.check_register(ins, state, 'rcx', 32)
        for name in ('rax', 'rdx'):
            state['known'][name] = (1 << 64) - 1
            state['pointers'].pop(name, None)
    else:
        for name in ('rax', 'rdx'):
            state['known'][name] = (1 << 64) - 1
            state['pointers'].pop(name, None)
    return True


def lower(function, ins):
    op = ins.mnemonic
    if op not in OPERATIONS:
        return False
    if op in ('pause', 'monitorx', 'mwaitx'):
        return True
    if op == 'cpuid':
        leaf = function.load('rax', 32)
        registers = {'eax': '0', 'ebx': '0', 'ecx': '0', 'edx': '0'}
        leaves = [
            (0, {'eax': MAX_STANDARD_LEAF}),
            (1, {'eax': LEAF1_EAX, 'ecx': LEAF1_ECX, 'edx': LEAF1_EDX}),
            (7, {'ebx': LEAF7_EBX}),
            (0x80000000, {'eax': MAX_EXTENDED_LEAF}),
            (0x80000001, {'ecx': EXTENDED_LEAF1_ECX}),
        ]
        for value, fields in leaves:
            match = function.emit(f'icmp eq i32 {leaf}, {value}')
            for name in ('eax', 'ebx', 'ecx', 'edx'):
                if name in fields:
                    registers[name] = function.emit(f'select i1 {match}, i32 {fields[name]}, i32 {registers[name]}')
        for name, value in registers.items():
            function.store({'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx'}[name], value, 32)
        return True
    if op == 'xgetbv':
        function.check_register(ins, function.states[ins.address], 'rcx', 32)
        function.store('rax', str(XCR0), 32)
        function.store('rdx', '0', 32)
        return True
    counter = function.emit('call i64 @llvm.readcyclecounter()')
    low = function.emit(f'trunc i64 {counter} to i32')
    high = function.emit(f'lshr i64 {counter}, 32')
    high = function.emit(f'trunc i64 {high} to i32')
    function.store('rax', low, 32)
    function.store('rdx', high, 32)
    return True

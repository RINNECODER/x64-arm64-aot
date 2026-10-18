import ctypes
import io
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from elftools.elf.elffile import ELFFile

import system
from test_integer import Harness


class SystemHarness(Harness):
    def finish(self, instruction):
        system.lower(self, instruction)
        for index, name in enumerate(('rax', 'rbx', 'rcx', 'rdx')):
            address = self.emit(f'getelementptr i64, ptr %output, i64 {index}')
            self.lines.append(f'  store i64 {self.load(name)}, ptr {address}, align 8')
        self.lines.extend(['  ret void', '}'])
        return '\n'.join(self.lines)


class SystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='anyps5-system-')
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

    def execute(self, assembly, rax=0, rcx=0):
        ins, stem = self.assemble(assembly)
        harness = SystemHarness(ins)
        state = harness.states[ins.address]
        self.assertTrue(system.analyze(harness, ins, state))
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
        output = (ctypes.c_uint64 * 4)()
        function(rax, 0, rcx, 0, 0, 0, output)
        return [value & 0xffffffff for value in output]

    def test_cpuid_reports_the_rosetta_feature_set(self):
        for leaf, index, expected in [(1, 2, system.LEAF1_ECX), (1, 3, system.LEAF1_EDX),
                                      (7, 1, system.LEAF7_EBX), (0x80000001, 2, system.EXTENDED_LEAF1_ECX)]:
            registers = self.execute('cpuid', rax=leaf)
            self.assertEqual(registers[index], expected, (hex(leaf), index))
        self.assertEqual(self.execute('cpuid', rax=0)[0], system.MAX_STANDARD_LEAF)
        self.assertEqual(self.execute('cpuid', rax=0x80000000)[0], system.MAX_EXTENDED_LEAF)

    def test_xgetbv_reports_xcr0(self):
        registers = self.execute('xgetbv', rcx=0)
        self.assertEqual(registers[0] | (registers[3] << 32), system.XCR0)

    def test_rdtsc_is_monotonic(self):
        first = self.execute('rdtsc')
        second = self.execute('rdtsc')
        value = lambda registers: registers[0] | (registers[3] << 32)
        self.assertGreaterEqual(value(second), value(first))

    def test_pause_is_a_hint_with_no_state_effect(self):
        # `pause` is a spin-loop hint: it must leave every register the harness checks untouched.
        registers = self.execute('pause', rax=0x1234, rcx=0x5678)
        self.assertEqual(registers[0], 0x1234)
        self.assertEqual(registers[2], 0x5678)

    def test_monitorx_is_a_hint_with_no_state_effect(self):
        # `monitorx` only sets up a monitored range for `mwaitx`: it changes no architectural state.
        registers = self.execute('monitorx', rax=0x1234, rcx=0x5678)
        self.assertEqual(registers[0], 0x1234)
        self.assertEqual(registers[2], 0x5678)

    def test_mwaitx_is_a_hint_with_no_state_effect(self):
        # `mwaitx` waits for a monitored write or a timeout; it changes no architectural state.
        registers = self.execute('mwaitx', rax=0x1234, rcx=0x5678)
        self.assertEqual(registers[0], 0x1234)
        self.assertEqual(registers[2], 0x5678)

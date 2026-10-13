import ctypes
import subprocess
import unittest
from pathlib import Path

from compiler import Image, compile_image
from test_uniform import RegisterFile, fixture, uniform_function


class TLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        cls.temporary = tempfile.TemporaryDirectory(prefix='anyps5-tls-')
        cls.directory = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)

    def test_fs_access_reads_the_runtime_tls_block(self):
        code = bytes.fromhex('64488b042510000000c3')  # mov rax, fs:[0x10] ; ret
        raw, contracts = fixture(code, [uniform_function('sub_1000', 0x1000, len(code))])
        elf = self.directory / 'input.elf'
        elf.write_bytes(raw)
        ir, report = compile_image(Image(elf, contracts))
        self.assertIn('@NativeAotTlsBase_nid_no_patch', ir)
        self.assertIn('getelementptr i8, ptr', ir)
        ll = self.directory / 'tls.ll'
        ll.write_text(ir)
        provider = self.directory / 'provider.c'
        provider.write_text('#include <stdint.h>\n'
                            'static uint8_t block[0x1000] = { [0x10] = 0x34, [0x11] = 0x12 };\n'
                            'void* NativeAotTlsBase_nid_no_patch(void) { return block; }\n')
        binary = self.directory / 'tls.dylib'
        result = subprocess.run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-dynamiclib', str(ll), str(provider), '-o', str(binary)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        library = ctypes.CDLL(str(binary))
        function = library.sub_1000
        function.restype = None
        function.argtypes = [ctypes.POINTER(RegisterFile)]
        registers = RegisterFile()
        function(ctypes.byref(registers))
        self.assertEqual(registers.gpr[0], 0x1234)

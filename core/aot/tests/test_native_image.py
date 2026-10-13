import hashlib
import struct
import subprocess
import unittest
from pathlib import Path

import test_compiler
from compiler import Image, Rejected, compile_image
from toolchain import build_native_object


class NativeImageTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp

    def fixture(self, callback=False, result='void', relocations=None):
        pairs = [[0x2638, 0x2640], [0x2670, 0x2680]] if relocations is None else relocations
        if callback:
            pairs = pairs + [[0x2690, 0x1000]]
        raw, contracts = test_compiler.fixture(bytes.fromhex('31c0c3') if result != 'void' else b'\xc3', result=result, relocations=pairs)
        raw = bytearray(raw)
        struct.pack_into('<H', raw, 56, 4)
        struct.pack_into('<IIQQQQQQ', raw, 232, 0x61000001, 4, 0x2600, 0x2600, 0, 0x40, 0x40, 8)
        struct.pack_into('<Q', raw, 0x2600, 0x40)
        struct.pack_into('<I', raw, 0x2608, 0x4942524f)
        struct.pack_into('<Q', raw, 0x2640, 0x38)
        struct.pack_into('<QQ', raw, 0x2680, 0x78, 2)
        contracts['native_runtime_registration'] = True
        return raw, contracts

    def compile_ir(self, raw, contracts):
        contracts = dict(contracts, sha256=hashlib.sha256(raw).hexdigest())
        source = self.directory / 'image.elf'
        source.write_bytes(raw)
        return compile_image(Image(source, contracts))

    def test_registered_process_metadata_is_relocated_before_runtime_use(self):
        raw, contracts = self.fixture(callback=True)
        ir, report = self.compile_ir(raw, contracts)
        self.assertEqual(report['native_image']['process_parameters'], 0x2600)
        self.assertEqual(report['native_image']['allocator_callbacks'][0], 'test_entry')
        obj = self.directory / 'module.o'
        build_native_object(ir, obj)
        main = self.directory / 'main.cpp'
        main.write_text('#include "prx/libc/include/ApplicationHeap.hpp"\n#include <cstdint>\n#include <cstring>\n#include <sys/sysctl.h>\nextern "C" void test_entry();\nint main() { int translated=0; std::size_t size=sizeof(translated); if (sysctlbyname("sysctl.proc_translated", &translated, &size, nullptr, 0)==0 && translated) return 1; const auto* process=static_cast<const unsigned char*>(ApplicationProcessParameters_nid_no_patch()); std::uint32_t magic; std::memcpy(&magic,process+8,4); if(magic!=0x4942524f) return 2; const unsigned char* libc; std::memcpy(&libc,process+0x38,8); const unsigned char* replacement; std::memcpy(&replacement,libc+0x30,8); void(*callback)(); std::memcpy(&callback,replacement+0x10,8); if(callback!=test_entry) return 3; callback(); return 0; }\n')
        root = Path(__file__).resolve().parents[3]
        binary = self.directory / 'native-image'
        subprocess.run(['xcrun', 'clang++', '-arch', 'arm64', '-std=c++20', '-O2', '-I', str(root/'core/libs'), str(main), str(obj), str(root/'core/libs/native/NativeAotImage.cpp'), '-o', str(binary)], check=True, capture_output=True)
        self.assertEqual(subprocess.check_output(['xcrun', 'lipo', '-archs', str(binary)], text=True).strip(), 'arm64')
        subprocess.run([str(binary)], check=True, capture_output=True)

    def test_missing_or_duplicate_process_descriptor_rejects(self):
        for count in (3, 5):
            with self.subTest(count=count):
                raw, contracts = self.fixture()
                struct.pack_into('<H', raw, 56, count)
                if count == 5:
                    raw[288:344] = raw[232:288]
                with self.assertRaisesRegex(Rejected, 'exactly one process-parameters'):
                    self.compile_ir(raw, contracts)

    def test_metadata_pointers_require_relative_data_relocations(self):
        for pairs in ([], [[0x2638, 0x2640]], [[0x2638, 0x1000], [0x2670, 0x2680]]):
            with self.subTest(pairs=pairs):
                with self.assertRaisesRegex(Rejected, 'metadata pointer'):
                    self.compile_ir(*self.fixture(relocations=pairs))

    def test_metadata_sizes_magic_and_version_reject(self):
        for address, value in ((0x2600, 0x30), (0x2608, 0), (0x2640, (1 << 64)-1), (0x2680, 0x70), (0x2688, 3)):
            with self.subTest(address=address, value=value):
                raw, contracts = self.fixture()
                struct.pack_into('<Q', raw, address, value)
                with self.assertRaises(Rejected):
                    self.compile_ir(raw, contracts)

    def test_allocator_callback_requires_matching_native_abi(self):
        with self.assertRaisesRegex(Rejected, 'callback native ABI mismatch'):
            self.compile_ir(*self.fixture(callback=True, result='i64'))

    def test_literal_callback_and_incomplete_allocator_table_reject(self):
        raw, contracts = self.fixture()
        struct.pack_into('<Q', raw, 0x2690, 0x1000)
        with self.assertRaisesRegex(Rejected, 'callback lacks a native code relocation'):
            self.compile_ir(raw, contracts)
        raw, contracts = self.fixture(relocations=[[0x2638, 0x2640], [0x2670, 0x2680], [0x26a0, 0x1000]], result='ptr')
        contracts['functions'][0]['parameters'] = ['u64']
        with self.assertRaisesRegex(Rejected, 'allocator API replacement is incomplete'):
            self.compile_ir(raw, contracts)

    def test_registration_flag_must_be_boolean(self):
        raw, contracts = self.fixture()
        contracts['native_runtime_registration'] = 1
        with self.assertRaisesRegex(Rejected, 'must be a boolean'):
            self.compile_ir(raw, contracts)


if __name__ == '__main__':
    unittest.main()

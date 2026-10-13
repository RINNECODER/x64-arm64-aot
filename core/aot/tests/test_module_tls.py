import hashlib
import struct
import subprocess
import unittest
from pathlib import Path

from compiler import Image, Rejected, compile_image
import test_effects
from toolchain import build_native_object


class ModuleTlsTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    fixture = test_effects.CallEffectsTests.fixture

    def tls_fixture(self, arbitrary=False):
        begin = '' if arbitrary else 'lea rdi, [rip+image_other]\n'
        code = begin + 'sub rsp,8\ncall [rip+image_cell]\nadd rsp,8\nmov ecx,[rax]\nadd ecx,1\nmov [rax],ecx\nmov eax,ecx\nret'
        imports = {'tlsResolver': {'name': 'Aps5GuestTlsGetAddr_nid_no_patch', 'parameters': ['ptr'], 'result': 'ptr',
                                  'tls_resolver': True, 'memory_effects': {'writes': [], 'callbacks': False,
                                    'evidence': 'Qualified TLS resolver writes only its newly allocated thread-local block'}}}
        raw, contract = self.fixture([('test_entry', code, ['ptr'] if arbitrary else [], 'u32')], imports=imports)
        raw = bytearray(raw)
        struct.pack_into('<H', raw, 56, 4)
        struct.pack_into('<IIQQQQQQ', raw, 232, 7, 4, 0x2800, 0x2800, 0, 4, 8, 4)
        struct.pack_into('<I', raw, 0x2800, 7)
        struct.pack_into('<QQq', raw, 0x2380, 0x2010, 16, 0)
        for offset in range(0x2400, 0x2500, 16):
            if struct.unpack_from('<q', raw, offset)[0] == 8:
                struct.pack_into('<Q', raw, offset + 8, 24)
        contract.update(module_image=True, native_namespace='probe_', tls_model='general-dynamic',
                        immutable_data=[{'address': 0x2000, 'evidence': 'Fixture image data is immutable after native binding'}])
        return raw, contract

    def image(self, raw, contract):
        path = self.directory / 'input.elf'
        path.write_bytes(raw)
        return Image(path, dict(contract, sha256=hashlib.sha256(raw).hexdigest()))

    def test_native_general_dynamic_template_and_thread_isolation(self):
        image = self.image(*self.tls_fixture())
        ir, report = compile_image(image)
        obj, source, binary = self.directory/'module.o', self.directory/'main.cpp', self.directory/'native'
        build_native_object(ir, obj)
        source.write_text('''#include "prx/libkernel/Pthread/include/GuestTlsMacOs.hpp"
#include <thread>
#include <pthread.h>
extern "C" unsigned test_entry();
extern "C" GuestTlsDescriptor probe_tls_descriptor;
int main() {
 if(test_entry()!=8 || test_entry()!=9) return 1;
 unsigned result=0;
 std::thread thread([&]{result=test_entry();}); thread.join();
 if(result!=8 || test_entry()!=10) return 2;
 GuestTlsIndex zero{&probe_tls_descriptor,4};
 if(*static_cast<unsigned*>(Aps5GuestTlsGetAddr_nid_no_patch(&zero))!=0) return 3;
 Aps5GuestTlsReleaseCurrentThread_nid_no_patch(&probe_tls_descriptor);
 if(pthread_getspecific(static_cast<pthread_key_t>(probe_tls_descriptor.key))!=nullptr) return 4;
 return 0;
}
''')
        root = Path(__file__).resolve().parents[3]
        subprocess.run(['xcrun', 'clang++', '-arch', 'arm64', '-std=c++20', '-O2', '-I', str(root/'core/libs'),
                        str(source), str(obj), str(root/'core/libs/native/NativeAotReadonly.cpp'),
                        str(root/'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp'), '-o', str(binary)], check=True, capture_output=True)
        subprocess.run([str(binary)], check=True, capture_output=True)
        self.assertEqual(report['tls']['initialized'], 4)
        self.assertEqual(report['tls']['bytes'], 8)
        self.assertEqual(report['tls_indexes'], [0x2010])

    def test_unqualified_profile_mutable_index_and_arbitrary_argument_reject(self):
        raw, contract = self.tls_fixture()
        contract.pop('tls_model')
        with self.assertRaisesRegex(Rejected, 'qualified general-dynamic'):
            self.image(raw, contract)
        raw, contract = self.tls_fixture()
        contract.pop('immutable_data')
        with self.assertRaisesRegex(Rejected, 'immutable'):
            self.image(raw, contract)
        with self.assertRaisesRegex(Rejected, 'resolver argument'):
            compile_image(self.image(*self.tls_fixture(True)))

    def test_layout_and_offset_boundaries_reject(self):
        for offset, value, error in ((232+32, 9, 'template extent'), (232+48, 3, 'alignment'), (0x2018, 8, 'offset outside')):
            raw, contract = self.tls_fixture()
            struct.pack_into('<Q', raw, offset, value)
            with self.subTest(offset=offset), self.assertRaisesRegex(Rejected, error):
                self.image(raw, contract)

    def test_initial_exec_is_not_silently_accepted(self):
        raw, contract = self.tls_fixture()
        struct.pack_into('<Q', raw, 0x2380 + 8, 18)
        with self.assertRaisesRegex(Rejected, 'initial-exec'):
            self.image(raw, contract)

    def test_resolver_signature_is_checked(self):
        raw, contract = self.tls_fixture()
        contract['imports']['tlsResolver']['result'] = 'u64'
        with self.assertRaisesRegex(Rejected, 'resolver ABI'):
            self.image(raw, contract)


if __name__ == '__main__':
    unittest.main()

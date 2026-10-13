import hashlib
import struct
import subprocess
import unittest
from pathlib import Path

import test_effects
from compiler import Image, Rejected, compile_image
from toolchain import build_native_object


class ImmutableDataTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    fixture = test_effects.CallEffectsTests.fixture

    def immutable(self, raw, contracts):
        contracts['immutable_data'] = [{'address': 0x2000, 'evidence': 'Fixture data has no permitted writes after native linking'}]
        return raw, contracts

    def compile_ir(self, raw, contracts):
        source = self.directory / 'image.elf'
        source.write_bytes(raw)
        return compile_image(Image(source, dict(contracts, sha256=hashlib.sha256(raw).hexdigest())))

    def build(self, raw, contracts, source):
        ir, report = self.compile_ir(raw, contracts)
        obj, main, binary = self.directory/'module.o', self.directory/'main.cpp', self.directory/'native'
        build_native_object(ir, obj)
        main.write_text(source)
        root = Path(__file__).resolve().parents[3]
        subprocess.run(['xcrun', 'clang++', '-arch', 'arm64', '-std=c++20', '-O2', '-I', str(root/'core/libs'), str(main), str(obj), str(root/'core/libs/native/NativeAotReadonly.cpp'), '-o', str(binary)], check=True, capture_output=True)
        self.assertEqual(subprocess.check_output(['xcrun','lipo','-archs',str(binary)],text=True).strip(),'arm64')
        return binary, ir, report, obj.with_suffix('.optimized.ll').read_text()

    def import_fixture(self):
        return self.fixture([('test_entry','call [rip+image_cell]\ncall [rip+image_cell]\nret',[],'u64')],
                            imports={'nativeNid': {'name':'native_probe','parameters':[],'result':'u64'}})

    def test_static_imports_survive_unknown_calls_and_fold_to_native_symbols(self):
        raw, contracts = self.immutable(*self.import_fixture())
        main = 'extern "C" unsigned long long test_entry(); extern "C" unsigned long long native_probe() { static unsigned long long value=40; return ++value; } int main() { return test_entry()==42?0:1; }\n'
        binary, ir, report, optimized = self.build(raw, contracts, main)
        subprocess.run([str(binary)],check=True,capture_output=True)
        self.assertIn('constant <{ ptr',ir)
        self.assertNotIn('store ptr @native_probe',ir)
        self.assertRegex(optimized,r'\bcall\b[^\n]*@native_probe\(')
        self.assertEqual(report['immutable_data'],contracts['immutable_data'])

    def test_mutable_imports_still_lose_unknown_call_proofs(self):
        with self.assertRaisesRegex(Rejected,'import target has no proven native pointer origin'):
            self.compile_ir(*self.import_fixture())

    def test_relative_pointer_is_initialized_by_native_linker(self):
        raw, contracts = self.immutable(*self.fixture([
            ('test_entry','mov rax, [rip+image_cell]\nmov rax, [rax]\nret',[],'u64')],relocations=[[0x2000,0x2010]]))
        raw=bytearray(raw);struct.pack_into('<Q',raw,0x2010,42)
        main='#include <cstring>\nextern "C" unsigned long long test_entry();\nextern "C" unsigned char data_2000[];\nint main(){ const void* pointer; std::memcpy(&pointer,data_2000,sizeof(pointer)); return pointer==data_2000+16 && test_entry()==42?0:1; }\n'
        binary, ir, _, _ = self.build(raw,contracts,main)
        subprocess.run([str(binary)],check=True,capture_output=True)
        self.assertNotIn('store ptr getelementptr',ir)

    def test_direct_and_callee_writes_to_immutable_data_reject(self):
        cases=[[
            ('test_entry','mov QWORD PTR [rip+image_other], 42\nret',[],'void')],[
            ('test_entry','lea rdi, [rip+image_other]\ncall writer\nret',[],'void'),
            ('writer','mov QWORD PTR [rdi], 42\nret',['ptr'],'void')]]
        for bodies in cases:
            with self.subTest(bodies=bodies):
                with self.assertRaisesRegex(Rejected,'immutable image data'):
                    self.compile_ir(*self.immutable(*self.fixture(bodies)))

    def test_unknown_call_cannot_receive_a_known_immutable_pointer(self):
        raw, contracts = self.immutable(*self.fixture([
            ('test_entry','lea rdi, [rip+image_other]\ncall [rip+image_cell]\nret',[],'void')],
            imports={'nativeNid': {'name':'native_probe','parameters':['ptr'],'result':'void'}}))
        with self.assertRaisesRegex(Rejected,'immutable image pointer passed'):
            self.compile_ir(raw,contracts)

    def test_native_page_protection_stops_opaque_write(self):
        raw, contracts = self.immutable(*self.import_fixture())
        main='#include <csignal>\n#include <cstdlib>\nextern "C" unsigned long long test_entry();\nextern "C" unsigned long long native_probe(){return 42;}\nextern "C" unsigned char data_2000[];\nstatic void stopped(int){std::_Exit(77);}\nint main(){if(test_entry()!=42)return 1;std::signal(SIGSEGV,stopped);std::signal(SIGBUS,stopped);reinterpret_cast<volatile unsigned char*>(data_2000)[0]=0;return 2;}\n'
        binary, _, _, _ = self.build(raw,contracts,main)
        result=subprocess.run([str(binary)],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,77)

    def test_runtime_verification_rejects_writable_memory(self):
        raw, contracts = self.fixture([('test_entry','ret',[],'void')])
        main='#include "prx/libc/include/NativeAotImage.hpp"\n#include <stdexcept>\nint main(){unsigned long value=0;NativeAotDataRange range{&value,sizeof(value)};try{NativeAotRequireReadOnly_nid_no_patch(&range,1);}catch(const std::runtime_error&){return 0;}return 1;}\n'
        binary, _, _, _ = self.build(raw,contracts,main)
        subprocess.run([str(binary)],check=True,capture_output=True)

    def test_invalid_immutable_contract_rejects(self):
        for records in (True,[{'address':0x2008,'evidence':'fixture'}],[{'address':0x2000,'evidence':''}],[{'address':0x2000,'evidence':'fixture'}]*2):
            with self.subTest(records=records):
                raw,contracts=self.import_fixture()
                contracts['immutable_data']=records
                with self.assertRaisesRegex(Rejected,'immutable'):
                    self.compile_ir(raw,contracts)


if __name__ == '__main__':
    unittest.main()

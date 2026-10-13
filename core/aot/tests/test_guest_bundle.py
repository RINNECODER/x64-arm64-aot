import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import guest_emit
import guest_lab


class GuestBundleTests(unittest.TestCase):
    def test_sealed_ranges_exclude_inaccessible_pages(self):
        from guest_regions import immutable_ranges
        self.assertEqual(immutable_ranges([{'vaddr': 0, 'memsz': 16384, 'flags': 0}]), [])
        self.assertEqual(immutable_ranges([{'vaddr': 0, 'memsz': 16384, 'flags': 4}]), [(0, 16384)])

    def test_namespace_changes_only_symbol_tokens(self):
        text = '@__aps5_guest_base = global i64 0\n@label = constant [22 x i8] c"@__aps5_guest_base\\00"\n'
        result = guest_emit.namespace_ir(text, 'module_')
        self.assertIn('@module___aps5_guest_base =', result)
        self.assertIn('c"@__aps5_guest_base\\00"', result)
        with self.assertRaisesRegex(ValueError, 'namespace'):
            guest_emit.namespace_ir(text, '../bad')

    def test_provided_module_precedes_native_provider(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            inputs = []
            for name, source, imports, abi in [
                ('app', '.globl _start\n_start:\nsub rsp, 8\ncall qword ptr [rip + peer_slot]\nmov edi, eax\ncall qword ptr [rip + exit_slot]\n.p2align 3\npeer_slot: .quad 0\nexit_slot: .quad 0\n', [('peer', 'peer_slot'), ('exit', 'exit_slot')], 'sce-app'),
                ('peer', '.globl _start\n_start:\nret\npeer:\nmov eax, 42\nret\n.p2align 3\npeer_slot: .quad 0\n', [('peer', 'peer_slot')], 'sce-module'),
            ]:
                folder = directory / name
                folder.mkdir()
                code, labels = guest_lab.assemble_program(source, folder)
                raw = bytearray(guest_lab.program_image(code, labels, imports))
                if name == 'peer':
                    symbol = guest_lab.DYNAMIC + 0x800 + 24
                    struct.pack_into('<H', raw, symbol + 6, 1)
                    struct.pack_into('<Q', raw, symbol + 8, guest_lab.CODE + labels['peer'])
                input_path = folder / 'input.elf'
                input_path.write_bytes(raw)
                guest_emit.build(input_path, folder / 'ir', shards=1, jobs=1, abi=abi, namespace=name + '_')
                for module in (folder / 'ir').glob('*.ll'):
                    obj = module.with_suffix('.o')
                    guest_lab.run(['xcrun', 'clang', '-O2', '-c', str(module), '-o', str(obj)])
                    inputs.append(str(obj))
            main = directory / 'main.cpp'
            main.write_text('''#include "native/NativeAotGuest.hpp"
#include <cstdlib>
extern "C" const NativeAotGuestImage app___aps5_guest_image;
extern "C" const NativeAotGuestImage peer___aps5_guest_image;
void Exit(NativeAotGuestState& state) { std::_Exit(static_cast<int>(NativeAotGuest::Argument(state, 0))); }
void WrongPeer(NativeAotGuestState& state) { NativeAotGuest::Return(state, 99); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding providers[] = {{"exit", Exit, nullptr}, {"peer", WrongPeer, nullptr}};
    NativeAotGuest::RegisterProviders(providers, 2);
    const NativeAotGuest::ImageBinding images[] = {{&app___aps5_guest_image, NativeAotGuest::Abi::SceApplication},
        {&peer___aps5_guest_image, NativeAotGuest::Abi::SceModule}};
    NativeAotGuest::LoadBundle(images, 0);
    NativeAotGuest::StartSceApplication(app___aps5_guest_image, argc, argv);
}
''')
            binary = directory / 'test'
            guest_lab.run(['xcrun', 'clang++', '-std=c++20', '-O2', f'-I{guest_lab.ROOT / "core/libs"}', str(main),
                           str(guest_lab.NATIVE / 'NativeAotGuest.cpp'), str(guest_lab.ROOT / 'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp'),
                           *inputs, '-o', str(binary)])
            result = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 42, result.stderr)

    def test_address_only_import_is_real_but_not_callable(self):
        launcher = '''#include "native/NativeAotGuest.hpp"
#include <cstdlib>
extern "C" const NativeAotGuestImage __aps5_guest_image;
extern char** environ;
void Exit(NativeAotGuestState& state) { std::_Exit(static_cast<int>(NativeAotGuest::Argument(state, 0))); }
void NativeOnly() { std::_Exit(99); }
int main(int argc, char** argv) {
    const NativeAotGuest::ProviderBinding providers[] = {{"exit", Exit, nullptr},
        {"opaque", nullptr, nullptr, false, false, reinterpret_cast<const void*>(NativeOnly)}};
    NativeAotGuest::RegisterProviders(providers, 2);
    NativeAotGuest::Start(__aps5_guest_image, argc, argv, environ);
}
'''
        for call in (False, True):
            with self.subTest(call=call), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                action = 'call qword ptr [rip + opaque_slot]' if call else 'mov rax, qword ptr [rip + opaque_slot]\ntest rax, rax\nsetz dil'
                source = '.globl _start\n_start:\nand rsp, -16\nxor edi, edi\n' + action + '\ncall qword ptr [rip + exit_slot]\n.p2align 3\nopaque_slot: .quad 0\nexit_slot: .quad 0\n'
                code, labels = guest_lab.assemble_program(source, folder)
                raw = guest_lab.program_image(code, labels, [('opaque', 'opaque_slot'), ('exit', 'exit_slot')])
                binary, _ = guest_lab.build_program(raw, folder, launcher=launcher)
                result = subprocess.run([str(binary)], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 127 if call else 0, result.stderr)
                if call:
                    self.assertIn(b'no qualified call ABI', result.stderr)
    def test_module_tls_descriptor_relocation_and_real_thread_isolation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            objects=[]
            counter=0
            for name,source,imports,abi in [
                ('app','.globl _start\n_start:\nret\n',[],'sce-app'),
                ('tls','.globl _start\n_start:\nsub rsp, 8\nlea rdi, [rip + tls_index]\ncall qword ptr [rip + resolve_slot]\nadd dword ptr [rax], 1\nmov eax, dword ptr [rax]\nadd rsp, 8\nret\n.p2align 3\nresolve_slot: .quad 0\ntls_index: .quad 0\n.quad 4\n',[('resolve','resolve_slot')],'sce-module')]:
                folder=directory/name;folder.mkdir()
                code,labels=guest_lab.assemble_program(source,folder)
                raw=bytearray(guest_lab.program_image(code,labels,imports,
                    relative=[('tls_index','_start')] if name=='tls' else (),
                    tls=(struct.pack('<II',11,19),16,8) if name=='tls' else None))
                if name=='tls':
                    struct.pack_into('<Qq',raw,guest_lab.DYNAMIC+0x1400+8,16,0)
                    counter=guest_lab.CODE+labels['_start']
                path=folder/'input.elf';path.write_bytes(raw)
                guest_emit.build(path,folder/'ir',shards=1,jobs=1,abi=abi,namespace=name+'_')
                for module in (folder/'ir').glob('*.ll'):
                    obj=module.with_suffix('.o');guest_lab.run(['xcrun','clang','-O2','-c',str(module),'-o',str(obj)]);objects.append(str(obj))
            main=directory/'main.cpp'
            main.write_text('''#include "native/NativeAotGuest.hpp"
#include "prx/libkernel/Pthread/include/GuestTlsMacOs.hpp"
#include <thread>
extern "C" const NativeAotGuestImage app___aps5_guest_image;
extern "C" const NativeAotGuestImage tls___aps5_guest_image;
void Resolve(NativeAotGuestState& state) {
    const auto* index=reinterpret_cast<const GuestTlsIndex*>(NativeAotGuest::Argument(state,0));
    NativeAotGuest::Return(state,reinterpret_cast<std::uint64_t>(Aps5GuestTlsGetAddr_nid_no_patch(index)));
}
int main() {
    GuestTlsDescriptor descriptor{};
    const NativeAotGuest::ProviderBinding provider{"resolve",Resolve,nullptr,false,false,reinterpret_cast<const void*>(Aps5GuestTlsGetAddr_nid_no_patch)};
    NativeAotGuest::RegisterProviders(&provider,1);
    const NativeAotGuest::ImageBinding images[]={{&app___aps5_guest_image,NativeAotGuest::Abi::SceApplication},
        {&tls___aps5_guest_image,NativeAotGuest::Abi::SceModule,&descriptor}};
    NativeAotGuest::LoadBundle(images,0);
    auto call=[] {
        NativeAotGuestState state{};
        const auto top=NativeAotGuest::AllocateStack(65536);
        state.Gpr[4]=top;
        const auto result=NativeAotGuest::Invoke(state,*tls___aps5_guest_image.Base + COUNTER);
        NativeAotGuest::FreeStack(top,65536);
        return result;
    };
    if(call()!=20 || call()!=21) return 1;
    std::uint64_t other=0;
    std::thread thread([&] { other=call(); });thread.join();
    if(other!=20 || call()!=22) return 2;
    Aps5GuestTlsReleaseCurrentThread_nid_no_patch(&descriptor);
    return call()==20 ? 0 : 3;
}
'''.replace('COUNTER',str(counter)))
            binary=directory/'test'
            guest_lab.run(['xcrun','clang++','-std=c++20','-O2',f'-I{guest_lab.ROOT/"core/libs"}',str(main),
                str(guest_lab.NATIVE/'NativeAotGuest.cpp'),str(guest_lab.ROOT/'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp'),*objects,'-o',str(binary)])
            result=subprocess.run([str(binary)],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)

    def test_native_provider_exception_restores_call_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary)
            source='.globl _start\n_start:\nsub rsp, 8\ncall qword ptr [rip + throw_slot]\nadd rsp, 8\nret\n.p2align 3\nthrow_slot: .quad 0\n'
            code,labels=guest_lab.assemble_program(source,directory)
            raw=guest_lab.program_image(code,labels,[('throw','throw_slot')])
            launcher='''#include "native/NativeAotGuest.hpp"
#include <stdexcept>
extern "C" const NativeAotGuestImage __aps5_guest_image;
void Throw(NativeAotGuestState&) { throw std::runtime_error("provider failure"); }
int main() {
    const NativeAotGuest::ProviderBinding provider{"throw",Throw,nullptr};
    NativeAotGuest::RegisterProviders(&provider,1);
    const auto base=NativeAotGuest::Load(__aps5_guest_image);
    NativeAotGuestState state{};
    const auto top=NativeAotGuest::AllocateStack(65536);state.Gpr[4]=top;
    try { NativeAotGuest::Invoke(state,base+__aps5_guest_image.EntryPoint); return 1; }
    catch(const std::runtime_error&) {}
    if(state.Gpr[4]!=top) return 2;
    NativeAotGuest::FreeStack(top,65536);
    NativeAotGuest::CurrentState();
    return 3;
}
'''
            binary,_=guest_lab.build_program(raw,directory,launcher=launcher)
            result=subprocess.run([str(binary)],capture_output=True,timeout=10)
            self.assertEqual(result.returncode,127,result.stderr)
            self.assertIn(b'no active guest state',result.stderr)


if __name__ == '__main__':
    unittest.main()

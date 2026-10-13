import argparse
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from bundle import SCHEMA, compile_bundle
from contract_recipe import fact_digest, verify_structured_sources
from debug_candidates import recover_debug_dossier
from dynamic import parse_dynamic
from recover import load_elf, read_address, recover_image


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SHA_REVISION = '3ada439fa044f60c8b488678577a740761385711'
SHA_FILES = {'self_update_sha256.c': 'b2de6512ae23d44518b1330315472078832519181c2fa780cc90b3f08812a870',
             'self_update_sha256.h': 'c86b5fdf45bd6281e5eefebae7b9b183b3daca03e7fe5972ca758ec8db1b1cc3'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(command, cwd):
    result = subprocess.run(list(map(str, command)), cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    require(result.returncode == 0, result.stdout)
    return result.stdout


def host_bindings(folder):
    result = {
        '__tls_get_addr': {'name': 'Aps5GuestTlsGetAddr_nid_no_patch', 'parameters': ['ptr'], 'result': 'ptr', 'tls_resolver': True,
                           'memory_effects': {'writes': [], 'callbacks': False, 'evidence': 'GuestTlsMacOs copies into a newly allocated thread-local block and updates only the host key; it does not mutate guest image data.'}},
        'record_event': {'name': 'record_event', 'parameters': ['u32'], 'result': 'void'},
        'wait_peers': {'name': 'wait_peers', 'parameters': [], 'result': 'void'},
    }
    for name, contract in result.items():
        contract['host_binding_evidence'] = 'Qualified fixture provider ABI for ' + name + '; source identities are recorded in the acceptance receipt.'
    for name, count, output in (('Create', 5, 0), ('Join', 2, 1)):
        result['scePthread' + name] = {'name': 'NativeAotPthread' + name + '_nid_no_patch', 'parameters': ['ptr'] * count, 'result': 'i32',
            'host_binding_evidence': 'Reviewed NativeAotThreads.cpp delegates to the production AnyPS5 provider; default joinable attributes and qualified native callbacks.',
            'pointer_outputs': {'success': 'zero', 'fields': [{'parameter': output, 'offset': 0}],
                                'evidence': 'On success the provider publishes the native thread handle or qualified native callback result.'}}
    catalog = json.loads((ROOT/'core/aot/catalogs/apple-runtime.json').read_text())
    for entry in catalog['entries']:
        if entry['contract']['name'] not in ('memcpy', 'memset', 'strlen'):
            continue
        verify_structured_sources(entry['sources'], ROOT)
        for source in entry['sources']:
            target = folder/source['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT/source['path']).read_bytes())
        contract = copy.deepcopy(entry['contract'])
        contract['host_binding_evidence'] = 'Existing qualified provider catalog entry ' + entry['facts_sha256']
        result[contract['name']] = contract
    return result


def reference_registry():
    lines = ['#include "api.h"', '#include "prx/libc/include/NativeAotBundle.hpp"', '#include <array>', 'namespace {']
    for name, functions in (('counter', ['counter_init', 'counter_fini', 'counter_step', 'counter_zero', 'counter_address']),
                            ('worker', ['worker_init', 'worker_fini', 'worker_fill', 'worker_address']),
                            ('app', ['app_init', 'app_fini', 'app_worker', 'app_run'])):
        lines.append(f'const void* {name}_functions[]{{' + ','.join('reinterpret_cast<const void*>(&'+f+')' for f in functions) + '};')
        lines += [f'const NativeAotLifecycleFunction {name}_initializers[]{{&{name}_init}};',
                  f'const NativeAotLifecycleFunction {name}_finalizers[]{{&{name}_fini}};']
    lines += ['const void* entries[]{reinterpret_cast<const void*>(&app_worker)};',
              'const NativeAotModuleDependency worker_dependencies[]{{0,1}};',
              'const NativeAotModuleDependency app_dependencies[]{{1,1}};',
              'const NativeAotModule modules[]{',
              '{3,"counter",1,nullptr,0,nullptr,0,nullptr,0,counter_functions,5,nullptr,0,counter_initializers,1,counter_finalizers,1,nullptr,0,nullptr,0},',
              '{3,"worker",1,nullptr,0,nullptr,0,worker_dependencies,1,worker_functions,4,nullptr,0,worker_initializers,1,worker_finalizers,1,nullptr,0,nullptr,0},',
              '{3,"app",1,nullptr,0,nullptr,0,app_dependencies,1,app_functions,4,nullptr,0,app_initializers,1,app_finalizers,1,nullptr,0,entries,1}};',
              '}', 'extern "C" NativeAotBundleRegistry* NativeAotCompiledBundle_nid_no_patch(){static NativeAotBundleRegistry registry(modules,2);return &registry;}']
    return '\n'.join(lines) + '\n'


def build(args, folder):
    started = time.monotonic()
    require(run(['git', '-C', args.sha_root, 'rev-parse', 'HEAD'], folder).strip() == SHA_REVISION, 'SHA source revision changed')
    external = args.sha_root/'examples/self-update'
    for name, expected in SHA_FILES.items():
        require(digest(external/name) == expected, 'SHA source changed: ' + name)
    for name in ('api.h', 'counter.c', 'worker.c', 'app.c', 'driver.cpp'):
        shutil.copyfile(HERE/name, folder/name)
    headers = folder/'headers'
    headers.mkdir()
    (headers/'stdint.h').write_text('typedef __UINT32_TYPE__ uint32_t; typedef __UINT64_TYPE__ uint64_t;\n')
    (headers/'stddef.h').write_text('typedef __SIZE_TYPE__ size_t;\n#define NULL ((void*)0)\n')
    (headers/'string.h').write_text('#include <stddef.h>\nvoid *memcpy(void*,const void*,size_t); void *memset(void*,int,size_t); size_t strlen(const char*);\n')
    cc = ['xcrun', 'clang', '--target=x86_64-unknown-freebsd']
    graph = [('counter', None), ('worker', 'counter'), ('app', 'worker')]
    for name, dependency in graph:
        run([*cc, '-nostdinc', '-isystem', headers, '-I', external, '-O1', '-fPIC', '-g', '-gdwarf-4',
             '-fno-omit-frame-pointer', '-ftls-model=global-dynamic', '-c', name+'.c', '-o', name+'.o'], folder)
        arrays = f'.hidden {name}_init\n.hidden {name}_fini\n.section .init_array,"aw",@init_array\n.p2align 3\n.quad {name}_init\n.section .fini_array,"aw",@fini_array\n.p2align 3\n.quad {name}_fini\n'
        (folder/(name+'-arrays.S')).write_text(arrays)
        run([*cc, '-c', name+'-arrays.S', '-o', name+'-arrays.o'], folder)
        objects = [folder/(name+'.o'), folder/(name+'-arrays.o')]
        if args.zig:
            link = [args.zig, 'build-lib', '-dynamic', '-target', 'x86_64-linux-musl', '-fno-compiler-rt',
                    '-fno-each-lib-rpath', '-z', 'now', '-fsoname='+name+'.prx']
            if name == 'app':
                link.append('-fentry=app_run')
            output = ['-femit-bin='+name+'.so']
        else:
            link = [args.ld_lld, '-shared', '--hash-style=sysv', '-z', 'now', '-soname', name+'.prx']
            if name == 'app':
                link += ['-e', 'app_run']
            output = ['-o', name+'.so']
        if dependency:
            objects.append(folder/(dependency+'.so'))
        run([*link, *objects, *output], folder)
    inputs, prototypes = {}, {}
    for name, _ in graph:
        source = folder/(name+'.so')
        recovered = recover_image(source, [])
        dossier = recover_debug_dossier(source)
        _, elf = load_elf(source)
        dynamic = parse_dynamic(elf, lambda address, size: read_address(elf, address, size))
        functions = []
        for row in dossier['functions']:
            require('boundary' in row['facts'] and 'source_abi' in row['facts'], 'ABI/boundary qualification missing: ' + row['symbol'])
            function = {'name': row['symbol'], **row['facts']['boundary'], **row['facts']['source_abi'],
                        'stack_objects': row['facts'].get('fixed_stack_objects', [])}
            functions.append(function)
            prototypes[row['symbol']] = {'name': row['symbol'], **row['facts']['source_abi']}
        inputs[name] = (recovered, dossier, elf, dynamic, functions)
    providers = host_bindings(folder)
    policies = {'checked_pointer_bases': {'bytes': 1, 'evidence': 'Qualified C corpus with valid native object extents and lifetimes.'},
                'checked_pointer_arguments': {'bytes': 1, 'nullable': True, 'evidence': 'Qualified source ABI for {callee}; thread handles are checked by the native adapter.'}}
    modules = []
    for name, dependency in graph:
        recovered, dossier, elf, dynamic, functions = inputs[name]
        imports, data, tls = {}, {}, {}
        for symbol in dynamic['symbols'][1:]:
            if symbol['section']:
                continue
            kind = symbol['info'] & 15
            if kind in (0, 2):
                contract = providers.get(symbol['name']) or prototypes.get(symbol['name'])
                require(contract is not None, 'unqualified function import: ' + symbol['name'])
                imports[symbol['name']] = copy.deepcopy(contract)
            elif kind == 1:
                require(symbol['name'] == 'shared_value', 'unqualified data object')
                data[symbol['name']] = {'name': symbol['name'], 'size': 4, 'evidence': 'api.h shared unsigned object, LP64 C profile.'}
            elif kind == 6:
                require(symbol['name'] == 'counter_tls', 'unqualified TLS import')
                tls[symbol['name']] = {'size': 4, 'evidence': 'api.h declares the same unsigned counter TLS object.'}
            else:
                require(False, 'unsupported import kind')
        contract = {'schema': 1, 'sha256': recovered['sha256'], 'functions': functions, 'imports': imports,
                    'data_imports': data, 'tls_imports': tls, 'data': recovered['data'], 'pointer_relocations': recovered['pointer_relocations']}
        if any(s['p_type'] == 'PT_TLS' and s['p_memsz'] for s in elf.iter_segments()):
            contract['tls_model'] = 'general-dynamic'
        (folder/(name+'.contracts.json')).write_text(json.dumps(contract, indent=2)+'\n')
        sources = [{'path': item, 'sha256': digest(folder/item)} for item in (name+'.c', 'api.h')]
        guards = {'policies': policies, 'facts_sha256': fact_digest(contract, policies), 'sources': sources}
        modules.append({'id': name, 'version': 1, 'input': name+'.so', 'contracts': name+'.contracts.json',
                        'dependencies': {dependency: 1} if dependency else {}, 'guards': guards})
        (folder/(name+'.dossier.json')).write_text(json.dumps(dossier, indent=2)+'\n')
    specification = {'schema': SCHEMA, 'main': 'app', 'modules': modules}
    (folder/'manifest.json').write_text(json.dumps(specification, indent=2)+'\n')
    report = compile_bundle(specification, folder, folder/'native')
    for name, _ in graph:
        run(['xcrun', 'clang', '-arch', 'arm64', '-O2', '-I', external,
             '-DscePthreadCreate=NativeAotPthreadCreate_nid_no_patch', '-DscePthreadJoin=NativeAotPthreadJoin_nid_no_patch',
             '-c', name+'.c', '-o', name+'-reference.o'], folder)
    (folder/'reference-registry.cpp').write_text(reference_registry())
    common = ['xcrun', 'clang++', '-arch', 'arm64', '-std=c++20', '-O2', '-fexperimental-library', '-I', ROOT/'core/libs', '-I', folder]
    for reference in (False, True):
        objects = [folder/(name+'-reference.o') if reference else folder/'native'/(name+'.o') for name, _ in graph]
        registry = folder/'reference-registry.cpp' if reference else folder/'native/registry.cpp'
        run([*common, *(['-DBUNDLE_REFERENCE'] if reference else []), 'driver.cpp', registry, *objects,
             args.runtime, args.image_runtime, '-Wl,-dead_strip', '-framework', 'CoreFoundation', '-o', 'reference' if reference else 'aot'], folder)
    runtime_sources = ('core/libs/native/NativeAotThreads.cpp', 'core/libs/native/NativeAotBundle.cpp',
                       'core/libs/prx/libkernel/Pthread/src/Thread.cpp', 'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp')
    report.update(source_revision=SHA_REVISION, external_hashes=SHA_FILES,
                  runtime_archives={str(args.runtime): digest(args.runtime), str(args.image_runtime): digest(args.image_runtime)},
                  runtime_sources={name: digest(ROOT/name) for name in runtime_sources},
                  source_hashes={name: digest(folder/name) for name in ('api.h', 'counter.c', 'worker.c', 'app.c', 'driver.cpp')},
                  binaries={name: digest(folder/name) for name in ('aot', 'reference')},
                  input_hashes={name: digest(folder/(name+'.so')) for name, _ in graph},
                  compiler=run(['xcrun', 'clang', '--version'], folder).splitlines()[0],
                  elf_linker=run([args.zig, 'version'] if args.zig else [args.ld_lld, '--version'], folder).strip(),
                  build_seconds=time.monotonic()-started,
                  qualification=['Coordinated C declarations, LP64 layouts and standard SysV machine ABI for the recorded compilation profile.',
                                 'Original SHA-256 implementation unchanged; independent native compilation for the reference.',
                                 'Valid source object lifetimes; default joinable threads; shared data written only before start/after join.',
                                 'Static closed startup group and explicit C entry ABI; not the console OS entry convention.'],
                  limitations=['Source-built ELF main image and two ELF modules, not arbitrary Sony PRX or stripped-input qualification.',
                               'No guest C++ EH, dynamic unload, cancel/detach or general atomic/memory-model claim.',
                               'No speedup or port-completion percentage claim.'])
    (folder/'build.json').write_text(json.dumps(report, indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser()
    for name in ('sha-root', 'runtime', 'image-runtime', 'output-parent'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--run', action='store_true')
    linker = parser.add_mutually_exclusive_group(required=True)
    linker.add_argument('--ld-lld', type=Path)
    linker.add_argument('--zig', type=Path)
    args = parser.parse_args()
    for name, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, name, value.resolve())
    args.output_parent.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='module-bundle-', dir=args.output_parent))
    build(args, folder)
    print(folder/'build.json')
    if args.run:
        from verify import verify
        acceptance = verify(folder)
        (folder/'acceptance.json').write_text(json.dumps(acceptance, indent=2)+'\n')
        print(folder/'acceptance.json')


if __name__ == '__main__':
    main()

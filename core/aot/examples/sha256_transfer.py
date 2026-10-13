import argparse
import ctypes
import hashlib
import json
import mmap
import random
import subprocess
import tempfile
import time
from pathlib import Path

from compiler import Image, compile_image
from contract_recipe import SCHEMA, fact_digest, materialize
from debug_candidates import recover_debug_dossier
from dynamic import parse_dynamic
from provider_catalog import resolve_imports
from recover import load_elf, read_address, recover_image
from toolchain import build_native_object
from pad_input.build import PIN, ROOT, require, run, sha


REVISION = '3ada439fa044f60c8b488678577a740761385711'
SOURCES = {'self_update_sha256.c': 'b2de6512ae23d44518b1330315472078832519181c2fa780cc90b3f08812a870',
           'self_update_sha256.h': 'c86b5fdf45bd6281e5eefebae7b9b183b3daca03e7fe5972ca758ec8db1b1cc3'}
EXPORTS = ('start', 'add', 'finish', 'hex', 'matches')


def check_library(path, prefix):
    require(subprocess.check_output(['xcrun', 'lipo', '-archs', path], text=True).strip() == 'arm64', 'non-native library')
    library = ctypes.CDLL(str(path))
    functions = {name: getattr(library, prefix + 'self_update_sha256_' + name) for name in EXPORTS}
    signatures = {'start': [ctypes.c_void_p], 'add': [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t],
                  'finish': [ctypes.c_void_p, ctypes.c_void_p], 'hex': [ctypes.c_void_p, ctypes.c_void_p],
                  'matches': [ctypes.c_void_p, ctypes.c_void_p]}
    for name, function in functions.items():
        function.argtypes = signatures[name]
        function.restype = ctypes.c_int if name == 'matches' else None
    vectors = [b'', b'abc', b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq']
    require([hashlib.sha256(data).hexdigest() for data in vectors] == [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'], 'independent reference failed known vectors')
    vectors.extend(random.Random(length).randbytes(length) for length in (1, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1024))
    cases = []
    for data in vectors:
        expected = hashlib.sha256(data).digest()
        for chunk in (1, 7, 64, 257):
            context = (ctypes.c_ubyte * 144)(*[165] * 144)
            state = ctypes.addressof(context) + 16
            functions['start'](state)
            functions['add'](state, None, 0)
            for begin in range(0, len(data), chunk):
                piece = ctypes.create_string_buffer(data[begin:begin + chunk])
                functions['add'](state, ctypes.addressof(piece), min(chunk, len(data) - begin))
            digest = (ctypes.c_ubyte * 64)(*[165] * 64)
            output = ctypes.addressof(digest) + 16
            functions['finish'](state, output)
            require(bytes(digest)[16:48] == expected, 'SHA-256 differs from independent reference')
            require(bytes(context)[:16] == bytes([165]) * 16 and bytes(context)[128:] == bytes([165]) * 16,
                    'context guard bytes modified')
            require(bytes(digest)[:16] == bytes([165]) * 16 and bytes(digest)[48:] == bytes([165]) * 16,
                    'digest guard bytes modified')
            text = (ctypes.c_ubyte * 97)(*[165] * 97)
            functions['hex'](output, ctypes.addressof(text) + 16)
            require(bytes(text)[16:81] == expected.hex().encode() + b'\0', 'hex conversion mismatch')
            require(bytes(text)[:16] == bytes([165]) * 16 and bytes(text)[81:] == bytes([165]) * 16,
                    'text guard bytes modified')
            wrong = ('0' if expected.hex()[0] != '0' else '1') + expected.hex()[1:]
            for value, wanted in ((expected.hex(), 1), (expected.hex().upper(), 1), (wrong, 0), ('abc', 0), ('g' * 64, 0)):
                buffer = ctypes.create_string_buffer(value.encode())
                require(functions['matches'](output, ctypes.addressof(buffer)) == wanted, 'digest comparison mismatch')
            require(functions['matches'](output, None) == 0, 'null digest text not rejected')
            cases.append({'length': len(data), 'chunk': chunk, 'input_sha256': expected.hex()})
    return {'library_sha256': sha(path), 'cases': cases, 'architecture': 'arm64'}


def check_holdout(path, prefix):
    require(subprocess.check_output(['xcrun', 'lipo', '-archs', path], text=True).strip() == 'arm64', 'non-native library')
    library = ctypes.CDLL(str(path))
    compare = getattr(library, prefix + 'memcmp')
    compare.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    compare.restype = ctypes.c_int
    randoms = random.Random(941267)
    cases = []
    for size in (0, 1, 2, 7, 15, 16, 31, 32, 63, 64, 65, 255):
        for offset in (0, 1, 7):
            for changed in (-1, 0, max(0, size - 1)):
                left = randoms.randbytes(size)
                right = bytearray(left)
                if changed >= 0 and size:
                    right[changed] ^= 255
                expected = next((a - b for a, b in zip(left, right) if a != b), 0)
                a = ctypes.create_string_buffer(bytes([165]) * offset + left + bytes([90]) * 16)
                b = ctypes.create_string_buffer(bytes([165]) * offset + right + bytes([90]) * 16)
                before = (a.raw, b.raw)
                require(compare(ctypes.addressof(a) + offset, ctypes.addressof(b) + offset, size) == expected,
                        'holdout differs from bytewise independent oracle')
                require((a.raw, b.raw) == before, 'read-only holdout modified a buffer')
                require(compare(ctypes.addressof(a) + offset, ctypes.addressof(a) + offset, size) == 0,
                        'aliased holdout mismatch')
                cases.append({'size': size, 'offset': offset, 'changed': changed, 'result': expected})
    libc = ctypes.CDLL(None)
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    pages = [mmap.mmap(-1, mmap.PAGESIZE * 2) for _ in range(2)]
    addresses = [ctypes.addressof(ctypes.c_char.from_buffer(page)) for page in pages]
    try:
        for address in addresses:
            ctypes.memset(address, 71, mmap.PAGESIZE)
            require(libc.mprotect(address + mmap.PAGESIZE, mmap.PAGESIZE, 0) == 0, 'cannot protect holdout guard page')
        for size in (0, 1, 7, 16, 31, 64, 255):
            pointers = [address + mmap.PAGESIZE - size for address in addresses]
            require(compare(*pointers, size) == 0, 'page-boundary comparison mismatch')
    finally:
        for address, page in zip(addresses, pages):
            require(libc.mprotect(address + mmap.PAGESIZE, mmap.PAGESIZE, mmap.PROT_READ | mmap.PROT_WRITE) == 0,
                    'cannot restore holdout page')
            page.close()
    return {'library_sha256': sha(path), 'cases': cases, 'architecture': 'arm64'}


def build(args, folder):
    begin = time.monotonic()
    holdout = args.holdout_source is not None
    if holdout:
        source_revision = 'AssemblyScript/musl@aad50fcd791e009961621ddfbe3d4c245fd689a3'
        source_hashes = {'memcmp.c': '826b1b5e84d3c0fb68be827c051f6dc0d67da17ee3a444e94be0e5360586916f'}
        require(sha(args.holdout_source) == source_hashes['memcmp.c'], 'holdout source changed')
        external = folder
        (folder / 'memcmp.c').write_bytes(args.holdout_source.read_bytes())
        source_name, exports = 'memcmp.c', ('memcmp',)
    else:
        require(run(['git', '-C', args.source_root, 'rev-parse', 'HEAD'], folder).strip() == REVISION, 'external source revision changed')
        external = args.source_root / 'examples/self-update'
        for name, expected in SOURCES.items():
            require(sha(external / name) == expected, 'external source requires requalification: ' + name)
        source_revision, source_hashes = REVISION, SOURCES
        source_name, exports = 'self_update_sha256.c', tuple('self_update_sha256_' + name for name in EXPORTS)
    require(run(['git', '-C', args.sdk, 'rev-parse', 'HEAD'], folder).strip() == PIN, 'CRT revision changed')
    require(sha(args.sdk / 'linker/crt1.S') == '1e1b25f288179c18d78d69bae7d307274722254298e8a95c44c6848f67044656', 'CRT changed')
    headers = folder / 'headers'
    headers.mkdir()
    (headers / 'stdint.h').write_text('typedef __UINT32_TYPE__ uint32_t; typedef __UINT64_TYPE__ uint64_t;\n')
    (headers / 'stddef.h').write_text('typedef __SIZE_TYPE__ size_t;\n#define NULL ((void*)0)\n')
    (headers / 'string.h').write_text('#include <stddef.h>\nvoid *memcpy(void*, const void*, size_t); void *memset(void*, int, size_t); size_t strlen(const char*);\n')
    (folder / 'main.c').write_text('#include "' + source_name + '"\nint main(void) { return 0; }\n')
    cc = ['xcrun', 'clang', '--target=x86_64-unknown-freebsd']
    run([*cc, '-nostdinc', '-isystem', headers, '-I', external, '-' + args.optimization, '-fPIC', '-g', '-gdwarf-4',
         '-fno-omit-frame-pointer', '-c', 'main.c', '-o', 'main.o'], folder)
    run([*cc, '-c', args.sdk / 'linker/crt1.S', '-o', 'crt.o'], folder)
    run([args.linker, 'app.elf', 'crt.o', 'main.o'], folder)
    source = folder / 'app.elf'
    recovered = recover_image(source, [folder / 'main.o', folder / 'crt.o'])
    dossier = recover_debug_dossier(source, folder / 'main.o')
    names = {row['symbol'] for row in dossier['functions']}
    expected = {'memcmp', 'main'} if holdout else set(exports) | {'compress', 'main'}
    if args.optimization == 'O0' and not holdout:
        expected.add('rotate')
    require(names == expected, 'changed source function inventory')
    functions = []
    for row in dossier['functions']:
        require('boundary' in row['facts'] and 'source_abi' in row['facts'], 'missing ABI or boundary evidence')
        functions.append({'name': 'guest_' + row['symbol'], **row['facts']['boundary'], **row['facts']['source_abi'],
                          'stack_objects': row['facts'].get('fixed_stack_objects', [])})
    _, elf = load_elf(source)
    dynamic = parse_dynamic(elf, lambda address, size: read_address(elf, address, size))
    for name, parameters in (('_start', ['ptr', 'ptr']), ('_init', []), ('_fini', [])):
        rows = [r for r in recovered['functions'] if r['symbol'] == name]
        require(len(rows) == 1, 'ambiguous CRT boundary')
        row = rows[0]
        if name != '_start':
            require(read_address(elf, row['address'], 1) == b'\xc3', 'CRT lifecycle changed')
        functions.append({'name': 'guest' + name, 'address': row['address'], 'size': row['size'] if name == '_start' else 1,
                          'parameters': parameters, 'result': 'void'})
    imports, resolution = resolve_imports(source, json.loads((ROOT / 'core/aot/catalogs/apple-runtime.json').read_text()), ROOT)
    require(len(resolution['missing']) == 1, 'unqualified provider')
    missing = resolution['missing'][0]
    require(missing['identity'] == {'nid': 'bzQExy189ZI', 'library': 'libc', 'library_version': 1,
                                   'module': 'libc', 'module_version': 257}, 'unexpected startup binding')
    imports[missing['symbol']] = {'name': 'aot_bridge_init_env', 'result': 'void', 'parameters': ['ptr']}
    got = dynamic['tags']['DT_PLTGOT']
    require(any(d['address'] == got and d['size'] == 24 + 8 * len(imports) for d in recovered['data']), 'non-dedicated GOT')
    contracts = {'schema': 1, 'sha256': recovered['sha256'], 'functions': functions, 'imports': imports,
                 'data': recovered['data'], 'pointer_relocations': recovered['pointer_relocations'],
                 'lifecycle': {'owner': 'entry', 'init': dynamic['tags']['DT_INIT'], 'fini': dynamic['tags']['DT_FINI']},
                 'immutable_data': [{'address': got, 'evidence': 'Static qualified CRT and linker; readonly bindings verified at native load.'}]}
    policies = {'checked_pointer_bases': {'bytes': 1, 'evidence': 'Qualified unchanged C source; valid C object lifetimes and extents.'},
                'checked_pointer_arguments': {'bytes': 1, 'nullable': True, 'evidence': 'Qualified source ABI and valid native objects for {callee}.'}}
    recipe = {'schema': SCHEMA, 'contracts': contracts, 'policies': policies,
              'qualification': {'facts_sha256': fact_digest(contracts, policies),
                                'sources': [{'path': 'core/aot/examples/sha256_transfer.py', 'sha256': sha(Path(__file__))}]}}
    contracts, guards = materialize(source, recipe, ROOT)
    ir, report = compile_image(Image(source, contracts))
    (folder / 'module.ll').write_text(ir)
    report['native_object'] = build_native_object(ir, folder / 'module.o')
    (folder / 'bridge.cpp').write_text('extern "C" void _init_env_nid_postfix();\nextern "C" void aot_bridge_init_env(void*) { _init_env_nid_postfix(); }\n')
    (folder / 'exports.txt').write_text(''.join('_guest_' + name + '\n' for name in exports))
    run(['xcrun', 'clang++', '-arch', 'arm64', '-dynamiclib', '-fexperimental-library', '-Wl,-dead_strip',
         '-Wl,-exported_symbols_list,' + str(folder / 'exports.txt'), 'module.o', 'bridge.cpp', args.runtime,
         args.image_runtime, '-framework', 'CoreFoundation', '-o', 'aot.dylib'], folder)
    run(['xcrun', 'clang', '-arch', 'arm64', '-O2', '-dynamiclib', external / source_name, '-o', 'reference.dylib'], folder)
    checker = check_holdout if holdout else check_library
    aot, reference = checker(folder / 'aot.dylib', 'guest_'), checker(folder / 'reference.dylib', '')
    require(aot['cases'] == reference['cases'], 'different acceptance corpus')
    stripped = recover_image(source, [])
    require(not stripped['companions'] and not stripped['functions'], 'unassisted recovery profile changed')
    require(elf.get_section_by_name('.symtab') is None and elf.get_section_by_name('.debug_info') is None,
            'unassisted image unexpectedly contains source symbols or debug information')
    report.update(source_revision=source_revision, source_hashes=source_hashes, optimization=args.optimization,
                  provider_resolution=resolution, debug_dossier=dossier, guard_derivation=guards,
                  aot=aot, reference=reference, unassisted_recovery=stripped,
                  manual_facts=['Unchanged public C source and SysV machine ABI for this compiler profile.',
                                'C object bounds/lifetimes, reviewed LP64 layouts and nonoverlapping memcpy arguments where used.',
                                'Qualified static CRT startup and readonly import bindings.',
                                'Nullable native-pointer argument and native-base guard policies.'],
                  qualification_seconds=None, offline_build_and_acceptance_seconds=time.monotonic() - begin,
                  runtime_archives={str(args.runtime): sha(args.runtime), str(args.image_runtime): sha(args.image_runtime)},
                  toolchain=run(['xcrun', 'clang', '--version'], folder).splitlines()[0], linker_sha256=sha(args.linker),
                  limitations=['External component harness, not a complete application or its original loader.',
                               'Source/debug qualification remains required; unassisted image recovery is not a compilable ABI contract.',
                               'Scoped debug locations are reported but are not promoted into object-lifetime proofs.',
                               'Human qualification time is not measured by the automated build timer; no speedup claim.'])
    for name, value in (('contracts.json', contracts), ('dossier.json', dossier), ('unassisted.json', stripped)):
        (folder / name).write_text(json.dumps(value, indent=2) + '\n')
    report['hashes'] = {name: sha(folder / name) for name in ('app.elf', 'main.o', 'crt.o', 'module.o', 'module.ll',
                                                           'contracts.json', 'aot.dylib', 'reference.dylib')}
    (folder / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument('--source-root', type=Path)
    sources.add_argument('--holdout-source', type=Path)
    for name in ('sdk', 'linker', 'runtime', 'image-runtime', 'output-parent'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--optimization', choices=('O0', 'O2'), default='O2')
    args = parser.parse_args()
    for name in ('source_root', 'holdout_source', 'sdk', 'linker', 'runtime', 'image_runtime', 'output_parent'):
        if getattr(args, name) is not None:
            setattr(args, name, getattr(args, name).resolve())
    args.output_parent.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='component-', dir=args.output_parent))
    build(args, folder)
    print(folder / 'acceptance.json')


if __name__ == '__main__':
    main()

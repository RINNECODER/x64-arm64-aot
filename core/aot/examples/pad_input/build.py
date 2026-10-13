import argparse
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from compiler import Image, compile_image
from contract_recipe import SCHEMA, fact_digest, materialize
from debug_candidates import recover_debug_candidates, recover_debug_dossier
from dynamic import parse_dynamic
from provider_catalog import imported_functions, resolve_imports
from recover import load_elf, read_address, recover_image
from toolchain import build_native_object


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PIN = 'ea771e535378740b6a058b8e5419eb8a0e0e0ec8'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, folder):
    return subprocess.check_output(list(map(str, command)), cwd=folder, stderr=subprocess.STDOUT, text=True)


def build(sdk, linker, folder, optimization="O0"):
    require(optimization in ("O0", "O2"), "unqualified optimization profile")
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'pad_input requires native Apple ARM64')
    require(run(['git', '-C', sdk, 'rev-parse', 'HEAD'], folder).strip() == PIN, 'SDK revision changed')
    sources = {'examples/pad_input/main.c': 'aad4bf06b8aa505375417019bafb02872ef513693bd5067b31654aff0f8d0c77', 'linker/crt1.S': '1e1b25f288179c18d78d69bae7d307274722254298e8a95c44c6848f67044656'}
    for name, expected in sources.items():
        require(sha(sdk / name) == expected, 'source requires requalification: ' + name)
    cc = ['xcrun', 'clang', '--target=x86_64-unknown-freebsd']
    run([*cc, '-' + optimization, '-fPIC', '-g', '-gdwarf-4', '-fno-omit-frame-pointer', '-c', sdk / 'examples/pad_input/main.c', '-o', 'main.o'], folder)
    run([*cc, '-c', sdk / 'linker/crt1.S', '-o', 'crt.o'], folder)
    run([linker, 'app.elf', 'crt.o', 'main.o'], folder)
    source = folder / 'app.elf'
    recovered = recover_image(source, [folder / 'crt.o', folder / 'main.o'])
    if optimization == 'O0':
        candidates = recover_debug_candidates(source, folder / 'main.o')
        require(len(candidates['functions']) == 4 and all(not f['obligations'] for f in candidates['functions']),
                'source compilation profile changed or unresolved debug facts remain')
        functions = [row['candidate'] for row in candidates['functions']]
        require({f['name'] for f in functions} == {'guest_main', 'guest_notify', 'guest_append', 'guest_append_uint'},
                'unexpected source function inventory')
    else:
        candidates = recover_debug_dossier(source, folder / 'main.o')
        require(len(candidates['functions']) == 1 and candidates['functions'][0]['symbol'] == 'main',
                'optimized function inventory needs qualification')
        row = candidates['functions'][0]
        require(row['facts'].get('source_abi') == {'parameters': [], 'result': 'i32'}, 'main ABI changed')
        functions = [{'name': 'guest_main', **row['facts']['boundary'], **row['facts']['source_abi'],
                      'stack_objects': row['facts']['fixed_stack_objects']}]
    _, elf = load_elf(source)
    dynamic = parse_dynamic(elf, lambda address, size: read_address(elf, address, size))
    for symbol, result, parameters in [('_start', 'void', ['ptr', 'ptr']), ('_init', 'void', []), ('_fini', 'void', [])]:
        found = [f for f in recovered['functions'] if f['symbol'] == symbol]
        require(len(found) == 1, 'CRT boundary evidence missing or ambiguous')
        item = found[0]
        size = item['size']
        if symbol != '_start':
            require(read_address(elf, item['address'], 1) == b'\xc3', 'CRT lifecycle no longer empty')
            size = 1
        functions.append({'name': 'guest' + symbol, 'address': item['address'], 'size': size,
                          'result': result, 'parameters': parameters})
    if optimization == 'O0':
        next(f for f in functions if f['name'] == 'guest_append_uint')['integer_division'] = 'nonzero-no-overflow'
    catalog = json.loads((ROOT / 'core/aot/catalogs/apple-runtime.json').read_text())
    imports, providers = resolve_imports(source, catalog, ROOT)
    require(len(providers['missing']) == 1, 'unqualified provider beyond source startup')
    missing = providers['missing'][0]
    require(missing['identity'] == {'nid': 'bzQExy189ZI', 'library': 'libc', 'library_version': 1,
                                   'module': 'libc', 'module_version': 257}, 'unknown startup binding')
    imports[missing['symbol']] = {'name': 'aot_bridge_init_env', 'result': 'void', 'parameters': ['ptr']}
    got = dynamic['tags']['DT_PLTGOT']
    require(any(d['address'] == got and d['size'] == 24 + 8 * len(imports) for d in recovered['data']),
            'GOT is not a dedicated fixed import table')
    contracts = {'schema': 1, 'sha256': recovered['sha256'], 'functions': functions, 'imports': imports,
                 'data': recovered['data'], 'pointer_relocations': recovered['pointer_relocations'],
                 'lifecycle': {'owner': 'entry', 'init': dynamic['tags']['DT_INIT'], 'fini': dynamic['tags']['DT_FINI']},
                 'native_runtime_registration': True, 'guard_diagnostics': True,
                 'immutable_data': [{'address': got, 'evidence': 'Pinned static CRT and linker; native startup verifies the dedicated GOT is readonly; no provider rebinding in this profile.'}]}
    policies = {'checked_pointer_bases': {'bytes': 1, 'evidence': 'Pinned source uses native pointers with C object bounds and lifetimes. Mapping guards do not replace these preconditions.'},
                'checked_pointer_arguments': {'bytes': 1, 'nullable': True, 'evidence': 'Source-qualified native ABI for {callee}; unknown origins retain mapping checks.'}}
    local_sources = [{'path': 'core/aot/examples/pad_input/build.py', 'sha256': sha(HERE / 'build.py')}]
    recipe = {'schema': SCHEMA, 'contracts': contracts, 'policies': policies,
              'qualification': {'facts_sha256': fact_digest(contracts, policies), 'sources': local_sources}}
    contracts, guards = materialize(source, recipe, ROOT)
    image = Image(source, contracts)
    try:
        ir, report = compile_image(image)
    except ValueError:
        print(run(['xcrun', 'clang', '--version'], folder), file=sys.stderr)
        print('Rejected input sha256: ' + contracts['sha256'], file=sys.stderr)
        for function in functions:
            print('Function contract: ' + json.dumps(function, sort_keys=True), file=sys.stderr)
            for instruction in image.decoder.disasm(image.read(function['address'], function['size']), function['address']):
                print(f'{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}', file=sys.stderr)
        raise
    (folder / 'module.ll').write_text(ir)
    report['native_object'] = build_native_object(ir, folder / 'module.o')
    run(['xcrun', 'clang', '-arch', 'arm64', '-O2', '-Dmain=guest_source_main',
         '-DscePadInit=scePadInit_nid_postfix', '-DscePadOpen=scePadOpen_nid_postfix',
         '-DscePadClose=scePadClose_nid_postfix', '-DsceKernelUsleep=sceKernelUsleep_nid_postfix',
         '-DsceKernelSendNotificationRequest=aot_bridge_sceKernelSendNotificationRequest',
         '-c', sdk / 'examples/pad_input/main.c', '-o', 'reference.o'], folder)
    report.update(optimization=optimization, sdk_revision=PIN, source_hashes=sources, provider_resolution=providers,
                  debug_candidates=candidates, guard_derivation=guards,
                  remaining_manual_facts=['Pinned C source and SysV compilation profile; native object lifetimes.',
                                          'Unsigned append_uint divisions have constant divisor 10 and zero high dividend.',
                                          'CRT startup ABI, null allocator tables and readonly static bindings.',
                                          'Nullable pointer-argument and native-address guard policies.'],
                  limitations=['Source-built qualified C profile; scoped debug values remain candidates and are not lifetime contracts.',
                               'O2 uses only main source ABI and fixed objects; compiler dataflow checks the machine frame. No stripped or performance claim.',
                               'Seven catalog providers are newly qualified here; only three predate this consumer.',
                               'Simulated input is not physical-controller qualification.'])
    for name, value in [('build.json', report), ('contracts.json', contracts), ('recovery.json', recovered)]:
        (folder / name).write_text(json.dumps(value, indent=2) + '\n')
    report['hashes'] = {name: sha(folder / name) for name in
                        ('app.elf', 'main.o', 'crt.o', 'module.ll', 'module.o', 'reference.o', 'contracts.json')}
    report['toolchain'] = run(['xcrun', 'clang', '--version'], folder).splitlines()[0]
    report['linker_sha256'] = sha(linker)
    (folder / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--linker', type=Path, required=True)
    parser.add_argument('--optimization', choices=('O0', 'O2'), default='O0')
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument('--output', type=Path)
    outputs.add_argument('--output-parent', type=Path)
    args = parser.parse_args()
    if args.output_parent:
        args.output_parent.mkdir(parents=True, exist_ok=True)
        args.output = Path(tempfile.mkdtemp(prefix='build-', dir=args.output_parent))
    output = args.output.resolve()
    require(not output.exists() or (output.is_dir() and not output.is_symlink() and not any(output.iterdir())),
            'choose a fresh artifact directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='pad-input-build-', dir=output.parent) as temporary:
        folder = Path(temporary)
        build(args.sdk.resolve(), args.linker.resolve(), folder, args.optimization)
        folder.rename(output)
    print(output / 'build.json')


if __name__ == '__main__':
    main()

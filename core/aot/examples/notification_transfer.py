import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from elftools.dwarf.dwarf_expr import DWARFExprParser

from compiler import Image, compile_image
from debug_candidates import object_size, recover_debug_candidates
from dynamic import parse_dynamic
from provider_catalog import resolve_imports
from recover import load_elf, read_address, recover_image
from toolchain import build_native_object
from pad_input.build import PIN, ROOT, require, run, sha


SOURCE_REVISION = 'f5d40f02770e9b0001dd9e18056eca70b3da8b40'
SOURCE_HASH = '31f47abaf76a21a8c0be7f13b2a41abc807cff1a555fbf4242893c881c53ae46'


def build(args, folder):
    require(sha(args.source) == SOURCE_HASH, 'independent source changed; requalification required')
    require(run(['git', '-C', args.sdk, 'rev-parse', 'HEAD'], folder).strip() == PIN, 'CRT SDK revision changed')
    require(sha(args.sdk / 'linker/crt1.S') == '1e1b25f288179c18d78d69bae7d307274722254298e8a95c44c6848f67044656', 'CRT changed')
    headers = folder / 'headers'
    headers.mkdir()
    (headers / 'stdio.h').write_text('')
    (headers / 'string.h').write_text('typedef __SIZE_TYPE__ size_t;\nvoid bzero(void*, size_t);\nchar* strncpy(char*, const char*, size_t);\n')
    cc = ['xcrun', 'clang', '--target=x86_64-unknown-freebsd']
    run([*cc, '-nostdinc', '-isystem', headers, '-O0', '-g', '-gdwarf-4', '-fPIC', '-fno-omit-frame-pointer',
         '-c', args.source, '-o', 'main.o'], folder)
    run([*cc, '-c', args.sdk / 'linker/crt1.S', '-o', 'crt.o'], folder)
    run([args.linker, 'app.elf', 'crt.o', 'main.o'], folder)
    source = folder / 'app.elf'
    recovered = recover_image(source, [folder / 'crt.o', folder / 'main.o'])
    candidates = recover_debug_candidates(source, folder / 'main.o')
    require(len(candidates['functions']) == 1 and candidates['functions'][0]['obligations'] == ['unprototyped debug function'],
            'independent source qualification profile changed')
    _, obj = load_elf(folder / 'main.o')
    dwarf = obj.get_dwarf_info()
    parser = DWARFExprParser(dwarf.structs)
    objects = []
    for unit in dwarf.iter_CUs():
        for die in unit.iter_DIEs():
            if die.tag != 'DW_TAG_subprogram' or die.attributes.get('DW_AT_name', None) is None:
                continue
            require(die.attributes['DW_AT_name'].value == b'main', 'unexpected debug function')
            frame = parser.parse_expr(die.attributes['DW_AT_frame_base'].value)
            require(len(frame) == 1 and frame[0].op_name == 'DW_OP_reg6', 'frame requires separate qualification')
            for child in die.iter_children():
                if child.tag != 'DW_TAG_variable':
                    continue
                require(child.attributes['DW_AT_name'].value == b'req', 'unexpected local')
                location = parser.parse_expr(child.attributes['DW_AT_location'].value)
                size = object_size(child.get_DIE_from_attribute('DW_AT_type'))
                require(len(location) == 1 and location[0].op_name == 'DW_OP_fbreg' and size == 3120, 'request layout changed')
                objects.append({'offset': location[0].args[0] - 8, 'size': size, 'alignment': 1})
    require(len(objects) == 1, 'request object not uniquely qualified')
    _, elf = load_elf(source)
    dynamic = parse_dynamic(elf, lambda address, size: read_address(elf, address, size))
    signatures = {'_start': ('void', ['ptr', 'ptr']), '_init': ('void', []), '_fini': ('void', []), 'main': ('i32', [])}
    functions = []
    for item in recovered['functions']:
        name = item['symbol']
        require(name in signatures, 'unqualified function')
        size = item['size']
        if name in ('_init', '_fini'):
            require(read_address(elf, item['address'], 1) == b'\xc3', 'nonempty lifecycle')
            size = 1
        result, parameters = signatures[name]
        spec = {'name': 'guest_main' if name == 'main' else 'guest' + name, 'address': item['address'],
                'size': size, 'result': result, 'parameters': parameters}
        if name == 'main':
            require(read_address(elf, item['address'], 4) == bytes.fromhex('554889e5'), 'frame prologue changed')
            spec['stack_objects'] = objects
        functions.append(spec)
    require(len(functions) == 4, 'unqualified function coverage')
    catalog = json.loads((ROOT / 'core/aot/catalogs/apple-runtime.json').read_text())
    imports, resolution = resolve_imports(source, catalog, ROOT)
    manual = {'bzQExy189ZI': ('aot_bridge_init_env', 'void', ['ptr']),
              '6sJWiWSRuqk': ('strncpy', 'ptr', ['ptr', 'ptr', 'u64'])}
    require({row['identity']['nid'] for row in resolution['missing']} == set(manual), 'different provider obligations')
    for row in resolution['missing']:
        require(row['identity']['library'] == row['identity']['module'] == 'libc' and
                row['identity']['library_version'] == 1 and row['identity']['module_version'] == 257, 'unqualified libc identity')
        name, result, parameters = manual[row['identity']['nid']]
        imports[row['symbol']] = {'name': name, 'result': result, 'parameters': parameters}
    got = dynamic['tags']['DT_PLTGOT']
    require(any(d['address'] == got and d['size'] == 24 + 8 * len(imports) for d in recovered['data']), 'non-dedicated GOT')
    contracts = {'schema': 1, 'sha256': recovered['sha256'], 'functions': functions, 'imports': imports,
                 'data': recovered['data'], 'pointer_relocations': recovered['pointer_relocations'],
                 'native_runtime_registration': True, 'lifecycle': {'owner': 'entry', 'init': dynamic['tags']['DT_INIT'], 'fini': dynamic['tags']['DT_FINI']},
                 'immutable_data': [{'address': got, 'evidence': 'Qualified static CRT with readonly GOT; no rebinding or writes.'}]}
    ir, report = compile_image(Image(source, contracts))
    (folder / 'module.ll').write_text(ir)
    report['native_object'] = build_native_object(ir, folder / 'module.o')
    run(['xcrun', 'clang', '-arch', 'arm64', '-O2', '-Dmain=guest_source_main', '-c', args.source, '-o', 'reference.o'], folder)
    executions = []
    for reference in (False, True):
        binary = folder / ('reference' if reference else 'aot')
        run(['xcrun', 'clang++', '-arch', 'arm64', '-std=c++20', '-O2', '-I', ROOT / 'core/libs',
             *(['-DPAD_INPUT_REFERENCE'] if reference else []), ROOT / 'core/aot/examples/pad_input/launcher.cpp',
             folder / ('reference.o' if reference else 'module.o'), args.runtime, args.image_runtime,
             '-Wl,-dead_strip', '-framework', 'CoreFoundation', '-o', binary], folder)
        require(run(['xcrun', 'lipo', '-archs', binary], folder).strip() == 'arm64', 'non-native binary')
        execution = subprocess.run([binary], capture_output=True, text=True, timeout=10)
        require(execution.returncode == 0 and 'architecture=arm64 translated=0' in execution.stderr and
                '[notification] Hello, world!' in execution.stderr and 'teardown completed' in execution.stderr, 'transfer execution failed')
        executions.append({'binary_sha256': sha(binary), 'stderr': execution.stderr, 'exit_code': execution.returncode})
    require(executions[0]['stderr'] == executions[1]['stderr'], 'transfer observable mismatch')
    report.update(source_revision=SOURCE_REVISION, source_sha256=SOURCE_HASH, provider_resolution=resolution,
                  debug_candidates=candidates, executions=executions, contracts=contracts,
                  runtime_archives={str(args.runtime): sha(args.runtime), str(args.image_runtime): sha(args.image_runtime)},
                  limitations=['Independent source is unchanged, but uses declaration-only cross headers and the ps5link CRT, not its original payload loader.',
                               'main() ABI and request layout require this explicit source profile. memset and strncpy use host libc bindings.',
                               'Four provider contracts resolved automatically, including the subsequently qualified memset. No console, performance or general SDK compatibility claim.'])
    (folder / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    for name in ('source', 'sdk', 'linker', 'runtime', 'image-runtime', 'output-parent'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    for name, value in vars(args).items():
        setattr(args, name, value.resolve())
    args.output_parent.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix='transfer-', dir=args.output_parent))
    build(args, folder)
    print(folder / 'acceptance.json')


if __name__ == '__main__':
    main()

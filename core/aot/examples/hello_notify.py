import argparse
import hashlib
import io
import json
import os
import platform
import struct
import subprocess
import sys
import time
from pathlib import Path

from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile

from compiler import Image, compile_image
from dynamic import parse_dynamic
from recover import object_mappings, read_address, symbol_candidates
from toolchain import build_native_object


SOURCES = {
    'examples/hello_notify/main.c': '21437c11004d6916faa341b3db188bf0ef6a63942474ee0974b3306a168dc2e2',
    'linker/crt1.S': '1e1b25f288179c18d78d69bae7d307274722254298e8a95c44c6848f67044656',
}
IMPORTS = {
    'bzQExy189ZI': ('_init_env_nid_postfix', 'void', []),
    '8G2LB+A3rzg': ('atexit', 'i32', ['ptr']),
    'uMei1W9uyNo': ('exit', 'void', ['i32']),
    '8zTFvBIAIN8': ('memset', 'ptr', ['ptr', 'i32', 'u64']),
    'zl7hupSO0C0': ('sceKernelSendNotificationRequest', 'i32', ['i32', 'ptr', 'u64', 'i32']),
    '1jfXLRVzisc': ('sceKernelUsleep_nid_postfix', 'i32', ['u32']),
}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def run(arguments, directory):
    subprocess.run([str(value) for value in arguments], cwd=directory, check=True)


def request_object(companion):
    dwarf = companion.get_dwarf_info()
    parser = DWARFExprParser(dwarf.structs)
    matches = []
    for unit in dwarf.iter_CUs():
        for function in unit.iter_DIEs():
            if function.tag != 'DW_TAG_subprogram' or function.attributes.get('DW_AT_name', None) is None:
                continue
            if function.attributes['DW_AT_name'].value != b'main' or 'DW_AT_frame_base' not in function.attributes:
                continue
            frame = parser.parse_expr(function.attributes['DW_AT_frame_base'].value)
            require(len(frame) == 1 and frame[0].op_name == 'DW_OP_reg6', 'example requires the verified rbp frame base')
            for variable in function.iter_children():
                if variable.tag != 'DW_TAG_variable' or variable.attributes.get('DW_AT_name', None) is None:
                    continue
                if variable.attributes['DW_AT_name'].value != b'req':
                    continue
                location = parser.parse_expr(variable.attributes['DW_AT_location'].value)
                require(len(location) == 1 and location[0].op_name == 'DW_OP_fbreg', 'request has no fixed debug stack location')
                array = variable.get_DIE_from_attribute('DW_AT_type')
                require(array.tag == 'DW_TAG_array_type', 'request debug type is not an array')
                element = array.get_DIE_from_attribute('DW_AT_type')
                require(element.attributes['DW_AT_byte_size'].value == 1, 'request element is not one byte')
                bounds = list(array.iter_children())
                require(len(bounds) == 1, 'request has ambiguous array bounds')
                attributes = bounds[0].attributes
                count = attributes['DW_AT_count'].value if 'DW_AT_count' in attributes else attributes['DW_AT_upper_bound'].value + 1
                require(count == 3120 and ('DW_AT_lower_bound' not in attributes or attributes['DW_AT_lower_bound'].value == 0),
                        'request debug size differs from the source declaration')
                matches.append({'offset': location[0].args[0] - 8, 'size': 3120, 'alignment': 1})
    require(len(matches) == 1, 'request does not have exactly one debug stack object')
    return matches[0]


def contracts_for(source, objects):
    raw = source.read_bytes()
    elf = ELFFile(io.BytesIO(raw))
    functions = []
    signatures = {'_start': ('guest_start', 'void', ['ptr', 'ptr']), '_init': ('guest_init', 'void', []),
                  '_fini': ('guest_fini', 'void', []), 'main': ('guest_main', 'i32', [])}
    for path in objects:
        companion, evidence, mappings = object_mappings(elf, path)
        for candidate in symbol_candidates(companion, mappings):
            symbol = candidate['symbol']
            require(symbol in signatures, f'unexpected example function {symbol}')
            name, result, parameters = signatures[symbol]
            size = candidate['size']
            if symbol in ('_init', '_fini'):
                require(read_address(elf, candidate['address'], 1) == b'\xc3', 'example lifecycle function is no longer an empty return')
                size = 1
            entry = {'address': candidate['address'], 'size': size, 'name': name, 'result': result, 'parameters': parameters}
            if symbol == 'main':
                require(read_address(elf, candidate['address'], 4) == bytes.fromhex('554889e5'), 'example frame prologue changed')
                entry['stack_objects'] = [request_object(companion)]
            functions.append(entry)
    require({f['name'] for f in functions} == {v[0] for v in signatures.values()} and len(functions) == 4,
            'example function coverage differs from its source')
    dynamic = parse_dynamic(elf, lambda address, count: read_address(elf, address, count))
    imports = {}
    pointers = []
    for relocation in dynamic['relocations']:
        if relocation['kind'] == 8:
            require(relocation['symbol_index'] == 0, 'unexpected relative relocation symbol')
            pointers.append([relocation['slot'], relocation['addend']])
        else:
            require(relocation['kind'] == 7 and relocation['addend'] == 0, 'unexpected example import relocation')
            key = dynamic['symbols'][relocation['symbol_index']]['name']
            nid = key.split('#')[0]
            require(nid in IMPORTS, f'example import is not implemented: {key}')
            name, result, parameters = IMPORTS[nid]
            imports[key] = {'name': name, 'result': result, 'parameters': parameters}
            if name == 'exit':
                imports[key]['noreturn'] = True
    data = [{'address': s['p_vaddr'], 'size': s['p_memsz']} for s in elf.iter_segments()
            if s['p_type'] == 'PT_LOAD' and not s['p_flags'] & 1]
    got = dynamic['tags']['DT_PLTGOT']
    require(any(d['address'] == got for d in data), 'GOT is not a dedicated example segment')
    return {'schema': 1, 'sha256': hashlib.sha256(raw).hexdigest(), 'functions': functions,
            'imports': imports, 'data': data, 'pointer_relocations': pointers,
            'native_runtime_registration': True,
            'lifecycle': {'owner': 'entry', 'init': dynamic['tags']['DT_INIT'], 'fini': dynamic['tags']['DT_FINI']},
            'immutable_data': [{'address': got, 'evidence': 'Pinned source example uses a dedicated static GOT; native startup verifies read-only mapping.'}]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--linker', type=Path, required=True)
    parser.add_argument('--runtime', type=Path)
    parser.add_argument('--image-runtime', type=Path)
    parser.add_argument('--compile-only', action='store_true')
    parser.add_argument('--target', choices=('apple-arm64', 'linux-arm64'), default='apple-arm64')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--original-delay', action='store_true')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    require(not (args.compile_only and args.run), 'compile-only mode cannot execute a program')
    require(args.compile_only or (args.runtime and args.image_runtime), 'native runtime archives are required for linking')
    folder = args.output.resolve()
    if args.original_delay:
        folder = folder / 'original'
    folder.mkdir(parents=True, exist_ok=True)
    for relative, digest in SOURCES.items():
        require(hashlib.sha256((args.sdk / relative).read_bytes()).hexdigest() == digest, f'example source changed: {relative}')
    text = (args.sdk / 'examples/hello_notify/main.c').read_text()
    if not args.original_delay:
        require(text.count('30000000') == 1, 'example sleep constant is ambiguous')
        text = text.replace('30000000', '1000')
    (folder / 'main.c').write_text(text)
    cc = (['xcrun', 'clang'] if sys.platform == 'darwin' else [os.environ.get('ANYPS5_AOT_CLANG', 'clang')]) + ['--target=x86_64-unknown-freebsd']
    run([*cc, '-c', args.sdk / 'linker/crt1.S', '-o', 'crt.o'], folder)
    run([*cc, '-O2', '-fPIC', '-g', '-gdwarf-4', '-fno-omit-frame-pointer', '-c', 'main.c', '-o', 'main.o'], folder)
    run([args.linker, 'app.elf', 'crt.o', 'main.o'], folder)
    source = folder / 'app.elf'
    contracts = contracts_for(source, [folder / 'crt.o', folder / 'main.o'])
    (folder / 'contracts.json').write_text(json.dumps(contracts, indent=2) + '\n')
    ir, report = compile_image(Image(source, contracts, args.target))
    (folder / 'module.ll').write_text(ir)
    report['native_object'] = build_native_object(ir, folder / 'module.o', args.target)
    report['source_variant'] = 'original 30-second delay' if args.original_delay else 'CI source variant: sleep changed to 1000 microseconds'
    if args.compile_only:
        (folder / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(folder / 'module.o')
        return
    binary = folder / 'hello-notify-arm64'
    if args.target == 'apple-arm64':
        require(sys.platform == 'darwin' and platform.machine() == 'arm64', 'Apple execution requires a native Apple ARM64 host')
        run(['xcrun', 'clang++', '-arch', 'arm64', '-std=c++20', '-O2', 'module.o', args.runtime,
             args.image_runtime, '-Wl,-dead_strip', '-o', binary], folder)
        architecture = subprocess.check_output(['xcrun', 'lipo', '-archs', str(binary)], text=True).strip()
        require(architecture == 'arm64', 'example executable is not ARM64-only')
    else:
        require(sys.platform == 'linux' and platform.machine() == 'aarch64', 'Linux execution requires a native AArch64 host')
        run(['clang++', '-std=c++20', '-O2', 'module.o', args.runtime, args.image_runtime,
             '-Wl,--gc-sections,-z,relro,-z,now', '-o', binary], folder)
        header = binary.read_bytes()[:64]
        require(len(header) == 64 and header[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', header, 18)[0] == 183,
                'example executable is not AArch64 ELF')
    if args.run:
        begin = time.monotonic()
        executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=40 if args.original_delay else 10)
        elapsed = time.monotonic() - begin
        require(executed.returncode == 0, f'native program failed: {executed.returncode}: {executed.stderr}')
        marker = 'architecture=arm64 translated=0' if args.target == 'apple-arm64' else 'architecture=arm64 host=aarch64 format=ELF'
        require(marker in executed.stderr, 'native execution was not confirmed')
        require('[notification] ps5link: hello from a real title (not a payload)!' in executed.stderr, 'notification missing')
        require('native teardown completed' in executed.stderr, 'registered teardown did not execute')
        if args.original_delay:
            require(elapsed >= 29.9, 'original sleep did not complete')
        report['execution'] = {'exit_code': executed.returncode, 'elapsed_seconds': elapsed, 'stderr': executed.stderr}
        print(executed.stderr, end='')
    (folder / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(binary)


if __name__ == '__main__':
    main()

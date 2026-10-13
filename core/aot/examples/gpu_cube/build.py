import argparse
import difflib
import hashlib
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from compiler import Image, compile_image
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from recover import object_mappings
from toolchain import build_native_object
from variant import source_variant
from reference import separate_multiply_add


PIN = 'ea771e535378740b6a058b8e5419eb8a0e0e0ec8'
SOURCE_SHA = '43a5944745bce3f8f7596dec17e126b1044f41bf0dd98f9d035cacc253fd6db1'
HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def run(arguments, directory):
    return subprocess.check_output([str(v) for v in arguments], cwd=directory, text=True, stderr=subprocess.STDOUT)


def verify_contract_sources(value, root):
    if isinstance(value, dict):
        if 'path' in value and 'excerpt' in value:
            path = root / value['path']
            require(path.is_file() and digest(path) == value['sha256'] and value['excerpt'] in path.read_text(),
                    'provider declaration requires requalification: ' + value['path'])
        for item in value.values():
            verify_contract_sources(item, root)
    elif isinstance(value, list):
        for item in value:
            verify_contract_sources(item, root)


def build(sdk, folder):
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64', 'gpu_cube build requires native Apple ARM64')
    require(run(['git', '-C', sdk, 'rev-parse', 'HEAD'], folder).strip() == PIN, 'unexpected SDK revision')
    source = sdk / 'examples/gpu_cube/main.c'
    require(digest(source) == SOURCE_SHA, 'gpu_cube source changed')
    original = source.read_text()
    modified = source_variant(original)
    (folder / 'main-current-abi.c').write_text(modified)
    (folder / 'source.patch').write_text(''.join(difflib.unified_diff(original.splitlines(True), modified.splitlines(True),
        fromfile='sdk/examples/gpu_cube/main.c', tofile='variant/main.c')))
    shaders = sdk / 'shaders'
    for stage in ('vs', 'ps'):
        run([sys.executable, shaders / 'tools/agcpack.py', 'array', folder / f'mesh_{stage}_sb.h',
            f'mesh_{stage}_sb', shaders / f'third_party/sharpprospero/mesh_{stage}.sb'], folder)
    cc = ['xcrun', 'clang', '--target=x86_64-unknown-freebsd']
    run([*cc, '-O2', '-fPIC', '-I', folder, '-c', 'main-current-abi.c', '-o', 'main.o'], folder)
    run([*cc, '-O2', '-fPIC', '-g', '-gdwarf-4', '-I', folder, '-c', 'main-current-abi.c', '-o', 'main-debug.o'], folder)
    run([*cc, '-c', sdk / 'linker/crt1.S', '-o', 'crt1.o'], folder)
    catalog = (sdk / 'linker/catalog.c').read_text()
    marker = 'static const StubExport exports_VideoOut[] = {'
    require(catalog.count(marker) == 1, 'SDK VideoOut catalog changed')
    (folder / 'catalog.c').write_text(catalog.replace(marker, marker + '\n    { "sceVideoOutAddFlipEvent" },\n    { "sceVideoOutDeleteFlipEvent" },'))
    sources = ['link_real.c', 'elf_object.c', 'linker.c', 'dynwriter.c', 'catalog_extra.c', 'catalog_lookup.c', 'nid.c', 'sha1.c']
    run(['xcrun', 'clang', '-std=c11', '-O2', '-I', sdk / 'linker', *[sdk / 'linker' / v for v in sources],
         'catalog.c', '-o', 'ps5link'], folder)
    (folder / 'link.log').write_text(run([folder / 'ps5link', 'app.elf', 'crt1.o', 'main.o'], folder))
    contracts = json.loads((HERE / 'contracts.json').read_text())
    require(digest(folder / 'app.elf') == contracts['sha256'],
        'compiler output differs from the qualified image; regenerate and review contracts before native execution')
    verify_contract_sources(contracts, HERE.parents[3])
    image = Image(folder / 'app.elf', contracts)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    for spec in image.functions.values():
        for instruction in decoder.disasm(image.read(spec['address'], spec['size']), spec['address']):
            require(not any(name in instruction.mnemonic for name in ('fmadd', 'fmsub', 'fnmadd', 'fnmsub')),
                    'source reference policy requires an input without fused multiply-add instructions')
    _, _, mappings = object_mappings(image.elf, folder / 'main-debug.o')
    require(bool(mappings), 'debug companion does not cover the executable')
    ir, report = compile_image(image)
    (folder / 'module.ll').write_text(ir)
    report['native_object'] = build_native_object(ir, folder / 'module.o')
    run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-ffp-contract=on', '-fno-fast-math',
         '-Dmain=guest_source_main', '-I', folder, '-S', '-emit-llvm', 'main-current-abi.c', '-o', 'reference-source.ll'], folder)
    reference, separated = separate_multiply_add((folder / 'reference-source.ll').read_text())
    (folder / 'reference.ll').write_text(reference)
    run(['xcrun', 'clang', '-arch', 'arm64', '-O3', '-c', 'reference.ll', '-o', 'reference.o'], folder)
    report['reference_policy'] = {'source': 'C compiled independently for ARM64',
        'constant_folding': 'clang -ffp-contract=on, matching the source x86 compiler',
        'runtime_arithmetic': 'separate multiply and add, matching SSE2 code in the input',
        'separated_multiply_adds': separated}
    (folder / 'contracts.json').write_text(json.dumps(contracts, indent=2) + '\n')
    files = ['app.elf', 'main-current-abi.c', 'main.o', 'main-debug.o', 'module.o', 'reference.o', 'reference-source.ll', 'reference.ll', 'contracts.json', 'mesh_vs_sb.h', 'mesh_ps_sb.h']
    report.update(sdk_revision=PIN, source_sha256=SOURCE_SHA,
        compiler=run(['xcrun', 'clang', '--version'], folder).splitlines()[0],
        hashes={name: digest(folder / name) for name in files},
        scope='Source-qualified graphics fixture; execution and image comparison are separate acceptance steps')
    (folder / 'build.json').write_text(json.dumps(report, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists() or (output.is_dir() and not output.is_symlink() and not any(output.iterdir())),
            'output already contains files; choose a fresh directory')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='gpu-cube-build-', dir=output.parent) as temporary:
        folder = Path(temporary)
        build(args.sdk.resolve(), folder)
        folder.rename(output)
    print(output / 'build.json')


if __name__ == '__main__':
    main()

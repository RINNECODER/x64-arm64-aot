import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--name', required=True)
    parser.add_argument('--optimization', choices=('-O1', '-O2', '-O3'), default='-O2')
    parser.add_argument('--profile', choices=('single', 'ordered', 'epochs'), default='ordered')
    parser.add_argument('--optimize-calls', action='store_true')
    parser.add_argument('--seal-image', action='store_true')
    parser.add_argument('--thin-lto', action='store_true')
    args = parser.parse_args()
    worktree = Path(__file__).resolve().parents[3]
    sys.path[:0] = [str(worktree / 'core/aot'), str(worktree / '3rdparty/pyelftools'), str(worktree / '3rdparty/capstone/bindings/python')]
    import guest_emit
    started = time.monotonic()
    output = args.output.resolve()
    if output.exists():
        parser.error('choose a fresh output folder')
    if Path(args.name).name != args.name or args.name in ('', '.', '..'):
        parser.error('name must be one file name')
    lto = ['-flto=thin'] if args.thin_lto else []
    ir = output / 'ir'
    report = guest_emit.build(args.input, ir, concurrent=args.profile != 'single', memory_epochs=args.profile == 'epochs', optimize_calls=args.optimize_calls, seal_image=args.seal_image)
    lowered = time.monotonic()
    modules = sorted(ir.glob('*.ll'))
    from concurrent.futures import ThreadPoolExecutor
    def compile_ir(module):
        subprocess.run(['xcrun', 'clang', '-c', args.optimization, '-arch', 'arm64', *lto, '-Wno-override-module', str(module), '-o', str(module) + '.o'], check=True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(compile_ir, modules))
    compiled = time.monotonic()
    native = worktree / 'core/libs/native'
    runtime = sorted(native.glob('NativeAotGuest*.cpp')) + sorted(native.glob('NativeAotGlibc*.cpp')) + [worktree / 'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp']
    binary = output / args.name
    subprocess.run(['xcrun', 'clang++', '-std=c++20', args.optimization, *lto, '-arch', 'arm64', f'-I{worktree / "core/libs"}', *map(str, runtime),
                    *[f'{module}.o' for module in modules], '-o', str(binary)], check=True)
    linked = time.monotonic()
    head = subprocess.run(['git', '-C', str(worktree), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(['git', '-C', str(worktree), 'status', '--porcelain', '--', 'core'], capture_output=True, text=True, check=True).stdout
    clang = subprocess.run(['xcrun', 'clang', '--version'], capture_output=True, text=True, check=True).stdout.splitlines()[0]
    receipt = {'schema': 'anyps5.transfer.conversion-receipt.v1', 'input': str(args.input.resolve()), 'input_sha256': digest(args.input),
               'compiler_revision': head, 'compiler_dirty': bool(dirty), 'native_compiler': clang, 'optimization': args.optimization + ' '.join([''] + lto), 'profile': args.profile, 'optimized_calls': args.optimize_calls or args.profile == 'epochs', 'sealed_image': args.seal_image,
               'output': str(binary), 'output_sha256': digest(binary),
               'runtime_sources': {str(path.relative_to(worktree)): digest(path) for path in runtime},
               'lowering': {key: report[key] for key in ('units', 'instructions', 'jump_tables', 'imports')},
               'obligations': report['obligations'], 'unsupported': report['unsupported'],
               'seconds': {'lowering': round(lowered - started, 3), 'native_compile': round(compiled - lowered, 3),
                           'link': round(linked - compiled, 3)},
               'translation_in_distributed_program': 'none: the executable contains only AOT-compiled ARM64 code, the native runtime and providers'}
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({key: receipt[key] for key in ('output_sha256', 'lowering', 'seconds')}, indent=1))


if __name__ == '__main__':
    main()

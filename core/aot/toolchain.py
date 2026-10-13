import os
import platform
import re
import struct
import subprocess
import tempfile
from pathlib import Path

from optimize import merge_constant_stores
from targets import target_spec


def build_native_object(ir, destination, target='apple-arm64', strict=True):
    destination = Path(destination)
    spec = target_spec(target)
    compiler = [os.environ.get('ANYPS5_AOT_CLANG', 'clang'), '--target=' + spec['triple']]
    if target == 'apple-arm64' and platform.system() == 'Darwin' and 'ANYPS5_AOT_CLANG' not in os.environ:
        compiler = ['xcrun', 'clang', '-arch', 'arm64']
    with tempfile.TemporaryDirectory(prefix='anyps5-native-build-') as directory:
        folder = Path(directory)
        source, optimized, merged, object_file = (folder / name for name in ('input.ll', 'optimized.ll', 'merged.ll', 'native.o'))
        source.write_text(ir)
        subprocess.run([*compiler, '-O3', '-S', '-emit-llvm', str(source), '-o', str(optimized)],
                       check=True, capture_output=True, text=True)
        result, count = merge_constant_stores(optimized.read_text())
        machine_state = bool(re.search(r'%(?:rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r[8-9]|r1[0-5]|(?:xmm|ymm_hi)(?:[0-9]|1[0-5])|[czsop]f)(?:\.\w+)?\s*=\s*alloca', result) or re.search(r'\bfreeze\b[^\n]*\b(?:poison|undef)\b', result))
        if machine_state and strict:
            raise ValueError('native lowering left unresolved machine-state values')
        if re.search(r'^\s*ret\b.*\b(?:undef|poison)\b', result, re.MULTILINE):
            raise ValueError('native lowering produced an undefined return value')
        merged.write_text(result)
        subprocess.run([*compiler, '-O3', '-c', str(merged), '-o', str(object_file)],
                       check=True, capture_output=True, text=True)
        raw = object_file.read_bytes()
        if target == 'apple-arm64':
            if len(raw) < 32 or struct.unpack_from('<II', raw) != (0xfeedfacf, 0x100000c) or struct.unpack_from('<I', raw, 12)[0] != 1:
                raise ValueError('compiler did not produce an ARM64 Mach-O object')
        elif len(raw) < 64 or raw[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<HH', raw, 16) != (1, 183):
            raise ValueError('compiler did not produce an AArch64 ELF object')
        destination.write_bytes(raw)
        destination.with_suffix('.optimized.ll').write_text(result)
        return {'target': target, 'optimizer_freezes': len(re.findall(r'\bfreeze\b', result)), 'object_bytes': len(raw), 'constant_byte_runs_reconstructed': count, 'machine_state_allocas': int(machine_state),
                'status': 'native_object_not_product_qualified'}

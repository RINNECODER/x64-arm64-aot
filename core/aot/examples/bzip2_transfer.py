import argparse
import bz2
import hashlib
import json
import os
import random
import subprocess
import tempfile
from pathlib import Path


def execute(binary, arguments, data=b'', directory=None):
    result = subprocess.run(['bzip2', *arguments], executable=str(binary), input=data, capture_output=True,
                            cwd=directory, env=dict(os.environ, LC_ALL='C', TZ='UTC'), timeout=20)
    return result.returncode, result.stdout, result.stderr


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--aot', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('choose a fresh receipt path')
    binaries = [args.aot.resolve(), args.reference.resolve()]
    rng = random.Random(14971)
    data_sets = [b'', b'x', b'one line\n', bytes(range(256)) * 16, b'A' * 131072,
                rng.randbytes(65536), 'città 日本語 😀\n'.encode() * 8192]
    results = []
    for index, data in enumerate(data_sets):
        for level in (1, 5, 9):
            actual, expected = [execute(p, [f'-{level}', '-c'], data) for p in binaries]
            valid = actual == expected and actual[0] == 0 and bz2.decompress(actual[1]) == data
            results.append({'kind': 'compress', 'case': index, 'level': level, 'equal': valid, 'input_sha256': digest(data)})
            compressed = bz2.compress(data, compresslevel=level)
            actual, expected = [execute(p, ['-d', '-c'], compressed) for p in binaries]
            results.append({'kind': 'decompress', 'case': index, 'level': level,
                            'equal': actual == expected and actual[0] == 0 and actual[1] == data})
    for data in (b'not compressed', b'BZh9', bz2.compress(b'partial' * 100)[:-5]):
        actual, expected = [execute(p, ['-d', '-c'], data) for p in binaries]
        results.append({'kind': 'invalid-input', 'equal': actual == expected and actual[0] != 0,
                        'input_sha256': digest(data), 'exit': actual[0], 'stderr_sha256': digest(actual[2])})
    artifacts = []
    for binary in binaries:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'input'
            data = data_sets[-1]
            source.write_bytes(data)
            source.chmod(0o640)
            os.utime(source, (1660000000, 1660000000))
            compressed = execute(binary, ['input'], directory=directory)
            packed = Path(directory) / 'input.bz2'
            before = (source.exists(), packed.exists())
            extracted = execute(binary, ['-d', 'input.bz2'], directory=directory)
            stat = source.stat() if source.exists() else None
            artifacts.append((compressed, before, extracted, source.read_bytes() if source.exists() else None,
                              stat.st_mode & 0o777 if stat else None, int(stat.st_mtime) if stat else None, packed.exists()))
    results.append({'kind': 'file-lifecycle', 'equal': artifacts[0] == artifacts[1] and artifacts[0][0][0] == 0
                    and artifacts[0][1] == (False, True) and artifacts[0][2][0] == 0 and artifacts[0][3] == data_sets[-1]
                    and artifacts[0][4:] == (0o640, 1660000000, False)})
    receipt = {'schema': 'anyps5.bzip2-transfer.v1', 'passed': sum(r['equal'] for r in results), 'total': len(results),
               'cases': results, 'binaries': [{'path': str(p), 'sha256': digest(p.read_bytes())} for p in binaries],
               'claim': 'source-equivalent adapted CLI with independent Python bz2 decoder; not console compatibility'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'{receipt["passed"]}/{receipt["total"]} cases passed')
    raise SystemExit(0 if receipt['passed'] == receipt['total'] else 1)


if __name__ == '__main__':
    main()

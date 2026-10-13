import argparse
import hashlib
import json
import platform
import statistics
from pathlib import Path

from zstd_benchmark import execute


def main():
    parser = argparse.ArgumentParser()
    for name in ('aot', 'arm64', 'x86', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--baseline-aot', type=Path)
    parser.add_argument('--repeats', type=int, default=9)
    parser.add_argument('--rows', type=int, default=30000)
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('requires an Apple ARM64 host')
    if args.repeats < 3 or args.rows < 1 or args.output.exists():
        parser.error('use at least three rounds, positive rows and a fresh output folder')
    output = args.output.resolve()
    output.mkdir(parents=True)
    dataset = output / 'input.json'
    dataset.write_text(json.dumps([{'id': i, 'group': (i * 17) % 43, 'value': i % 97,
                                   'text': f'value-{i:06}'} for i in range(args.rows)]))
    program = 'group_by(.group) | map({group: .[0].group, count: length, sum: (map(.value)|add)})'
    paths = {'aot': args.aot.resolve(), 'arm64': args.arm64.resolve(), 'rosetta': args.x86.resolve()}
    if args.baseline_aot:
        paths['baseline_aot'] = args.baseline_aot.resolve()
    import subprocess
    for name, path in paths.items():
        architecture = subprocess.check_output(['xcrun', 'lipo', '-archs', str(path)], text=True).strip()
        if architecture != ('x86_64' if name == 'rosetta' else 'arm64'):
            raise ValueError(f'{name}: unexpected architecture {architecture}')
    commands = {name: (['/usr/bin/arch', '-x86_64'] if name == 'rosetta' else []) +
                [str(path), '-c', program, str(dataset)] for name, path in paths.items()}
    expected = None
    for command in commands.values():
        _, result = execute(command)
        if expected is None:
            expected = result
        if result != expected:
            raise ValueError('output mismatch before timing')
    for _ in range(2):
        for command in commands.values():
            if execute(command)[1] != expected:
                raise ValueError('output mismatch during warmup')
    records = []
    for run in range(args.repeats):
        names = list(commands)
        names = names[run % len(names):] + names[:run % len(names)]
        for name in names:
            measure, result = execute(commands[name])
            if result != expected:
                raise ValueError('output mismatch during timing')
            records.append({'round': run, 'variant': name, **measure})
    summary = {name: {metric: {'median': statistics.median(r[metric] for r in records if r['variant'] == name),
                               'min': min(r[metric] for r in records if r['variant'] == name),
                               'max': max(r[metric] for r in records if r['variant'] == name)}
                      for metric in ('wall_seconds', 'cpu_seconds', 'peak_rss_bytes')} for name in commands}
    receipt = {'schema': 'anyps5.jq-benchmark.v1', 'host': platform.platform(), 'program': program,
               'profile': 'warm CLI including startup, parsing, grouping, allocation and IO; not cold or pure kernel',
               'comparison': 'caller-supplied source-equivalent builds require separate qualification; not identical ELF',
               'dataset_sha256': hashlib.sha256(dataset.read_bytes()).hexdigest(), 'rows': args.rows,
               'binaries': {name: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                            for name, path in paths.items()}, 'warmups': 2, 'records': records, 'summary': summary}
    (output / 'benchmark.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()

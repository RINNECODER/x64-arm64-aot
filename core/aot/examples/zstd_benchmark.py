import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(command, timeout=60):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        started = time.perf_counter()
        process = subprocess.Popen(command, stdout=output, stderr=error)
        while True:
            pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if pid:
                break
            if time.perf_counter() - started > timeout:
                process.kill()
                process.wait()
                raise TimeoutError(command)
            time.sleep(0.001)
        elapsed = time.perf_counter() - started
        process.returncode = os.waitstatus_to_exitcode(status)
        output.seek(0)
        error.seek(0)
        data, errors = output.read(), error.read()
        if process.returncode != 0:
            raise RuntimeError(f'{command}: exit {process.returncode}: {errors.decode(errors="replace")}')
        return {'wall_seconds': elapsed, 'cpu_seconds': usage.ru_utime + usage.ru_stime,
                'peak_rss_bytes': usage.ru_maxrss, 'output_sha256': hashlib.sha256(data).hexdigest()}, data


def main():
    parser = argparse.ArgumentParser()
    for name in ('aot', 'arm64', 'x86', 'decoder', 'dataset', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=9)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--single-thread', action='store_true')
    parser.add_argument('--baseline-aot', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Darwin' or platform.machine() != 'arm64':
        parser.error('the comparison requires an Apple ARM64 host')
    if args.output.exists():
        parser.error('output already exists; choose a new receipt path')
    if args.repeats < 3 or args.workers < 1:
        parser.error('at least three rounds and one worker are required')
    binaries = {'aot': args.aot.resolve(), 'arm64': args.arm64.resolve(), 'rosetta': args.x86.resolve()}
    if args.baseline_aot is not None:
        binaries['baseline_aot'] = args.baseline_aot.resolve()
    for name, path in binaries.items():
        architecture = subprocess.check_output(['xcrun', 'lipo', '-archs', str(path)], text=True).strip()
        expected = 'x86_64' if name == 'rosetta' else 'arm64'
        if architecture != expected:
            raise ValueError(f'{name}: expected {expected}, got {architecture}')
    commands = {name: (['/usr/bin/arch', '-x86_64'] if name == 'rosetta' else []) + [str(path)]
                for name, path in binaries.items()}
    options = [('--single-thread' if args.single_thread else f'-T{args.workers}'), '-3', '-c', str(args.dataset.resolve())]
    if args.single_thread:
        options.append('--no-asyncio')
    data = args.dataset.read_bytes()
    first, checks = {}, {}
    for name, command in commands.items():
        first[name], compressed = execute(command + options)
        decoded = subprocess.run([str(args.decoder.resolve()), '-dc'], input=compressed, capture_output=True, timeout=60, check=True)
        if decoded.stdout != data:
            raise ValueError(f'{name}: decoder output mismatch')
        checks[name] = hashlib.sha256(compressed).hexdigest()
    if len(set(checks.values())) != 1:
        raise ValueError('compressed outputs differ between configurations')
    for _ in range(2):
        for command in commands.values():
            execute(command + options)
    rows = []
    names = list(commands)
    for round_number in range(args.repeats):
        for index in range(len(names)):
            name = names[(index + round_number) % len(names)]
            row, _ = execute(commands[name] + options)
            if row['output_sha256'] != checks[name]:
                raise ValueError(f'{name}: measured run produced a different output')
            rows.append({'round': round_number, 'variant': name, **row})
    summary = {}
    for name in names:
        summary[name] = {}
        for metric in ('wall_seconds', 'cpu_seconds', 'peak_rss_bytes'):
            values = [row[metric] for row in rows if row['variant'] == name]
            summary[name][metric] = {'median': statistics.median(values), 'min': min(values), 'max': max(values)}
    result = {'schema': 'anyps5.zstd-benchmark.v1', 'host': platform.platform(),
              'profile': {'single_thread': args.single_thread, 'workers': 0 if args.single_thread else args.workers, 'level': 3, 'warmups': 2, 'rounds': args.repeats},
              'binaries': {name: {'path': str(path), 'sha256': digest(path)} for name, path in binaries.items()},
              'arguments': options,
              'dataset': {'path': str(args.dataset.resolve()), 'sha256': digest(args.dataset), 'bytes': len(data)},
              'decoder': {'path': str(args.decoder.resolve()), 'sha256': digest(args.decoder)},
              'comparison': 'caller-supplied binaries; hashes, architecture and output equivalence checked; source and feature equivalence require separate qualification',
              'measurement': 'warm CLI end-to-end including process startup and I/O; CPU is child user+system; cold caches and pure steady-state kernel time are not established',
              'first_observed_not_cold': first, 'samples': rows, 'summary': summary,
              'aot_wall_over_rosetta': summary['aot']['wall_seconds']['median'] / summary['rosetta']['wall_seconds']['median']}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'summary': summary, 'aot_wall_over_rosetta': result['aot_wall_over_rosetta']}, indent=2))


if __name__ == '__main__':
    main()

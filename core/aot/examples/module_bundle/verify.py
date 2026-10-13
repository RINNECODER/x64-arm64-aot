import argparse
import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify(folder):
    manifest = json.loads((folder/'build.json').read_text())
    for name, expected in manifest['source_hashes'].items():
        require(digest(folder/name) == expected, 'consumer source changed')
    for name, expected in manifest['input_hashes'].items():
        require(digest(folder/(name+'.so')) == expected, 'input module changed')
    for archive, expected in manifest['runtime_archives'].items():
        require(digest(archive) == expected, 'runtime archive changed')
    for module in manifest['modules']:
        for suffix, key in (('.o', 'object_sha256'), ('.ll', 'ir_sha256'), ('.contracts.json', 'contracts_sha256')):
            require(digest(folder/'native'/(module['id']+suffix)) == module[key], 'converted module artifact changed')
    require(digest(folder/'native/registry.cpp') == manifest['registry_sha256'], 'registry source changed')
    results = {}
    for scenario in ('normal', 'fail-init'):
        runs = []
        for name in ('aot', 'reference'):
            binary = folder/name
            require(digest(binary) == manifest['binaries'][name], 'binary changed after linking')
            require(subprocess.check_output(['xcrun', 'lipo', '-archs', binary], text=True).strip() == 'arm64', 'binary is not ARM64-only')
            started = time.monotonic()
            run = subprocess.run([binary, *(['fail-init'] if scenario == 'fail-init' else [])], capture_output=True, text=True, timeout=30)
            require(run.returncode == 0, f'{name}/{scenario}: exit {run.returncode}: {run.stdout}\n{run.stderr}')
            lines = [line for line in run.stdout.splitlines() if line.startswith(('architecture=', 'input=', 'teardown=', 'rollback='))]
            require(lines and lines[0] == 'architecture=arm64 translated=0', 'native execution marker missing')
            if scenario == 'fail-init':
                require(lines == ['architecture=arm64 translated=0', 'rollback=10,20,110'], 'rollback trace mismatch')
            else:
                require(len(lines) == 10 and lines[-1] == 'teardown=130,120,110 outstanding=0', 'incomplete lifecycle or worker output')
                expected_inputs = [value for iteration in range(4) for value in (2+iteration, 100+iteration)]
                for line, value in zip(lines[1:-1], expected_inputs):
                    match = re.fullmatch(r'input=(\d+) result=(\d+) counter_zero=(\d+) worker_zero=(\d+) digest=([0-9a-f]{64})', line)
                    require(match is not None, 'invalid worker record')
                    require(tuple(map(int, match.groups()[:4])) == (value, 227+value, 0, 0), 'worker value/TLS mismatch')
                    require(match[5] == hashlib.sha256(value.to_bytes(4, 'little')).hexdigest(), 'SHA-256 differs from independent hashlib reference')
            runs.append({'binary': name, 'sha256': digest(binary), 'seconds': time.monotonic()-started,
                         'stdout': run.stdout, 'stderr': run.stderr, 'observable': lines, 'exit_code': run.returncode})
        require(runs[0]['observable'] == runs[1]['observable'], 'AOT/native reference mismatch')
        results[scenario] = runs
    return {'schema': 'anyps5.aot.module-acceptance.v1', 'build_sha256': digest(folder/'build.json'), 'runs': results,
            'scope': 'Three source-built ELF images converted separately; native production create/join providers; TLS, SHA-256, ownership guards and lifecycle.',
            'limitations': manifest['limitations']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--output-parent', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.build.resolve())
    args.output_parent.mkdir(parents=True, exist_ok=True)
    destination = Path(tempfile.mkdtemp(prefix='run-', dir=args.output_parent))/'acceptance.json'
    destination.write_text(json.dumps(result, indent=2)+'\n')
    print(destination)


if __name__ == '__main__':
    main()

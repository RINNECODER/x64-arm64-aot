import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_link(binary, manifest_path, manifest, object_name):
    path = Path(binary)
    receipt = json.loads(path.with_suffix('.link.json').read_text())
    require(receipt['binary_sha256'] == hashlib.sha256(path.read_bytes()).hexdigest(), 'linked binary changed')
    require(receipt['build_manifest_sha256'] == hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            'binary belongs to a different build manifest')
    require(receipt['object_sha256'] == manifest['hashes'][object_name], 'binary belongs to a different AOT/reference object')
    for archive, expected in receipt['runtime_archives'].items():
        require(hashlib.sha256(Path(archive).read_bytes()).hexdigest() == expected, 'runtime archive changed')
    return receipt


def verify(aot, reference):
    outcomes = {}
    for scenario, counts, presses, failure in [('edges', (8, 7, 1), 2, None), ('read-error', (9, 8, 1), 2, None),
            ('timeout', (625, 625, 1), 0, None), ('user-error', (0, 0, 0), 0, 'sceUserServiceGetInitialUser'),
            ('init-error', (0, 0, 0), 0, 'scePadInit'), ('open-error', (0, 0, 0), 0, 'scePadOpen')]:
        runs = []
        for binary in (aot, reference):
            require(subprocess.check_output(['xcrun', 'lipo', '-archs', binary], text=True).strip() == 'arm64',
                    'test binary is not ARM64-only')
            env = dict(os.environ)
            env.pop('APS5_PAD_INPUT_FILE', None)
            begin = time.monotonic()
            run = subprocess.run([binary, scenario], text=True, capture_output=True, timeout=25, env=env)
            require(run.returncode == (1 if failure else 0), f'{scenario}: bad exit: {run.returncode}: {run.stderr}')
            lines = run.stderr.splitlines()
            require('architecture=arm64 translated=0' in lines, 'native architecture not confirmed')
            require('native pad guest teardown completed' in lines, 'teardown missing')
            expected = (['[notification] pad_input: ' + failure + ' failed'] if failure else
                        ['[notification] pad_input: controller open - press CROSS, or OPTIONS to finish early'] +
                        [f'[notification] pad_input: CROSS #{index}' for index in range(1, presses + 1)] +
                        [f'[notification] pad_input: done, CROSS pressed {presses} times'])
            require([line for line in lines if line.startswith('[notification]')] == expected, 'wrong input notifications')
            require(f'input-test reads={counts[0]} sleeps={counts[1]} closes={counts[2]}' in lines, 'input lifecycle mismatch')
            runs.append({'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                         'exit_code': run.returncode, 'stderr': run.stderr, 'stdout': run.stdout,
                         'seconds': time.monotonic() - begin})
        require(runs[0]['stderr'] == runs[1]['stderr'] and runs[0]['stdout'] == runs[1]['stdout'], 'AOT/source observable mismatch')
        outcomes[scenario] = runs
    return {'schema': 'anyps5.aot.pad-input-acceptance.v1', 'cases': outcomes,
            'scope': 'Unchanged public source, AOT and independently source-compiled ARM64; deterministic input with production PadData providers.',
            'limitations': ['Initialization/user errors are test injections; read/open errors use invalid arguments to real providers.',
                            'Test sleeps are counted without delay. Production sleep requires separate smoke execution.',
                            'No physical-controller, console or performance qualification.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--aot', required=True)
    parser.add_argument('--reference', required=True)
    parser.add_argument('--build', type=Path, required=True)
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument('--output', type=Path)
    outputs.add_argument('--output-parent', type=Path)
    parser.add_argument('--production')
    args = parser.parse_args()
    if args.output_parent:
        args.output_parent.mkdir(parents=True, exist_ok=True)
        args.output = Path(tempfile.mkdtemp(prefix='run-', dir=args.output_parent)) / 'acceptance.json'
    require(not args.output.exists(), 'choose a fresh acceptance report')
    manifest = json.loads(args.build.read_text())
    for name, expected in manifest['hashes'].items():
        require(hashlib.sha256((args.build.parent / name).read_bytes()).hexdigest() == expected, 'build artifact changed: ' + name)
    links = [verify_link(binary, args.build, manifest, obj) for binary, obj in
             ((args.aot, 'module.o'), (args.reference, 'reference.o'))]
    require(links[0]['runtime_archives'] == links[1]['runtime_archives'], 'different runtime in AOT/reference comparison')
    report = verify(args.aot, args.reference)
    report['links'] = links
    report['input_sha256'] = manifest['input_sha256']
    if args.production:
        report['production_link'] = verify_link(args.production, args.build, manifest, 'module.o')
        env = dict(os.environ)
        env.pop('APS5_PAD_INPUT_FILE', None)
        begin = time.monotonic()
        run = subprocess.run([args.production], text=True, capture_output=True, timeout=25, env=env)
        elapsed = time.monotonic() - begin
        require(run.returncode == 0 and elapsed >= 10, 'production sleep/exit failed')
        require('architecture=arm64 translated=0' in run.stderr and 'native pad guest teardown completed' in run.stderr,
                'production architecture/teardown missing')
        require('pad_input: done, CROSS pressed 0 times' in run.stderr, 'production input summary missing')
        report['production'] = {'binary_sha256': hashlib.sha256(Path(args.production).read_bytes()).hexdigest(),
                                'seconds': elapsed, 'stderr': run.stderr, 'exit_code': run.returncode}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(args.output)


if __name__ == '__main__':
    main()

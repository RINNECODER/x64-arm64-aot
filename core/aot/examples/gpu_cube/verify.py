import argparse
import hashlib
import json
import os
import re
import subprocess
import time
import tempfile
from pathlib import Path

from images import compare_captured_frames, compare_frames

# The guest flips frames 0..599; the Metal capture is frame-indexed so both runs capture the same
# frames (the Vulkan path uses APS5_DUMP_FRAMES_EVERY for the same spacing).
FLIP_TOTAL = 600
CAPTURE_EVERY = 75
CAPTURE_COUNT = 8
EXPECTED_CAPTURES = list(range(0, FLIP_TOTAL, CAPTURE_EVERY))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _capture_environment(environment, folder, capture):
    if capture == 'metal':
        frames = folder / 'frames'
        frames.mkdir()
        environment.update(ANYPS5_FRAME_CAPTURE_DIR=str(frames), ANYPS5_FRAME_CAPTURE_EVERY=str(CAPTURE_EVERY),
                           ANYPS5_FRAME_CAPTURE_INTERVAL_MS='200')
    else:
        environment.update(APS5_DUMP_FRAMES=str(CAPTURE_COUNT), APS5_DUMP_FRAMES_EVERY=str(CAPTURE_EVERY),
                           APS5_DUMP_SCALE='1', APS5_CAPTURE_TRACE='1', ANYPS5_REQUIRE_VULKAN='1')


def _metal_events(output):
    events = []
    for line in output.splitlines():
        if line.startswith('{"schema_version"'):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError('unparseable Metal capture event: ' + line) from error
    return events


def run(binary, folder, reference, capture):
    folder.mkdir(parents=True, exist_ok=False)
    architecture = subprocess.check_output(['xcrun', 'lipo', '-archs', str(binary)], text=True).strip()
    require(architecture == 'arm64', 'graphics executable must be ARM64-only')
    meta = folder / 'app0/sce_sys'
    meta.mkdir(parents=True)
    (meta / 'param.json').write_text(json.dumps({'titleId': 'PPSA99999', 'localizedParameters': {
        'defaultLanguage': 'en-US', 'en-US': {'titleName': 'Native ARM64 graphics comparison'}}}))
    environment = os.environ.copy()
    unexpected = [k for k in environment if k.startswith('APS5_') or k.startswith('ANYPS5_FRAME_CAPTURE')]
    require(not unexpected, 'unset diagnostic overrides before acceptance: ' + ', '.join(unexpected))
    _capture_environment(environment, folder, capture)
    start = time.monotonic()
    with (folder / 'execution.log').open('wb') as log:
        result = subprocess.run([str(binary)], cwd=folder, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=30)
    output = (folder / 'execution.log').read_text(errors='replace')
    require(result.returncode == 0, f'graphics executable exited with {result.returncode}; see {folder / "execution.log"}')
    require('architecture=arm64 translated=0' in output, 'native execution marker missing')
    require('[notification] mesh_test: fin' in output, '600-frame source loop did not finish')
    require('native GPU guest teardown completed' in output, 'guest teardown did not run')
    require('[gpu] skipped draw:' not in output and '[metal] skipped draw' not in output, 'driver skipped a draw')
    report = {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'reference': reference,
              'seconds': time.monotonic() - start, 'architecture': architecture, 'capture': capture}
    if capture == 'metal':
        events = _metal_events(output)
        require(not [e for e in events if e.get('event') == 'frame_capture_failed'], 'the driver failed to capture a frame')
        captured = [e for e in events if e.get('event') == 'frame_captured']
        indices = [e['flip_index'] for e in captured]
        require(indices == EXPECTED_CAPTURES,
                f'captured frames {indices} do not match the expected {EXPECTED_CAPTURES}')
        presented = [e['count'] for e in events if e.get('event') == 'frames_presented']
        require(presented and presented[-1] == FLIP_TOTAL,
                f'presented frame count {presented[-1] if presented else None} does not match {FLIP_TOTAL}')
        for event in captured:
            require(Path(event['path']).is_file(), 'captured frame is missing: ' + event['path'])
        report['completed_flips'] = presented[-1]
        report['captured_frames'] = captured
    else:
        trace = (folder / 'capture-trace.log').read_text()
        flips = [int(v) for v in re.findall(r'display-flip-complete output=\d+ buffer=\d+ argument=(\d+)', trace)]
        require(flips == list(range(FLIP_TOTAL)), 'completed flip sequence does not match source frames 0 through 599')
        report['completed_flips'] = len(flips)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--aot', type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--build', type=Path)
    parser.add_argument('--paths', type=Path)
    parser.add_argument('--capture', choices=('bmp', 'metal'), default='bmp',
                        help='bmp: APS5_DUMP_FRAMES + capture-trace (Vulkan); metal: ANYPS5_FRAME_CAPTURE_DIR PNG + manifest')
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument('--output', type=Path)
    outputs.add_argument('--output-parent', type=Path)
    args = parser.parse_args()
    if args.paths:
        require(not (args.aot or args.reference or args.build), '--paths cannot be combined with explicit artifact paths')
        paths = json.loads(args.paths.read_text())
        args.aot, args.reference, args.build = (Path(paths[key]) for key in ('aot', 'reference', 'build'))
    require(args.aot and args.reference and args.build, 'both binaries and build manifest are required')
    if args.output_parent:
        args.output_parent.mkdir(parents=True, exist_ok=True)
        args.output = Path(tempfile.mkdtemp(prefix='run-', dir=args.output_parent))
    else:
        require(not args.output.exists(), 'acceptance output must be fresh')
        args.output.mkdir(parents=True)
    manifest = json.loads((args.build / 'build.json').read_text())
    for name, expected in manifest['hashes'].items():
        require(hashlib.sha256((args.build / name).read_bytes()).hexdigest() == expected, 'build artifact changed: ' + name)
    links = []
    for binary, name in ((args.aot, 'module.o'), (args.reference, 'reference.o')):
        link = json.loads(binary.with_suffix('.link.json').read_text())
        require(hashlib.sha256(binary.read_bytes()).hexdigest() == link['binary_sha256'], 'executable changed after linking')
        require(link['object_sha256'] == manifest['hashes'][name], 'executable belongs to a different object build')
        require(link['build_manifest_sha256'] == hashlib.sha256((args.build / 'build.json').read_bytes()).hexdigest(),
                'executable belongs to a different source manifest')
        links.append(link)
    require(links[0]['runtime_archives'] == links[1]['runtime_archives'], 'AOT and reference use different runtimes')
    aot = run(args.aot.resolve(), args.output / 'aot', False, args.capture)
    reference = run(args.reference.resolve(), args.output / 'reference', True, args.capture)
    if args.capture == 'metal':
        pairs = [(f'flip_{frame["flip_index"]:03d}', frame['path'], other['path'])
                 for frame, other in zip(aot['captured_frames'], reference['captured_frames'])]
        comparison = compare_captured_frames(pairs)
    else:
        comparison = compare_frames(args.output / 'aot', args.output / 'reference')
    report = {'build': manifest, 'links': links, 'runs': [aot, reference], 'comparison': comparison}
    (args.output / 'acceptance.json').write_text(json.dumps(report, indent=2) + '\n')
    require(comparison['passed'], 'graphics reference comparison failed; see acceptance.json')
    print(args.output / 'acceptance.json')


if __name__ == '__main__':
    main()

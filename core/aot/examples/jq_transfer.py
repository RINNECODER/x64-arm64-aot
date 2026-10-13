import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


CASES = [
    (['-cn', expression], '') for expression in (
        '1+2', '[range(100)] | map(. * .) | add', 'reduce range(200) as $x (0; . + $x)',
        '[range(30)] | group_by(. % 3) | map(add)', '{a: 3, b: [1, 2]} | paths',
        '[1,2,3] | combinations(2)', '[range(20)] | reverse | sort',
        '"àé日本語" | explode | implode', '"abc\\u0000xyz" | @base64 | @base64d',
        '[range(25)] | map(select(. % 2 == 0))', '[1,2,3] | reduce .[] as $x ([]; . + [$x])',
        'try error("expected") catch .', 'def factorial: if . < 2 then 1 else . * ((.-1)|factorial) end; 8|factorial',
        '1e300 + 1e300', '1e-300 * 1e-10', '[nan, infinite, -infinite]',
        '9 | sqrt',
        'pow(2;10)', '[(-3.25 | modf), (12 | frexp)]', '0 | gmtime',
        '"2024-02-29T12:34:56Z" | fromdateiso8601 | todateiso8601',
        '[1,2,3] | tostream | fromstream(1|truncate_stream(inputs))',
    )
]
CASES += [
    (['-c', '.items | sort_by(.n) | map(.s)'], '{"items":[{"n":2,"s":"b"},{"n":1,"s":"a"}]}'),
    (['-c', '.["😀"]'], '{"😀":"value"}'),
    (['-cn', '--arg', 'x', 'a b', '$x'], ''),
    (['-cn', '--argjson', 'x', '{"n":3}', '$x.n'], ''),
    (['-c', '.'], '{"invalid":'),
    (['-cn', 'invalid('], ''),
    (['-en', 'false'], ''),
    (['-en', 'empty'], ''),
    (['-Rs', 'split("\\n")'], 'a\nb\n'),
    (['-s', 'add'], '1\n2\n3\n'),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(binary, arguments, data):
    environment = dict(os.environ, LC_ALL='C', TZ='UTC')
    result = subprocess.run([str(binary), *arguments], input=data.encode(), capture_output=True, timeout=20, env=environment)
    return result.returncode, result.stdout, result.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--aot', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('choose a new receipt path')
    binaries = [args.aot.resolve(), args.reference.resolve()]
    results = []
    for index, (arguments, data) in enumerate(CASES):
        actual, expected = [execute(binary, arguments, data) for binary in binaries]
        results.append({'case': index, 'arguments': arguments, 'input': data, 'equal': actual == expected,
                        'exit': actual[0], 'stdout_sha256': hashlib.sha256(actual[1]).hexdigest(),
                        'stderr_sha256': hashlib.sha256(actual[2]).hexdigest()})
        if actual != expected:
            results[-1]['actual'] = [actual[0], actual[1].decode(errors='replace'), actual[2].decode(errors='replace')]
            results[-1]['expected'] = [expected[0], expected[1].decode(errors='replace'), expected[2].decode(errors='replace')]
    receipt = {'schema': 'anyps5.jq-transfer.v1', 'binaries': [{'path': str(p), 'sha256': digest(p)} for p in binaries],
               'cases': results, 'passed': sum(r['equal'] for r in results), 'total': len(results),
               'claim': 'adapted source-equivalent CLI transfer, not an unseen holdout or console compatibility'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'{receipt["passed"]}/{receipt["total"]} cases match output, errors and exit status')
    raise SystemExit(0 if receipt['passed'] == receipt['total'] else 1)


if __name__ == '__main__':
    main()

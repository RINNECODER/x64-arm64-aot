import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--build', type=Path, required=True)
    parser.add_argument('--archive', type=Path, action='append', default=[])
    args = parser.parse_args()
    manifest = json.loads(args.build.read_text())
    actual = digest(args.object)
    if manifest['hashes'][args.object.name] != actual:
        raise ValueError('linked object no longer matches its build manifest')
    result = {'binary_sha256': digest(args.binary), 'object_sha256': actual,
              'input_sha256': manifest['input_sha256'], 'build_manifest_sha256': digest(args.build),
              'runtime_archives': {str(path.resolve()): digest(path) for path in args.archive}}
    args.binary.with_suffix('.link.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

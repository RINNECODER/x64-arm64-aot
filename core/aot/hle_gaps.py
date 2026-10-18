"""Report the guest imports a native image cannot bind to an HLE implementation.

The native runtime binds a guest import by symbol name: the compiler emits a direct call to the HLE
entry point, and `tools/native/stub_undefined.sh` lowers an import that no runtime archive defines to
a bare `ret` (or, for a name the host C library also defines, to a trampoline to it). Both fallbacks
are silent: the guest call returns zero and the boot continues with the wrong value. This module
classifies every import in a contracts file against the symbols a native image links, so a missing
HLE implementation is a named gap instead of a count.

`resolve_import_name` mirrors the naming rule in `tools/native/title_image.py`. The two must agree;
`core/aot/tests/test_hle_gaps.py` drives `title_image.py` itself to keep them equal.

usage: hle_gaps.py --contracts <contracts.json> --symbols <nm output|one name per line>
                   [--host-symbols <same>] [--json <path>] [--limit N]
"""
import argparse
import json
import sys

POSTFIX = '_nid_postfix'
GUEST_PREFIX = '__aps5_guest_'


def resolve_import_name(name, symbols):
    """The symbol the compiler emits a call to for a guest import called `name`.

    A runtime that defines `<name>_nid_postfix` or `<name>` serves the import directly; anything
    else is namespaced so the stub generator can lower it without interposing on libSystem.
    """
    if name + POSTFIX in symbols:
        return name + POSTFIX
    if name in symbols:
        return name
    return GUEST_PREFIX + name


def read_symbols(path):
    """A symbol set from `nm -g` output or from one bare name per line."""
    symbols = set()
    for line in open(path, 'r', errors='replace'):
        fields = line.split()
        if len(fields) >= 3 and fields[1] in ('T', 'D', 'B', 'S', 'W'):
            symbols.add(fields[2][1:] if fields[2].startswith('_') else fields[2])
        elif len(fields) == 1:
            symbols.add(fields[0])
    return symbols


def classify(imports, symbols, host_symbols=frozenset()):
    """Split the contracts' imports by how the native image will bind each one.

    `bound` is served by the runtime, `host` is deliberately routed to the host C library, and
    `unbound` is a bare `ret`: split into the ones the contract already declares as a stub and the
    typed ones, which are the HLE gaps a caller has to close.
    """
    report = {'bound': [], 'host': [], 'declared': [], 'gaps': []}
    for key, contract in sorted(imports.items()):
        name = contract['name']
        record = {'nid': key.split('#', 1)[0], 'name': name,
                  'emitted': resolve_import_name(name, symbols)}
        if record['emitted'] != GUEST_PREFIX + name:
            report['bound'].append(record)
        elif name in host_symbols:
            report['host'].append(record)
        elif contract.get('stub'):
            report['declared'].append(record)
        else:
            report['gaps'].append(record)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Report the HLE gaps of a native title image.')
    parser.add_argument('--contracts', required=True)
    parser.add_argument('--symbols', required=True, help='nm output for every archive the image links')
    parser.add_argument('--host-symbols', help='host C library symbols; names bound there are not gaps')
    parser.add_argument('--json', help='write the full report here')
    parser.add_argument('--limit', type=int, default=40, help='gap names printed')
    args = parser.parse_args(argv)
    contracts = json.loads(open(args.contracts).read())
    host = read_symbols(args.host_symbols) if args.host_symbols else frozenset()
    report = classify(contracts['imports'], read_symbols(args.symbols), host)
    total = sum(len(report[key]) for key in report)
    print('imports %d: bound %d, host-routed %d, contract stubs %d, HLE gaps %d' % (
        total, len(report['bound']), len(report['host']), len(report['declared']), len(report['gaps'])))
    for record in report['gaps'][:args.limit]:
        print('  gap %s %s' % (record['nid'], record['name']))
    if len(report['gaps']) > args.limit:
        print('  ... %d more' % (len(report['gaps']) - args.limit))
    if args.json:
        with open(args.json, 'w') as handle:
            json.dump(report, handle, indent=1)
    return 1 if report['gaps'] else 0


if __name__ == '__main__':
    sys.exit(main())

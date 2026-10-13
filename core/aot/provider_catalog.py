import copy
import hashlib
import json

from abi import signature
from contract_recipe import verify_structured_sources
from dynamic import parse_dynamic
from effects import validate_provider
from pointer_outputs import validate as validate_outputs
from recover import load_elf, read_address


SCHEMA = 'anyps5.aot.provider-catalog.v1'
IDENTITY_FIELDS = ('nid', 'library', 'library_version', 'module', 'module_version')
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def decode_id(text):
    require(isinstance(text, str) and 1 <= len(text) <= 3 and all(c in ALPHABET for c in text),
            'invalid import identity index')
    value = 0
    for char in text:
        value = value * 64 + ALPHABET.index(char)
    require(value <= 65535 and (len(text) == 1 or text[0] != 'A'), 'noncanonical import identity index')
    return value


def identity_key(value):
    require(isinstance(value, dict) and set(value) == set(IDENTITY_FIELDS), 'incomplete provider identity')
    for field in ('nid', 'library', 'module'):
        require(isinstance(value[field], str) and bool(value[field]), f'invalid provider {field}')
    for field in ('library_version', 'module_version'):
        require(type(value[field]) is int and 0 <= value[field] <= 65535, f'invalid provider {field}')
    return tuple(value[field] for field in IDENTITY_FIELDS)


def imported_functions(source):
    raw, elf = load_elf(source)
    dynamic = parse_dynamic(elf, lambda address, size: read_address(elf, address, size))
    imports = {}
    for relocation in dynamic['relocations']:
        if relocation['kind'] in (0, 8):
            continue
        require(relocation['kind'] in (6, 7) and relocation['addend'] == 0,
                f'non-function relocation at 0x{relocation["slot"]:x} needs separate qualification')
        symbol = dynamic['symbols'][relocation['symbol_index']]
        name = symbol['name']
        require(symbol['section'] == 0 and symbol['info'] == 0x12 and symbol['other'] == 0,
                f'{name}: require strong undefined function with default visibility')
        parts = name.split('#')
        require(len(parts) == 3, f'{name}: missing SCE provider identity')
        nid, library, module = parts
        lib = dynamic['identities']['libraries'].get(decode_id(library))
        mod = dynamic['identities']['modules'].get(decode_id(module))
        require(lib is not None and mod is not None, f'{name}: unresolved library/module identity')
        identity = {'nid': nid, 'library': lib['name'], 'library_version': lib['version'],
                    'module': mod['name'], 'module_version': mod['version']}
        identity_key(identity)
        item = imports.setdefault(name, {'identity': identity, 'slots': []})
        item['slots'].append(relocation['slot'])
    return hashlib.sha256(raw).hexdigest(), imports


def resolve_imports(source, catalog, source_root, target='apple-arm64'):
    require(isinstance(catalog, dict) and set(catalog) == {'schema', 'target', 'entries'}, 'invalid catalog fields')
    require(catalog['schema'] == SCHEMA and catalog['target'] == target, 'catalog schema or target mismatch')
    require(isinstance(catalog['entries'], list), 'catalog entries must be a list')
    entries = {}
    for entry in catalog['entries']:
        require(isinstance(entry, dict) and set(entry) == {'identity', 'contract', 'sources', 'facts_sha256'},
                'invalid catalog entry fields')
        key = identity_key(entry['identity'])
        require(key not in entries, 'ambiguous provider catalog identity')
        facts = {key: value for key, value in entry.items() if key != 'facts_sha256'}
        require(entry['facts_sha256'] == digest(facts), 'provider facts changed; requalification required')
        require(isinstance(entry['sources'], list) and entry['sources'], 'provider source evidence required')
        for evidence in entry['sources']:
            require(isinstance(evidence, dict) and set(evidence) == {'path', 'sha256', 'excerpt'},
                    'provider evidence requires path, hash and declaration')
        entries[key] = entry
    input_sha, observed = imported_functions(source)
    resolved, reused, missing = {}, [], []
    root = source_root.resolve()
    for symbol, observation in observed.items():
        entry = entries.get(identity_key(observation['identity']))
        if entry is None:
            missing.append({'symbol': symbol, **observation})
            continue
        verify_structured_sources(entry['sources'], root)
        verify_structured_sources(entry['contract'], root)
        signature(entry['contract'])
        validate_provider(entry['contract'])
        validate_outputs(entry['contract'])
        resolved[symbol] = copy.deepcopy(entry['contract'])
        reused.append({'symbol': symbol, **observation, 'facts_sha256': entry['facts_sha256']})
    report = {'schema': 'anyps5.aot.provider-resolution.v1', 'input_sha256': input_sha,
              'catalog_sha256': digest(catalog), 'target': target, 'reused': reused, 'missing': missing,
              'limitations': ['Source identities bind reviewed facts; hashes do not prove their semantics.',
                              'Guest pointer lifetime, call preconditions and function ABIs remain separate obligations.',
                              'Final executable linkage and compiler binding guards still require verification.']}
    return resolved, report


def require_complete(report):
    require(not report['missing'], 'provider qualification required: ' + json.dumps(report['missing'], sort_keys=True))

import argparse
import copy
import hashlib
import json
from pathlib import Path

from capstone.x86 import X86_OP_MEM

from compiler import Image


SCHEMA = 'anyps5.aot.guard-recipe.v1'
FIELDS = ('checked_pointer_bases', 'checked_pointer_arguments')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fact_digest(contracts, policies):
    data = json.dumps({'contracts': contracts, 'policies': policies}, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(data.encode()).hexdigest()


def check_policy(policy, arguments):
    fields = {'bytes', 'evidence', 'nullable'} if arguments else {'bytes', 'evidence'}
    require(isinstance(policy, dict) and set(policy) == fields, 'guard policy has unknown or missing fields')
    require(type(policy['bytes']) is int and 1 <= policy['bytes'] <= 65536, 'guard extent must be bounded')
    require(isinstance(policy['evidence'], str) and policy['evidence'].strip(), 'guard policy needs qualification evidence')
    if arguments:
        require(type(policy['nullable']) is bool, 'argument nullability must be boolean')


def verify_structured_sources(value, root):
    if isinstance(value, dict):
        if 'path' in value and 'sha256' in value:
            name = value['path']
            require(isinstance(name, str) and name and not Path(name).is_absolute(), 'source path must be relative')
            path = (root / name).resolve()
            require(path.is_relative_to(root), 'source path escapes root')
            require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == value['sha256'],
                    f'source changed; requalification required: {name}')
            if 'excerpt' in value:
                require(isinstance(value['excerpt'], str) and value['excerpt'] and value['excerpt'] in path.read_text(),
                        f'source declaration absent: {name}')
        for item in value.values():
            verify_structured_sources(item, root)
    elif isinstance(value, list):
        for item in value:
            verify_structured_sources(item, root)


def materialize(source, recipe, source_root):
    require(isinstance(recipe, dict) and set(recipe) == {'schema', 'contracts', 'policies', 'qualification'},
            'guard recipe has unknown or missing fields')
    require(recipe['schema'] == SCHEMA, 'unsupported guard recipe schema')
    contracts, policies, qualification = (recipe[key] for key in ('contracts', 'policies', 'qualification'))
    require(isinstance(policies, dict) and set(policies) == set(FIELDS), 'both guard policies must be explicit')
    for key in FIELDS:
        check_policy(policies[key], key == 'checked_pointer_arguments')
    require(isinstance(qualification, dict) and set(qualification) == {'facts_sha256', 'sources'},
            'guard qualification requires a fact digest and source identities')
    require(qualification['facts_sha256'] == fact_digest(contracts, policies),
            'declared facts or guard policies changed; requalification required')
    sources = qualification['sources']
    require(isinstance(sources, list) and sources, 'guard qualification requires source identities')
    root = Path(source_root).resolve()
    seen = set()
    for evidence in sources:
        require(isinstance(evidence, dict) and set(evidence) == {'path', 'sha256'}, 'invalid source identity')
        name = evidence['path']
        require(isinstance(name, str) and name and not Path(name).is_absolute(), 'source path must be relative')
        path = (root / name).resolve()
        require(path.is_relative_to(root) and path not in seen, 'source path escapes root or repeats')
        seen.add(path)
        require(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == evidence['sha256'],
                f'source changed; requalification required: {name}')
    verify_structured_sources(contracts, root)
    output = copy.deepcopy(contracts)
    for spec in output['functions']:
        require(not any(key in spec for key in FIELDS), f'{spec["name"]}: derived guard sites must not be supplied')
    image = Image(source, output)
    summaries = []
    for spec in output['functions']:
        instructions = list(image.decoder.disasm(image.read(spec['address'], spec['size']), spec['address']))
        require(sum(ins.size for ins in instructions) == spec['size'], f'{spec["name"]}: incomplete instruction decoding')
        bases, arguments = [], []
        for ins in instructions:
            if ins.mnemonic == 'call':
                try:
                    callee, _ = image.call(ins, spec)
                except ValueError as error:
                    raise ValueError(f'{spec["name"]} at 0x{ins.address:x}: call ABI/target obligation: {error}') from error
                for index, parameter in enumerate(callee['parameters']):
                    if parameter == 'ptr':
                        policy = policies['checked_pointer_arguments']
                        arguments.append({'address': ins.address, 'parameter': index, 'bytes': policy['bytes'],
                                          'nullable': policy['nullable'],
                                          'evidence': policy['evidence'].replace('{callee}', callee['name'])})
            if ins.mnemonic in ('lea', 'nop'):
                continue
            for index, operand in enumerate(ins.operands):
                if operand.type != X86_OP_MEM:
                    continue
                base = ins.reg_name(operand.mem.base)
                if not base or base in ('rsp', 'rbp', 'rip'):
                    continue
                require(ins.addr_size == 8 and not operand.mem.segment,
                        f'{spec["name"]} at 0x{ins.address:x}: unsupported address domain')
                bases.append({'address': ins.address, 'operand': index, **policies['checked_pointer_bases']})
        spec['checked_pointer_bases'] = bases
        spec['checked_pointer_arguments'] = arguments
        summaries.append({'name': spec['name'], 'decoded_instructions': len(instructions),
                          'derived_bases': len(bases), 'derived_arguments': len(arguments),
                          'remaining_site_annotations': {key: len(spec.get(key, [])) for key in
                              ('checked_pointer_loads', 'checked_stack_accesses', 'checked_frame_exclusion')}})
    report = {'schema': 'anyps5.aot.guard-derivation.v1', 'input_sha256': output['sha256'],
              'facts_sha256': qualification['facts_sha256'], 'sources': copy.deepcopy(sources),
              'declared_function_abis': len(output['functions']), 'declared_import_abis': len(output['imports']),
              'functions': summaries,
              'derived_sites': {key: sum(len(spec[key]) for spec in output['functions']) for key in FIELDS},
              'limitations': ['ABI, object layout, lifetime and native-address assumptions remain declared.',
                              'Mapping guards do not establish object identity, extent or lifetime.',
                              'Derivation counts expanded records, not independent manual facts or binary coverage.',
                              'The generated contracts still require full compiler validation.']}
    return output, report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('--recipe', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists() and not args.output.with_suffix('.derivation.json').exists(),
            'choose fresh contract and report output paths')
    contracts, report = materialize(args.input, json.loads(args.recipe.read_text()), args.source_root)
    args.output.write_text(json.dumps(contracts, indent=2) + '\n')
    args.output.with_suffix('.derivation.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

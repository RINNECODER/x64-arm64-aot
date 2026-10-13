from elf_segments import runtime_segments
import copy
import hashlib
import json
import re
from pathlib import Path

from calls import structural_signature
from contract_recipe import SCHEMA as RECIPE_SCHEMA, fact_digest, materialize, verify_structured_sources, check_policy
from compiler import Image, compile_image
from dynamic import parse_dynamic
from provider_catalog import decode_id
from recover import load_elf, read_address
from toolchain import build_native_object
import module_tls


SCHEMA = 'anyps5.aot.bundle.v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(dynamic, symbol, exported, owner):
    name = symbol['name']
    if '#' not in name:
        return ('elf', owner, name)
    parts = name.split('#')
    require(len(parts) == 3, 'invalid SCE symbol identity')
    prefix = 'export_' if exported else ''
    libraries = dynamic['identities'][prefix + 'libraries']
    modules = dynamic['identities'][prefix + 'modules']
    lib, mod = libraries.get(decode_id(parts[1])), modules.get(decode_id(parts[2]))
    require(lib is not None and mod is not None, 'missing SCE library/module identity')
    return ('sce', parts[0], lib['name'], lib['version'], mod['name'], mod['version'])


def plan_bundle(specification, root):
    require(isinstance(specification, dict) and set(specification) == {'schema', 'main', 'modules'}, 'invalid bundle fields')
    require(specification['schema'] == SCHEMA and isinstance(specification['modules'], list)
            and 0 < len(specification['modules']) <= 64, 'unsupported bundle schema or module count')
    root = Path(root).resolve()
    modules = {}
    for record in specification['modules']:
        require(isinstance(record, dict) and set(record) in ({'id', 'version', 'input', 'contracts', 'dependencies'},
                {'id', 'version', 'input', 'contracts', 'dependencies', 'guards'}), 'invalid module fields')
        name = record['id']
        require(isinstance(name, str) and len(name) <= 128 and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name) and name not in modules,
                'invalid or duplicate module id')
        require(type(record['version']) is int and 0 <= record['version'] <= 65535, 'invalid module version')
        paths = []
        for key in ('input', 'contracts'):
            require(isinstance(record[key], str) and not Path(record[key]).is_absolute(), 'bundle paths must be relative')
            path = (root / record[key]).resolve()
            require(path.is_relative_to(root) and path.is_file(), 'bundle path escapes root or is absent')
            paths.append(path)
        source, contract_path = paths
        contracts = json.loads(contract_path.read_text())
        guards = record.get('guards')
        if guards is not None:
            require(isinstance(guards, dict) and set(guards) == {'policies', 'facts_sha256', 'sources'}, 'invalid module guard qualification')
            require(guards['facts_sha256'] == fact_digest(contracts, guards['policies']), 'module guard facts changed')
            require(set(guards['policies']) == {'checked_pointer_bases', 'checked_pointer_arguments'}, 'invalid module guard policies')
            for key, policy in guards['policies'].items():
                check_policy(policy, key == 'checked_pointer_arguments')
            require(isinstance(guards['sources'], list) and guards['sources'], 'module guards need source identities')
            verify_structured_sources(guards['sources'], root)
        raw, elf = load_elf(source)
        require(hashlib.sha256(raw).hexdigest() == contracts.get('sha256'), 'bundle input/contract identity mismatch')
        dynamic = parse_dynamic(elf, lambda a, size: read_address(elf, a, size), include_exports=True)
        require(not any(tag in dynamic['tags'] for tag in ('DT_VERSYM', 'DT_VERDEF', 'DT_VERNEED')),
                'GNU symbol versioning needs separate qualification')
        tls_contract = dict(contracts, module_image=True, native_namespace='aps5_' + name + '_')
        tls = module_tls.layout(elf, raw, tls_contract)
        modules[name] = {'tls': tls, 'record': record, 'source': source, 'contracts': contracts, 'dynamic': dynamic,
                         'namespace': 'aps5_' + name + '_', 'exports': {},
                         'relro': [(seg['p_vaddr'], seg['p_vaddr'] + seg['p_memsz']) for seg in runtime_segments(elf)
                                   if seg['p_type'] == 'PT_GNU_RELRO']}
    require(specification['main'] in modules, 'bundle main module is absent')
    visited, active, ordered = set(), set(), []
    sonames = {}
    for name, module in modules.items():
        soname = module['dynamic']['soname'] or Path(module['record']['input']).name
        require(soname not in sonames, 'duplicate bundle SONAME')
        sonames[soname] = name

    def visit(name):
        require(name not in active, 'cyclic module dependency graph')
        if name in visited:
            return
        active.add(name)
        dependencies = modules[name]['record']['dependencies']
        require(isinstance(dependencies, dict), 'module dependencies must be a versioned mapping')
        for dependency, version in dependencies.items():
            require(dependency in modules and type(version) is int and modules[dependency]['record']['version'] == version,
                    'missing module or dependency version mismatch')
            visit(dependency)
        needed = modules[name]['dynamic']['needed']
        require(all(file in sonames for file in needed) and {sonames[file] for file in needed} == set(dependencies),
                'DT_NEEDED differs from the qualified graph')
        active.remove(name)
        visited.add(name)
        ordered.append(name)

    visit(specification['main'])
    require(visited == set(modules), 'bundle contains unreachable modules')
    global_exports = set()
    for name, module in modules.items():
        contracts, dynamic = module['contracts'], module['dynamic']
        functions = {f['address']: f for f in contracts['functions']}
        for symbol in dynamic['symbols'][1:]:
            if not symbol['section'] or symbol['other'] in (2, 3):
                continue
            require(symbol['info'] >> 4 == 1 and symbol['other'] == 0, 'bundle exports require strong default-visible definitions')
            require(0 < len(symbol['name'].encode()) < 256, 'module export name exceeds runtime bounds')
            key = identity(dynamic, symbol, True, name)
            require(key not in module['exports'], 'ambiguous module export identity')
            global_key = ('elf', symbol['name']) if key[0] == 'elf' else key
            require(global_key not in global_exports, 'interposed or duplicate default-visible export requires qualification')
            global_exports.add(global_key)
            kind = symbol['info'] & 15
            if kind == 2:
                require(symbol['value'] in functions, 'exported function has no qualified ABI')
                item = {'kind': 'function', 'contract': functions[symbol['value']],
                        'native': module['namespace'] + functions[symbol['value']]['name']}
            elif kind == 1:
                require(symbol['size'] > 0, 'data export needs a bounded ELF object')
                item = {'kind': 'data', 'address': symbol['value'], 'size': symbol['size'],
                        'native': module['namespace'] + 'object_' + str(symbol['value']) + '_' + str(symbol['size'])}
            elif kind == 6:
                tls = module['tls']
                require(tls is not None and 0 <= symbol['value'] < tls['bytes'] and 0 < symbol['size'] <= tls['bytes'] - symbol['value'],
                        'TLS export exceeds its qualified template')
                item = {'kind': 'tls', 'offset': symbol['value'], 'size': symbol['size'], 'bytes': tls['bytes'],
                        'descriptor': tls['name'], 'native': module['namespace'] + 'tls_object_' + str(symbol['value']) + '_' + str(symbol['size'])}
            else:
                require(False, 'untyped module export requires separate lowering')
            item['symbol'] = symbol['name']
            module['exports'][key] = item
    planned = []
    for name in ordered:
        module = modules[name]
        contracts = copy.deepcopy(module['contracts'])
        require(not contracts.get('native_namespace'), 'module namespace already assigned')
        contracts['native_namespace'] = module['namespace']
        contracts['module_image'] = True
        contracts['bundle_main'] = name == specification['main']
        contracts['lifecycle'] = {'owner': 'bundle'}
        immutable = contracts.setdefault('immutable_data', [])
        selected = {row['address'] for row in immutable}
        for data in contracts['data']:
            if data['address'] not in selected and any(a <= data['address'] and data['address'] + data['size'] <= b for a, b in module['relro']):
                immutable.append({'address': data['address'], 'evidence': 'Complete input PT_LOAD covered by PT_GNU_RELRO; closed AOT binding initialized before guest execution.'})
        require(not contracts.get('native_runtime_registration') or name == specification['main'],
                'only the main module may own process parameters')
        for function in contracts['functions']:
            function['name'] = module['namespace'] + function['name']
        bindings = []
        local_data = [(r['slot'], module['dynamic']['symbols'][r['symbol_index']]['value'])
                      for r in module['dynamic']['relocations'] if r['kind'] == 6
                      and module['dynamic']['symbols'][r['symbol_index']]['section']
                      and module['dynamic']['symbols'][r['symbol_index']]['info'] & 15 == 1]
        contracts['pointer_relocations'] = [*contracts['pointer_relocations'], *local_data]
        external, tls_imports = {}, {}
        for symbol in module['dynamic']['symbols'][1:]:
            if symbol['section']:
                continue
            require(symbol['info'] >> 4 == 1 and symbol['other'] == 0, 'bundle imports require strong default-visible symbols')
            candidates = []
            for dependency in modules:
                key = identity(module['dynamic'], symbol, False, dependency)
                item = modules[dependency]['exports'].get(key)
                if item is not None:
                    candidates.append((dependency, item))
            if not candidates:
                require(symbol['name'] in contracts['imports'], 'unresolved module import: ' + symbol['name'])
                host = contracts['imports'][symbol['name']]
                evidence = host.get('host_binding_evidence')
                require(host.get('native_binding_qualification') or (isinstance(evidence, str) and evidence.strip()),
                        'host import requires explicit binding qualification: ' + symbol['name'])
                continue
            require(len(candidates) == 1, 'ambiguous bundle import: ' + symbol['name'])
            dependency, target = candidates[0]
            if target['kind'] == 'function':
                require(symbol['info'] & 15 in (0, 2), 'function/data module kind mismatch')
                expected = contracts['imports'].get(symbol['name'])
                require(expected is not None and structural_signature(expected) == structural_signature(target['contract']),
                        'cross-module function ABI mismatch')
                expected['name'] = target['native']
                expected.pop('memory_effects', None)
                expected.pop('pointer_outputs', None)
            elif target['kind'] == 'tls':
                require(symbol['info'] & 15 == 6, 'TLS module kind mismatch')
                declared = contracts.get('tls_imports', {}).get(symbol['name'])
                require(isinstance(declared, dict) and set(declared) == {'size', 'evidence'} and declared['size'] == target['size']
                        and isinstance(declared['evidence'], str) and declared['evidence'].strip(), 'TLS layout requires matching qualification')
                tls_imports[symbol['name']] = {'name': target['descriptor'], 'offset': target['offset'], 'size': target['size'],
                                               'bytes': target['bytes'], 'evidence': declared['evidence']}
            else:
                require(symbol['info'] & 15 == 1, 'function/data module kind mismatch')
                declared = contracts.get('data_imports', {}).get(symbol['name'])
                require(declared is not None and declared['size'] == target['size'] and declared.get('evidence'),
                        'cross-module data layout requires matching qualification')
                external[symbol['name']] = dict(declared, name=target['native'])
            bindings.append({'symbol': symbol['name'], 'module': dependency, 'native': target['native'], 'kind': target['kind']})
        contracts['data_imports'] = external
        contracts['tls_imports'] = tls_imports
        planned.append({'id': name, 'source': module['source'], 'contracts': contracts,
                        'exports': list(module['exports'].values()), 'bindings': bindings, 'guards': module['record'].get('guards')})
    return planned


def compile_bundle(specification, root, destination):
    destination = Path(destination)
    require(not destination.exists(), 'bundle output must be fresh')
    modules = plan_bundle(specification, root)
    destination.mkdir(parents=True)
    results = []
    for module in modules:
        if module['guards'] is not None:
            guards = module['guards']
            recipe = {'schema': RECIPE_SCHEMA, 'contracts': module['contracts'], 'policies': guards['policies'],
                      'qualification': {'facts_sha256': fact_digest(module['contracts'], guards['policies']), 'sources': guards['sources']}}
            module['contracts'], module['guard_derivation'] = materialize(module['source'], recipe, root)
        image = Image(module['source'], module['contracts'])
        ir, report = compile_image(image)
        module['lifecycle'] = image.module_lifecycle
        module['tls'] = image.tls_layout
        aliases = []
        for export in module['exports']:
            if export['kind'] == 'data':
                aliases.append(f"@{export['native']} = alias i8, ptr {image.pointer(export['address'], export['size'])}")
            elif export['kind'] == 'tls':
                aliases.append(f"@{export['native']} = constant {{ ptr, i64 }} {{ ptr @{export['descriptor']}, i64 {export['offset']} }}, align 8")
        ir += '\n' + '\n'.join(dict.fromkeys(aliases)) + '\n'
        output = destination / module['id']
        output.with_suffix('.ll').write_text(ir)
        report['native_object'] = build_native_object(ir, output.with_suffix('.o'))
        report['bindings'] = module['bindings']
        report['guard_derivation'] = module.get('guard_derivation')
        output.with_suffix('.contracts.json').write_text(json.dumps(module['contracts'], indent=2) + '\n')
        output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
        results.append({'id': module['id'], 'input_sha256': image.contracts['sha256'],
                        'object_sha256': hashlib.sha256(output.with_suffix('.o').read_bytes()).hexdigest(),
                        'bindings': module['bindings'],
                        'contracts_sha256': hashlib.sha256(output.with_suffix('.contracts.json').read_bytes()).hexdigest(),
                        'ir_sha256': hashlib.sha256(output.with_suffix('.ll').read_bytes()).hexdigest()})
    (destination / 'registry.cpp').write_text(registry_source(specification, modules))
    return {'schema': SCHEMA, 'main': specification['main'], 'modules': results,
            'registry_sha256': hashlib.sha256((destination / 'registry.cpp').read_bytes()).hexdigest()}


def registry_source(specification, modules):
    types = {'ptr': 'void*', 'void': 'void', 'f32': 'float', 'f64': 'double'}
    types.update({prefix + str(width): 'std::' + ('u' if prefix == 'u' else '') + f'int{width}_t'
                  for prefix in ('i', 'u') for width in (8, 16, 32, 64)})
    lines = ['#include "prx/libc/include/NativeAotBundle.hpp"', '#include <array>', 'extern "C" {']
    for module in modules:
        prefix = module['contracts']['native_namespace']
        for data in module['contracts']['data']:
            lines.append(f"extern const unsigned char {prefix}data_{data['address']:x}[];")
        for function in module['contracts']['functions']:
            arguments = ', '.join(types[kind] for kind in function['parameters'])
            lines.append(f"{types[function['result']]} {function['name']}({arguments});")
        if module.get('tls'):
            lines.append(f"extern GuestTlsDescriptor {module['tls']['name']};")
        for export in module['exports']:
            if export['kind'] == 'tls':
                lines.append(f"extern const GuestTlsIndex {export['native']};")
            elif export['kind'] == 'data':
                lines.append(f"extern unsigned char {export['native']}[];")
    lines += ['}', 'namespace {']
    positions = {module['id']: i for i, module in enumerate(modules)}
    records = {r['id']: r for r in specification['modules']}
    for module in modules:
        name, prefix = module['id'], module['contracts']['native_namespace']
        data = module['contracts']['data']
        lines.append(f'static const std::array<NativeAotDataRange, {len(data)}> {name}_ranges{{{{')
        lines += [f"    {{{prefix}data_{row['address']:x}, {row['size']}}}," for row in data]
        lines.append('}};')
        exports = module['exports']
        lines.append(f'static const std::array<NativeAotModuleExport, {len(exports)}> {name}_exports{{{{')
        for export in exports:
            kind = {'function': 1, 'data': 2, 'tls': 3}[export['kind']]
            pointer = 'reinterpret_cast<const void*>(&' + export['native'] + ')' if kind == 1 else ('&' + export['native'] if kind == 3 else export['native'])
            lines.append(f"    {{{json.dumps(export['symbol'])}, {pointer}, {export.get('size', 0)}, {kind}}},")
        lines.append('}};')
        functions = module['contracts']['functions']
        lines.append(f'static const std::array<const void*, {len(functions)}> {name}_functions{{{{')
        lines += [f"    reinterpret_cast<const void*>(&{function['name']})," for function in functions]
        lines.append('}};')
        entries = [f['name'] for f in functions if f['result'] == 'ptr' and f['parameters'] == ['ptr'] and not f.get('noreturn')
                   and f.get('guest_calling_convention', 'x86_64-sysv') == 'x86_64-sysv'
                   and 'guest_locations' not in f and 'guest_return_register' not in f]
        lines.append(f'static const std::array<const void*, {len(entries)}> {name}_thread_entries{{{{')
        lines += [f'    reinterpret_cast<const void*>(&{entry}),' for entry in entries]
        lines.append('}};')
        for stage in ('preinit', 'init', 'fini'):
            callbacks = module.get('lifecycle', {}).get(stage, [])
            lines.append(f'static const std::array<NativeAotLifecycleFunction, {len(callbacks)}> {name}_{stage}{{{{')
            lines += [f'    &{callback},' for callback in callbacks]
            lines.append('}};')
        dependencies = records[name]['dependencies']
        lines.append(f'static const std::array<NativeAotModuleDependency, {len(dependencies)}> {name}_dependencies{{{{')
        lines += [f'    {{{positions[dependency]}, {version}}},' for dependency, version in dependencies.items()]
        lines.append('}};')
    lines.append(f'static const std::array<NativeAotModule, {len(modules)}> modules{{{{')
    for module in modules:
        name = module['id']
        tls = module.get('tls')
        tls_pointer = '&' + tls['name'] if tls else 'nullptr'
        tls_bytes = tls['bytes'] if tls else 0
        lines.append(f'    {{3, "{name}", {records[name]["version"]}, {name}_ranges.data(), {name}_ranges.size(), '
                     f'{name}_exports.data(), {name}_exports.size(), {name}_dependencies.data(), {name}_dependencies.size(), '
                     f'{name}_functions.data(), {name}_functions.size(), '
                     f'{name}_preinit.data(), {name}_preinit.size(), {name}_init.data(), {name}_init.size(), {name}_fini.data(), {name}_fini.size(), {tls_pointer}, {tls_bytes}, {name}_thread_entries.data(), {name}_thread_entries.size()}},')
    lines += ['}};', '}', 'extern "C" NativeAotBundleRegistry* NativeAotCompiledBundle_nid_no_patch() {',
              f'    static NativeAotBundleRegistry registry(modules, {positions[specification["main"]]});',
              '    return &registry;', '}']
    return '\n'.join(lines) + '\n'


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    specification = json.loads(args.manifest.read_text())
    report = compile_bundle(specification, args.manifest.resolve().parent, args.output)
    (args.output / 'bundle.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

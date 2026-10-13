import copy
import hashlib
import json
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from bundle import SCHEMA, compile_bundle, identity, plan_bundle
from compiler import Image, compile_image
from contract_recipe import fact_digest
from test_compiler import fixture


def module_image(directory, name, code, imported=None, exported_kind=2):
    imported = imported or []
    raw, contracts = fixture(code, parameters=['u32'], result='u32')
    raw = bytearray(raw)
    strings = bytearray(b'\0')
    def string(value):
        offset = len(strings)
        strings.extend(value.encode() + b'\0')
        return offset
    symbols = [(0, 0, 0, 0, 0, 0)]
    needed = []
    imports, data_imports = {}, {}
    for index, (owner, symbol, kind) in enumerate(imported, 1):
        needed.append(string(owner + '.prx'))
        symbols.append((string(symbol), 0x10 | kind, 0, 0, 0, 0))
        struct.pack_into('<QQq', raw, 0x4000 + (index - 1) * 24, 0x2000 + (index - 1) * 8, (index << 32) | 6, 0)
        if kind == 2:
            imports[symbol] = {'name': symbol, 'parameters': ['u32'], 'result': 'u32'}
        else:
            data_imports[symbol] = {'name': symbol, 'size': 4, 'evidence': 'Qualified fixture unsigned object'}
    symbol = 'value' if exported_kind == 1 else name + '_step'
    symbols.append((string(symbol), 0x10 | exported_kind, 0, 1, 0x2a00 if exported_kind == 1 else 0x1000,
                    4 if exported_kind == 1 else len(code)))
    soname = string(name + '.prx')
    for index, symbol in enumerate(symbols):
        struct.pack_into('<IBBHQQ', raw, 0x3800 + index * 24, *symbol)
    raw[0x3000:0x3000 + len(strings)] = strings
    tags = [(5, 0x3000), (10, len(strings)), (6, 0x3800), (11, 24), (7, 0x4000), (8, len(imported) * 24), (9, 24),
            (14, soname), *[(1, offset) for offset in needed], (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into('<qQ', raw, 0x4800 + index * 16, *tag)
    struct.pack_into('<IIQQQQQQ', raw, 176, 2, 6, 0x4800, 0x4800, 0, len(tags) * 16, len(tags) * 16, 8)
    struct.pack_into('<IIQQQQIIQQ', raw, 0x5040, 1, 11, 2, 0x3800, 0x3800, len(symbols) * 24, 2, 1, 8, 24)
    struct.pack_into('<I', raw, 0x2a00, 42)
    contracts.update(sha256=hashlib.sha256(raw).hexdigest(), imports=imports, data_imports=data_imports)
    (directory / (name + '.elf')).write_bytes(raw)
    (directory / (name + '.json')).write_text(json.dumps(contracts))
    return {'id': name, 'version': 1, 'input': name + '.elf', 'contracts': name + '.json',
            'dependencies': {owner: 1 for owner, _, _ in imported}}


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        leaf = module_image(self.directory, 'leaf', bytes.fromhex('89f883c001c3'))
        app = module_image(self.directory, 'app', bytes.fromhex('ff25fa0f0000'), [('leaf', 'leaf_step', 2)])
        self.spec = {'schema': SCHEMA, 'main': 'app', 'modules': [app, leaf]}

    def test_dependency_order_namespaces_and_machine_abi_binding(self):
        modules = plan_bundle(self.spec, self.directory)
        self.assertEqual([m['id'] for m in modules], ['leaf', 'app'])
        self.assertEqual(modules[1]['contracts']['imports']['leaf_step']['name'], 'aps5_leaf_test_entry')
        self.assertNotEqual(modules[0]['contracts']['native_namespace'], modules[1]['contracts']['native_namespace'])

    def test_native_bundle_function_and_registry_execute(self):
        output = self.directory / 'native'
        report = compile_bundle(self.spec, self.directory, output)
        source = output / 'main.cpp'
        source.write_text('#include "prx/libc/include/NativeAotBundle.hpp"\nextern "C" unsigned aps5_app_test_entry(unsigned);\nextern "C" NativeAotBundleRegistry* NativeAotCompiledBundle_nid_no_patch();\nint main(){auto* r=NativeAotCompiledBundle_nid_no_patch();return r->InitializationOrder().size()==2 && aps5_app_test_entry(41)==42?0:1;}\n')
        root = Path(__file__).resolve().parents[3]
        binary = output / 'run'
        subprocess.run(['xcrun', 'clang++', '-arch', 'arm64', '-std=c++20', '-O2', '-I', str(root / 'core/libs'),
                        str(source), str(output/'registry.cpp'), str(output/'app.o'), str(output/'leaf.o'),
                        str(root/'core/libs/native/NativeAotBundle.cpp'), str(root/'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp'), '-o', str(binary)], check=True, capture_output=True)
        subprocess.run([str(binary)], check=True, capture_output=True)
        self.assertEqual(len(report['modules']), 2)

    def test_cross_module_data_binding_has_checked_extent(self):
        leaf = module_image(self.directory, 'leaf', bytes.fromhex('89f8c3'), exported_kind=1)
        app = module_image(self.directory, 'app', bytes.fromhex('488b05f90f00008b00c3'), [('leaf', 'value', 1)])
        spec = {'schema': SCHEMA, 'main': 'app', 'modules': [app, leaf]}
        output = self.directory / 'data'
        compile_bundle(spec, self.directory, output)
        (output/'main.c').write_text('extern unsigned aps5_app_test_entry(unsigned); int main(void){return aps5_app_test_entry(0)==42?0:1;}\n')
        subprocess.run(['xcrun', 'clang', '-arch', 'arm64', str(output/'main.c'), str(output/'app.o'), str(output/'leaf.o'), '-o', str(output/'run')], check=True, capture_output=True)
        subprocess.run([str(output/'run')], check=True, capture_output=True)
        path = self.directory/'app.json'
        contract = json.loads(path.read_text())
        contract['data_imports']['value']['size'] = 8
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, 'data layout'):
            plan_bundle(spec, self.directory)

    def test_data_only_module_has_no_fabricated_entry_function(self):
        leaf = module_image(self.directory, 'leaf', bytes.fromhex('c3'), exported_kind=1)
        source = self.directory / 'leaf.elf'
        raw = bytearray(source.read_bytes())
        struct.pack_into('<Q', raw, 24, 0)
        source.write_bytes(raw)
        path = self.directory / 'leaf.json'
        contract = json.loads(path.read_text())
        contract.update(functions=[], sha256=hashlib.sha256(raw).hexdigest())
        path.write_text(json.dumps(contract))
        spec = {'schema': SCHEMA, 'main': 'leaf', 'modules': [leaf]}
        output = self.directory / 'data-only'
        result = compile_bundle(spec, self.directory, output)
        self.assertEqual(result['modules'][0]['id'], 'leaf')
        report = json.loads((output / 'leaf.json').read_text())
        self.assertEqual(report['functions'], [])

    def test_stale_input_and_path_escape_reject(self):
        spec = copy.deepcopy(self.spec)
        spec['modules'][0]['input'] = '../outside.elf'
        with self.assertRaisesRegex(ValueError, 'escapes root'):
            plan_bundle(spec, self.directory)
        path = self.directory/'app.elf'
        path.write_bytes(path.read_bytes() + b'\0')
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            plan_bundle(self.spec, self.directory)

    def test_missing_wrong_version_and_cycle_reject(self):
        for dependencies, error in [({'leaf': 2}, 'version mismatch'), ({'missing': 1}, 'missing module'), ({}, 'DT_NEEDED')]:
            spec = copy.deepcopy(self.spec)
            spec['modules'][0]['dependencies'] = dependencies
            with self.subTest(dependencies=dependencies), self.assertRaisesRegex(ValueError, error):
                plan_bundle(spec, self.directory)
        self.spec['modules'][1]['dependencies'] = {'app': 1}
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            plan_bundle(self.spec, self.directory)

    def test_abi_mismatch_duplicate_module_and_unreachable_reject(self):
        spec = copy.deepcopy(self.spec)
        spec['modules'].append(copy.deepcopy(spec['modules'][0]))
        with self.assertRaisesRegex(ValueError, 'duplicate module'):
            plan_bundle(spec, self.directory)
        spec = copy.deepcopy(self.spec)
        spec['main'] = 'leaf'
        with self.assertRaisesRegex(ValueError, 'unreachable'):
            plan_bundle(spec, self.directory)
        path = self.directory/'app.json'
        contract = json.loads(path.read_text())
        contract['imports']['leaf_step']['result'] = 'f64'
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, 'ABI mismatch'):
            plan_bundle(self.spec, self.directory)

    def test_transitive_binding_uses_the_closed_group(self):
        middle = module_image(self.directory, 'middle', bytes.fromhex('ff25fa0f0000'), [('leaf', 'leaf_step', 2)])
        app = module_image(self.directory, 'app', bytes.fromhex('ff25fa0f0000'), [('middle', 'leaf_step', 2)])
        spec = dict(self.spec, modules=[app, middle, self.spec['modules'][1]])
        modules = plan_bundle(spec, self.directory)
        self.assertEqual(modules[-1]['bindings'][0]['module'], 'leaf')

    def test_missing_guest_export_cannot_fall_back_to_an_unqualified_host_name(self):
        app = module_image(self.directory, 'app', bytes.fromhex('ff25fa0f0000'), [('leaf', 'absent', 2)])
        with self.assertRaisesRegex(ValueError, 'host import requires explicit'):
            plan_bundle(dict(self.spec, modules=[app, self.spec['modules'][1]]), self.directory)

    def test_guard_recipe_binds_facts_and_source(self):
        record = self.spec['modules'][0]
        path = self.directory / record['contracts']
        contract = json.loads(path.read_text())
        source = self.directory / 'reviewed.c'
        source.write_text('unsigned probe(unsigned value) { return value + 1; }\n')
        policies = {'checked_pointer_bases': {'bytes': 1, 'evidence': 'Qualified source objects'},
                    'checked_pointer_arguments': {'bytes': 1, 'nullable': True, 'evidence': 'Qualified native ABI'}}
        record['guards'] = {'policies': policies, 'facts_sha256': fact_digest(contract, policies),
                            'sources': [{'path': source.name, 'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}]}
        self.assertEqual(len(plan_bundle(self.spec, self.directory)), 2)
        source.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            plan_bundle(self.spec, self.directory)
        record['guards']['facts_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'guard facts changed'):
            plan_bundle(self.spec, self.directory)

    def test_sce_identity_uses_versions_and_names_not_local_indices(self):
        imported = {'identities': {'libraries': {0: {'name': 'math', 'version': 2}}, 'modules': {1: {'name': 'calc', 'version': 3}}}}
        exported = {'identities': {'export_libraries': {2: {'name': 'math', 'version': 2}}, 'export_modules': {5: {'name': 'calc', 'version': 3}}}}
        first = identity(imported, {'name': 'abc#A#B'}, False, 'unused')
        self.assertEqual(first, identity(exported, {'name': 'abc#C#F'}, True, 'unused'))
        exported['identities']['export_modules'][5]['version'] = 4
        self.assertNotEqual(first, identity(exported, {'name': 'abc#C#F'}, True, 'unused'))


if __name__ == '__main__':
    unittest.main()

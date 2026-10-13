import copy
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

import test_compiler
from compiler import Image, Rejected, compile_image
from contract_recipe import FIELDS, SCHEMA, fact_digest, materialize


class ContractRecipeTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp

    def recipe(self, raw, contracts):
        source = self.directory / 'input.elf'
        source.write_bytes(raw)
        evidence = self.directory / 'declarations.c'
        evidence.write_text('source-qualified native address profile\n')
        policies = {'checked_pointer_bases': {'bytes': 8, 'evidence': 'Native address values are a reviewed source precondition.'},
                    'checked_pointer_arguments': {'bytes': 8, 'nullable': False, 'evidence': 'Qualified native ABI: {callee}.'}}
        return source, {'schema': SCHEMA, 'contracts': contracts, 'policies': policies,
                        'qualification': {'facts_sha256': fact_digest(contracts, policies), 'sources': [
                            {'path': evidence.name, 'sha256': hashlib.sha256(evidence.read_bytes()).hexdigest()}]}}

    def materialize(self, source, recipe):
        return materialize(source, recipe, self.directory)

    def test_memory_sites_come_from_binary_without_mutating_input(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('488b07483306c3'), ['u64', 'u64']))
        original = copy.deepcopy(recipe)
        contracts, report = self.materialize(source, recipe)
        self.assertEqual(recipe, original)
        sites = contracts['functions'][0]['checked_pointer_bases']
        self.assertEqual([(r['address'], r['operand']) for r in sites], [(0x1000, 1), (0x1003, 1)])
        self.assertEqual(report['derived_sites'][FIELDS[0]], 2)
        ir, _ = compile_image(Image(source, contracts))
        self.assertIn('NativeAotReadablePointer_nid_no_patch', ir)
        self.assertEqual(self.materialize(source, recipe), (contracts, report))

    def test_pointer_arguments_follow_the_resolved_import_abi(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('ff15fa0f0000c3'), ['u64'], imports={
            'testNid': {'name': 'provider', 'parameters': ['ptr'], 'result': 'i64'}}))
        contracts, report = self.materialize(source, recipe)
        sites = contracts['functions'][0]['checked_pointer_arguments']
        self.assertEqual([(r['address'], r['parameter']) for r in sites], [(0x1000, 0)])
        self.assertIn('provider', sites[0]['evidence'])
        self.assertEqual(report['declared_import_abis'], 1)
        compile_image(Image(source, contracts))

    def test_lea_and_frame_addresses_do_not_become_native_base_assertions(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('488d07488b0424c3'), ['ptr']))
        contracts, report = self.materialize(source, recipe)
        self.assertEqual(report['derived_sites'][FIELDS[0]], 0)

    def test_changed_input_rejects_even_if_instruction_shape_is_unchanged(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('488b07c3'), ['u64']))
        raw = bytearray(source.read_bytes())
        raw[0x1002] = 6
        source.write_bytes(raw)
        with self.assertRaisesRegex(Rejected, 'input hash'):
            self.materialize(source, recipe)

    def test_changed_abi_binding_layout_or_policy_requires_requalification(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('488b07c3'), ['u64']))
        mutations = [lambda r: r['contracts']['functions'][0].update(parameters=['ptr']),
                     lambda r: r['contracts']['functions'][0].update(name='other'),
                     lambda r: r['contracts']['functions'][0].update(stack_objects=[{'offset': -16, 'size': 8, 'alignment': 8}]),
                     lambda r: r['policies'][FIELDS[0]].update(bytes=1)]
        for mutate in mutations:
            changed = copy.deepcopy(recipe)
            mutate(changed)
            with self.subTest(change=changed), self.assertRaisesRegex(ValueError, 'facts or guard policies changed'):
                self.materialize(source, changed)

    def test_changed_source_requires_requalification(self):
        source, recipe = self.recipe(*test_compiler.fixture(b'\xc3'))
        (self.directory / 'declarations.c').write_text('different declaration\n')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.materialize(source, recipe)

    def test_provider_source_changes_invalidate_unchanged_recipe(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('ff15fa0f0000c3'), ['u64'], imports={
            'testNid': {'name': 'provider', 'parameters': ['ptr'], 'result': 'i64'}})
        provider = self.directory / 'provider.c'
        provider.write_text('int provider(const void *value);')
        contracts['imports']['testNid']['evidence'] = {
            'path': provider.name, 'sha256': hashlib.sha256(provider.read_bytes()).hexdigest(),
            'excerpt': 'int provider(const void *value);'}
        source, recipe = self.recipe(raw, contracts)
        self.materialize(source, recipe)
        provider.write_text('void provider(void);')
        with self.assertRaisesRegex(ValueError, 'source changed.*provider.c'):
            self.materialize(source, recipe)

    def test_source_paths_cannot_escape_the_qualification_root(self):
        source, recipe = self.recipe(*test_compiler.fixture(b'\xc3'))
        recipe['qualification']['sources'][0]['path'] = '../outside.c'
        with self.assertRaisesRegex(ValueError, 'escapes root'):
            self.materialize(source, recipe)

    def test_missing_source_or_duplicate_site_input_rejects(self):
        source, recipe = self.recipe(*test_compiler.fixture(b'\xc3'))
        original = copy.deepcopy(recipe)
        recipe['qualification']['sources'] = []
        with self.assertRaisesRegex(ValueError, 'source identities'):
            self.materialize(source, recipe)
        original['contracts']['functions'][0]['checked_pointer_bases'] = []
        original['qualification']['facts_sha256'] = fact_digest(original['contracts'], original['policies'])
        with self.assertRaisesRegex(ValueError, 'must not be supplied'):
            self.materialize(source, original)

    def test_undecoded_bytes_and_segment_address_domains_reject(self):
        for code, reason in [(b'\x0f', 'incomplete instruction'), (bytes.fromhex('64488b07c3'), 'address domain')]:
            with self.subTest(code=code):
                source, recipe = self.recipe(*test_compiler.fixture(code, ['u64']))
                with self.assertRaisesRegex(ValueError, reason):
                    self.materialize(source, recipe)

    def test_indirect_target_is_an_obligation_not_a_guess(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('ffd0c3')))
        with self.assertRaisesRegex(ValueError, 'test_entry at 0x1000: call ABI/target obligation'):
            self.materialize(source, recipe)

    def test_unknown_instruction_still_rejects_in_the_compiler(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('0fa2c3')))
        contracts, _ = self.materialize(source, recipe)
        with self.assertRaises(Rejected):
            compile_image(Image(source, contracts))

    def test_expanded_contracts_emit_reproducible_ir_across_hash_seeds(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('4889f84883c00348d3e0c3'), ['u64'] * 4))
        contracts, _ = self.materialize(source, recipe)
        path = self.directory / 'contracts.json'
        path.write_text(json.dumps(contracts))
        outputs = []
        for seed in ('1', '17', '109'):
            output = self.directory / ('output-' + seed + '.ll')
            subprocess.run([sys.executable, str(Path(__file__).parents[1] / 'compiler.py'), str(source),
                            '--contracts', str(path), '--output', str(output)],
                           env=dict(os.environ, PYTHONHASHSEED=seed), check=True, capture_output=True)
            outputs.append(output.read_bytes())
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(outputs[0], outputs[2])

    def test_cli_produces_contracts_and_provenance_receipt(self):
        source, recipe = self.recipe(*test_compiler.fixture(bytes.fromhex('488b07c3'), ['u64']))
        path, output = self.directory / 'recipe.json', self.directory / 'contracts.json'
        path.write_text(json.dumps(recipe))
        command = [sys.executable, str(Path(__file__).parents[1] / 'contract_recipe.py'), str(source),
                   '--recipe', str(path), '--source-root', str(self.directory), '--output', str(output)]
        subprocess.run(command, check=True, capture_output=True)
        expected, report = self.materialize(source, recipe)
        self.assertEqual(json.loads(output.read_text()), expected)
        self.assertEqual(json.loads(output.with_suffix('.derivation.json').read_text()), report)
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.assertEqual(json.loads(output.read_text()), expected)


if __name__ == '__main__':
    unittest.main()

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from debug_candidates import recover_debug_candidates, recover_debug_dossier
from recover import load_elf
from test_compiler import fixture


class DebugCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def build(self, text, flags=()):
        source = self.directory / 'source.c'
        source.write_text(text)
        companion = self.directory / 'source.o'
        cc = ['xcrun', 'clang'] if sys.platform == 'darwin' else ['clang']
        subprocess.run([*cc, '--target=x86_64-unknown-freebsd', '-O0', '-g', '-gdwarf-4',
                        '-fno-omit-frame-pointer', *flags, '-c', source, '-o', companion], check=True, capture_output=True)
        _, obj = load_elf(companion)
        raw, _ = fixture(obj.get_section_by_name('.text').data())
        image = self.directory / 'source.elf'
        image.write_bytes(raw)
        return image, companion

    def test_scalar_types_and_frame_arrays_recovered_from_matching_object(self):
        image, companion = self.build('unsigned long sample(const char *p, unsigned int n) { char b[23]; b[0] = *p; return n + b[0]; }')
        report = recover_debug_candidates(image, companion)
        item, = report['functions']
        self.assertEqual(item['obligations'], [])
        self.assertEqual(item['candidate']['parameters'], ['ptr', 'u32'])
        self.assertEqual(item['candidate']['result'], 'u64')
        self.assertIn(23, [obj['size'] for obj in item['candidate']['stack_objects']])
        self.assertEqual(item['evidence']['companion']['sha256'], hashlib.sha256(companion.read_bytes()).hexdigest())

    def test_different_code_cannot_reuse_debug_facts(self):
        image, companion = self.build('int sample(int a) { return a + 1; }')
        raw = bytearray(image.read_bytes())
        raw[0x1000] ^= 1
        image.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, '0 image matches'):
            recover_debug_candidates(image, companion)

    def test_plain_struct_local_is_storage_not_an_aggregate_abi(self):
        image, companion = self.build('int sample(int x) { struct { char a[7]; int b; } p; p.b=x; return p.b; }')
        item, = recover_debug_candidates(image, companion)['functions']
        self.assertEqual(item['obligations'], [])
        self.assertIn(12, [o['size'] for o in item['candidate']['stack_objects']])

    def test_bitfield_storage_remains_unresolved(self):
        image, companion = self.build('int sample(int x) { struct { unsigned a:3; } p; p.a=x; return p.a; }')
        item, = recover_debug_candidates(image, companion)['functions']
        self.assertNotIn('candidate', item)
        self.assertIn('nonplain', item['obligations'][0])

    def test_variadic_and_aggregate_abis_are_unresolved(self):
        for source, message in [('int sample(int a, ...) { return a; }', 'variadic'),
                                ('struct P {int a,b;}; int sample(struct P p) {return p.a;}', 'non-scalar')]:
            image, companion = self.build(source)
            item, = recover_debug_candidates(image, companion)['functions']
            self.assertNotIn('candidate', item)
            self.assertIn(message, item['obligations'][0])

    def test_optimized_locations_remain_obligations(self):
        image, companion = self.build('int sample(int a) { return a + 1; }', ['-O2'])
        item, = recover_debug_candidates(image, companion)['functions']
        self.assertNotIn('candidate', item)
        self.assertTrue(item['obligations'])

    def test_missing_debug_info_rejects(self):
        image, companion = self.build('int sample(void) { return 1; }', ['-g0'])
        with self.assertRaisesRegex(ValueError, 'no DWARF'):
            recover_debug_candidates(image, companion)

    def test_independent_two_function_source_needs_no_signature_list(self):
        image, companion = self.build('static int twice(int x) { return x * 2; } int sample(int x) { return twice(x) + 3; }')
        result = recover_debug_candidates(image, companion)
        self.assertEqual({x['symbol'] for x in result['functions']}, {'sample', 'twice'})
        self.assertTrue(all(not x['obligations'] for x in result['functions']))
        self.assertEqual(result, recover_debug_candidates(image, companion))

    def test_partial_dossier_keeps_boundaries_and_abi_for_optimized_values(self):
        image, companion = self.build('int sample(int a) { return a + 1; }', ['-O2'])
        item, = recover_debug_dossier(image, companion)['functions']
        self.assertEqual(item['facts']['source_abi'], {'parameters': ['i32'], 'result': 'i32'})
        self.assertEqual(item['facts']['boundary']['address'], 0x1000)
        self.assertTrue(item['value_locations'])
        self.assertTrue(item['unresolved'])
        self.assertNotIn('candidate', item)

    def test_partial_dossier_retains_storage_despite_unknown_layout(self):
        image, companion = self.build('int sample(int a) { char good[17]; struct {unsigned b:3;} bad; good[0]=a; bad.b=a; return good[0]+bad.b; }')
        item, = recover_debug_dossier(image, companion)['functions']
        self.assertIn(17, [r['size'] for r in item['storage_candidates']])
        self.assertTrue(any('nonplain' in r['reason'] for r in item['unresolved']))
        self.assertNotIn('candidate', item)

    def test_partial_dossier_never_turns_register_values_into_storage(self):
        image, companion = self.build('int sample(int a) { return a * 2; }', ['-O2'])
        item, = recover_debug_dossier(image, companion)['functions']
        self.assertEqual(item['storage_candidates'], [])
        for row in item['value_locations']:
            self.assertLess(row['pc_begin'], row['pc_end'])
            self.assertGreaterEqual(row['pc_begin'], item['facts']['boundary']['address'])
            self.assertLessEqual(row['pc_end'], item['facts']['boundary']['address'] + item['facts']['boundary']['size'])

    def test_partial_dossier_invalidates_on_changed_input(self):
        image, companion = self.build('int sample(int a) { return a; }')
        raw = bytearray(image.read_bytes())
        raw[0x1000] ^= 1
        image.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, '0 image matches'):
            recover_debug_dossier(image, companion)

    def test_concrete_out_of_line_function_inherits_abstract_return_type(self):
        image, companion = self.build('static int helper(int a) { return a + 1; } int (*expose(void))(int) { return helper; } int sample(int a) { return helper(a); }', ['-O2'])
        rows = {r['symbol']: r for r in recover_debug_dossier(image, companion)['functions']}
        self.assertEqual(rows['helper']['facts']['source_abi'], {'parameters': ['i32'], 'result': 'i32'})
        self.assertEqual(rows['expose']['facts']['source_abi'], {'parameters': [], 'result': 'ptr'})


if __name__ == '__main__':
    unittest.main()

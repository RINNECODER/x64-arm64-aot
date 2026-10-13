import copy
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from provider_catalog import SCHEMA, decode_id, digest, imported_functions, require_complete, resolve_imports
from test_dynamic import BASE, Fixture


def provider_image(directory, library_id='A', module_id='B', library='libdemo', version=1):
    fixture = Fixture()
    strings = ('\0libdemo.prx\0abc#' + library_id + '#' + module_id + '\0' + library + '\0module\0').encode()
    fixture.raw[0x600:0x600 + len(strings)] = strings
    fixture.set(10, len(strings))
    fixture.set(8, 24)
    struct.pack_into('<I', fixture.raw, 0x700 + 24, strings.index(b'abc'))
    fixture.tags.extend([(0x61000049, strings.index(library.encode() + b'\0') | (version << 32) | (decode_id(library_id) << 48)),
                         (0x61000045, strings.index(b'module\0') | (257 << 32) | (decode_id(module_id) << 48))])
    fixture.elf()
    path = directory / ('image-' + library_id + module_id + '.elf')
    path.write_bytes(fixture.raw)
    return fixture, path


class ProviderCatalogTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.fixture, self.source = provider_image(self.directory)
        provider = self.directory / 'provider.c'
        provider.write_text('int provider(int value) { return value + 1; }\n')
        self.entry = {'identity': {'nid': 'abc', 'library': 'libdemo', 'library_version': 1,
                                  'module': 'module', 'module_version': 257},
                      'contract': {'name': 'provider', 'parameters': ['i32'], 'result': 'i32'},
                      'sources': [{'path': provider.name, 'sha256': hashlib.sha256(provider.read_bytes()).hexdigest(),
                                   'excerpt': 'int provider(int value)'}]}
        self.entry['facts_sha256'] = digest(self.entry)
        self.catalog = {'schema': SCHEMA, 'target': 'apple-arm64', 'entries': [self.entry]}

    def resolve(self, source=None, catalog=None):
        return resolve_imports(source or self.source, catalog or self.catalog, self.directory)

    def test_same_provider_reused_across_different_import_indices(self):
        first, report = self.resolve()
        _, other = provider_image(self.directory, 'C', 'F')
        second, transferred = self.resolve(other)
        require_complete(report)
        require_complete(transferred)
        self.assertEqual(first['abc#A#B'], second['abc#C#F'])
        self.assertNotEqual(report['input_sha256'], transferred['input_sha256'])
        self.assertEqual(len(report['reused']), 1)
        self.assertEqual(report['reused'][0]['slots'], [BASE + 0x900, BASE + 0x918])

    def test_same_nid_with_different_library_or_version_is_missing(self):
        for library, version in [('another', 1), ('libdemo', 2)]:
            _, source = provider_image(self.directory, library=library, version=version)
            resolved, report = self.resolve(source)
            self.assertEqual(resolved, {})
            with self.assertRaisesRegex(ValueError, 'qualification required.*abc'):
                require_complete(report)

    def test_provider_change_invalidates_unchanged_catalog(self):
        (self.directory / 'provider.c').write_text('int provider(int value) { return value - 1; }')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            self.resolve()

    def test_fact_changes_and_duplicate_identities_reject(self):
        changed = copy.deepcopy(self.catalog)
        changed['entries'][0]['contract']['result'] = 'void'
        with self.assertRaisesRegex(ValueError, 'facts changed'):
            self.resolve(catalog=changed)
        self.catalog['entries'].append(copy.deepcopy(self.entry))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.resolve()

    def test_missing_or_duplicate_module_record_rejects(self):
        self.fixture.tags = [(t, v) for t, v in self.fixture.tags if t != 0x61000045]
        self.source.write_bytes(self.fixture.elf().stream.getvalue())
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.resolve()
        self.fixture.tags.extend([(0x61000045, 1), (0x61000045, 1)])
        self.source.write_bytes(self.fixture.elf().stream.getvalue())
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.resolve()

    def test_weak_defined_or_object_symbols_do_not_become_function_bindings(self):
        for info, section in [(0x22, 0), (0x11, 0), (0x12, 0xfff1)]:
            raw = bytearray(self.source.read_bytes())
            struct.pack_into('<BBH', raw, 0x700 + 24 + 4, info, 0, section)
            self.source.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'strong undefined function'):
                self.resolve()

    def test_foreign_target_and_noncanonical_indices_reject(self):
        self.catalog['target'] = 'linux-arm64'
        with self.assertRaisesRegex(ValueError, 'target mismatch'):
            self.resolve()
        for value in ('AA', '', '@', 'QQQQ', 'QQQ'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_id(value)

    def test_source_escape_and_changed_dependency_reject(self):
        self.entry['sources'][0]['path'] = '../provider.c'
        self.entry['facts_sha256'] = digest({k: v for k, v in self.entry.items() if k != 'facts_sha256'})
        with self.assertRaisesRegex(ValueError, 'escapes root'):
            self.resolve()

    def test_resolution_does_not_mutate_catalog(self):
        original = copy.deepcopy(self.catalog)
        resolved, _ = self.resolve()
        resolved['abc#A#B']['parameters'][0] = 'ptr'
        self.assertEqual(self.catalog, original)


if __name__ == '__main__':
    unittest.main()

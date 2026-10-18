"""The native image must bind a guest import to its HLE implementation, and report it when it cannot.

The compiler emits a direct call to the HLE entry point for every import the linked runtime defines,
and `tools/native/stub_undefined.sh` lowers the rest to a bare `ret`. That fallback is silent, so a
component dropped from the native runtime's component list turns a guest library call into a zero
return with no diagnostic anywhere in the build. These tests pin the binding rule at the reporting
level (`hle_gaps`) and at the real consumer boundary (`tools/native/title_image.py`); before them
nothing tested the import-naming rule at all, and the stub step only printed a count.
"""
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_compiler
from hle_gaps import GUEST_PREFIX, classify, main, read_symbols, resolve_import_name

ROOT = Path(__file__).resolve().parents[3]

# The HLE entry points the guest's start-up path reaches before the title's main loop, and the
# component that must serve each one. Every one of these has a verified ABI in the contracts, so a
# component that stops providing it turns the guest's call into a silent zero return. The map is
# kept here rather than derived from the component sources so the check reads only the runtime's
# component list: the compiler-repo mirror carries `core/libs/native` but not the component sources,
# and the list is what the boot depends on. `StartupComponentSourceTests` cross-checks the map
# against the sources where they exist.
STARTUP_PROVIDERS = {
    'sceSysmoduleLoadModule': 'libSceSysmodule',
    'sceCommonDialogInitialize': 'libSceCommonDialog',
    'sceSystemGestureInitializePrimitiveTouchRecognizer': 'libSceSystemGesture',
    'sceSaveDataInitialize3': 'libSceSaveData.native',
    'sceSaveDataCreateTransactionResource': 'libSceSaveData.native',
    'sceNpGameIntentInitialize': 'libSceNpGameIntent',
    'sceSystemServiceParamGetString': 'libSceSystemService',
    'sceAppContentInitialize': 'libSceAppContent',
    'sceAppContentTemporaryDataMount2': 'libSceAppContent',
    'sceUserServiceInitialize': 'libSceUserService',
    'sceUserServiceGetInitialUser': 'libSceUserService',
    'sceUserServiceGetUserName': 'libSceUserService',
    'sceImeKeyboardOpen': 'libSceIme',
    '_ZN3sce4Json11InitializerC1Ev': 'libSceJson2',
    '_ZN3sce4Json11Initializer10initializeEPKNS0_14InitParameter2E': 'libSceJson2',
    '_ZN3sce4Json14InitParameter2C2Ev': 'libSceJson2',
    '_ZN3sce4Json14InitParameter217setFileBufferSizeEm': 'libSceJson2',
    '_ZN3sce4Json18InitParameterRtti216setAllocatorRttiEPNS0_14AllocParamRttiEPv': 'libSceJson2',
}


def native_components():
    """The component targets core/libs/native/CMakeLists.txt compiles into the runtime."""
    text = (ROOT / 'core/libs/native/CMakeLists.txt').read_text()
    match = re.search(r'set\(nativeComponents(.*?)\)', text, re.S)
    return re.findall(r'[A-Za-z_][A-Za-z_0-9.]*', match.group(1))


def component_exported_entry_points(component):
    """The guest entry points a component's own sources define (APS5_VABI marks the guest ABI)."""
    names = set()
    for source in (ROOT / 'core/libs/prx' / component).rglob('*'):
        if source.suffix not in ('.cpp', '.hpp', '.h') or 'test' in str(source).lower():
            continue
        for name in re.findall(r'APS5_VABI\s+([A-Za-z_][A-Za-z_0-9]*)\s*\(', source.read_text(errors='replace')):
            names.add(name)
    return names


def imports(name, stub=False):
    contract = {'name': name, 'result': 'i32', 'parameters': []}
    if stub:
        contract['stub'] = True
    return {'AAAABBBBCCC#t#s': contract}


class ImportBindingTests(unittest.TestCase):
    def test_an_import_the_runtime_defines_binds_to_the_hle_entry_point(self):
        self.assertEqual(resolve_import_name('sceExampleEntry', {'sceExampleEntry'}),
                         'sceExampleEntry')

    def test_a_nid_postfix_symbol_wins_over_the_bare_name(self):
        # The runtime defines most guest entry points with the suffix; the bare name may be a host
        # C library function, so the suffixed symbol has to be preferred.
        symbols = {'sceExampleEntry', 'sceExampleEntry_nid_postfix'}
        self.assertEqual(resolve_import_name('sceExampleEntry', symbols), 'sceExampleEntry_nid_postfix')

    def test_an_import_the_runtime_does_not_define_is_namespaced_for_the_stub_generator(self):
        self.assertEqual(resolve_import_name('sceExampleEntry', set()),
                         GUEST_PREFIX + 'sceExampleEntry')

    def test_a_typed_import_with_no_runtime_symbol_is_reported_as_a_gap(self):
        # The regression: this import becomes a bare `ret`, so the guest call returns zero and the
        # boot carries on. It has to be named, not counted.
        report = classify(imports('sceExampleEntry'), set())
        self.assertEqual([record['name'] for record in report['gaps']], ['sceExampleEntry'])
        self.assertEqual([record['nid'] for record in report['gaps']], ['AAAABBBBCCC'])
        self.assertEqual(report['bound'], [])

    def test_an_import_the_runtime_defines_is_not_a_gap(self):
        report = classify(imports('sceExampleEntry'), {'sceExampleEntry'})
        self.assertEqual([record['name'] for record in report['bound']], ['sceExampleEntry'])
        self.assertEqual(report['gaps'], [])

    def test_a_host_library_name_is_routed_to_the_host_not_reported_as_a_gap(self):
        # stub_undefined.sh trampolines a namespaced import whose bare name the host defines, so it
        # is a deliberate route to libSystem rather than a missing HLE implementation.
        report = classify(imports('strlen'), set(), host_symbols={'strlen'})
        self.assertEqual([record['name'] for record in report['host']], ['strlen'])
        self.assertEqual(report['gaps'], [])

    def test_an_import_the_contract_already_stubs_is_not_reported_as_a_gap(self):
        # `stub: true` is the contracts' own statement that the ABI is unverified and a zero return
        # is the intended answer; the gap report is about the typed imports that lost their provider.
        report = classify(imports('sceExampleEntry', stub=True), set())
        self.assertEqual([record['name'] for record in report['declared']], ['sceExampleEntry'])
        self.assertEqual(report['gaps'], [])

    def test_read_symbols_accepts_nm_output_and_bare_names(self):
        with tempfile.TemporaryDirectory(prefix='anyps5-hle-symbols-') as folder:
            path = Path(folder) / 'symbols.txt'
            path.write_text('0000000101a1ef60 T _sceKernelOpen\nsceKernelRead\n')
            self.assertEqual(read_symbols(str(path)), {'sceKernelOpen', 'sceKernelRead'})

    def test_the_cli_exits_nonzero_for_a_typed_unbound_import(self):
        with tempfile.TemporaryDirectory(prefix='anyps5-hle-gaps-') as folder:
            folder = Path(folder)
            (folder / 'contracts.json').write_text(json.dumps({'imports': imports('sceExampleEntry')}))
            (folder / 'symbols.txt').write_text('sceSomethingElse\n')
            result = main(['--contracts', str(folder / 'contracts.json'),
                           '--symbols', str(folder / 'symbols.txt'),
                           '--json', str(folder / 'report.json')])
            report = json.loads((folder / 'report.json').read_text())
        self.assertEqual(result, 1)
        self.assertEqual([record['name'] for record in report['gaps']], ['sceExampleEntry'])


class StartupComponentCoverageTests(unittest.TestCase):
    """The routing itself: the components that serve the start-up imports are in the runtime.

    Reads only `core/libs/native/CMakeLists.txt`, so it holds in the compiler-repo mirror too.
    """

    def test_every_startup_entry_point_is_provided_by_a_native_component(self):
        # The regression: a component is dropped from nativeComponents, so the import has no
        # provider, the image namespaces it, and the stub generator lowers the guest's library call
        # to a bare `ret` with no build-time diagnostic.
        components = native_components()
        missing = sorted({component for component in STARTUP_PROVIDERS.values()
                          if component not in components})
        self.assertEqual(missing, [])

    def test_the_save_data_component_is_the_transaction_resource_variant(self):
        # libSceSaveData and libSceSaveData.native both export sceSaveDataInitialize3, so only the
        # variant that also carries the transaction-resource entry points may be compiled in.
        self.assertIn('libSceSaveData.native', native_components())
        self.assertNotIn('libSceSaveData', native_components())


class StartupComponentSourceTests(unittest.TestCase):
    """The map above against the component sources, where this checkout carries them.

    The compiler-repo mirror exports `core/libs/native` and only the `core/libs/prx` files its
    compiler tests include, so it has nothing to scan here. Skipping there is honest: the guard
    that matters in that repo is the component list, which `StartupComponentCoverageTests` checks
    without the sources. A component renamed at home is also a missing source directory for CMake,
    so the build reports it before this test would.
    """

    def carried_sources(self):
        root = ROOT / 'core/libs/prx'
        providers = sorted(set(STARTUP_PROVIDERS.values()))
        return [component for component in providers if (root / component).is_dir()], providers

    def setUp(self):
        carried, providers = self.carried_sources()
        if len(carried) != len(providers):
            self.skipTest('this checkout carries %d of %d component sources' %
                          (len(carried), len(providers)))

    def test_each_startup_entry_point_comes_from_the_component_that_exports_it(self):
        for name, component in sorted(STARTUP_PROVIDERS.items()):
            self.assertIn(name, component_exported_entry_points(component),
                          '%s is mapped to %s, which does not export it' % (name, component))

    def test_the_transaction_resource_entry_point_is_in_the_variant_compiled_in(self):
        self.assertIn('sceSaveDataCreateTransactionResource',
                      component_exported_entry_points('libSceSaveData.native'))

    def test_the_initialiser_alone_does_not_distinguish_the_two_save_data_variants(self):
        # Both variants export sceSaveDataInitialize3, so the list check above cannot be dropped in
        # favour of a source scan: it is the transaction-resource entry point that decides.
        self.assertIn('sceSaveDataInitialize3',
                      component_exported_entry_points('libSceSaveData'))


class TitleImageBindingTests(unittest.TestCase):
    """The same rule at the consumer boundary: what title_image.py actually emits."""

    def emit(self, symbols, folder):
        raw, contracts = test_compiler.fixture(bytes.fromhex('ff15fa0f0000c3'), result='i32',
                                              imports=imports('sceExampleEntry'))
        root = Path(__file__).resolve().parents[3]
        (folder / 'in.elf').write_bytes(raw)
        (folder / 'contracts.json').write_text(json.dumps(contracts))
        (folder / 'symbols.txt').write_text('\n'.join(symbols) + '\n')
        result = subprocess.run([sys.executable, str(root / 'tools/native/title_image.py'),
                                 '--elf', str(folder / 'in.elf'),
                                 '--contracts', str(folder / 'contracts.json'),
                                 '--nid-symbols', str(folder / 'symbols.txt'),
                                 '--entries', 'entry',
                                 '--output', str(folder / 'out.ll')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return (folder / 'out.ll').read_text()

    def test_title_image_calls_the_hle_entry_point_when_the_runtime_defines_it(self):
        with tempfile.TemporaryDirectory(prefix='anyps5-hle-bound-') as folder:
            folder = Path(folder)
            ir = self.emit(['sceExampleEntry'], folder)
        self.assertIn('@sceExampleEntry(', ir)
        self.assertNotIn(GUEST_PREFIX, ir)

    def test_title_image_namespaces_the_import_when_no_component_provides_it(self):
        # This is the state the native runtime was in for every component that was missing from its
        # list: the call is emitted, but against a namespaced symbol the stub generator lowers to a
        # bare `ret`, so the guest sees a successful zero.
        with tempfile.TemporaryDirectory(prefix='anyps5-hle-unbound-') as folder:
            folder = Path(folder)
            ir = self.emit(['sceSomethingElse'], folder)
        self.assertIn('@' + GUEST_PREFIX + 'sceExampleEntry(', ir)
        self.assertNotIn('@sceExampleEntry(', ir)


if __name__ == '__main__':
    unittest.main()

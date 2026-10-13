import copy
import ctypes
import unittest

import test_effects
from compiler import Rejected


class ProviderEffectsTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir
    spill_caller = test_effects.CallEffectsTests.spill_caller

    def provider(self, parameters=None, writes=None, result='void', callbacks=False):
        return {'nativeNid': {'name': 'native_probe', 'parameters': parameters or [], 'result': result,
                             'memory_effects': {'writes': writes or [], 'callbacks': callbacks,
                                                'evidence': 'Native C provider included in this test fixture'}}}

    def test_repeated_readonly_import_executes_without_losing_binding(self):
        raw, contracts = self.fixture([
            ('test_entry', 'call [rip+image_cell]\ncall [rip+image_cell]\nret', [], 'i64')],
            imports=self.provider(result='i64'))
        function, report, _ = self.compile(raw, contracts, extra='unsigned long long native_probe(void) { return 42; }')
        self.assertEqual(function(), 42)
        self.assertEqual(report['functions'][0]['memory_effects']['required_provider_bindings'], [0x2000])
        self.assertEqual(report['provider_effect_contracts']['nativeNid'], contracts['imports']['nativeNid']['memory_effects'])

    def test_bounded_frame_write_preserves_disjoint_pointer_spill(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nsub rsp, 16\nmov rdi, rsp\nmov esi, 8\ncall [rip+image_cell]\nadd rsp, 16\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')],
            imports=self.provider(['ptr', 'u64'], [{'parameter': 0, 'size_parameter': 1}]))
        function, _, _ = self.compile(raw, contracts, extra='#include <string.h>\nvoid native_probe(void* p, unsigned long n) { memset(p, 0, n); }')
        value = ctypes.c_uint64(42)
        self.assertEqual(function(ctypes.addressof(value)), 42)

    def test_partial_frame_write_invalidates_overlapping_pointer(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nlea rdi, [rsp+7]\ncall [rip+image_cell]\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')],
            imports=self.provider(['ptr'], [{'parameter': 0, 'size': 1}]))
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_provider_image_write_preserves_disjoint_relocated_pointer(self):
        raw, contracts = self.fixture([
            ('test_entry', 'lea rdi, [rip+image_other+8]\ncall [rip+image_cell]\nmov rax, [rip+image_other]\nmov rax, [rax]\nret', [], 'i64')],
            imports=self.provider(['ptr'], [{'parameter': 0, 'size': 8}]), relocations=[[0x2010, 0x2018]])
        function, report, _ = self.compile(raw, contracts, extra='void native_probe(unsigned long long* p) { *p = 42; }')
        self.assertEqual(function(), 42)
        self.assertEqual(report['functions'][0]['memory_effects']['image_writes'], [{'address': 0x2018, 'size': 8}])

    def test_provider_write_to_import_slot_invalidates_next_call(self):
        raw, contracts = self.fixture([
            ('test_entry', 'lea rdi, [rip+image_cell+7]\ncall [rip+image_cell]\ncall [rip+image_cell]\nret', [], 'void')],
            imports=self.provider(['ptr'], [{'parameter': 0, 'size': 1}]))
        with self.assertRaisesRegex(Rejected, 'import target has no proven native pointer origin'):
            self.compile_ir(raw, contracts)

    def test_unknown_write_length_and_unknown_destination_remain_conservative(self):
        for body, parameters in [
                ('push rdi\nmov rdi, rsp\ncall [rip+image_cell]\npop rax\nmov rax, [rax]\nret', ['ptr', 'u64']),
                ('push rdi\nmov esi, 8\ncall [rip+image_cell]\npop rax\nmov rax, [rax]\nret', ['ptr'])]:
            with self.subTest(body=body):
                raw, contracts = self.fixture([('test_entry', body, parameters, 'i64')],
                    imports=self.provider(['ptr', 'u64'], [{'parameter': 0, 'size_parameter': 1}]))
                with self.assertRaisesRegex(Rejected, 'pointer origin'):
                    self.compile_ir(raw, contracts)

    def test_zero_extent_preserves_pointer_even_for_unknown_destination(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nxor esi, esi\ncall [rip+image_cell]\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')],
            imports=self.provider(['ptr', 'u64'], [{'parameter': 0, 'size_parameter': 1}]))
        function, _, _ = self.compile(raw, contracts, extra='#include <string.h>\nvoid native_probe(void* p, unsigned long n) { memset(p, 0, n); }')
        value = ctypes.c_uint64(42)
        self.assertEqual(function(ctypes.addressof(value)), 42)

    def test_extent_uses_declared_integer_width(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\nmov esi, 256\ncall [rip+image_cell]\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')],
            imports=self.provider(['ptr', 'u8'], [{'parameter': 0, 'size_parameter': 1}]))
        function, _, _ = self.compile(raw, contracts, extra='#include <string.h>\nvoid native_probe(void* p, unsigned char n) { memset(p, 0, n); }')
        value = ctypes.c_uint64(42)
        self.assertEqual(function(ctypes.addressof(value)), 42)

    def test_out_of_frame_and_overflowing_extents_remain_unknown(self):
        for size in (16, (1 << 64) - 1):
            with self.subTest(size=size):
                raw, contracts = self.fixture([
                    ('test_entry', 'push rdi\nmov rdi, rsp\ncall [rip+image_cell]\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64')],
                    imports=self.provider(['ptr'], [{'parameter': 0, 'size': size}]))
                with self.assertRaisesRegex(Rejected, 'pointer origin'):
                    self.compile_ir(raw, contracts)

    def test_callback_provider_cannot_claim_no_memory_writes(self):
        raw, contracts = self.fixture([self.spill_caller('call [rip+image_cell]')],
                                      imports=self.provider(callbacks=True))
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_rebound_import_cannot_reuse_original_provider_effects(self):
        raw, contracts = self.fixture([
            self.spill_caller('lea rax, [rip+replacement]\nmov [rip+image_cell], rax\ncall [rip+image_cell]'),
            ('replacement', 'ret', [], 'void')], imports=self.provider())
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_rebound_import_invalidates_transitive_summary_precondition(self):
        raw, contracts = self.fixture([
            self.spill_caller('lea rax, [rip+replacement]\nmov [rip+image_cell], rax\ncall helper'),
            ('helper', 'call [rip+image_cell]\nret', [], 'void'), ('replacement', 'ret', [], 'void')],
            imports=self.provider())
        with self.assertRaisesRegex(Rejected, 'provider bindings'):
            self.compile_ir(raw, contracts)

    def test_unknown_callee_summary_still_enforces_provider_preconditions(self):
        raw, contracts = self.fixture([
            ('test_entry', 'lea rax, [rip+replacement]\nmov [rip+image_cell], rax\nlea rdi, [rip+image_other]\ncall helper\nret', [], 'void'),
            ('helper', 'push rbx\nmov rbx, rdi\ncall [rip+image_cell]\nmov BYTE PTR [rbx], 0\npop rbx\nret', ['ptr'], 'void'),
            ('replacement', 'ret', [], 'void')], imports=self.provider())
        with self.assertRaisesRegex(Rejected, 'native callee requires original provider bindings'):
            self.compile_ir(raw, contracts)

    def test_indirect_callee_provider_preconditions_cannot_be_bypassed(self):
        raw, contracts = self.fixture([
            ('test_entry', 'lea rax, [rip+replacement]\nmov [rip+image_cell], rax\nlea rax, [rip+helper]\ncall rax\nret', [], 'void'),
            ('helper', 'call [rip+image_cell]\nret', [], 'void'), ('replacement', 'ret', [], 'void')],
            imports=self.provider())
        owner, helper = contracts['functions'][:2]
        offset = raw[0x1000:0x1000 + owner['size']].index(b'\xff\xd0')
        owner['indirect_calls'] = [{'address': 0x1000 + offset, 'parameters': [], 'result': 'void', 'targets': [helper['address']]}]
        with self.assertRaisesRegex(Rejected, 'native callee requires original provider bindings'):
            self.compile_ir(raw, contracts)

    def test_tail_callee_provider_preconditions_cannot_be_bypassed(self):
        raw, contracts = self.fixture([
            ('test_entry', 'lea rax, [rip+replacement]\nmov [rip+image_cell], rax\njmp helper', [], 'void'),
            ('helper', 'call [rip+image_cell]\nret', [], 'void'), ('replacement', 'ret', [], 'void')],
            imports=self.provider())
        with self.assertRaisesRegex(Rejected, 'native callee requires original provider bindings'):
            self.compile_ir(raw, contracts)

    def test_frame_write_invalidates_saved_frame_origin(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rbp\nmov rbp, rsp\npush rbp\nmov rdi, rsp\ncall [rip+image_cell]\npop rbp\nlea rax, [rbp-8]\nmov rax, [rax]\npop rbp\nret', [], 'i64')],
            imports=self.provider(['ptr'], [{'parameter': 0, 'size': 8}]))
        with self.assertRaisesRegex(Rejected, 'dynamic frame offset'):
            self.compile_ir(raw, contracts)

    def test_binding_proof_is_intersected_at_control_flow_join(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\ntest esi, esi\njz clean\nlea rax, [rip+replacement]\nmov [rip+image_cell], rax\nclean:\ncall [rip+image_cell]\npop rax\nmov rax, [rax]\nret', ['ptr', 'i32'], 'i64'),
            ('replacement', 'ret', [], 'void')], imports=self.provider())
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_callee_private_provider_write_does_not_escape_summary(self):
        raw, contracts = self.fixture([
            self.spill_caller(),
            ('helper', 'sub rsp, 8\nmov rdi, rsp\ncall [rip+image_cell]\nadd rsp, 8\nret', [], 'void')],
            imports=self.provider(['ptr'], [{'parameter': 0, 'size': 8}]))
        function, report, _ = self.compile(raw, contracts, extra='void native_probe(unsigned long long* p) { *p = 42; }')
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 123)
        self.assertEqual(report['functions'][0]['memory_effects']['image_writes'], [])
        self.assertEqual(report['functions'][0]['memory_effects']['required_provider_bindings'], [0x2000])

    def test_internal_effect_annotation_cannot_override_inference(self):
        raw, contracts = self.fixture([('test_entry', 'ret', [], 'void')])
        contracts['functions'][0]['memory_effects'] = self.provider()['nativeNid']['memory_effects']
        with self.assertRaisesRegex(Rejected, 'internal memory effects must be inferred'):
            self.compile_ir(raw, contracts)

    def test_malformed_effect_annotations_reject(self):
        raw, contracts = self.fixture([('test_entry', 'ret', [], 'void')], imports=self.provider(['ptr', 'u64']))
        annotations = [None, [], {}, {'writes': [], 'callbacks': False, 'evidence': ''},
                       {'writes': [], 'callbacks': 0, 'evidence': 'fixture'},
                       {'writes': [], 'callbacks': False, 'evidence': 'fixture', 'ignored': True}]
        malformed_writes = [None, [None], [{}], [{'parameter': True, 'size': 1}],
                            [{'parameter': 1, 'size': 1}], [{'parameter': 0, 'size': -1}],
                            [{'parameter': 0, 'size': True}], [{'parameter': 0, 'size': 1 << 64}],
                            [{'parameter': 0, 'size_parameter': 0}], [{'parameter': 0, 'size_parameter': 2}],
                            [{'parameter': 0, 'size': 8, 'size_parameter': 1}], [{'parameter': 0, 'size': 8, 'offset': 1}]]
        annotations.extend({'writes': writes, 'callbacks': False, 'evidence': 'fixture'} for writes in malformed_writes)
        for annotation in annotations:
            with self.subTest(annotation=annotation):
                candidate = copy.deepcopy(contracts)
                candidate['imports']['nativeNid']['memory_effects'] = annotation
                with self.assertRaisesRegex(Rejected, 'provider'):
                    self.compile_ir(raw, candidate)


if __name__ == '__main__':
    unittest.main()

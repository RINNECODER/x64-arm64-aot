import ctypes
import unittest

import test_effects
import test_provider_effects
from compiler import Rejected


class LoopRangeTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir
    provider = test_provider_effects.ProviderEffectsTests.provider

    def loop_fixture(self, start=0, limit=12, step=4, scale=1, initialize=None, update=None,
                     prefix='', before_guard='', between_guard='', after_loop='', store=None):
        initialize = f'mov ebx, {start}' if initialize is None else initialize
        update = f'add rbx, {step}' if update is None else update
        store = f'mov BYTE PTR [rsp+rbx*{scale}], bl' if store is None else store
        body = f'push rbx\nsub rsp, 32\nmov [rsp+24], rdi\n{initialize}\n{prefix}\nloop_head:\n{store}\n{before_guard}\ncmp rbx, {limit}\n{between_guard}\nje done\nincrement:\n{update}\njmp loop_head\ndone:\n{after_loop}\nmov rdi, rsp\ncall [rip+image_cell]\nmov rcx, rax\nmov rax, [rsp+24]\nmov rax, [rax]\nadd rax, rcx\nadd rsp, 32\npop rbx\nret'
        return self.fixture([('test_entry', body, ['ptr', 'i64'], 'i64')],
                            imports=self.provider(['ptr'], result='u64'))

    def test_bounded_loop_preserves_pointer_and_executes_all_stores(self):
        for start, limit, step, scale in [(0, 12, 4, 1), (3, 15, 4, 1), (0, 0, 1, 1), (0, 8, 2, 2)]:
            with self.subTest(start=start, limit=limit, step=step, scale=scale):
                raw, contracts = self.loop_fixture(start, limit, step, scale)
                provider = f'unsigned long long native_probe(const unsigned char* p) {{ unsigned long long sum = 0; for (unsigned i = {start}; i <= {limit}; i += {step}) sum += p[i * {scale}]; return sum; }}'
                function, report, _ = self.compile(raw, contracts, extra=provider)
                value = ctypes.c_uint64(123)
                self.assertEqual(function(ctypes.addressof(value), 0), 123 + sum(range(start, limit + 1, step)))
                proof = report['functions'][0]['bounded_loops'][0]
                self.assertEqual((proof['minimum'], proof['maximum'], proof['step']), (start, limit, step))
                self.assertEqual(report['functions'][0]['memory_effects']['image_writes'], [])

    def test_unreachable_limit_and_nonpositive_steps_are_not_proofs(self):
        for limit, step in [(10, 4), (12, 0), (12, -4), (-1, 4)]:
            with self.subTest(limit=limit, step=step):
                with self.assertRaises(Rejected):
                    self.compile_ir(*self.loop_fixture(limit=limit, step=step))

    def test_wrapping_initial_counter_is_not_a_bounded_range(self):
        with self.assertRaises(Rejected):
            self.compile_ir(*self.loop_fixture(limit=4, step=8, initialize='mov rbx, -4'))

    def test_runtime_initial_counter_is_not_a_constant_proof(self):
        with self.assertRaises(Rejected):
            self.compile_ir(*self.loop_fixture(initialize='mov rbx, rsi'))

    def test_partial_counter_update_and_extra_definition_reject(self):
        for update in ('add ebx, 4', 'add rbx, 4\ninc rbx', 'mov ebx, 4', 'sub rbx, -4'):
            with self.subTest(update=update):
                with self.assertRaises(Rejected):
                    self.compile_ir(*self.loop_fixture(update=update))

    def test_external_entry_after_guard_cannot_bypass_range_proof(self):
        with self.assertRaises(Rejected):
            self.compile_ir(*self.loop_fixture(prefix='test esi, esi\njnz increment'))

    def test_second_exit_and_modified_comparison_flags_reject(self):
        for before, between in [('test esi, esi\njnz done', ''), ('', 'test esi, esi')]:
            with self.subTest(before=before, between=between):
                with self.assertRaises(Rejected):
                    self.compile_ir(*self.loop_fixture(before_guard=before, between_guard=between))

    def test_call_inside_loop_cannot_preserve_counter_proof(self):
        with self.assertRaises(Rejected):
            self.compile_ir(*self.loop_fixture(before_guard='mov rdi, rsp\ncall [rip+image_cell]'))

    def test_range_invalidates_partially_overlapping_pointer_cell(self):
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(*self.loop_fixture(limit=8, store='mov BYTE PTR [rsp+rbx+16], bl'))

    def test_indexed_write_cannot_escape_native_frame(self):
        with self.assertRaises(Rejected):
            self.compile_ir(*self.loop_fixture(store='mov BYTE PTR [rsp+rbx+40], bl'))

    def test_loop_range_does_not_apply_to_later_instructions(self):
        with self.assertRaises(Rejected):
            self.compile_ir(*self.loop_fixture(after_loop='mov ebx, 1000000\nmov BYTE PTR [rsp+rbx], 0'))

    def test_indexed_pointer_store_does_not_create_cell_proof(self):
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(*self.loop_fixture(limit=0, store='mov [rsp+rbx], rdi',
                after_loop='mov rax, [rsp]\nmov rax, [rax]'))

    def test_internal_loop_summary_preserves_callers_pointer(self):
        raw, contracts = self.fixture([
            ('test_entry', 'push rdi\ncall helper\npop rax\nmov rax, [rax]\nret', ['ptr'], 'i64'),
            ('helper', 'push rbx\nsub rsp, 16\nxor ebx, ebx\nloop_head:\nmov BYTE PTR [rsp+rbx], bl\ncmp rbx, 12\nje done\nadd rbx, 4\njmp loop_head\ndone:\nadd rsp, 16\npop rbx\nret', [], 'void')])
        function, report, _ = self.compile(raw, contracts)
        value = ctypes.c_uint64(123)
        self.assertEqual(function(ctypes.addressof(value)), 123)
        self.assertEqual(len(report['functions'][1]['bounded_loops']), 1)
        self.assertEqual(report['functions'][1]['memory_effects']['image_writes'], [])


if __name__ == '__main__':
    unittest.main()

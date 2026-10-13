import copy
import ctypes
import os
import resource
import signal
import unittest

import test_effects
from compiler import Rejected


class PointerOutputTests(unittest.TestCase):
    setUp = test_effects.CallEffectsTests.setUp
    compile = test_effects.CallEffectsTests.compile
    fixture = test_effects.CallEffectsTests.fixture
    compile_ir = test_effects.CallEffectsTests.compile_ir

    def case(self, guard='js failed', predicate='nonnegative', between='', after='', prefix=''):
        body = prefix + 'sub rsp, 8\nmov esi, edi\nmov rdi, rsp\ncall [rip+image_cell]\n' + between + 'test eax, eax\n' + guard
        body += '\n' + after + 'mov rax, [rsp]\nmov rax, [rax]\nadd rsp, 8\nret\nfailed:\nmov eax, 777\nadd rsp, 8\nret'
        provider = {'name': 'native_make', 'parameters': ['ptr', 'i32'], 'result': 'i32',
                    'pointer_outputs': {'success': predicate, 'fields': [{'parameter': 0, 'offset': 0}],
                                        'evidence': 'Test provider writes a native static pointer exactly on successful return.'}}
        return self.fixture([('test_entry', body, ['i32'], 'i64')], imports={'nativeNid': provider})

    def test_native_output_is_usable_only_after_success(self):
        raw, contracts = self.case()
        provider = 'int native_make(void **out, int status) { static unsigned long long value=42; if(status<0) return -1; *out=&value; return 0; }'
        function, report, _ = self.compile(raw, contracts, provider)
        function.argtypes = [ctypes.c_int32]
        self.assertEqual(function(0), 42)
        self.assertEqual(function(-1), 777)
        self.assertIn('nativeNid', report['provider_pointer_outputs'])

    def test_zero_success_guard_executes_native_output(self):
        raw, contracts = self.case('jne failed', 'zero')
        function, _, _ = self.compile(raw, contracts, 'int native_make(void **out, int status) { static unsigned long long value=91; if(status) return status; *out=&value; return 0; }')
        self.assertEqual(function(0), 91)
        self.assertEqual(function(5), 777)

    def test_failed_or_nonmatching_guard_does_not_prove_output(self):
        for guard, predicate in [('jns failed', 'nonnegative'), ('je failed', 'zero'), ('js failed', 'zero')]:
            with self.subTest(guard=guard, predicate=predicate):
                with self.assertRaisesRegex(Rejected, 'pointer origin'):
                    self.compile_ir(*self.case(guard, predicate))

    def test_overwritten_status_and_unguarded_flow_reject(self):
        for guard, between in [('', ''), ('js failed', 'xor eax, eax\n'), ('jns same\nsame:', '')]:
            with self.subTest(guard=guard, between=between):
                with self.assertRaisesRegex(Rejected, 'pointer origin'):
                    self.compile_ir(*self.case(guard, between=between))

    def test_output_overwrite_invalidates_pointer(self):
        for store in ('mov qword ptr [rsp], 8192', 'mov byte ptr [rsp+1], 1', 'pxor xmm0, xmm0\nmovups [rsp-8], xmm0'):
            with self.subTest(store=store):
                with self.assertRaisesRegex(Rejected, 'pointer origin|literal-derived'):
                    self.compile_ir(*self.case(after=store+'\n'))

    def test_rebound_provider_cannot_supply_output_proof(self):
        raw, contracts = self.case(prefix='mov [rip+image_cell], rdi\n')
        contracts['functions'][0]['parameters'] = ['ptr']
        with self.assertRaisesRegex(Rejected, 'pointer origin'):
            self.compile_ir(raw, contracts)

    def test_contract_schema_rejects_unsupported_outputs(self):
        raw, contracts = self.case()
        mutations = [lambda x: x.update(success='positive'), lambda x: x.update(evidence=''),
                     lambda x: x.update(fields=[]), lambda x: x['fields'][0].update(parameter=1),
                     lambda x: x['fields'][0].update(offset=-8), lambda x: x['fields'][0].update(offset=4),
                     lambda x: x['fields'].append(dict(x['fields'][0]))]
        for mutate in mutations:
            value = copy.deepcopy(contracts)
            mutate(value['imports']['nativeNid']['pointer_outputs'])
            with self.assertRaisesRegex(Rejected, 'pointer output'):
                self.compile_ir(raw, value)

    def test_internal_postconditions_cannot_be_declared_without_proof(self):
        raw, contracts = self.case()
        contracts['functions'][0]['parameters'] = ['ptr']
        contracts['functions'][0]['pointer_outputs'] = contracts['imports']['nativeNid']['pointer_outputs']
        with self.assertRaisesRegex(Rejected, 'internal pointer outputs'):
            self.compile_ir(raw, contracts)


    def internal_case(self, body):
        raw, contracts = self.fixture([
            ('test_entry', 'sub rsp, 8\nlea rdi, [rip+image_other]\nmov rsi, rsp\ncall helper\ntest eax, eax\njne failed\nmov rax, [rsp]\nmov rax, [rax]\nadd rsp, 8\nret\nfailed:\nmov eax, 777\nadd rsp, 8\nret', [], 'i64'),
            ('helper', body, ['ptr', 'ptr'], 'i32')])
        contracts['functions'][1]['pointer_outputs'] = {
            'success': 'zero', 'fields': [{'parameter': 1, 'offset': 0, 'within_parameter': 0}],
            'evidence': 'Native guard checks the actual pointer against the source image region after successful return.'}
        return raw, contracts

    def test_internal_output_is_checked_against_native_source_region(self):
        raw, contracts = self.internal_case('lea rax, [rdi+8]\nmov [rsi], rax\nxor eax, eax\nret')
        function, _, optimized = self.compile(raw, contracts)
        self.assertEqual(function(), 0)

    def test_invalid_internal_output_traps_instead_of_gaining_provenance(self):
        raw, contracts = self.internal_case('mov qword ptr [rsi], 8192\nxor eax, eax\nret')
        function, _, _ = self.compile(raw, contracts)
        pid = os.fork()
        if pid == 0:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            function()
            os._exit(0)
        _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertIn(os.WTERMSIG(status), (signal.SIGILL, signal.SIGTRAP))

    def test_failed_internal_call_does_not_read_invalid_output(self):
        raw, contracts = self.internal_case('mov qword ptr [rsi], 8192\nmov eax, -1\nret')
        function, _, _ = self.compile(raw, contracts)
        self.assertEqual(function(), 777)


if __name__ == '__main__':
    unittest.main()

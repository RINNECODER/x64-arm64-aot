import copy
import subprocess
import unittest

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

from compiler import Rejected
import test_immutable_data


class FiniteTableTests(unittest.TestCase):
    setUp = test_immutable_data.ImmutableDataTests.setUp
    fixture = test_immutable_data.ImmutableDataTests.fixture
    immutable = test_immutable_data.ImmutableDataTests.immutable
    compile_ir = test_immutable_data.ImmutableDataTests.compile_ir
    build = test_immutable_data.ImmutableDataTests.build

    def call_fixture(self):
        return self.immutable(*self.fixture([
            ('test_entry', 'lea rax, [rip+image_cell]\nsub rsp, 8\ncall [rax+rdi*8]\nadd rsp, 8\nret', ['u64'], 'u64'),
            ('one', 'mov eax, 41\nret', [], 'u64'), ('two', 'mov eax, 42\nret', [], 'u64')],
            relocations=[[0x2000, 0x1100], [0x2008, 0x1200]]))

    def jump_fixture(self):
        body = 'lea rax, [rip+image_cell]\njmp [rax+rdi*8]\nmov eax, 41\nret\nmov eax, 42\nret'
        raw, contracts = self.fixture([('test_entry', body, ['u64'], 'u64')])
        decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        targets = [ins.address for ins in decoder.disasm(raw[0x1000:0x1000 + contracts['functions'][0]['size']], 0x1000)
                   if ins.mnemonic == 'mov']
        return self.immutable(*self.fixture([('test_entry', body, ['u64'], 'u64')],
                                          relocations=[[0x2000 + 8 * i, target] for i, target in enumerate(targets)]))

    def test_relocation_table_calls_execute_and_reject_out_of_bounds(self):
        raw, contracts = self.call_fixture()
        source = '''#include <csignal>
#include <cstdlib>
extern "C" unsigned long long test_entry(unsigned long long);
static void trapped(int) { std::_Exit(77); }
int main(int argc, char**) {
    std::signal(SIGILL, trapped);
    std::signal(SIGTRAP, trapped);
    if (argc > 1) return int(test_entry(~0ull));
    return test_entry(0) == 41 && test_entry(1) == 42 ? 0 : 1;
}
'''
        binary, ir, report, _ = self.build(raw, contracts, source)
        subprocess.run([str(binary)], check=True, capture_output=True)
        self.assertEqual(subprocess.run([str(binary), 'invalid'], capture_output=True).returncode, 77)
        self.assertEqual(report['finite_tables'][0]['targets'], [0x1100, 0x1200])
        self.assertIn('target_invalid_', ir)

    def test_local_jump_table_executes_distinct_native_blocks(self):
        raw, contracts = self.jump_fixture()
        source = '''#include <csignal>
#include <cstdlib>
extern "C" unsigned long long test_entry(unsigned long long);
static void trapped(int) { std::_Exit(77); }
int main(int argc, char**) {
    std::signal(SIGILL, trapped);
    std::signal(SIGTRAP, trapped);
    if (argc > 1) return int(test_entry(2));
    return test_entry(0) == 41 && test_entry(1) == 42 ? 0 : 1;
}
'''
        binary, ir, report, _ = self.build(raw, contracts, source)
        subprocess.run([str(binary)], check=True, capture_output=True)
        self.assertEqual(subprocess.run([str(binary), 'invalid'], capture_output=True).returncode, 77)
        self.assertIn('indirectbr', ir)
        self.assertEqual(report['finite_tables'][0]['kind'], 'jmp')

    def test_mutable_tables_and_mismatched_abis_remain_rejected(self):
        raw, contracts = self.call_fixture()
        contracts.pop('immutable_data')
        with self.assertRaisesRegex(Rejected, 'indirect calls'):
            self.compile_ir(raw, contracts)
        raw, contracts = self.call_fixture()
        contracts['functions'][2]['result'] = 'f64'
        with self.assertRaisesRegex(ValueError, 'incompatible target ABIs'):
            self.compile_ir(raw, contracts)

    def test_jump_into_middle_of_instruction_rejects(self):
        raw, contracts = self.jump_fixture()
        targets = copy.deepcopy(contracts['pointer_relocations'])
        targets[1][1] = targets[0][1] + 1
        body = 'lea rax, [rip+image_cell]\njmp [rax+rdi*8]\nmov eax, 41\nret\nmov eax, 42\nret'
        raw, contracts = self.immutable(*self.fixture([('test_entry', body, ['u64'], 'u64')], relocations=targets))
        with self.assertRaisesRegex(Rejected, 'overlapping instruction'):
            self.compile_ir(raw, contracts)

    def test_known_alias_write_to_table_rejects(self):
        raw, contracts = self.immutable(*self.fixture([
            ('test_entry', 'lea rax, [rip+image_cell]\nmov QWORD PTR [rax], 0\ncall [rax+rdi*8]\nret', ['u64'], 'u64'),
            ('one', 'mov eax, 41\nret', [], 'u64')], relocations=[[0x2000, 0x1100]]))
        with self.assertRaisesRegex(Rejected, 'immutable image data'):
            self.compile_ir(raw, contracts)

    def test_declared_callback_rejects_an_undeclared_native_target(self):
        from test_calls import callback_fixture
        raw, contracts = callback_fixture()
        source = """#include <csignal>
#include <cstdlib>
extern "C" unsigned long long test_entry(void*, unsigned long long);
extern "C" unsigned long long callback_inverse(unsigned long long);
extern "C" unsigned long long other(unsigned long long value) { return value; }
static void trapped(int) { std::_Exit(77); }
int main(int argc, char**) {
    std::signal(SIGILL, trapped);
    std::signal(SIGTRAP, trapped);
    if (argc > 1) return int(test_entry(reinterpret_cast<void*>(&other), 5));
    return test_entry(reinterpret_cast<void*>(&callback_inverse), 5) == ~5ull ? 0 : 1;
}
"""
        binary, _, _, _ = self.build(raw, contracts, source)
        subprocess.run([str(binary)], check=True, capture_output=True)
        self.assertEqual(subprocess.run([str(binary), 'invalid'], capture_output=True).returncode, 77)


if __name__ == '__main__':
    unittest.main()

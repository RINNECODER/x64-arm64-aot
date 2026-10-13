import ctypes
import random
import unittest

import test_compiler
import test_checked_pointers
import test_contract_recipe


class RecipeExecutionTests(unittest.TestCase):
    setUp = test_compiler.CompilerTests.setUp
    recipe = test_contract_recipe.ContractRecipeTests.recipe
    materialize = test_contract_recipe.ContractRecipeTests.materialize
    compile = test_checked_pointers.CheckedPointerTests.compile
    assert_traps = test_checked_pointers.CheckedPointerTests.assert_traps

    def test_independent_load_xor_executes_with_derived_guards(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('488b07483306c3'), ['u64', 'u64'])
        source, recipe = self.recipe(raw, contracts)
        generated, report = self.materialize(source, recipe)
        function, _, _ = self.compile(raw, generated)
        randomizer = random.Random(179)
        for _ in range(128):
            left, right = ctypes.c_uint64(randomizer.getrandbits(64)), ctypes.c_uint64(randomizer.getrandbits(64))
            self.assertEqual(function(ctypes.addressof(left), ctypes.addressof(right)), left.value ^ right.value)
        self.assert_traps(function, 8192, ctypes.addressof(right))
        self.assert_traps(function, ctypes.addressof(left), 0)
        self.assertEqual(report['derived_sites']['checked_pointer_bases'], 2)

    def test_independent_import_executes_with_derived_argument_guard(self):
        raw, contracts = test_compiler.fixture(bytes.fromhex('ff15fa0f0000c3'), ['u64'], imports={
            'testNid': {'name': 'provider', 'parameters': ['ptr'], 'result': 'u64'}})
        source, recipe = self.recipe(raw, contracts)
        generated, _ = self.materialize(source, recipe)
        function, _, _ = self.compile(raw, generated, extra='unsigned long long provider(const unsigned long long *p) { return *p + 17; }')
        for n in (0, 17, 0xffffffffffffffff):
            value = ctypes.c_uint64(n)
            self.assertEqual(function(ctypes.addressof(value)), (n + 17) & 0xffffffffffffffff)
        self.assert_traps(function, 0)


if __name__ == '__main__':
    unittest.main()

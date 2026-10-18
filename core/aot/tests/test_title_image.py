import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_compiler


class TitleImageTests(unittest.TestCase):
    def test_a_frontier_plt_thunk_is_lowered_not_stubbed(self):
        # Contract: a six-byte PLT thunk (`jmp *[slot]` with an import slot) is lowerable, so the
        # bounded image must not mark one as a reporting stub just because the walk left it in the
        # frontier. Regression: a thunk enqueued but not popped within `--limit` was stubbed, and
        # the boot then stopped at the import it resolves instead of calling it. Existing coverage
        # misses this: the ABI test exercises the import-annotation boundary, not the frontier
        # promotion, and no test builds a thunk outside the native closure.
        entry = bytes.fromhex('e801000000c3')       # 0x1000: call 0x1006; ret
        thunk = bytes.fromhex('ff25f40f0000')       # 0x1006: jmp *[rip+0xff4] -> 0x2000
        raw, contracts = test_compiler.fixture(
            entry + thunk, result='void',
            functions=[{'name': 'entry', 'address': 0x1000, 'size': len(entry), 'uniform': True, 'result': 'void', 'parameters': []},
                       {'name': 'thunk', 'address': 0x1006, 'size': len(thunk), 'uniform': True, 'result': 'void', 'parameters': []}],
            imports={'F8bUHwAG284#s#Y': {'name': 'scePthreadMutexattrInit', 'result': 'i32', 'parameters': ['ptr']}})
        root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory(prefix='anyps5-thunk-') as folder:
            folder = Path(folder)
            (folder / 'in.elf').write_bytes(raw)
            (folder / 'contracts.json').write_text(json.dumps(contracts))
            result = subprocess.run([sys.executable, str(root / 'tools/native/title_image.py'),
                                     '--elf', str(folder / 'in.elf'), '--contracts', str(folder / 'contracts.json'),
                                     '--limit', '1', '--output', str(folder / 'out.ll')],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            ir = (folder / 'out.ll').read_text()
        self.assertNotIn('NativeAotReportUnimplemented', ir)
        self.assertIn('scePthreadMutexattrInit', ir)


if __name__ == '__main__':
    unittest.main()

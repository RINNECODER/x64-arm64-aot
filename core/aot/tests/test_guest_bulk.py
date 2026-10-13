import unittest
import json
from pathlib import Path

import guest_lab


class GuestBulkTests(unittest.TestCase):
    def test_sparse_writeback_against_independent_register_oracle(self):
        cases = json.loads((Path(__file__).parent / 'guest_lab_cases.json').read_text())
        selected = cases[::7]
        with guest_lab.lab_directory() as directory:
            failures = guest_lab.Lab(directory, memory_epochs=True).compare(selected, samples=16, seed=91)
        self.assertEqual(failures[:3], [])

    def test_private_bulk_matches_sequential_memory_and_live_registers(self):
        cases = [{'asm': [f'rep {name}']} for name in ('movsb', 'movsw', 'movsd', 'movsq', 'stosb')]
        with guest_lab.lab_directory() as directory:
            lab = guest_lab.Lab(directory)
            binary, roots = lab.lifted_binary(cases, memory_epochs=True)
            records, expected = [], []
            for root, step, fill in zip(roots, [1, 2, 4, 8, 1], [False] * 4 + [True]):
                for source, destination in ((0, 256), (65, 64), (64, 65), (64, 64), (64, 72), (72, 64), (192, 320)):
                    for count in (0, 1, 2, 7, 15, 16):
                        data = bytearray((i * 17 + 3) % 256 for i in range(guest_lab.BUFFER_SIZE))
                        gpr = [0] * 16
                        gpr[0] = 0x123456789abcde7f
                        gpr[1] = count
                        gpr[6] = guest_lab.BUFFER_MARK + source
                        gpr[7] = guest_lab.BUFFER_MARK + destination
                        gpr[15] = guest_lab.SCRATCH_MARK
                        records.append((root - guest_lab.CODE, list(gpr), bytes(256), guest_lab.ALL_FLAGS | 2, bytes(data)))
                        for index in range(count):
                            offset = index * step
                            value = bytes([0x7f]) if fill else bytes(data[source + offset:source + offset + step])
                            data[destination + offset:destination + offset + step] = value
                        gpr[1] = 0
                        gpr[7] += count * step
                        if not fill:
                            gpr[6] += count * step
                        expected.append((gpr, bytes(data)))
            source, output = Path(directory) / 'input.bin', Path(directory) / 'output.bin'
            lab.write_inputs(records, source)
            guest_lab.run([str(binary), str(source), str(output)])
            for index, (actual, (gpr, data)) in enumerate(zip(lab.read_outputs(output, len(records)), expected)):
                self.assertEqual(actual[3], data, f'memory case {index}')
                for register in (0, 1, 6, 7):
                    self.assertEqual(actual[0][register], gpr[register], f'register {register}, case {index}')
                self.assertEqual(actual[2] & guest_lab.ALL_FLAGS, guest_lab.ALL_FLAGS)
            ir = (Path(directory) / 'lifted/shard00.ll').read_text()
            self.assertIn('call void @llvm.memcpy.', ir)
            self.assertIn('call void @llvm.memset.', ir)
            self.assertIn('load atomic volatile', ir)


if __name__ == '__main__':
    unittest.main()

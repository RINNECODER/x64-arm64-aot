import random
import struct
import unittest
from pathlib import Path

import guest_lab


class GuestAvxTests(unittest.TestCase):
    def test_integer_lanes_upper_state_and_aliases(self):
        cases, operations = [], []
        for bits, register in ((128, 'xmm'), (256, 'ymm')):
            for operation in ('vpand', 'vpor', 'vpxor', 'vpsllvd', 'vpshufd', 'vpbroadcastd'):
                for source in ('register', 'memory'):
                    operand = f'{register}1' if source == 'register' else f'{"xmmword" if bits == 128 else "ymmword"} ptr [rsi + 32]'
                    if operation == 'vpshufd':
                        body = f'vpshufd {register}0, {operand}, 27'
                    elif operation == 'vpbroadcastd':
                        body = f'vpbroadcastd {register}0, ' + ('xmm1' if source == 'register' else 'dword ptr [rsi + 32]')
                    else:
                        body = f'{operation} {register}0, {register}0, {operand}'
                    cases.append({'asm': ['vmovups ymm0, ymmword ptr [rsi]', 'vmovups ymm1, ymmword ptr [rsi + 32]', body,
                                           'vmovups ymmword ptr [rsi + 128], ymm0']})
                    operations.append((bits, operation))
        for operation in ('legacy', 'zero', 'move'):
            middle = {'legacy': 'movdqu xmm0, xmmword ptr [rsi + 32]', 'zero': 'vzeroupper', 'move': 'vmovd xmm0, eax'}[operation]
            cases.append({'asm': ['vmovups ymm0, ymmword ptr [rsi]', middle, 'vmovups ymmword ptr [rsi + 128], ymm0']})
            operations.append((256, operation))
        with guest_lab.lab_directory() as directory:
            lab = guest_lab.Lab(directory, memory_epochs=getattr(self, 'memory_epochs', False))
            binary, roots = lab.lifted_binary(cases)
            rng = random.Random(8821)
            records, expected = [], []
            for root, (bits, operation) in zip(roots, operations):
                for sample in range(64):
                    a = [rng.getrandbits(32) for _ in range(8)]
                    b = [rng.choice([0, 1, 31, 32, 33, 0xffffffff, rng.getrandbits(32)]) for _ in range(8)]
                    data = bytearray([0xa5] * guest_lab.BUFFER_SIZE)
                    data[:32] = struct.pack('<8I', *a)
                    data[32:64] = struct.pack('<8I', *b)
                    count = bits // 32
                    if operation in ('vpand', 'vpor', 'vpxor', 'vpsllvd'):
                        result = []
                        for x, y in zip(a[:count], b[:count]):
                            result.append({'vpand': lambda: x & y, 'vpor': lambda: x | y, 'vpxor': lambda: x ^ y,
                                           'vpsllvd': lambda: (x << y) & 0xffffffff if y < 32 else 0}[operation]())
                    elif operation == 'vpshufd':
                        result = [b[(index // 4) * 4 + 3 - index % 4] for index in range(count)]
                    elif operation == 'vpbroadcastd':
                        result = [b[0]] * count
                    elif operation == 'legacy':
                        result = b[:4] + a[4:]
                    elif operation == 'zero':
                        result = a[:4] + [0] * 4
                    else:
                        result = [0x89abcdef] + [0] * 7
                    result += [0] * (8 - len(result))
                    gpr = [0] * 16
                    gpr[0] = 0x1234567889abcdef
                    gpr[6] = guest_lab.BUFFER_MARK
                    gpr[15] = guest_lab.SCRATCH_MARK
                    records.append((root - guest_lab.CODE, gpr, bytes(256), guest_lab.ALL_FLAGS | 2, bytes(data)))
                    data[128:160] = struct.pack('<8I', *result)
                    expected.append(bytes(data))
            source, output = Path(directory) / 'inputs.bin', Path(directory) / 'outputs.bin'
            lab.write_inputs(records, source)
            guest_lab.run([str(binary), str(source), str(output)])
            for index, (actual, wanted) in enumerate(zip(lab.read_outputs(output, len(records)), expected)):
                self.assertEqual(actual[3], wanted, f'case {index // 64}, sample {index % 64}')
                self.assertEqual(actual[2] & guest_lab.ALL_FLAGS, guest_lab.ALL_FLAGS)

    def test_sparse_epoch_writeback_preserves_upper_lanes(self):
        self.memory_epochs = True
        self.test_integer_lanes_upper_state_and_aliases()

    def test_cache_flush_preserves_guest_state(self):
        with guest_lab.lab_directory() as directory:
            failures = guest_lab.Lab(directory).compare([
                {'asm': ['clflush byte ptr [rsi]'], 'pointers': {'rsi': 64}},
                {'asm': ['clflush byte ptr [rsi + 63]'], 'pointers': {'rsi': 64}},
            ], samples=16, seed=81)
        self.assertEqual(failures, [])


if __name__ == '__main__':
    unittest.main()

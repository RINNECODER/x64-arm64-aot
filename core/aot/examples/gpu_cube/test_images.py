import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from images import compare, compare_frames, compare_png, read_bmp, read_png


def write_bmp(path, rows, bits=32, top_down=True):
    width, height = len(rows[0]), len(rows)
    stride = ((width * bits + 31) // 32) * 4
    pixels = bytearray()
    for row in rows if top_down else reversed(rows):
        packed = b''.join(bytes(color) + (b'\xff' if bits == 32 else b'') for color in row)
        pixels.extend(packed + b'\0' * (stride - len(packed)))
    header = b'BM' + struct.pack('<IHHI', 54 + len(pixels), 0, 0, 54)
    header += struct.pack('<IiiHHIIiiII', 40, width, -height if top_down else height, 1, bits, 0, len(pixels), 0, 0, 0, 0)
    path.write_bytes(header + pixels)


def png_chunk(kind, body):
    return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(kind + body) & 0xffffffff)


def write_png(path, rows, filters, colour=2):
    """Encode an 8-bit PNG with one filter type per row, so the reader's filters are exercised."""
    width, height = len(rows[0]), len(rows)
    channels = 4 if colour == 6 else 3
    stride = width * channels
    raw = bytearray()
    previous = bytes(stride)
    for row, filter_type in zip(rows, filters):
        line = bytearray()
        for color in row:
            line += bytes(color) + (b'\xff' if colour == 6 else b'')
        encoded = bytearray(stride)
        for x in range(stride):
            left = line[x - channels] if x >= channels else 0
            up = previous[x]
            corner = previous[x - channels] if x >= channels else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = up
            elif filter_type == 3:
                predictor = (left + up) >> 1
            elif filter_type == 4:
                estimate = left + up - corner
                pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - corner)
                predictor = left if (pa <= pb and pa <= pc) else (up if pb <= pc else corner)
            else:
                raise ValueError('bad filter')
            encoded[x] = (line[x] - predictor) & 0xFF
        raw.append(filter_type)
        raw += encoded
        previous = bytes(line)
    header = struct.pack('>IIBBBBB', width, height, 8, colour, 0, 0, 0)
    path.write_bytes(b'\x89PNG\r\n\x1a\n' + png_chunk(b'IHDR', header)
                     + png_chunk(b'IDAT', zlib.compress(bytes(raw))) + png_chunk(b'IEND', b''))


class Images(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.rows = [[(10, 20, 30), (40, 50, 60), (70, 80, 90)], [(1, 2, 3), (4, 5, 6), (7, 8, 9)]]

    def test_row_order_and_padding(self):
        a, b = self.folder / 'a.bmp', self.folder / 'b.bmp'
        write_bmp(a, self.rows, 24, False)
        write_bmp(b, self.rows)
        self.assertEqual(read_bmp(a), read_bmp(b))
        self.assertEqual(compare(a, b)['different_pixels'], 0)

    def test_one_pixel_difference_fails_exact_comparison(self):
        a, b = self.folder / 'a.bmp', self.folder / 'b.bmp'
        write_bmp(a, self.rows)
        self.rows[1][2] = (7, 8, 10)
        write_bmp(b, self.rows)
        result = compare(a, b)
        self.assertEqual(result['different_pixels'], 1)
        self.assertEqual(result['first_differences'], [[2, 1]])

    def test_truncated_or_oversized_capture_rejects(self):
        path = self.folder / 'a.bmp'
        write_bmp(path, self.rows)
        good = path.read_bytes()
        path.write_bytes(good[:-1])
        with self.assertRaises(ValueError):
            read_bmp(path)
        raw = bytearray(good)
        struct.pack_into('<i', raw, 18, 8193)
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            read_bmp(path)

    def test_missing_extra_blank_and_frozen_captures_reject(self):
        a, b = self.folder / 'a', self.folder / 'b'
        a.mkdir(); b.mkdir()
        with self.assertRaises(ValueError):
            compare_frames(a, b, 2)
        for folder in (a, b):
            for index in range(2):
                write_bmp(folder / f'frame_{index:03d}.bmp', [[(0, 0, 0)]])
        self.assertFalse(compare_frames(a, b, 2)['passed'])
        for folder in (a, b):
            for index in range(2):
                write_bmp(folder / f'frame_{index:03d}.bmp', self.rows)
        self.assertFalse(compare_frames(a, b, 2)['passed'])
        self.rows[0][0] = (20, 10, 30)
        for folder in (a, b):
            write_bmp(folder / 'frame_001.bmp', self.rows)
        self.assertTrue(compare_frames(a, b, 2)['passed'])
        write_bmp(a / 'frame_002.bmp', self.rows)
        with self.assertRaises(ValueError):
            compare_frames(a, b, 2)

    # Contract: read_png/compare_png are the Metal capture reader. They must decode every PNG
    # filter to the same RGB as the BMP reader and reject unsupported layouts. The BMP tests
    # above cannot catch a broken PNG unfilter, which is why these exist.
    def test_png_reader_decodes_every_filter_to_bmp_pixels(self):
        for filter_type in range(5):
            png, bmp = self.folder / f'f{filter_type}.png', self.folder / f'f{filter_type}.bmp'
            write_png(png, self.rows, [filter_type] * len(self.rows))
            write_bmp(bmp, self.rows)
            self.assertEqual(read_png(png), read_bmp(bmp))

    def test_png_reader_strips_alpha_and_compares_exactly(self):
        a, b = self.folder / 'a.png', self.folder / 'b.png'
        write_png(a, self.rows, [2, 4], colour=6)
        write_png(b, self.rows, [0, 3], colour=2)
        self.assertEqual(compare_png(a, b)['different_pixels'], 0)
        self.rows[1][2] = (7, 8, 10)
        write_png(b, self.rows, [0, 0], colour=2)
        result = compare_png(a, b)
        self.assertEqual(result['different_pixels'], 1)
        self.assertEqual(result['first_differences'], [[2, 1]])

    def test_png_reader_rejects_unsupported_layout(self):
        path = self.folder / 'a.png'
        write_png(path, self.rows, [0, 0])
        good = path.read_bytes()
        path.write_bytes(good[:20])
        with self.assertRaises(ValueError):
            read_png(path)
        path.write_bytes(good[:8] + png_chunk(b'IHDR', struct.pack('>IIBBBBB', 3, 2, 16, 2, 0, 0, 0))
                         + png_chunk(b'IDAT', zlib.compress(b'\0' * 12)) + png_chunk(b'IEND', b''))
        with self.assertRaises(ValueError):
            read_png(path)


if __name__ == '__main__':
    unittest.main()

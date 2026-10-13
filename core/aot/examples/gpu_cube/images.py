import hashlib
import struct
import zlib
from pathlib import Path


def read_bmp(path):
    data = Path(path).read_bytes()
    if len(data) < 54 or data[:2] != b'BM':
        raise ValueError('invalid BMP header')
    declared, offset = struct.unpack_from('<IxxxxI', data, 2)
    header, width, height, planes, bits, compression = struct.unpack_from('<IiiHHI', data, 14)
    if declared != len(data) or header < 40 or offset < 14 + header or width <= 0 or height == 0 or planes != 1 or bits not in (24, 32) or compression != 0:
        raise ValueError('unsupported BMP layout')
    if width > 8192 or abs(height) > 8192:
        raise ValueError('BMP exceeds comparison bounds')
    stride = ((width * bits + 31) // 32) * 4
    if len(data) - offset != stride * abs(height):
        raise ValueError('truncated BMP pixels')
    result = bytearray(width * abs(height) * 3)
    for y in range(abs(height)):
        source_y = y if height < 0 else height - 1 - y
        row = data[offset + source_y * stride:offset + (source_y + 1) * stride]
        for x in range(width):
            start = x * (bits // 8)
            result[(y * width + x) * 3:(y * width + x + 1) * 3] = row[start:start + 3]
    return width, abs(height), bytes(result)


def _add_byte_lanes(left, right):
    """Per-byte (left + right) mod 256 for two equal-length buffers, without carries between bytes.

    The PNG "Up" filter is row-wise byte addition; doing it with Python big integers keeps the
    common case at C speed instead of a per-byte loop.
    """
    size = len(left)
    a = int.from_bytes(left, 'big')
    b = int.from_bytes(right, 'big')
    low = int.from_bytes(b'\x7f' * size, 'big')
    high = int.from_bytes(b'\x80' * size, 'big')
    return (((a & low) + (b & low)) ^ ((a ^ b) & high)).to_bytes(size, 'big')


def read_png(path):
    data = Path(path).read_bytes()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('invalid PNG signature')
    position, header, compressed = 8, None, bytearray()
    while position + 12 <= len(data):
        length = struct.unpack_from('>I', data, position)[0]
        kind = data[position + 4:position + 8]
        body = data[position + 8:position + 8 + length]
        if len(body) != length:
            raise ValueError('truncated PNG chunk')
        position += 12 + length
        if kind == b'IHDR':
            header = struct.unpack('>IIBBBBB', body)
        elif kind == b'IDAT':
            compressed += body
        elif kind == b'IEND':
            break
    if header is None:
        raise ValueError('PNG has no IHDR')
    width, height, depth, colour, compression, filter_method, interlace = header
    if depth != 8 or colour not in (2, 6) or compression != 0 or filter_method != 0 or interlace != 0:
        raise ValueError('unsupported PNG layout')
    if width == 0 or height == 0 or width > 8192 or height > 8192:
        raise ValueError('PNG exceeds comparison bounds')
    channels = 4 if colour == 6 else 3
    stride = width * channels
    raw = zlib.decompress(bytes(compressed))
    if len(raw) != (stride + 1) * height:
        raise ValueError('truncated PNG pixels')
    rows = []
    previous = bytes(stride)
    for y in range(height):
        start = y * (stride + 1)
        filter_type = raw[start]
        line = bytearray(raw[start + 1:start + 1 + stride])
        if filter_type == 0:
            pass
        elif filter_type == 2:
            line = bytearray(_add_byte_lanes(bytes(line), previous))
        else:
            for x in range(stride):
                left = line[x - channels] if x >= channels else 0
                up = previous[x]
                corner = previous[x - channels] if x >= channels else 0
                if filter_type == 1:
                    line[x] = (line[x] + left) & 0xFF
                elif filter_type == 3:
                    line[x] = (line[x] + ((left + up) >> 1)) & 0xFF
                elif filter_type == 4:
                    estimate = left + up - corner
                    pa, pb, pc = abs(estimate - left), abs(estimate - up), abs(estimate - corner)
                    predictor = left if (pa <= pb and pa <= pc) else (up if pb <= pc else corner)
                    line[x] = (line[x] + predictor) & 0xFF
                else:
                    raise ValueError('unsupported PNG filter')
        rows.append(bytes(line))
        previous = rows[-1]
    if channels == 3:
        pixels = b''.join(rows)
    else:
        result = bytearray(width * height * 3)
        for y, line in enumerate(rows):
            for x in range(width):
                result[(y * width + x) * 3:(y * width + x + 1) * 3] = line[x * 4:x * 4 + 3]
        pixels = bytes(result)
    return width, height, pixels


def _pixel_report(width, height, a, b):
    if len(a) != len(b):
        raise ValueError('capture pixel buffers differ in size')
    # Byte equality is C-speed; only count differing pixels when the frames actually differ.
    changed = [] if a == b else [i // 3 for i in range(0, len(a), 3) if a[i:i + 3] != b[i:i + 3]]
    return {'dimensions': [width, height], 'different_pixels': len(changed),
            'first_differences': [[i % width, i // width] for i in changed[:16]],
            'aot_pixels_sha256': hashlib.sha256(a).hexdigest(),
            'reference_pixels_sha256': hashlib.sha256(b).hexdigest(),
            'aot_colors': len({a[i:i + 3] for i in range(0, len(a), 3)}),
            'reference_colors': len({b[i:i + 3] for i in range(0, len(b), 3)})}


def compare(left, right):
    width, height, a = read_bmp(left)
    other_width, other_height, b = read_bmp(right)
    if (width, height) != (other_width, other_height):
        raise ValueError('capture dimensions differ')
    return _pixel_report(width, height, a, b)


def compare_png(left, right):
    width, height, a = read_png(left)
    other_width, other_height, b = read_png(right)
    if (width, height) != (other_width, other_height):
        raise ValueError('capture dimensions differ')
    return _pixel_report(width, height, a, b)


def compare_frames(left, right, count=8):
    expected = [f'frame_{index:03d}.bmp' for index in range(count)]
    for folder in (left, right):
        if sorted(p.name for p in Path(folder).glob('frame_*.bmp')) != expected:
            raise ValueError('capture set is incomplete or contains unexpected frames')
    frames = [dict(frame=name, **compare(Path(left) / name, Path(right) / name)) for name in expected]
    nonblank = all(f['aot_colors'] >= 2 and f['reference_colors'] >= 2 for f in frames)
    moving = len({f['aot_pixels_sha256'] for f in frames}) >= min(4, count)
    return {'frames': frames, 'nonblank': nonblank, 'moving': moving,
            'passed': nonblank and moving and all(f['different_pixels'] == 0 for f in frames),
            'comparison': 'Exact RGB equality; alpha is not compared'}


def compare_captured_frames(pairs):
    """Compare the Metal path's PNG captures: `pairs` is (name, aot_path, reference_path)."""
    if not pairs:
        raise ValueError('capture set is empty')
    frames = [dict(frame=name, **compare_png(aot, reference)) for name, aot, reference in pairs]
    nonblank = all(f['aot_colors'] >= 2 and f['reference_colors'] >= 2 for f in frames)
    moving = len({f['aot_pixels_sha256'] for f in frames}) >= min(4, len(frames))
    return {'frames': frames, 'nonblank': nonblank, 'moving': moving,
            'passed': nonblank and moving and all(f['different_pixels'] == 0 for f in frames),
            'comparison': 'Exact RGB equality; alpha is not compared'}

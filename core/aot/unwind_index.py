import struct

MAX64 = (1 << 64) - 1
PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_EH_FRAME = 0x6474e550
RULE = 'eh-frame-hdr-index'
RULE_VERSION = 1
OMIT = 0xff
FORMATS = {0x0: ('<Q', 8), 0x2: ('<H', 2), 0x3: ('<I', 4), 0x4: ('<Q', 8),
           0xa: ('<h', 2), 0xb: ('<i', 4), 0xc: ('<q', 8)}


class UnwindError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise UnwindError(message)


def range_fits(offset, size, limit):
    return 0 <= offset <= limit and 0 <= size <= limit - offset


class LoadView:
    def __init__(self, raw):
        require(len(raw) >= 64 and raw[:4] == b'\x7fELF', 'input is not an ELF image')
        require(raw[4] == 2 and raw[5] == 1, 'requires a little-endian ELF64 image')
        machine, = struct.unpack_from('<H', raw, 0x12)
        require(machine == 62, 'requires an x86-64 ELF image')
        self.raw = bytes(raw)
        self.type, = struct.unpack_from('<H', raw, 0x10)
        self.entry, phoff = struct.unpack_from('<QQ', raw, 0x18)
        self.section_table, = struct.unpack_from('<Q', raw, 0x28)
        phentsize, phnum = struct.unpack_from('<HH', raw, 0x36)
        self.section_count, = struct.unpack_from('<H', raw, 0x3c)
        require(phentsize == 56 and 0 < phnum < 0xffff, 'invalid program header count or size')
        require(range_fits(phoff, phnum * 56, len(raw)), 'truncated program header table')
        names = ('type', 'flags', 'offset', 'vaddr', 'paddr', 'filesz', 'memsz', 'align')
        self.segments = [dict(zip(names, struct.unpack_from('<IIQQQQQQ', raw, phoff + index * 56)))
                         for index in range(phnum)]
        self.loads = sorted((s for s in self.segments if s['type'] == PT_LOAD), key=lambda s: s['vaddr'])
        require(self.loads, 'image has no loadable segment')
        for segment in self.loads:
            require(segment['filesz'] <= segment['memsz'], 'load file size exceeds memory size')
            require(range_fits(segment['offset'], segment['filesz'], len(raw)), 'load segment exceeds input file')
            require(range_fits(segment['vaddr'], segment['memsz'], MAX64), 'load address range overflows')
        for left, right in zip(self.loads, self.loads[1:]):
            require(left['vaddr'] + left['memsz'] <= right['vaddr'], 'overlapping load segments')

    def segment(self, address, size=1, file_backed=True):
        key = 'filesz' if file_backed else 'memsz'
        for segment in self.loads:
            if address >= segment['vaddr'] and range_fits(address - segment['vaddr'], size, segment[key]):
                return segment
        return None

    def read(self, address, size):
        require(0 <= address <= MAX64 and size >= 0, 'invalid mapped read')
        segment = self.segment(address, max(size, 1))
        require(segment is not None, f'read 0x{address:x}+{size} is not inside one file-backed load segment')
        offset = segment['offset'] + address - segment['vaddr']
        return self.raw[offset:offset + size]

    def executable(self, address, size):
        segment = self.segment(address, max(size, 1))
        return segment is not None and bool(segment['flags'] & 1)

    def segment_end(self, address):
        segment = self.segment(address)
        require(segment is not None, f'0x{address:x} is not file-backed')
        return segment['vaddr'] + segment['filesz']


class Cursor:
    def __init__(self, view, address, end):
        self.view, self.address, self.end = view, address, end

    def take(self, size):
        require(range_fits(self.address, size, self.end), f'unwind field at 0x{self.address:x} exceeds its record')
        data = self.view.read(self.address, size)
        self.address += size
        return data

    def unpack(self, form):
        size = struct.calcsize(form)
        return struct.unpack(form, self.take(size))[0]

    def leb(self, signed=False):
        value, shift = 0, 0
        while True:
            byte = self.take(1)[0]
            require(shift < 64, 'overflowing LEB128 value')
            value |= (byte & 0x7f) << shift
            shift += 7
            if not byte & 0x80:
                break
        require(value >> 64 == 0, 'overflowing LEB128 value')
        if signed and byte & 0x40:
            value -= 1 << shift
            require(value >= -(1 << 63), 'overflowing signed LEB128 value')
        return value

    def cstring(self):
        start = self.address
        while self.take(1) != b'\0':
            pass
        return self.view.read(start, self.address - start - 1)

    def encoded(self, encoding, data_base=None, function_base=None, allow_indirect=True):
        require(encoding != OMIT, 'omitted pointer has no value')
        field = self.address
        kind, application = encoding & 0x0f, encoding & 0x70
        if kind == 0x1:
            value = self.leb()
        elif kind == 0x9:
            value = self.leb(True)
        else:
            require(kind in FORMATS, f'unsupported pointer format 0x{encoding:02x} at 0x{field:x}')
            value = self.unpack(FORMATS[kind][0])
        bases = {0x00: 0, 0x10: field, 0x30: data_base, 0x40: function_base}
        require(application in bases and bases[application] is not None,
                f'unsupported pointer application 0x{encoding:02x} at 0x{field:x}')
        require(allow_indirect or not encoding & 0x80, f'indirect pointer not allowed at 0x{field:x}')
        return (value + bases[application]) & MAX64, bool(encoding & 0x80)


def parse_cie(view, address, limit):
    cursor = Cursor(view, address, limit)
    length = cursor.unpack('<I')
    require(length != 0xffffffff, f'64-bit CIE at 0x{address:x} is unsupported')
    require(length >= 8, f'invalid CIE length at 0x{address:x}')
    end = cursor.address + length
    require(end <= limit, f'CIE at 0x{address:x} exceeds the unwind stream')
    cursor.end = end
    require(cursor.unpack('<I') == 0, f'record at 0x{address:x} is not a CIE')
    version = cursor.unpack('<B')
    require(version in (1, 3, 4), f'unsupported CIE version {version} at 0x{address:x}')
    augmentation = cursor.cstring().decode('ascii', 'replace')
    if version == 4:
        require(cursor.unpack('<B') == 8 and cursor.unpack('<B') == 0, 'unsupported CIE address size')
    code_alignment, data_alignment = cursor.leb(), cursor.leb(True)
    return_register = cursor.unpack('<B') if version == 1 else cursor.leb()
    require(return_register == 16, f'CIE at 0x{address:x} does not use the x86-64 return address column')
    cie = {'address': address, 'version': version, 'augmentation': augmentation, 'code_alignment': code_alignment,
           'data_alignment': data_alignment, 'pointer_encoding': 0, 'lsda_encoding': None,
           'personality': None, 'personality_indirect': False, 'signal_frame': False, 'end': end}
    if augmentation:
        require(augmentation[0] == 'z', f'unsupported CIE augmentation {augmentation!r} at 0x{address:x}')
        size = cursor.leb()
        augmentation_end = cursor.address + size
        require(augmentation_end <= end, f'CIE augmentation exceeds record at 0x{address:x}')
        for letter in augmentation[1:]:
            if letter == 'R':
                cie['pointer_encoding'] = cursor.unpack('<B')
            elif letter == 'L':
                cie['lsda_encoding'] = cursor.unpack('<B')
            elif letter == 'P':
                encoding = cursor.unpack('<B')
                cie['personality'], cie['personality_indirect'] = cursor.encoded(encoding)
            elif letter == 'S':
                cie['signal_frame'] = True
            else:
                require(False, f'unknown CIE augmentation field {letter!r} at 0x{address:x}')
        require(cursor.address == augmentation_end, f'CIE augmentation size mismatch at 0x{address:x}')
    require(cie['pointer_encoding'] & 0x80 == 0, f'indirect FDE address encoding at 0x{address:x}')
    cie['instructions'] = [cursor.address, end]
    return cie


def parse_fde(view, address, limit, cies):
    cursor = Cursor(view, address, limit)
    length = cursor.unpack('<I')
    require(length != 0xffffffff, f'64-bit FDE at 0x{address:x} is unsupported')
    require(length >= 8, f'invalid FDE length at 0x{address:x}')
    end = cursor.address + length
    require(end <= limit, f'FDE at 0x{address:x} exceeds the unwind stream')
    cursor.end = end
    field = cursor.address
    pointer = cursor.unpack('<I')
    require(0 < pointer <= field, f'record at 0x{address:x} is not an FDE')
    cie_address = field - pointer
    if cie_address not in cies:
        cies[cie_address] = parse_cie(view, cie_address, limit)
    cie = cies[cie_address]
    begin, _ = cursor.encoded(cie['pointer_encoding'], allow_indirect=False)
    size, _ = cursor.encoded(cie['pointer_encoding'] & 0x0f, allow_indirect=False)
    lsda = None
    if cie['augmentation'].startswith('z'):
        augmentation = cursor.leb()
        augmentation_end = cursor.address + augmentation
        require(augmentation_end <= end, f'FDE augmentation exceeds record at 0x{address:x}')
        if cie['lsda_encoding'] not in (None, OMIT):
            value, indirect = cursor.encoded(cie['lsda_encoding'], function_base=begin)
            lsda = {'address': value, 'indirect': indirect} if value else None
        require(cursor.address <= augmentation_end, f'FDE augmentation size mismatch at 0x{address:x}')
        cursor.address = augmentation_end
    return {'address': address, 'end': end, 'cie': cie_address, 'begin': begin, 'size': size,
            'lsda': lsda, 'instructions': [cursor.address, end]}


def header(view, segment):
    address = segment['vaddr']
    require(view.segment(address, segment['filesz']) is not None, 'PT_GNU_EH_FRAME is not inside a file-backed load segment')
    require(segment['filesz'] >= 4, 'PT_GNU_EH_FRAME is truncated')
    cursor = Cursor(view, address, address + segment['filesz'])
    version, frame_encoding, count_encoding, table_encoding = struct.unpack('<BBBB', cursor.take(4))
    require(version == 1, f'unsupported eh_frame_hdr version {version}')
    require(frame_encoding != OMIT, 'eh_frame_hdr omits the eh_frame pointer')
    frame, _ = cursor.encoded(frame_encoding, data_base=address, allow_indirect=False)
    result = {'address': address, 'size': segment['filesz'], 'version': version, 'eh_frame': frame,
              'encodings': [frame_encoding, count_encoding, table_encoding], 'table': None}
    if count_encoding == OMIT or table_encoding == OMIT:
        return result
    count, _ = cursor.encoded(count_encoding, data_base=address, allow_indirect=False)
    width = FORMATS.get(table_encoding & 0x0f, (None, 0))[1]
    require(width > 0, f'eh_frame_hdr table encoding 0x{table_encoding:02x} is not fixed-size')
    require(count <= (cursor.end - cursor.address) // (2 * width), 'eh_frame_hdr table exceeds PT_GNU_EH_FRAME')
    table = []
    for _ in range(count):
        location, _ = cursor.encoded(table_encoding, data_base=address, allow_indirect=False)
        fde, _ = cursor.encoded(table_encoding, data_base=address, allow_indirect=False)
        table.append((location, fde))
    result['table'] = table
    return result


def walk_stream(view, start, cies):
    limit = view.segment_end(start)
    address, records = start, []
    while True:
        if address == limit:
            return records, {'start': start, 'end': address, 'terminated': False, 'stop': 'segment end'}
        if not range_fits(address, 4, limit):
            return records, {'start': start, 'end': address, 'terminated': False, 'stop': 'partial length field'}
        length, = struct.unpack('<I', view.read(address, 4))
        if length == 0:
            return records, {'start': start, 'end': address + 4, 'terminated': True, 'stop': 'zero terminator'}
        try:
            identifier, = struct.unpack('<I', view.read(address + 4, 4))
            if identifier == 0:
                cies[address] = cies.get(address) or parse_cie(view, address, limit)
                records.append(('cie', address))
                address = cies[address]['end']
            else:
                fde = parse_fde(view, address, limit, cies)
                records.append(('fde', fde))
                address = fde['end']
        except UnwindError as error:
            return records, {'start': start, 'end': address, 'terminated': False, 'stop': f'unparseable record: {error}'}


def read_unwind_index(view, relocations=None):
    relocations = relocations or {}
    frames = [s for s in view.segments if s['type'] == PT_GNU_EH_FRAME]
    obligations = []
    if not frames:
        return {'rule': RULE, 'version': RULE_VERSION, 'header': None, 'cies': [], 'fdes': [], 'stream': None,
                'obligations': [{'kind': 'unwind-index-missing', 'subject': None,
                                 'needed': 'function range evidence from another qualified source',
                                 'detail': 'no PT_GNU_EH_FRAME; unindexed .eh_frame bytes are not located without a section table'}]}
    require(len(frames) == 1, 'multiple PT_GNU_EH_FRAME headers')
    loaded = view.segment(frames[0]['vaddr'], max(frames[0]['filesz'], 1))
    if loaded is None or loaded['offset'] + frames[0]['vaddr'] - loaded['vaddr'] != frames[0]['offset']:
        return {'rule': RULE, 'version': RULE_VERSION, 'header': None, 'cies': [], 'fdes': [], 'stream': None,
                'obligations': [{'kind': 'unwind-index-not-loaded', 'subject': {'address': frames[0]['vaddr']},
                                 'needed': 'function range evidence from another qualified source',
                                 'detail': 'PT_GNU_EH_FRAME file offset is not the loaded file offset of its address'}]}
    index = header(view, frames[0])
    cies = {}
    records, stream = walk_stream(view, index['eh_frame'], cies)
    walked = {record['address']: record for kind, record in records if kind == 'fde'}
    if not stream['terminated']:
        obligations.append({'kind': 'unwind-stream-end-ambiguous', 'subject': {'address': stream['end']},
                            'needed': 'bounded end of the eh_frame stream', 'detail': stream['stop']})
    fdes = {}
    if index['table'] is None:
        obligations.append({'kind': 'unwind-search-table-missing', 'subject': {'address': index['address']},
                            'needed': 'indexed FDE set', 'detail': 'eh_frame_hdr omits the search table; only walked FDEs are candidates'})
        stream_limit = stream['end']
        for record in walked.values():
            fdes[record['address']] = dict(record, indexed=False)
    else:
        locations = [location for location, _ in index['table']]
        require(all(left < right for left, right in zip(locations, locations[1:])),
                'eh_frame_hdr search table is not strictly sorted')
        stream_limit = view.segment_end(index['eh_frame'])
        for location, address in index['table']:
            fde = walked.get(address)
            if fde is None:
                require(view.segment(address, 8) is not None, f'indexed FDE 0x{address:x} is outside the image')
                fde = parse_fde(view, address, stream_limit, cies)
                obligations.append({'kind': 'indexed-fde-outside-walked-stream', 'subject': {'address': address},
                                    'needed': 'eh_frame stream that contains every indexed FDE',
                                    'detail': 'the indexed record was parsed directly'})
            require(fde['begin'] == location, f'FDE 0x{address:x} begins at 0x{fde["begin"]:x}, index says 0x{location:x}')
            fdes[address] = dict(fde, indexed=True)
        for address, record in walked.items():
            if address not in fdes:
                kind = 'unindexed-fde' if record['size'] else 'empty-fde'
                obligations.append({'kind': kind, 'subject': {'address': address, 'begin': record['begin'], 'size': record['size']},
                                    'needed': 'qualified reason for an FDE absent from eh_frame_hdr',
                                    'detail': 'walked FDE is not in the binary search table'})
    result = []
    for address, fde in sorted(fdes.items(), key=lambda item: (item[1]['begin'], item[0])):
        cie = cies[fde['cie']]
        entry = {'fde': address, 'cie': fde['cie'], 'begin': fde['begin'], 'size': fde['size'], 'indexed': fde['indexed'],
                 'lsda': fde['lsda'], 'personality': cie['personality'], 'personality_indirect': cie['personality_indirect'],
                 'signal_frame': cie['signal_frame'], 'status': 'qualified', 'problems': []}
        if not fde['size']:
            entry['problems'].append('empty range')
        elif not view.executable(fde['begin'], fde['size']):
            entry['problems'].append('range is not inside one executable file-backed segment')
        if cie['personality_indirect'] and cie['personality'] not in relocations and cie['personality'] is not None:
            entry['problems'].append('indirect personality slot has no relocation binding')
        if entry['problems']:
            entry['status'] = 'rejected'
            obligations.append({'kind': 'invalid-fde-range', 'subject': {'address': address, 'begin': fde['begin'], 'size': fde['size']},
                                'needed': 'FDE range inside executable image bytes', 'detail': '; '.join(entry['problems'])})
        result.append(entry)
    accepted = [entry for entry in result if entry['status'] == 'qualified']
    widest = None
    for right in accepted:
        left = widest
        if widest is None or right['begin'] + right['size'] > widest['begin'] + widest['size']:
            widest = right
        if left is not None and left['begin'] + left['size'] > right['begin']:
            for entry in (left, right):
                entry['status'] = 'conflict'
            obligations.append({'kind': 'overlapping-fde-ranges', 'subject': {'address': left['begin'], 'other': right['begin']},
                                'needed': 'disjoint unwind ranges or a qualified shared-code model',
                                'detail': f'0x{left["begin"]:x}+0x{left["size"]:x} overlaps 0x{right["begin"]:x}'})
    return {'rule': RULE, 'version': RULE_VERSION,
            'header': {key: value for key, value in index.items() if key != 'table'} | {'indexed': None if index['table'] is None else len(index['table'])},
            'cies': [{key: value for key, value in cie.items() if key != 'end'} for _, cie in sorted(cies.items())],
            'fdes': result, 'stream': stream, 'obligations': obligations}


def read_lsda(view, address, function_begin, function_size):
    cursor = Cursor(view, address, view.segment_end(address))
    start_encoding = cursor.unpack('<B')
    landing_base = function_begin
    if start_encoding != OMIT:
        landing_base, _ = cursor.encoded(start_encoding, function_base=function_begin, allow_indirect=False)
    type_encoding = cursor.unpack('<B')
    if type_encoding != OMIT:
        cursor.leb()
    call_encoding = cursor.unpack('<B')
    require(call_encoding & 0x70 == 0 and call_encoding & 0x80 == 0, f'unsupported LSDA call-site encoding 0x{call_encoding:02x}')
    table_size = cursor.leb()
    end = cursor.address + table_size
    require(end <= cursor.end, f'LSDA call-site table at 0x{address:x} exceeds its segment')
    sites = []
    while cursor.address < end:
        start, _ = cursor.encoded(call_encoding, allow_indirect=False)
        length, _ = cursor.encoded(call_encoding, allow_indirect=False)
        landing, _ = cursor.encoded(call_encoding, allow_indirect=False)
        action = cursor.leb()
        require(start + length <= function_size, f'LSDA call site exceeds its function at 0x{address:x}')
        pad = (landing_base + landing) if landing else None
        if pad is not None:
            require(function_begin <= pad < function_begin + function_size, f'LSDA landing pad 0x{pad:x} is outside its function')
        sites.append({'start': function_begin + start, 'size': length, 'landing_pad': pad, 'action': action})
    require(cursor.address == end, f'LSDA call-site table size mismatch at 0x{address:x}')
    return sites

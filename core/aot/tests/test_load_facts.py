import json
import struct
import unittest

import hashlib
import tempfile
from pathlib import Path

from load_facts import recover_load_facts
from recover import RecoveryError, materialize_contracts, recover_image
from unwind_index import LoadView, UnwindError, read_unwind_index

HDR = 0x400
FRAME = 0x500
CODE = 0x1000
DYNAMIC = 0x3000


def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def padded(body):
    return body + bytes(-(len(body) + 4) % 4)


def cie(augmentation=b'zR', return_column=16, personality=None, personality_slot=None):
    data = bytearray()
    if personality_slot is not None:
        field = FRAME + 15 + len(augmentation)
        data += bytes([0x9b]) + struct.pack('<i', personality_slot - field)
    elif b'P' in augmentation:
        data += bytes([0x00]) + struct.pack('<Q', personality)
    data += bytes([0x1b])
    body = struct.pack('<IB', 0, 1) + augmentation + b'\0' + uleb(1) + bytes([0x78, return_column])
    body += uleb(len(data)) + data + bytes([0x0c, 7, 8, 0x90, 1])
    body = padded(body)
    return struct.pack('<I', len(body)) + body


class Image:
    def __init__(self, ranges, code=b'', table=None, terminator=True, plt=None, cie_record=None, extra_relocations=()):
        self.raw = bytearray(0x4000)
        self.ranges = list(ranges)
        self.fdes = []
        frame = bytearray(cie_record or cie())
        for begin, size in self.ranges:
            address = FRAME + len(frame)
            field = address + 4
            body = struct.pack('<Iii', field - FRAME, begin - (field + 4), size) + uleb(0)
            body = padded(body)
            frame += struct.pack('<I', len(body)) + body
            self.fdes.append(address)
        self.terminator = FRAME + len(frame)
        frame += struct.pack('<I', 0) if terminator else b'\xff\xff\xff\x7f'
        self.raw[FRAME:FRAME + len(frame)] = frame
        entries = table if table is not None else sorted(zip((b for b, _ in self.ranges), self.fdes))
        header = struct.pack('<BBBBiI', 1, 0x1b, 0x03, 0x3b, FRAME - (HDR + 4), len(entries))
        header += b''.join(struct.pack('<ii', location - HDR, fde - HDR) for location, fde in entries)
        self.raw[HDR:HDR + len(header)] = header
        self.header_size = len(header)
        self.raw[CODE:CODE + 0x1000] = b'\xcc' * 0x1000
        self.raw[CODE:CODE + len(code)] = code
        self.segments = [(1, 4, 0, 0, 0x1000, 0x1000), (1, 5, CODE, CODE, 0x1000, 0x1000),
                         (0x6474e550, 4, HDR, HDR, self.header_size, self.header_size)]
        if plt is not None:
            self.dynamic(*plt, extra=extra_relocations)
        self.write_headers()

    def dynamic(self, symbol, slot_kind, pltgot, extra=()):
        strings = b'\0' + symbol + b'\0'
        symbols = bytes(24) + struct.pack('<IBBHQQ', 1, 0x12, 0, 0, 0, 0)
        tables = {'hash': DYNAMIC + 0x100, 'symbols': DYNAMIC + 0x140, 'strings': DYNAMIC + 0x180, 'plt': DYNAMIC + 0x1c0}
        self.raw[tables['hash']:tables['hash'] + 20] = struct.pack('<IIIII', 1, 2, 1, 0, 0)
        self.raw[tables['symbols']:tables['symbols'] + len(symbols)] = symbols
        self.raw[tables['strings']:tables['strings'] + len(strings)] = strings
        slot = pltgot + 24
        self.raw[tables['plt']:tables['plt'] + 24] = struct.pack('<QQq', slot, (1 << 32) | slot_kind, 0)
        rela = DYNAMIC + 0x200
        for index, (address, kind, addend) in enumerate(extra):
            struct.pack_into('<QQq', self.raw, rela + index * 24, address, kind, addend)
        relocation_tags = [(23, tables['plt']), (2, 24), (20, 7)] if slot_kind == 7 else [(7, tables['plt']), (8, 24), (9, 24)]
        if extra:
            relocation_tags += [(7, rela), (8, len(extra) * 24), (9, 24)]
        tags = [(4, tables['hash']), (5, tables['strings']), (10, len(strings)), (6, tables['symbols']), (11, 24),
                *relocation_tags, (3, pltgot), (0, 0)]
        for index, tag in enumerate(tags):
            struct.pack_into('<qQ', self.raw, DYNAMIC + index * 16, *tag)
        self.segments += [(1, 6, DYNAMIC, DYNAMIC, 0x1000, 0x1000), (2, 6, DYNAMIC, DYNAMIC, len(tags) * 16, len(tags) * 16)]
        self.slot = slot

    def write_headers(self):
        struct.pack_into('<16sHHIQQQIHHHHHH', self.raw, 0, b'\x7fELF\x02\x01\x01' + bytes(9), 3, 62, 1, CODE, 64,
                         0, 0, 64, 56, len(self.segments), 64, 0, 0)
        for index, (kind, flags, offset, address, filesz, memsz) in enumerate(self.segments):
            struct.pack_into('<IIQQQQQQ', self.raw, 64 + index * 56, kind, flags, offset, address, address, filesz, memsz, 0x1000)

    def bytes(self):
        return bytes(self.raw)


def unwind(raw):
    return read_unwind_index(LoadView(raw))


def obligations(report, kind):
    return [item for item in report['obligations'] if item['kind'] == kind]


class UnwindIndexTests(unittest.TestCase):
    def test_ranges_follow_search_table(self):
        result = unwind(Image([(0x1000, 0x10), (0x1020, 0x30)]).bytes())
        self.assertEqual([(f['begin'], f['size'], f['status']) for f in result['fdes']],
                         [(0x1000, 0x10, 'qualified'), (0x1020, 0x30, 'qualified')])
        self.assertTrue(result['stream']['terminated'])
        self.assertEqual(result['obligations'], [])

    def test_section_table_is_never_read(self):
        image = Image([(0x1000, 0x10)])
        clean = unwind(image.bytes())
        struct.pack_into('<Q', image.raw, 0x28, 0x3ff0)
        struct.pack_into('<HHH', image.raw, 0x3a, 64, 9, 7)
        self.assertEqual(unwind(image.bytes()), clean)

    def test_missing_index_is_an_obligation(self):
        image = Image([(0x1000, 0x10)])
        image.segments.pop()
        image.write_headers()
        result = unwind(image.bytes())
        self.assertEqual(result['fdes'], [])
        self.assertEqual([item['kind'] for item in result['obligations']], ['unwind-index-missing'])

    def test_unloaded_index_is_an_obligation(self):
        image = Image([(0x1000, 0x10)])
        image.segments[2] = (0x6474e550, 4, 0x3f00, 0, 4, 4)
        image.write_headers()
        result = unwind(image.bytes())
        self.assertEqual(result['fdes'], [])
        self.assertEqual([item['kind'] for item in result['obligations']], ['unwind-index-not-loaded'])

    def test_truncated_header_rejected(self):
        image = Image([(0x1000, 0x10)])
        image.segments[2] = (0x6474e550, 4, HDR, HDR, 3, 3)
        image.write_headers()
        with self.assertRaisesRegex(UnwindError, 'truncated'):
            unwind(image.bytes())

    def test_unsorted_and_duplicate_tables_rejected(self):
        base = Image([(0x1000, 0x10), (0x1020, 0x10)])
        swapped = list(reversed(sorted(zip((0x1000, 0x1020), base.fdes))))
        with self.assertRaisesRegex(UnwindError, 'not strictly sorted'):
            unwind(Image([(0x1000, 0x10), (0x1020, 0x10)], table=swapped).bytes())
        doubled = [(0x1000, base.fdes[0]), (0x1000, base.fdes[0])]
        with self.assertRaisesRegex(UnwindError, 'not strictly sorted'):
            unwind(Image([(0x1000, 0x10), (0x1020, 0x10)], table=doubled).bytes())

    def test_table_key_must_match_fde(self):
        base = Image([(0x1000, 0x10)])
        with self.assertRaisesRegex(UnwindError, 'index says 0x1004'):
            unwind(Image([(0x1000, 0x10)], table=[(0x1004, base.fdes[0])]).bytes())

    def test_indexed_pointer_outside_image_rejected(self):
        with self.assertRaisesRegex(UnwindError, 'outside the image'):
            unwind(Image([(0x1000, 0x10)], table=[(0x1000, 0x9000)]).bytes())

    def test_range_outside_executable_is_not_qualified(self):
        result = unwind(Image([(0x1000, 0x10), (0x0800, 0x10)]).bytes())
        status = {f['begin']: f['status'] for f in result['fdes']}
        self.assertEqual(status, {0x0800: 'rejected', 0x1000: 'qualified'})
        self.assertEqual(len(obligations(result, 'invalid-fde-range')), 1)

    def test_range_crossing_segment_end_is_not_qualified(self):
        result = unwind(Image([(0x1ff0, 0x20)]).bytes())
        self.assertEqual(result['fdes'][0]['status'], 'rejected')

    def test_overlapping_ranges_conflict(self):
        result = unwind(Image([(0x1000, 0x100), (0x1020, 0x10), (0x1080, 0x10)]).bytes())
        self.assertEqual({f['status'] for f in result['fdes']}, {'conflict'})
        self.assertEqual(len(obligations(result, 'overlapping-fde-ranges')), 2)

    def test_unindexed_fde_reported(self):
        base = Image([(0x1000, 0x10), (0x1020, 0x10)])
        result = unwind(Image([(0x1000, 0x10), (0x1020, 0x10)], table=[(0x1000, base.fdes[0])]).bytes())
        self.assertEqual([f['begin'] for f in result['fdes']], [0x1000])
        self.assertEqual(obligations(result, 'unindexed-fde')[0]['subject']['begin'], 0x1020)

    def test_unterminated_stream_is_ambiguous(self):
        result = unwind(Image([(0x1000, 0x10)], terminator=False).bytes())
        self.assertFalse(result['stream']['terminated'])
        self.assertEqual(len(obligations(result, 'unwind-stream-end-ambiguous')), 1)
        self.assertEqual(result['fdes'][0]['status'], 'qualified')

    def test_unsupported_encodings_rejected(self):
        image = Image([(0x1000, 0x10)])
        image.raw[HDR + 3] = 0x3d
        with self.assertRaisesRegex(UnwindError, 'not fixed-size'):
            unwind(image.bytes())
        image = Image([(0x1000, 0x10)])
        image.raw[HDR + 1] = 0x5b
        with self.assertRaisesRegex(UnwindError, 'unsupported pointer application'):
            unwind(image.bytes())

    def test_extended_length_rejected(self):
        image = Image([(0x1000, 0x10)])
        struct.pack_into('<I', image.raw, image.fdes[0], 0xffffffff)
        with self.assertRaisesRegex(UnwindError, '64-bit FDE'):
            unwind(image.bytes())

    def test_foreign_return_column_rejected(self):
        with self.assertRaisesRegex(UnwindError, 'return address column'):
            unwind(Image([(0x1000, 0x10)], cie_record=cie(return_column=30)).bytes())

    def test_personality_reported_as_exception_metadata(self):
        report = recover_load_facts(Image([(0x1000, 0x10)], cie_record=cie(b'zPR', personality=0x1100)).bytes())
        self.assertEqual(len(obligations(report, 'exception-metadata')), 1)


class LoadFactTests(unittest.TestCase):
    def plt_image(self, slot_kind=7, symbol=b'imported'):
        code = bytearray(b'\xcc' * 0x40)
        code[0:5] = b'\xe8' + struct.pack('<i', 0x1810 - 0x1005)
        code[5:10] = b'\xe8' + struct.pack('<i', 0x1020 - 0x100a)
        code[10] = 0xc3
        code[0x20:0x22] = b'\xff\xe0'
        image = Image([(0x1000, 0x10), (0x1020, 0x10)], code=bytes(code), plt=(symbol, slot_kind, DYNAMIC + 0x800))
        pltgot = DYNAMIC + 0x800
        plt0 = b'\xff\x35' + struct.pack('<i', pltgot + 8 - 0x1806) + b'\xff\x25' + struct.pack('<i', pltgot + 16 - 0x180c) + b'\x0f\x1f\x40\x00'
        stub = b'\xff\x25' + struct.pack('<i', image.slot - 0x1816) + b'\x68' + struct.pack('<I', 0) + b'\xe9' + struct.pack('<i', 0x1800 - 0x1820)
        image.raw[0x1800:0x1810] = plt0
        image.raw[0x1810:0x1820] = stub
        return image

    def facts(self, report, kind):
        return [fact for fact in report['facts'] if fact['kind'] == kind]

    def test_plt_binding_direct_calls_and_indirect_obligation(self):
        report = recover_load_facts(self.plt_image().bytes())
        binding = self.facts(report, 'plt-import-binding')
        self.assertEqual([(f['address'], f['symbol'], f['size']) for f in binding], [(0x1810, 'imported', 16)])
        calls = {f['address']: f for f in self.facts(report, 'direct-call')}
        self.assertEqual(calls[0x1000]['symbol'], 'imported')
        self.assertIn(binding[0]['id'], calls[0x1000]['dependencies'])
        self.assertEqual(calls[0x1005]['target'], 0x1020)
        self.assertEqual([o['address'] for o in obligations(report, 'unresolved-indirect-jmp')], [0x1020])
        self.assertEqual(obligations(report, 'unclassified-executable-bytes'), [])
        self.assertFalse(report['section_table_used'])

    def test_binding_change_changes_dependent_fact(self):
        original = recover_load_facts(self.plt_image().bytes())
        renamed = recover_load_facts(self.plt_image(symbol=b'replaced').bytes())
        self.assertNotEqual(original['input_sha256'], renamed['input_sha256'])
        self.assertEqual(self.facts(renamed, 'plt-import-binding')[0]['symbol'], 'replaced')
        self.assertTrue(any('binding of imported' in item for item in self.facts(original, 'plt-import-binding')[0]['invalidated_by']))

    def test_stub_without_jump_slot_is_not_bound(self):
        report = recover_load_facts(self.plt_image(slot_kind=6).bytes())
        self.assertEqual(self.facts(report, 'plt-import-binding'), [])
        self.assertEqual([o['address'] for o in obligations(report, 'call-target-without-unwind')], [0x1000])

    def test_interior_and_outside_targets_are_obligations(self):
        code = b'\xe8' + struct.pack('<i', 0x1028 - 0x1005) + b'\xe8' + struct.pack('<i', 0x0800 - 0x100a) + b'\xc3'
        report = recover_load_facts(Image([(0x1000, 0x10), (0x1020, 0x10)], code=code).bytes())
        self.assertEqual([o['address'] for o in obligations(report, 'call-into-range-interior')], [0x1000])
        self.assertEqual([o['address'] for o in obligations(report, 'transfer-outside-executable-image')], [0x1005])

    def test_unclassified_code_reported_and_padding_ignored(self):
        code = bytearray(b'\xcc' * 0x60)
        code[0] = 0xc3
        code[0x40:0x44] = b'\x48\x31\xc0\xc3'
        report = recover_load_facts(Image([(0x1000, 0x10)], code=bytes(code)).bytes())
        self.assertEqual([(o['address'], o['detail'].split()[0]) for o in obligations(report, 'unclassified-executable-bytes')],
                         [(0x1040, '4')])

    def test_entry_without_range_is_an_obligation(self):
        image = Image([(0x1010, 0x10)], code=b'\xc3' * 0x20)
        report = recover_load_facts(image.bytes())
        self.assertEqual([o['address'] for o in obligations(report, 'root-without-unwind-range')], [0x1000])

    def test_regeneration_is_deterministic(self):
        raw = self.plt_image().bytes()
        self.assertEqual(json.dumps(recover_load_facts(raw), sort_keys=True), json.dumps(recover_load_facts(raw), sort_keys=True))


def with_section_table(raw):
    names = b'\0.dynsym\0.dynstr\0.shstrtab\0'
    base = len(raw)
    table = base + 0x40
    sections = [bytes(64),
                struct.pack('<IIQQQQIIQQ', 1, 11, 2, DYNAMIC + 0x140, DYNAMIC + 0x140, 48, 2, 1, 8, 24),
                struct.pack('<IIQQQQIIQQ', 9, 3, 2, DYNAMIC + 0x180, DYNAMIC + 0x180, 0x20, 0, 0, 1, 0),
                struct.pack('<IIQQQQIIQQ', 17, 3, 0, 0, base, len(names), 0, 0, 1, 0)]
    result = bytearray(raw) + names.ljust(0x40, b'\0') + b''.join(sections)
    struct.pack_into('<Q', result, 0x28, table)
    struct.pack_into('<HHH', result, 0x3a, 64, len(sections), 3)
    return bytes(result)


class RecoverIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='anyps5-aot-load-facts-')
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def recover(self, raw, name):
        path = self.directory / name
        path.write_bytes(raw)
        result = recover_image(path)
        result.pop('sha256')
        return result

    def test_section_table_does_not_change_recovery(self):
        raw = LoadFactTests().plt_image().bytes()
        sectionless = self.recover(raw, 'sectionless.elf')
        sectioned = self.recover(with_section_table(raw), 'sectioned.elf')
        self.assertEqual(sectionless, sectioned)
        self.assertEqual([(f['address'], f['size']) for f in sectionless['functions']], [(0x1000, 0x10), (0x1020, 0x10)])
        self.assertEqual({e['kind'] for f in sectionless['functions'] for e in f['evidence']}, {'eh-frame-hdr-range'})
        self.assertEqual(sectionless['imports'], [{'symbol': 'imported', 'slots': [DYNAMIC + 0x818], 'abi': None}])

    def test_recovered_ranges_reach_contract_materialization(self):
        raw = LoadFactTests().plt_image().bytes()
        path = self.directory / 'image.elf'
        path.write_bytes(raw)
        recovered = recover_image(path)
        declaration = self.directory / 'declaration.h'
        declaration.write_text('long first(void);\nlong second(void);\nlong imported(void);\n')
        evidence = lambda excerpt: [{'path': declaration.name, 'sha256': hashlib.sha256(declaration.read_bytes()).hexdigest(),
                                     'excerpt': excerpt}]
        functions = [{'address': 0x1000, 'size': 0x10, 'name': 'first', 'result': 'i64', 'parameters': [],
                      'evidence': evidence('long first(void);')},
                     {'address': 0x1020, 'size': 0x10, 'name': 'second', 'result': 'i64', 'parameters': [],
                      'evidence': evidence('long second(void);')}]
        imports = {'imported': {'name': 'imported', 'result': 'i64', 'parameters': [], 'evidence': evidence('long imported(void);')}}
        annotations = {'schema': 1, 'sha256': recovered['sha256'], 'functions': functions, 'imports': imports}
        contracts = materialize_contracts(recovered, annotations, self.directory)
        self.assertEqual([f['address'] for f in contracts['functions']], [0x1000, 0x1020])
        with self.assertRaisesRegex(RecoveryError, 'do not cover every recovered candidate'):
            materialize_contracts(recovered, dict(annotations, functions=functions[:1]), self.directory)
        with self.assertRaisesRegex(RecoveryError, 'range differs from evidence'):
            materialize_contracts(recovered, dict(annotations, functions=[dict(functions[0], size=0x20), functions[1]]), self.directory)

    def test_unwind_obligations_block_materialization(self):
        raw = Image([(0x1000, 0x100), (0x1020, 0x10)]).bytes()
        path = self.directory / 'overlap.elf'
        path.write_bytes(raw)
        recovered = recover_image(path)
        self.assertEqual(recovered['functions'], [])
        self.assertEqual([u['obligation'] for u in recovered['unknowns']], ['overlapping-fde-ranges'])
        with self.assertRaisesRegex(RecoveryError, 'obligations remain unresolved'):
            materialize_contracts(recovered, {'schema': 1, 'sha256': recovered['sha256'], 'functions': [], 'imports': {}})

    def test_indirect_personality_requires_relocated_slot(self):
        slot = DYNAMIC + 0x900
        record = cie(b'zPR', personality_slot=slot)
        bound = Image([(0x1000, 0x10)], cie_record=record, plt=(b'imported', 7, DYNAMIC + 0x800),
                      extra_relocations=[(slot, 8, 0x1100)])
        path = self.directory / 'bound.elf'
        path.write_bytes(bound.bytes())
        recovered = recover_image(path)
        self.assertEqual([(f['address'], f['size']) for f in recovered['functions']], [(0x1000, 0x10)])
        self.assertEqual([u for u in recovered['unknowns'] if u['kind'] == 'unwind'], [])
        unbound = Image([(0x1000, 0x10)], cie_record=record, plt=(b'imported', 7, DYNAMIC + 0x800))
        path.write_bytes(unbound.bytes())
        recovered = recover_image(path)
        self.assertEqual(recovered['functions'], [])
        self.assertEqual([u['detail'] for u in recovered['unknowns']], ['indirect personality slot has no relocation binding'])

    def test_unloaded_index_does_not_reject_recovery(self):
        image = Image([(0x1000, 0x10)])
        image.segments[2] = (0x6474e550, 4, 0x3f00, 0, 4, 4)
        image.write_headers()
        path = self.directory / 'placeholder.elf'
        path.write_bytes(image.bytes())
        recovered = recover_image(path)
        self.assertEqual(recovered['functions'], [])
        self.assertEqual([u['obligation'] for u in recovered['unknowns']], ['unwind-index-not-loaded'])

    def test_sectionless_without_unwind_index_reports_obligation(self):
        image = Image([(0x1000, 0x10)])
        image.segments.pop()
        image.write_headers()
        path = self.directory / 'bare.elf'
        path.write_bytes(image.bytes())
        recovered = recover_image(path)
        self.assertEqual(recovered['functions'], [])
        self.assertEqual([u['obligation'] for u in recovered['unknowns']], ['unwind-index-missing'])


if __name__ == '__main__':
    unittest.main()

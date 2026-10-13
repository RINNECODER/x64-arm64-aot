import argparse
import hashlib
import io
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile

import dynamic
import unwind_index
from unwind_index import LoadView, UnwindError, require

SCHEMA = 'anyps5.aot.load-facts.v1'
RULES = {'unwind-index': unwind_index.RULE_VERSION, 'entry-root': 1, 'lifecycle-root': 1, 'export-root': 1, 'unwind-range': unwind_index.RULE_VERSION,
         'address-taken-code': 1, 'direct-call': 1, 'plt-import-binding': 1, 'got-import-call': 1}
LIFECYCLE = {'DT_INIT': None, 'DT_FINI': None, 'DT_PREINIT_ARRAY': 'DT_PREINIT_ARRAYSZ',
             'DT_INIT_ARRAY': 'DT_INIT_ARRAYSZ', 'DT_FINI_ARRAY': 'DT_FINI_ARRAYSZ'}
FILL = {'nop', 'int3'}
INPUT_INVALIDATION = 'any change to the input bytes (sha256)'


class Dossier:
    def __init__(self, digest):
        self.digest = digest
        self.facts = {}
        self.obligations = []

    def fact(self, kind, address, property, evidence, preconditions, invalidated_by=(), dependencies=(), status='qualified', **values):
        identifier = f'{kind}@{address:x}'
        if identifier in self.facts:
            existing = self.facts[identifier]
            existing['evidence'].extend(item for item in evidence if item not in existing['evidence'])
            existing['dependencies'] = sorted(set(existing['dependencies']) | set(dependencies))
            return identifier
        self.facts[identifier] = {'id': identifier, 'kind': kind, 'address': address, 'property': property,
                                  'rule': {'name': kind, 'version': RULES[kind]}, 'status': status,
                                  'input_sha256': self.digest, 'evidence': list(evidence),
                                  'preconditions': list(preconditions), 'dependencies': sorted(set(dependencies)),
                                  'invalidated_by': [INPUT_INVALIDATION, *invalidated_by], **values}
        return identifier

    def obligation(self, kind, address, needed, detail, dependencies=()):
        self.obligations.append({'kind': kind, 'address': address, 'needed': needed, 'detail': detail,
                                 'dependencies': sorted(set(dependencies))})


def relocation_map(parsed):
    result = {}
    if parsed is None:
        return result
    for relocation in parsed['relocations']:
        symbol = parsed['symbols'][relocation['symbol_index']] if relocation['symbol_index'] else None
        result[relocation['slot']] = dict(relocation, symbol=symbol['name'] if symbol else None)
    return result


def describe_relocation(relocation):
    return {'source': 'PT_DYNAMIC relocation', 'slot': relocation['slot'], 'type': relocation['kind'],
            'symbol': relocation['symbol'], 'addend': relocation['addend'], 'plt': relocation['plt']}


def parse_dynamic_view(view):
    if not any(segment['type'] == unwind_index.PT_DYNAMIC for segment in view.segments):
        return None
    try:
        return dynamic.parse_dynamic(ELFFile(io.BytesIO(view.raw)), view.read)
    except dynamic.DynamicError as error:
        raise UnwindError(f'dynamic metadata rejected: {error}') from error


def lifecycle_roots(view, dossier, parsed, relocations):
    if parsed is None:
        return
    tags = parsed['tags']
    for tag, size_tag in LIFECYCLE.items():
        if tag not in tags:
            continue
        if size_tag is None:
            address = tags[tag]
            dossier.fact('lifecycle-root', address, f'{tag} names a code address called by the loader',
                         [{'source': 'PT_DYNAMIC', 'tag': tag}], ['address is executable image bytes'])
            continue
        start, size = tags[tag], tags.get(size_tag, 0)
        require(size % 8 == 0, f'{size_tag} is not a multiple of eight')
        for slot in range(start, start + size, 8):
            relocation = relocations.get(slot)
            if relocation is None:
                if view.type == 3:
                    dossier.obligation('lifecycle-slot-unrelocated', slot, 'relocated lifecycle pointer',
                                       f'{tag} slot has no dynamic relocation in a position-independent image')
                    continue
                target, = struct.unpack('<Q', view.read(slot, 8))
                evidence = [{'source': 'PT_DYNAMIC', 'tag': tag, 'slot': slot, 'value': target}]
            elif relocation['kind'] == 8:
                target = relocation['addend']
                evidence = [{'source': 'PT_DYNAMIC', 'tag': tag}, describe_relocation(relocation)]
            else:
                dossier.obligation('lifecycle-slot-symbolic', slot, 'binding-qualified lifecycle target',
                                   f'{tag} slot uses relocation type {relocation["kind"]}')
                continue
            if target in (0, (1 << 64) - 1):
                continue
            dossier.fact('lifecycle-root', target, f'{tag} entry is called by the loader', evidence,
                         ['address is executable image bytes', 'slot is not written before lifecycle dispatch'],
                         invalidated_by=[f'relocation at 0x{slot:x}'])


def export_roots(view, dossier, parsed):
    if parsed is None:
        return
    for index, symbol in enumerate(parsed['symbols']):
        if index == 0 or not symbol['section'] or symbol['section'] == 0xfff1 or symbol['info'] & 15 != 2:
            continue
        dossier.fact('export-root', symbol['value'], 'dynamic export names a callable address',
                     [{'source': 'PT_DYNAMIC symbol', 'index': index, 'symbol': symbol['name'], 'size': symbol['size']}],
                     ['the export binding is the one used by the caller'], invalidated_by=['symbol interposition or version change'],
                     symbol=symbol['name'])


def address_taken(view, dossier, relocations):
    for slot, relocation in sorted(relocations.items()):
        if relocation['kind'] == 8 and view.executable(relocation['addend'], 1):
            dossier.fact('address-taken-code', relocation['addend'],
                         'a relocated data cell holds this code address (indirect-target candidate, not a complete target set)',
                         [describe_relocation(relocation)], ['the cell is not rewritten with another value'],
                         invalidated_by=[f'write to 0x{slot:x}'], status='candidate')


def rip_target(view, address, opcode):
    try:
        raw = view.read(address, 6)
    except UnwindError:
        return None
    if raw[:2] != opcode:
        return None
    return address + 6 + struct.unpack('<i', raw[2:])[0]


def plt_header(view, address, pltgot):
    if pltgot is None:
        return False
    return rip_target(view, address, b'\xff\x35') == pltgot + 8 and rip_target(view, address + 6, b'\xff\x25') == pltgot + 16


def plt_binding(view, address, relocations, pltgot):
    slot = rip_target(view, address, b'\xff\x25')
    relocation = relocations.get(slot)
    if relocation is None or relocation['kind'] != 7 or not relocation['plt']:
        return None
    size = 6
    try:
        tail = view.read(address + 6, 10)
    except UnwindError:
        tail = b''
    if len(tail) == 10 and tail[0] == 0x68 and tail[5] == 0xe9:
        resolver = address + 16 + struct.unpack('<i', tail[6:])[0]
        if plt_header(view, resolver, pltgot):
            size = 16
    return slot, relocation, size


def classify_transfers(view, dossier, ranges, relocations, pltgot):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    starts = {begin: identifier for begin, _, identifier in ranges}
    ordered = sorted(ranges)

    def containing(target):
        for begin, end, identifier in ordered:
            if begin <= target < end:
                return begin, end, identifier
        return None

    covered = []
    for begin, end, identifier in ordered:
        raw = view.read(begin, end - begin)
        cursor = begin
        for ins in decoder.disasm(raw, begin):
            cursor = ins.address + ins.size
            if ins.mnemonic not in ('call', 'jmp') or not ins.operands:
                continue
            operand = ins.operands[0]
            site = {'source': 'linear decode', 'site': ins.address, 'range': identifier, 'instruction': ins.mnemonic}
            if operand.type == X86_OP_IMM:
                target = operand.imm & ((1 << 64) - 1)
                if ins.mnemonic == 'jmp' and begin <= target < end:
                    continue
                stub = plt_binding(view, target, relocations, pltgot) if not containing(target) else None
                if stub is not None:
                    slot, relocation, size = stub
                    binding = dossier.fact('plt-import-binding', target, f'PLT stub jumps through the JUMP_SLOT of {relocation["symbol"]}',
                                           [{'source': 'decoded jmp [rip+disp32]', 'stub': target, 'slot': slot}, describe_relocation(relocation)],
                                           ['the slot is written only by the dynamic loader', 'the import binding is unchanged'],
                                           invalidated_by=[f'write to 0x{slot:x}', f'binding of {relocation["symbol"]}'],
                                           symbol=relocation['symbol'], slot=slot, size=size, lazy=size == 16)
                    covered.append((target, target + size))
                    if size == 16:
                        resolver = target + 16 + struct.unpack('<i', view.read(target + 12, 4))[0]
                        covered.append((resolver, resolver + 12))
                    if ins.mnemonic == 'call':
                        dossier.fact('direct-call', ins.address, f'direct call to import {relocation["symbol"]} through a PLT stub',
                                     [site], ['linear decode of the containing unwind range is instruction-aligned'],
                                     dependencies=[identifier, binding], target=target, symbol=relocation['symbol'])
                    else:
                        dossier.obligation('tail-call-candidate', ins.address, 'qualified tail call to an import',
                                           f'jmp to PLT stub of {relocation["symbol"]}', [identifier, binding])
                    continue
                inside = containing(target)
                if not view.executable(target, 1):
                    dossier.obligation('transfer-outside-executable-image', ins.address, 'executable target',
                                       f'{ins.mnemonic} to 0x{target:x}', [identifier])
                elif ins.mnemonic == 'call' and target in starts:
                    dossier.fact('direct-call', ins.address, 'direct call to the start of an unwind range',
                                 [site], ['linear decode of the containing unwind range is instruction-aligned'],
                                 dependencies=[identifier, starts[target]], target=target)
                elif ins.mnemonic == 'call' and inside:
                    dossier.obligation('call-into-range-interior', ins.address, 'function boundary at the call target',
                                       f'call to 0x{target:x} inside unwind range {inside[2]}', [identifier, inside[2]])
                elif ins.mnemonic == 'call':
                    dossier.obligation('call-target-without-unwind', ins.address, 'range or ABI evidence for the target',
                                       f'call to 0x{target:x} outside every unwind range', [identifier])
                elif target in starts:
                    dossier.obligation('tail-call-candidate', ins.address, 'qualified tail call or shared epilogue',
                                       f'jmp to unwind range start 0x{target:x}', [identifier, starts[target]])
                else:
                    dossier.obligation('cross-range-jump', ins.address, 'shared block or tail call qualification',
                                       f'jmp to 0x{target:x} outside the source unwind range', [identifier])
            elif operand.type == X86_OP_MEM and ins.reg_name(operand.mem.base) == 'rip' and not operand.mem.index:
                slot = ins.address + ins.size + operand.mem.disp
                relocation = relocations.get(slot)
                if relocation is not None and relocation['kind'] in (6, 7) and relocation['symbol']:
                    dossier.fact('got-import-call', ins.address, f'{ins.mnemonic} through the import slot of {relocation["symbol"]}',
                                 [site, describe_relocation(relocation)],
                                 ['the slot is written only by the dynamic loader', 'the import binding is unchanged'],
                                 invalidated_by=[f'write to 0x{slot:x}', f'binding of {relocation["symbol"]}'],
                                 dependencies=[identifier], symbol=relocation['symbol'], slot=slot, tail=ins.mnemonic == 'jmp')
                else:
                    dossier.obligation(f'unresolved-indirect-{ins.mnemonic}', ins.address, 'finite target set and target ABI',
                                       f'{ins.mnemonic} through memory 0x{slot:x}', [identifier])
            elif operand.type in (X86_OP_MEM, X86_OP_REG):
                dossier.obligation(f'unresolved-indirect-{ins.mnemonic}', ins.address, 'finite target set and target ABI',
                                   f'{ins.mnemonic} {ins.op_str}', [identifier])
        if cursor != end:
            dossier.obligation('linear-decode-gap', cursor, 'instruction-aligned code or a data-in-code classification',
                               f'linear decode stopped before 0x{end:x}', [identifier])
    return covered


def uncovered(view, dossier, covered):
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    for segment in view.loads:
        if not segment['flags'] & 1:
            continue
        cursor, end = segment['vaddr'], segment['vaddr'] + segment['filesz']
        spans = sorted((max(b, cursor), min(e, end)) for b, e in covered if b < end and e > cursor)
        gaps = []
        for begin, finish in spans:
            if begin > cursor:
                gaps.append((cursor, begin))
            cursor = max(cursor, finish)
        if cursor < end:
            gaps.append((cursor, end))
        for begin, finish in gaps:
            raw = view.read(begin, finish - begin)
            if raw.strip(b'\0') == b'':
                continue
            decoded = list(decoder.disasm(raw, begin))
            while decoded and decoded[0].mnemonic in FILL:
                head = decoded.pop(0)
                begin = head.address + head.size
            if sum(i.size for i in decoded) == finish - begin:
                while decoded and decoded[-1].mnemonic in FILL:
                    finish = decoded.pop().address
            if begin >= finish:
                continue
            dossier.obligation('unclassified-executable-bytes', begin, 'code range evidence or data classification',
                               f'{finish - begin} bytes up to 0x{finish:x} are covered by no qualified fact')


def recover_load_facts(raw):
    view = LoadView(raw)
    digest = hashlib.sha256(view.raw).hexdigest()
    dossier = Dossier(digest)
    parsed = parse_dynamic_view(view)
    relocations = relocation_map(parsed)
    unwind = unwind_index.read_unwind_index(view, relocations)
    for item in unwind['obligations']:
        subject = item['subject'] or {}
        dossier.obligation(item['kind'], subject.get('address'), item['needed'], item['detail'])
    header = None
    if unwind['header'] is not None:
        header = dossier.fact('unwind-index', unwind['header']['address'], 'PT_GNU_EH_FRAME locates a sorted FDE search table',
                              [{'source': 'PT_GNU_EH_FRAME', 'address': unwind['header']['address'], 'size': unwind['header']['size']}],
                              ['eh_frame_hdr version 1 with supported encodings'],
                              indexed=unwind['header']['indexed'], stream=unwind['stream'])
    ranges = []
    for fde in unwind['fdes']:
        identifier = dossier.fact('unwind-range', fde['begin'],
                                  'an FDE describes unwinding for this range; it is not proof of one source function or of its ABI',
                                  [{'source': 'FDE', 'record': fde['fde'], 'cie': fde['cie'], 'indexed': fde['indexed']}],
                                  ['FDE pc_begin equals the search-table key', 'range lies in one executable file-backed segment',
                                   'CIE return address column is x86-64 RIP'],
                                  dependencies=[header] if header else [], status=fde['status'],
                                  size=fde['size'], lsda=fde['lsda'], personality=fde['personality'])
        if fde['status'] == 'qualified':
            ranges.append((fde['begin'], fde['begin'] + fde['size'], identifier))
        if fde['lsda'] or fde['personality']:
            dossier.obligation('exception-metadata', fde['begin'], 'LSDA/personality qualification (C++ EH dossier)',
                               'unwind range carries a personality or LSDA', [identifier])
    require(view.executable(view.entry, 1) or view.entry == 0, 'entry point is not executable image bytes')
    if view.entry:
        dossier.fact('entry-root', view.entry, 'ELF entry point is the first guest instruction executed after loading',
                     [{'source': 'ELF header', 'field': 'e_entry'}], ['the image is started through its ELF entry'])
    lifecycle_roots(view, dossier, parsed, relocations)
    export_roots(view, dossier, parsed)
    address_taken(view, dossier, relocations)
    pltgot = parsed['tags'].get('DT_PLTGOT') if parsed else None
    covered = classify_transfers(view, dossier, ranges, relocations, pltgot)
    uncovered(view, dossier, [(begin, end) for begin, end, _ in ranges] + covered)
    starts = {begin for begin, _, _ in ranges}
    for fact in list(dossier.facts.values()):
        if fact['kind'] in ('entry-root', 'lifecycle-root', 'export-root', 'address-taken-code') and fact['address'] not in starts:
            dossier.obligation('root-without-unwind-range', fact['address'], 'range evidence for a root',
                               f'{fact["kind"]} is not the start of a qualified unwind range', [fact['id']])
    dossier.obligations.sort(key=lambda item: (item['kind'], item['address'] if item['address'] is not None else -1))
    counts = {}
    for item in dossier.obligations:
        counts[item['kind']] = counts.get(item['kind'], 0) + 1
    return {'schema': SCHEMA, 'input_sha256': digest, 'entry': view.entry, 'section_table_used': False,
            'sources': ['ELF header', 'program headers', 'PT_DYNAMIC' if parsed else None, 'PT_GNU_EH_FRAME' if unwind['header'] else None],
            'facts': sorted(dossier.facts.values(), key=lambda fact: (fact['address'], fact['id'])),
            'obligations': dossier.obligations, 'obligation_counts': dict(sorted(counts.items())),
            'limitations': ['Unwind ranges are evidence for unwinding, not semantic function boundaries or ABIs.',
                            'Linear decoding inside unwind ranges does not prove reachability or the absence of data in code.',
                            'Address-taken code is an indirect-target candidate; target sets stay unresolved obligations.',
                            'No CFA program, LSDA table or signature is interpreted by this rule set.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = recover_load_facts(args.input.read_bytes())
    except UnwindError as error:
        parser.exit(2, f'Load fact recovery rejected: {error}\n')
    args.output.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

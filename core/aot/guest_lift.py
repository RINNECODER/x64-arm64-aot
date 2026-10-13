import hashlib
import io
import json
import struct
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile

import dynamic
import guest_ops
import load_facts
from unwind_index import LoadView, UnwindError, read_lsda

TERMINAL = {'ret', 'hlt', 'ud2', 'int3'}
CALLEE_SAVED = {'rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'}
PT_TLS = 7
PT_GNU_RELRO = 0x6474e552
RELOCATIONS = {0, 1, 6, 7, 8}
CATALOG = json.loads((Path(__file__).parent / 'catalogs' / 'glibc-x86_64.json').read_text())
NORETURN = {name for name, entry in CATALOG['functions'].items() if entry.get('noreturn')}


class LiftError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise LiftError(message)


class Program:
    def __init__(self, raw, abi="glibc"):
        self.raw = bytes(raw)
        self.sha256 = hashlib.sha256(self.raw).hexdigest()
        try:
            self.view = LoadView(self.raw)
            self.facts = load_facts.recover_load_facts(self.raw)
            self.dynamic = dynamic.parse_dynamic(ELFFile(io.BytesIO(self.raw)), self.view.read, include_exports=abi != 'glibc')
        except (UnwindError, dynamic.DynamicError) as error:
            raise LiftError(str(error)) from error
        require(abi in ('glibc', 'sce-app', 'sce-module'), 'unknown guest startup ABI')
        self.abi = abi
        allowed = (3,) if abi == 'glibc' else (3, 0xfe18) if abi == 'sce-module' else (3, 0xfe10)
        require(self.view.type in allowed, f'{abi} lowering requires a compatible position-independent image')
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        self.decoder.detail = True
        self.decoded = {}
        self.relocations = {r['slot']: r for r in self.dynamic['relocations']}
        for relocation in self.dynamic['relocations']:
            require(relocation['kind'] in RELOCATIONS or (abi == 'sce-module' and relocation['kind'] == 16 and relocation['symbol_index'] == 0), f'relocation type {relocation["kind"]} at 0x{relocation["slot"]:x} needs guest TLS lowering')
        self.writable = [(s['vaddr'], s['vaddr'] + s['memsz']) for s in self.view.loads if s['flags'] & 2]
        relro = [s for s in self.view.segments if s['type'] == PT_GNU_RELRO]
        self.relro = (relro[0]['vaddr'], relro[0]['memsz']) if relro else (0, 0)
        tls = [s for s in self.view.segments if s['type'] == PT_TLS]
        require(len(tls) <= 1, 'multiple PT_TLS segments')
        self.tls = tls[0] if tls else None
        self.landing_pads = {}
        for fact in self.facts['facts']:
            if fact['kind'] != 'unwind-range' or fact['status'] != 'qualified' or not fact.get('lsda'):
                continue
            require(not fact['lsda']['indirect'], f'indirect LSDA pointer for 0x{fact["address"]:x}')
            try:
                sites = read_lsda(self.view, fact['lsda']['address'], fact['address'], fact['size'])
            except UnwindError as error:
                raise LiftError(f'LSDA for 0x{fact["address"]:x}: {error}') from error
            pads = sorted({site['landing_pad'] for site in sites if site['landing_pad'] is not None})
            if pads:
                self.landing_pads[fact['address']] = pads

    def import_name(self, slot):
        relocation = self.relocations.get(slot)
        if relocation is None or relocation['kind'] not in (6, 7) or not relocation['symbol_index']:
            return None
        return self.dynamic['symbols'][relocation['symbol_index']]['name']

    def called_import(self, ins):
        operand = ins.operands[0]
        if operand.type == X86_OP_MEM and ins.reg_name(operand.mem.base) == 'rip' and not operand.mem.index:
            return self.import_name(ins.address + ins.size + operand.mem.disp)
        if operand.type == X86_OP_IMM and self.executable(operand.imm):
            stub = self.decode(operand.imm)
            target = stub.operands[0] if stub.mnemonic == 'jmp' and stub.operands else None
            if target is not None and target.type == X86_OP_MEM and stub.reg_name(target.mem.base) == 'rip' and not target.mem.index:
                return self.import_name(stub.address + stub.size + target.mem.disp)
        return None

    def data_references(self):
        if not hasattr(self, '_references'):
            references = set(self.relocations)
            references.update(r['addend'] for r in self.dynamic['relocations'] if r['kind'] == 8)
            for fact in self.facts['facts']:
                if fact['kind'] == 'unwind-range' and fact['status'] == 'qualified':
                    raw = self.view.read(fact['address'], fact['size'])
                    for instruction in self.decoder.disasm(raw, fact['address']):
                        for operand in instruction.operands:
                            if operand.type == X86_OP_MEM and instruction.reg_name(operand.mem.base) == 'rip':
                                references.add(instruction.address + instruction.size + operand.mem.disp)
            self._references = references
        return self._references

    def executable(self, address):
        return self.view.executable(address, 1)

    def immutable(self, address, size):
        begin, length = self.relro
        if begin <= address and address + size <= begin + length:
            return True
        return not any(low < address + size and address < high for low, high in self.writable)

    def decode(self, address):
        if address not in self.decoded:
            require(self.executable(address), f'0x{address:x} is not executable image code')
            segment = self.view.segment(address)
            end = segment['vaddr'] + segment['filesz']
            raw = self.view.read(address, min(15, end - address))
            found = list(self.decoder.disasm(raw, address, count=1))
            require(found, f'cannot decode instruction at 0x{address:x}')
            self.decoded[address] = found[0]
        return self.decoded[address]

    def roots(self):
        hard, soft = set(), set()
        for fact in self.facts['facts']:
            if fact['kind'] == 'unwind-range' and fact['status'] == 'qualified':
                hard.add(fact['address'])
            elif fact['kind'] in ('entry-root', 'lifecycle-root', 'export-root'):
                hard.add(fact['address'])
            elif fact['kind'] == 'address-taken-code':
                soft.add(fact['address'])
        return hard, soft - hard


class Unit:
    def __init__(self, program, start):
        self.program, self.start = program, start
        self.instructions = {}
        self.successors = {}
        self.calls = {}
        self.tails = {}
        self.tables = {}
        self.indirect = set()
        self.pointers = set()
        self.noreturn = set()

    def explore(self, roots):
        self.landing_pads = list(self.program.landing_pads.get(self.start, []))
        pending = [self.start, *self.landing_pads]
        deferred = []
        while True:
            while pending:
                address = pending.pop()
                if address in self.instructions:
                    continue
                ins = self.program.decode(address)
                self.instructions[address] = ins
                successors = self.edges(ins, roots, deferred)
                self.successors[address] = successors
                pending.extend(successors)
            progress = False
            for address in list(deferred):
                table = jump_table(self, self.instructions[address])
                if table is not None:
                    deferred.remove(address)
                    self.tables[address] = table
                    self.successors[address] = sorted(set(table['targets']))
                    pending.extend(self.successors[address])
                    progress = True
            if not progress:
                break
        self.indirect.update(deferred)
        return self

    def edges(self, ins, roots, deferred):
        address, following, mnemonic = ins.address, ins.address + ins.size, ins.mnemonic
        for operand in ins.operands:
            if operand.type == X86_OP_MEM and ins.reg_name(operand.mem.base) == 'rip' and not operand.mem.index:
                target = following + operand.mem.disp
                if mnemonic == 'lea' and self.program.executable(target):
                    self.pointers.add(target)
        if mnemonic in TERMINAL:
            return []
        if mnemonic == 'call':
            operand = ins.operands[0]
            if operand.type == X86_OP_IMM:
                self.calls[address] = operand.imm
            else:
                self.indirect.add(address)
            if self.program.called_import(ins) in NORETURN:
                self.noreturn.add(address)
                return []
            try:
                self.program.decode(following)
            except LiftError:
                return []
            return [following]
        if mnemonic == 'jmp':
            operand = ins.operands[0]
            if operand.type != X86_OP_IMM:
                deferred.append(address)
                return []
            if operand.imm != self.start and operand.imm in roots:
                self.tails[address] = operand.imm
                return []
            return [operand.imm]
        if mnemonic.startswith('j'):
            target = ins.operands[0].imm
            if target != self.start and target in roots:
                self.tails[address] = target
                return [following]
            return [target, following]
        return [following]

    def predecessors(self, address):
        return [source for source, successors in self.successors.items() if address in successors]


def register_name(ins, register):
    return ins.reg_name(register) or ''


def full_register(name):
    table = {'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'ebx': 'rbx', 'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp'}
    if name in table:
        return table[name]
    if name.startswith('r') and name[-1] in 'dwb' and name[1:-1].isdigit():
        return name[:-1]
    return name


def written(ins):
    return {full_register(ins.reg_name(register)) for register in ins.regs_access()[1]}


def straight_block(unit, address):
    block = [unit.instructions[address]]
    current = address
    while True:
        sources = unit.predecessors(current)
        if len(sources) != 1:
            return block, sources
        source = unit.instructions[sources[0]]
        if source.mnemonic.startswith('j') or source.address + source.size != current or len(block) > 64:
            return block, sources
        block.insert(0, source)
        current = source.address


def operand_register(ins, operand):
    return full_register(register_name(ins, operand.reg)) if operand.type == X86_OP_REG else None


def jump_table(unit, ins):
    target = operand_register(ins, ins.operands[0])
    if target is None:
        return None
    block, sources = straight_block(unit, ins.address)
    body = block[:-1]
    position = len(body) - 1

    def find(predicate):
        nonlocal position
        while position >= 0:
            candidate = body[position]
            position -= 1
            if predicate(candidate):
                return candidate
        return None

    add = find(lambda i: target in written(i))
    if add is None or add.mnemonic != 'add' or operand_register(add, add.operands[0]) != target or add.operands[1].type != X86_OP_REG:
        return None
    entry = operand_register(add, add.operands[1])
    load = find(lambda i: target in written(i) or entry in written(i))
    if load is None or load.mnemonic != 'movsxd' or operand_register(load, load.operands[0]) != target:
        return None
    memory = load.operands[1].mem
    if full_register(register_name(load, memory.base)) != entry or memory.scale != 4 or memory.disp != 0 or not memory.index:
        return None
    index = full_register(register_name(load, memory.index))
    base = reaching_constant_address(unit, load.address, entry)
    if base is None:
        return None
    base_ins = find(lambda i: entry in written(i) or index in written(i))
    if base_ins is not None and entry not in written(base_ins):
        position += 1
    proven = bounded_table(unit, body, position, sources, block, index, base)
    result = proven if proven is not None else scanned_table(unit, ins, base, index)
    if result is not None:
        result['selector_load'] = load.address
    return result


def bounded_table(unit, body, position, sources, block, index, base):
    zero_extension = False
    for earlier in body[:position + 1]:
        if index in written(earlier):
            if is_self_zero_extension(earlier, index):
                zero_extension = True
            else:
                return None
    if len(sources) != 1:
        return None
    branch = unit.instructions[sources[0]]
    if branch.mnemonic not in ('ja', 'jae') or branch.address + branch.size != block[0].address:
        return None
    compare_block, _ = straight_block(unit, branch.address)
    if len(compare_block) < 2 or compare_block[-2].mnemonic != 'cmp':
        return None
    compare = compare_block[-2]
    ops = compare.operands
    if ops[1].type != X86_OP_IMM or operand_register(compare, ops[0]) != index or ops[0].size not in (4, 8):
        return None
    if ops[0].size == 4 and not zero_extension and not defined_by_32bit_write(compare_block[:-2], index):
        return None
    limit = ops[1].imm & ((1 << (8 * ops[0].size)) - 1)
    count = limit + 1 if branch.mnemonic == 'ja' else limit
    if count <= 0 or count > 4096 or not unit.program.immutable(base, count * 4):
        return None
    targets = []
    for slot in range(count):
        value, = struct.unpack('<i', unit.program.view.read(base + slot * 4, 4))
        address = (base + value) & ((1 << 64) - 1)
        if not unit.program.executable(address):
            return None
        targets.append(address)
    return {'base': base, 'count': count, 'index': index, 'compare': compare.address, 'targets': targets,
            'rule': 'relative-jump-table.v1', 'status': 'qualified'}


def containing_range(unit, address):
    for fact in unit.program.facts['facts']:
        if fact['kind'] == 'unwind-range' and fact['status'] == 'qualified' and fact['address'] <= address < fact['address'] + fact['size']:
            return fact['address'], fact['address'] + fact['size']
    return None


def scanned_table(unit, ins, base, index):
    extent = containing_range(unit, ins.address)
    if extent is None:
        return None
    references = unit.program.data_references()
    targets = []
    while len(targets) < 4096:
        slot = base + 4 * len(targets)
        if targets and slot in references:
            break
        if not unit.program.immutable(slot, 4):
            break
        value, = struct.unpack('<i', unit.program.view.read(slot, 4))
        address = (base + value) & ((1 << 64) - 1)
        if not extent[0] <= address < extent[1]:
            break
        try:
            unit.program.decode(address)
        except LiftError:
            break
        targets.append(address)
    if not targets:
        return None
    return {'base': base, 'count': len(targets), 'index': index, 'compare': None, 'targets': targets,
            'rule': 'scanned-relative-jump-table.v1', 'status': 'candidate'}


def rip_lea_value(ins, register):
    ops = ins.operands
    if ins.mnemonic != 'lea' or operand_register(ins, ops[0]) != register or ops[0].size != 8:
        return None
    memory = ops[1].mem
    if register_name(ins, memory.base) != 'rip' or memory.index:
        return None
    return ins.address + ins.size + memory.disp


def reaching_constant_address(unit, address, register):
    values = set()
    pending = list(unit.predecessors(address))
    seen = set()
    if address == unit.start:
        return None
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        ins = unit.instructions[current]
        if register in written(ins):
            value = rip_lea_value(ins, register)
            if value is None:
                return None
            values.add(value)
            continue
        if (ins.mnemonic == 'call' and register not in CALLEE_SAVED) or current == unit.start:
            return None
        sources = unit.predecessors(current)
        if not sources:
            return None
        pending.extend(sources)
    return values.pop() if len(values) == 1 else None


def is_self_zero_extension(ins, index):
    ops = ins.operands
    return ins.mnemonic == 'mov' and len(ops) == 2 and ops[0].type == ops[1].type == X86_OP_REG and ops[0].size == 4 \
        and operand_register(ins, ops[0]) == index and operand_register(ins, ops[1]) == index


def defined_by_32bit_write(block, index):
    for ins in reversed(block):
        if index in written(ins):
            ops = ins.operands
            return bool(ops) and ops[0].type == X86_OP_REG and operand_register(ins, ops[0]) == index and ops[0].size == 4 \
                and ins.mnemonic not in ('xchg', 'cmpxchg', 'xadd')
    return False


def flag_liveness(unit):
    effects = {address: guest_ops.flag_effects(ins) for address, ins in unit.instructions.items()}
    live = {address: frozenset() for address in unit.instructions}
    changed = True
    while changed:
        changed = False
        for address in sorted(unit.instructions, reverse=True):
            ins = unit.instructions[address]
            after = frozenset()
            if ins.mnemonic != 'call':
                for successor in unit.successors.get(address, []):
                    after |= live.get(successor, frozenset())
            uses, defs = effects[address]
            before = (after - defs) | uses
            if before != live[address]:
                live[address] = before
                changed = True
    problems = []
    for entry in [unit.start, *getattr(unit, 'landing_pads', [])]:
        if live[entry]:
            problems.append(f'flags {sorted(live[entry])} are read before definition at unit entry 0x{entry:x}')
    for address, ins in unit.instructions.items():
        following = address + ins.size
        if ins.mnemonic == 'call' and following in live and live[following]:
            problems.append(f'flags {sorted(live[following])} are read after the call at 0x{address:x}')
    return problems


def discover(program, extra=()):
    hard, soft = program.roots()
    hard |= set(extra)
    soft -= hard
    roots = set(hard) | set(soft)
    units, failures, obligations = {}, {}, []
    pending = sorted(hard) + sorted(soft)
    while pending:
        start = pending.pop()
        if start in units or start in failures:
            continue
        try:
            unit = Unit(program, start).explore(roots)
        except LiftError as error:
            if start in soft:
                obligations.append({'kind': 'address-taken-code-not-lifted', 'address': start, 'detail': str(error)})
                failures[start] = str(error)
                continue
            raise LiftError(f'unit 0x{start:x}: {error}') from error
        problems = flag_liveness(unit)
        if problems:
            if start in soft:
                obligations.append({'kind': 'address-taken-code-not-lifted', 'address': start, 'detail': problems[0]})
                failures[start] = problems[0]
                continue
            raise LiftError(f'unit 0x{start:x}: {problems[0]}')
        units[start] = unit
        for target in [*unit.calls.values(), *unit.tails.values()]:
            if target not in roots:
                roots.add(target)
                hard.add(target)
            if target not in units:
                pending.append(target)
        for pointer in unit.pointers:
            if pointer not in roots:
                roots.add(pointer)
                soft.add(pointer)
                pending.append(pointer)
    for unit in units.values():
        for site, table in unit.tables.items():
            if table['status'] != 'qualified':
                obligations.append({'kind': 'jump-table-extent-candidate', 'address': site, 'unit': unit.start,
                                    'detail': f'{table["count"]} entries from data; membership is checked at run time'})
        for address in unit.indirect:
            if unit.instructions[address].mnemonic == 'jmp':
                obligations.append({'kind': 'indirect-jump-dispatch', 'address': address, 'unit': unit.start,
                                    'detail': 'target must be a converted entry at run time, otherwise it traps'})
    return units, failures, obligations

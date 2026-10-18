from elf_segments import runtime_segments
import argparse
import bisect
import hashlib
import io
import json
import re
import subprocess
from collections import deque
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from elftools.elf.elffile import ELFFile
import abi
import atomics
import vector
import avx
import fma
import x87
import integer
import bmi
import system
import effects
import loop_ranges
import native_image
import module_lifecycle
import module_tls
import checked_stack
import finite_tables
import immutable_data
import stack_values
import pointer_outputs
import parameter_pointers
import frame_exclusion
import checked_pointers
import register_values
import register_aliases
import registers
from dynamic import parse_dynamic, DynamicError
from calls import validate_indirect_calls, CallError
from targets import TARGETS, target_spec


class Rejected(ValueError):
    pass


REGISTERS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + [f'r{i}' for i in range(8, 16)]
VECTOR_REGISTERS = [f'xmm{i}' for i in range(16)]
VECTOR_STORAGE = VECTOR_REGISTERS + [f'ymm_hi{i}' for i in range(16)]
# A stable order for the register spills, so the emitted IR is deterministic.
SLOT_INDEX = {name: index for index, name in enumerate(REGISTERS + VECTOR_STORAGE)}
# Block-local SSA for guest registers (REPORT15 section 3, cut 1). A test can turn it off to
# compare the optimized build against the plain per-instruction load/store build.
REGISTER_SSA = True
ARGUMENTS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
VOLATILE = {'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}
ALIASES = {}
for full, dword, word, low in zip(REGISTERS[:8], ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'],
                                ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'],
                                ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil']):
    for name, bits, shift in [(full, 64, 0), (dword, 32, 0), (word, 16, 0), (low, 8, 0)]:
        ALIASES[name] = (full, bits, shift)
for i, name in enumerate(['ah', 'ch', 'dh', 'bh']):
    ALIASES[name] = (REGISTERS[i], 8, 8)
for full in REGISTERS[8:]:
    for suffix, bits in [('', 64), ('d', 32), ('w', 16), ('b', 8)]:
        ALIASES[full + suffix] = (full, bits, 0)
for name in VECTOR_REGISTERS:
    ALIASES[name] = (name, 128, 0)
TYPES = abi.TYPES
MASK64 = (1 << 64) - 1
FLAG_BITS = {'cf': 0, 'pf': 2, 'zf': 6, 'sf': 7, 'of': 11}
FLAGS = {'zf', 'sf', 'cf', 'of', 'pf'}
CONDITIONS = {'e': {'zf'}, 'ne': {'zf'}, 'b': {'cf'}, 'ae': {'cf'}, 'a': {'cf', 'zf'},
              'be': {'cf', 'zf'}, 'l': {'sf', 'of'}, 'ge': {'sf', 'of'}, 'g': {'sf', 'of', 'zf'},
              'le': {'sf', 'of', 'zf'}, 's': {'sf'}, 'ns': {'sf'}, 'p': {'pf'}, 'np': {'pf'},
              'o': {'of'}, 'no': {'of'}}


def require(condition, message):
    if not condition:
        raise Rejected(message)


def alignment_of(address, limit=1 << 32):
    """The largest power of two dividing a known address, capped at `limit`.

    Used to prove the alignment of a scalar access before the IR claims one; see
    `Function.memory_alignment`.
    """
    if address == 0:
        return limit
    return min(limit, address & -address)


def signature(contract):
    try:
        return abi.signature(contract)
    except abi.ABIError as error:
        raise Rejected(str(error)) from error


class Image:
    def __init__(self, path, contracts, target='apple-arm64'):
        self.target = target
        self.target_spec = target_spec(target)
        self.contracts = contracts
        self.namespace = contracts.get('native_namespace', '')
        require(isinstance(self.namespace, str) and (not self.namespace or re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*_', self.namespace)), 'invalid native namespace')
        require(type(contracts.get('module_image', False)) is bool, 'module_image must be boolean')
        self.bytes = Path(path).read_bytes()
        require(contracts.get('schema') == 1, 'unsupported contract schema')
        require(type(contracts.get('guard_diagnostics', False)) is bool, 'guard_diagnostics must be a boolean')
        require(type(contracts.get('native_runtime_registration', False)) is bool, 'native_runtime_registration must be a boolean')
        require(hashlib.sha256(self.bytes).hexdigest() == contracts['sha256'], 'input hash does not match contracts')
        self.elf = ELFFile(io.BytesIO(self.bytes))
        require(self.elf.elfclass == 64 and self.elf.little_endian and self.elf['e_machine'] == 'EM_X86_64', 'expected little-endian x86-64 ELF')
        try:
            self.tls_layout = module_tls.layout(self.elf, self.bytes, contracts)
        except ValueError as error:
            raise Rejected(str(error)) from error
        self.segments = []
        self.process_parameters = []
        process_parameter_segments = []
        for segment in runtime_segments(self.elf):
            if segment['p_type'] == 0x61000001:
                self.process_parameters.append((segment['p_vaddr'], segment['p_filesz']))
                # The SCE process-parameter segment is not PT_LOAD but the runtime must map it and
                # read the title's libc parameters and allocator table from it.
                if segment['p_filesz'] and segment['p_memsz'] >= segment['p_filesz']:
                    process_parameter_segments.append(segment)
                continue
            if segment['p_type'] == 'PT_TLS':
                require(segment['p_memsz'] == 0 or contracts.get('allow_unlowered_tls', False) or self.tls_layout is not None,
                        'TLS requires native TLS lowering')
            if segment['p_type'] != 'PT_LOAD':
                continue
            require(segment['p_filesz'] <= segment['p_memsz'], 'segment file size exceeds memory size')
            require(segment['p_offset'] + segment['p_filesz'] <= len(self.bytes), 'truncated segment')
            require(segment['p_memsz'] <= contracts.get('max_segment_bytes', 64 * 1024 * 1024),
                    'segment exceeds current offline allocation limit')
            self.segments.append(segment)
        for segment in process_parameter_segments:
            # A process-parameter block a PT_LOAD already covers is mapped with it; mapping it
            # again with MAP_FIXED would zero the rest of its page.
            if any(other['p_type'] == 'PT_LOAD' and other['p_vaddr'] <= segment['p_vaddr']
                   and segment['p_vaddr'] + segment['p_memsz'] <= other['p_vaddr'] + other['p_memsz']
                   for other in self.segments):
                continue
            self.segments.append(segment)
        self.functions = {}
        for function in contracts['functions']:
            signature(function)
            try:
                pointer_outputs.validate(function, internal=True)
            except ValueError as error:
                raise Rejected(str(error)) from error
            require('memory_effects' not in function, 'internal memory effects must be inferred from code')
            objects = sorted(function.get('stack_objects', []), key=lambda o: o['offset'])
            for index, obj in enumerate(objects):
                require(obj['size'] > 0 and obj['offset'] + obj['size'] <= 0 and obj['offset'] >= -1024 * 1024,
                        'invalid native stack object')
                require(obj['alignment'] in (1, 2, 4, 8, 16), 'unsupported stack object alignment')
                if index:
                    require(objects[index - 1]['offset'] + objects[index - 1]['size'] <= obj['offset'], 'overlapping stack objects')
            address = function['address']
            require(address not in self.functions and function['size'] > 0, 'duplicate or empty function')
            require(self.segment(address, function['size'])['p_flags'] & 1, 'function is outside executable memory')
            self.functions[address] = function
        ordered = sorted(self.functions.values(), key=lambda f: f['address'])
        for left, right in zip(ordered, ordered[1:]):
            require(left['address'] + left['size'] <= right['address'], 'overlapping function contracts')
        self.function_starts = sorted(self.functions)
        self.function_ends = {function['address'] + function['size']: function for function in self.functions.values()}
        self.falls = {}
        require(self.elf['e_entry'] in self.functions or (contracts.get('module_image') and self.elf['e_entry'] == 0), 'entry function has no contract')
        self.imports = contracts['imports']
        self.hle_log = bool(contracts.get('hle_log'))
        self.hle_names = {}
        self.data_bindings = contracts.get('data_bindings', {})
        # guest_data: the title's data segments are not emitted as IR bytes; the image
        # references them at their guest vaddrs and the runtime maps the user's eboot there.
        self.guest_data = bool(contracts.get('guest_data'))
        # guest_base slides the title image like the Rosetta path's relinked base: a guest
        # vaddr V lives at guest_base + V, so a guest pointer is already a host pointer.
        self.guest_base = int(contracts.get('guest_base', 0))
        for contract in self.imports.values():
            signature(contract)
            try:
                effects.validate_provider(contract)
                pointer_outputs.validate(contract)
            except ValueError as error:
                raise Rejected(str(error)) from error
        self.data = []
        for spec in contracts['data']:
            seg = self.segment(spec['address'], spec['size'])
            require(not seg['p_flags'] & 1, 'executable bytes cannot become native data')
            require(spec['size'] > 0, 'empty data region')
            require(spec['address'] == seg['p_vaddr'] and spec['size'] == seg['p_memsz'], 'data contract must cover the complete segment')
            self.data.append(spec)
        self.import_slots = {}
        self.data_import_slots = {}
        self.data_imports = contracts.get('data_imports', {})
        require(isinstance(self.data_imports, dict), 'data_imports must be a mapping')
        self.relocations = []
        try:
            self.dynamic = parse_dynamic(self.elf, self.read)
        except DynamicError as error:
            raise Rejected(str(error)) from error
        tags = self.dynamic['tags']
        self.needed = self.dynamic['needed']
        lifecycle = contracts.get('lifecycle', {})
        if lifecycle.get('owner') != 'bundle':
            for tag, field in (('DT_INIT', 'init'), ('DT_FINI', 'fini')):
                address = tags.get(tag, 0)
                if address:
                    require(lifecycle.get('owner') == 'entry' and lifecycle.get(field) == address,
                            'nonzero INIT/FINI requires an explicit entry lifecycle contract')
                    require(address in self.functions and signature(self.functions[address]) == ('void', []),
                            'lifecycle function lacks a native void() contract')
            require(tags.get('DT_INIT_ARRAYSZ', 0) == 0 and tags.get('DT_FINI_ARRAYSZ', 0) == 0 and tags.get('DT_PREINIT_ARRAYSZ', 0) == 0,
                    'initializer arrays require native lifecycle lowering')
        referenced_imports = set()
        referenced_data = set()
        for relocation in self.dynamic['relocations']:
            slot, kind, index, addend = (relocation[key] for key in ('slot', 'kind', 'symbol_index', 'addend'))
            if kind in (0, 16, 17, 18):
                continue
            if kind in (6, 7):
                require(addend == 0, 'function import relocation has a nonzero addend')
                symbol = self.dynamic['symbols'][index]
                if contracts.get('module_image') and symbol['section'] != 0 and symbol['info'] & 15 == 1:
                    require(symbol['info'] >> 4 == 1 and symbol['other'] in (0, 2, 3) and symbol['size'] > 0,
                            'local data relocation needs a strong bounded object')
                    self.pointer(symbol['value'], symbol['size'])
                    self.relocations.append((slot, symbol['value']))
                    continue
                if contracts.get('module_image') and symbol['section'] != 0 and symbol['info'] & 15 == 2:
                    require(symbol['info'] >> 4 == 1 and symbol['other'] in (0, 2, 3), 'local function binding must be strong')
                    require(symbol['value'] in self.functions, 'local function relocation lacks a qualified ABI')
                    self.import_slots[slot] = self.functions[symbol['value']]
                    continue
                if symbol['info'] & 15 == 1 and symbol['name'] in self.data_imports:
                    name = symbol['name']
                    require(name in self.data_imports, 'data import requires a separate native binding')
                    binding = self.data_imports[name]
                    require(set(binding) == {'name', 'size', 'evidence'} and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', binding['name'])
                            and type(binding['size']) is int and 0 < binding['size'] <= 64 * 1024 * 1024
                            and isinstance(binding['evidence'], str) and binding['evidence'].strip(), 'invalid native data binding')
                    require(symbol['info'] >> 4 == 1 and symbol['other'] == 0, 'data binding requires a strong default-visible symbol')
                    require(symbol['size'] in (0, binding['size']), 'data binding size differs from ELF symbol')
                    self.data_import_slots[slot] = binding
                    referenced_data.add(name)
                    continue
                name = symbol['name']
                if symbol['info'] & 15 == 1:
                    require(name in self.data_bindings, f'missing data binding: {name}')
                    self.data_import_slots[slot] = self.data_bindings[name]
                    referenced_data.add(name)
                else:
                    require(symbol['info'] & 15 in (0, 2), 'unsupported import symbol type')
                    require(name in self.imports, f'missing import ABI: {name}')
                    self.import_slots[slot] = self.imports[name]
                    referenced_imports.add(name)
            elif kind == 1:
                symbol = self.dynamic['symbols'][index]
                require(symbol['info'] & 15 in (0, 1, 2), 'unsupported data import symbol type')
                name = symbol['name']
                require(name in self.data_bindings, f'missing data binding: {name}')
                self.data_import_slots[slot] = self.data_bindings[name]
                referenced_data.add(name)
            else:
                require(kind == 8 and index == 0, 'unsupported data relocation')
                self.relocations.append((slot, addend))
        expected = {tuple(pair) for pair in contracts['pointer_relocations']}
        require(set(self.relocations) == expected and len(expected) == len(self.relocations), 'pointer relocation contracts do not match the image')
        require(referenced_imports == set(self.imports), 'unused import contracts')
        require(referenced_data == set(self.data_bindings) | set(self.data_imports), 'unused data bindings')
        try:
            self.module_lifecycle = module_lifecycle.describe(self) if lifecycle.get('owner') == 'bundle' else {}
        except ValueError as error:
            raise Rejected(str(error)) from error
        try:
            module_tls.relocations(self)
        except ValueError as error:
            raise Rejected(str(error)) from error
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        self.decoder.detail = True
        try:
            self.finite_tables, self.jump_labels = finite_tables.discover(self)
        except ValueError as error:
            raise Rejected(str(error)) from error
        self.call_contracts = {}
        self.memory_effects = {}
        self.pointer_output_summaries = {}
        self.register_summaries = {}
        self.register_pool_masks = {}
        self.provider_requirements = {}
        try:
            immutable_data.configure(self)
            module_tls.validate_indexes(self)
        except ValueError as error:
            raise Rejected(str(error)) from error

    def segment(self, address, size=1):
        matches = [s for s in self.segments if s['p_vaddr'] <= address and address + size <= s['p_vaddr'] + s['p_memsz']]
        loads = [s for s in matches if s['p_type'] == 'PT_LOAD']
        if loads:
            matches = loads
        require(len(matches) == 1, f'ambiguous or unmapped address 0x{address:x}')
        return matches[0]

    def read(self, address, size):
        segment = self.segment(address, size)
        offset = address - segment['p_vaddr']
        available = max(0, min(size, segment['p_filesz'] - offset))
        begin = segment['p_offset'] + offset
        return self.bytes[begin:begin + available] + bytes(size - available)

    def read_code(self, address, size=15):
        """Read up to `size` instruction bytes without requiring a whole segment window.

        A function's last instruction, and a borrowed continuation entry, can sit close enough
        to the end of a segment that a fixed read would run off the mapped window.
        """
        segment = self.segment(address, 1)
        available = max(1, min(size, segment['p_vaddr'] + segment['p_memsz'] - address))
        return self.read(address, available)

    def pointer(self, address, size=1):
        if address in getattr(self, 'jump_labels', {}) and size == 1:
            return f'blockaddress(@{self.jump_labels[address]}, %b{address:x})'
        if address in self.functions and size == 1:
            return '@' + self.functions[address]['name']
        for spec in self.data:
            if spec['address'] <= address and address + size <= spec['address'] + spec['size']:
                if self.guest_data:
                    return f'inttoptr (i64 {self.guest_base + address} to ptr)'
                return f"getelementptr (i8, ptr @{self.namespace}data_{spec['address']:x}, i64 {address - spec['address']})"
        if self.guest_data and any(spec['p_vaddr'] <= address and address + size <= spec['p_vaddr'] + spec['p_memsz']
                                   for spec in self.segments):
            # Any other mapped segment: the SCE process-parameter segment, and the zero-filled tail a
            # segment's memory size adds past its file size. The runtime maps and zero-fills the whole
            # memory size, so an address in the tail is mapped and needs a contract too.
            return f'inttoptr (i64 {self.guest_base + address} to ptr)'
        raise Rejected(f'no native pointer contract for 0x{address:x}')

    def falls_through(self, function):
        """Whether the declared function's last instruction falls through into what follows.

        A function whose declared range ends without a terminal (`ret`, `jmp`, a trap) does not
        return on its own; the bytes after it are its continuation, whether or not the contract
        table also declares them as a function.
        """
        if function['address'] not in self.falls:
            decoded = list(self.decoder.disasm(self.read(function['address'], function['size']), function['address']))
            mnemonic = decoded[-1].mnemonic if decoded else ''
            self.falls[function['address']] = not (mnemonic in ('ret', 'ud2', 'int3') or mnemonic.startswith('j'))
        return self.falls[function['address']]

    def branches_into(self, function, target):
        """Whether the declared function conditionally branches to `target`.

        A conditional branch out of a declared range whose fall-through stays in it is an
        intra-function branch, so the target is a continuation even when the contract table also
        declares it as a function. An unconditional `jmp` is left out: that is how a real tail
        call leaves a function.
        """
        decoded = list(self.decoder.disasm(self.read(function['address'], function['size']), function['address']))
        end = function['address'] + function['size']
        for ins in decoded:
            if ins.mnemonic == 'jmp' or not ins.mnemonic.startswith('j') or not ins.operands:
                continue
            operand = ins.operands[0]
            if operand.type == X86_OP_IMM and operand.imm == target and function['address'] <= ins.address + ins.size < end:
                return True
        return False

    def containing_function(self, address):
        """The declared function whose declared range contains the address, if any."""
        index = bisect.bisect_right(self.function_starts, address) - 1
        if index < 0:
            return None
        function = self.functions[self.function_starts[index]]
        if function['address'] <= address < function['address'] + function['size']:
            return function
        return None

    def is_import_stub(self, address):
        """Whether the address is a PLT stub for an import (a tail-call target, not a code interior)."""
        if address in self.functions:
            return False
        try:
            self.callee(address)
            return True
        except Rejected:
            return False

    def callee(self, address):
        if address in self.functions:
            return self.functions[address]
        segment = self.segment(address, 6)
        require(segment['p_flags'] & 1, 'call target is not executable')
        raw = self.read(address, 6)
        require(raw[:2] == b'\xff\x25', f'unresolved call target 0x{address:x}')
        slot = address + 6 + int.from_bytes(raw[2:], 'little', signed=True)
        require(slot in self.import_slots, 'PLT slot lacks an import contract')
        return self.import_slots[slot]

    def annotated_calls(self, owner):
        address = owner['address']
        if address not in self.call_contracts:
            try:
                self.call_contracts[address] = validate_indirect_calls(self, owner)
                for site, descriptor in self.finite_tables.items():
                    if address <= site < address + owner['size'] and descriptor['kind'] == 'call':
                        require(site not in self.call_contracts[address], 'derived finite call conflicts with a supplied annotation')
                        self.call_contracts[address][site] = {'contract': descriptor['contract'], 'kind': 'operand',
                            'targets': [self.functions[target]['name'] for target in descriptor['targets']],
                            'target_addresses': descriptor['targets'], 'qualification': descriptor['qualification']}
            except CallError as error:
                # A whole-title build (dispatch enabled) falls back to the runtime dispatch table
                # for an indirect branch whose annotated target set names an address we cannot
                # resolve, instead of rejecting the whole function.
                if not self.contracts.get('dispatch'):
                    raise Rejected(str(error)) from error
                self.call_contracts[address] = {}
        return self.call_contracts[address]

    def call(self, ins, owner=None):
        operand = ins.operands[0]
        if operand.type == X86_OP_IMM:
            if operand.imm in self.functions:
                return self.functions[operand.imm], None
            contract = self.callee(operand.imm)
            raw = self.read(operand.imm, 6)
            slot = operand.imm + 6 + int.from_bytes(raw[2:], 'little', signed=True)
            return contract, slot
        if operand.type == X86_OP_MEM:
            mem = operand.mem
            if ins.reg_name(mem.base) == 'rip' and not mem.index and not mem.segment and ins.addr_size == 8:
                slot = ins.address + ins.size + mem.disp
                if slot in self.import_slots:
                    return self.import_slots[slot], slot
        if owner is not None:
            site = self.annotated_calls(owner).get(ins.address)
            if site is not None:
                return site['contract'], 'operand'
        raise Rejected('indirect calls require native signature and target-set reconstruction')


class Function:
    # `values is None` means this instance does not use the block-local register SSA (the
    # single-instruction test probes build a Function by hand and keep the plain load/store form).
    values = None
    dirty = frozenset()

    def __init__(self, image, contract):
        self.image, self.contract = image, contract
        self.uniform = abi.uniform(contract)
        if self.uniform:
            contract.setdefault('result', 'void')
            contract.setdefault('parameters', [])
        self.dispatch = bool(self.image.contracts.get('dispatch'))
        self.argument_locations = abi.uniform_locations() if self.uniform else abi.locations(contract['parameters'])
        self.stack_end = (abi.uniform_stack_end() if self.uniform else
                          max([8] + [loc['offset'] + 8 for loc in self.argument_locations if loc['kind'] == 'stack']))
        self.image.annotated_calls(contract)
        self.start = contract['address']
        self.end = contract['address'] + contract['size']
        self.prepare()

    def prepare(self):
        """Discover and index the contract at the current `start`/`end` extent."""
        self.instructions = {}
        self.successors = {}
        self.tail_calls = {}
        self.states = {}
        self.memory_writes = {}
        self.lines = []
        self.serial = 0
        # Register-file transfers recorded as (kind, [(line, register)]) so the whole-function
        # pass at the end of lowering can drop the ones this function does not need.
        self.groups = []
        self.uses_x87 = False
        # Block-local SSA for the guest register file: `values` caches the current SSA value of
        # each register inside a block and `dirty` marks the ones whose spill alloca is stale.
        self.values = {}
        self.dirty = set()
        self.depth = max([128] + [-obj['offset'] for obj in self.contract.get('stack_objects', [])])
        self.dispatch_calls = {}
        self.dispatch_jumps = {}
        self.switch_jumps = {}
        self.borrowed = set()
        self.discover()
        try:
            self.checked_accesses = checked_stack.parse(self)
            self.checked_pointer_loads = checked_pointers.parse(self)
            self.checked_pointer_arguments = checked_pointers.parse_arguments(self)
            self.checked_pointer_bases = checked_pointers.parse_bases(self)
            self.frame_exclusions = frame_exclusion.parse(self)
        except ValueError as error:
            raise Rejected(str(error)) from error
        self.index_ranges, self.loop_proofs = loop_ranges.discover(self, ALIASES, VOLATILE)

    def fail(self, ins, message):
        raise Rejected(f"{self.contract['name']} at 0x{ins.address:x} ({ins.mnemonic} {ins.op_str}): {message}")

    def fail_pointer(self, ins, message):
        if not getattr(self, 'collecting', False):
            self.fail(ins, message)

    def borrowable(self, address):
        """Whether an out-of-contract branch target may be decoded as a continuation entry.

        A false function start splits one real function into fragments, and a branch from one
        fragment then reaches the middle of another. When both contracts use the uniform
        register-file ABI their frames are interchangeable, so the target block is a valid
        continuation entry and decoding may cross the boundary. This only applies to addresses
        that would otherwise be rejected, so it cannot change a function that already stays
        inside its contract.
        """
        if not self.uniform or not self.image.contracts.get('borrow_interior_entries', True):
            return False
        if address in self.image.functions or self.image.is_import_stub(address):
            return False
        owner = self.image.containing_function(address)
        return owner is not None and owner['address'] != self.contract['address'] and abi.uniform(owner)

    def inside(self, address, start, end):
        if start <= address < end:
            return True
        if self.borrowable(address):
            owner = self.image.containing_function(address)
            if owner is not None:
                self.borrowed.add(owner['address'])
            return True
        return False

    def discover(self):
        start, end = self.start, self.end
        pending = [(start, None)]
        occupied = {}
        while pending:
            address, predecessor = pending.pop()
            if address in self.instructions:
                continue
            if not self.inside(address, start, end):
                raise Rejected(f"control flow escapes function contract to 0x{address:x} from {predecessor}")
            decoded = list(self.image.decoder.disasm(self.image.read_code(address), address, count=1))
            require(len(decoded) == 1, f'cannot decode 0x{address:x}')
            ins = decoded[0]
            for byte in range(address, address + ins.size):
                require(byte not in occupied, 'overlapping instruction streams')
                occupied[byte] = address
            self.instructions[address] = ins
            next_address = address + ins.size
            if ins.mnemonic in ('ret', 'ud2', 'int3'):
                successors = []
            elif ins.mnemonic == 'jmp' and address in self.image.finite_tables:
                successors = self.image.finite_tables[address]['targets']
            elif ins.mnemonic == 'jmp':
                operand = ins.operands[0]
                if operand.type == X86_OP_IMM and start <= operand.imm < end:
                    successors = [operand.imm]
                else:
                    targets = self.indirect_targets(ins)
                    if targets and all(start <= target < end for target in targets):
                        self.switch_jumps[address] = list(targets)
                        successors = list(targets)
                    else:
                        if operand.type == X86_OP_REG and not self.dispatch:
                            self.fail(ins, 'indirect branches require a proven direct function or GOT import target')
                        try:
                            self.tail_calls[address] = self.image.call(ins)
                            successors = []
                        except Rejected as error:
                            if not self.dispatch and operand.type == X86_OP_IMM and self.borrowable(operand.imm):
                                # A false function start split the real function: continue decoding
                                # at the interior entry instead of rejecting the tail call. A
                                # dispatch build keeps its runtime fallback for a direct jmp.
                                successors = [operand.imm]
                            elif not self.dispatch:
                                self.fail(ins, f'unresolved native tail-call target: {error}')
                            else:
                                self.dispatch_jumps[address] = True
                                successors = []
            elif ins.mnemonic.startswith('j'):
                require(ins.operands[0].type == X86_OP_IMM, 'indirect branches require target-set reconstruction')
                target = ins.operands[0].imm
                if not self.inside(target, start, end) and target in self.image.functions:
                    # A conditional branch into another function is a conditional tail call.
                    self.tail_calls[address] = (self.image.functions[target], None)
                    successors = [next_address]
                else:
                    successors = [target, next_address]
            elif ins.mnemonic == 'call':
                try:
                    callee, _ = self.image.call(ins, self.contract)
                    successors = [] if callee.get('noreturn') else [next_address]
                except Rejected:
                    if not self.dispatch:
                        raise
                    self.dispatch_calls[address] = True
                    successors = [next_address]
            elif next_address >= end and next_address in self.image.functions:
                # A fall-through into the next function is a tail call (the next function's
                # return is this function's return).
                self.tail_calls[address] = (self.image.functions[next_address], None)
                successors = []
            else:
                successors = [next_address]
            self.successors[address] = successors
            pending.extend((successor, address) for successor in successors)

    def indirect_targets(self, ins):
        try:
            site = self.image.annotated_calls(self.contract).get(ins.address)
        except CallError:
            return None
        return site.get('target_addresses') if site else None

    def dispatch_value(self, ins, operand):
        if operand.type == X86_OP_IMM:
            return str(operand.imm & MASK64)
        return self.read(ins, operand, 64)

    def reg(self, ins, operand):
        name = ins.reg_name(operand.reg)
        if name not in ALIASES:
            self.fail(ins, f'unsupported register {name}')
        return ALIASES[name]

    def check_register(self, ins, state, name, bits, shift=0):
        needed = ((1 << bits) - 1) << shift
        if state['known'].get(name, 0) & needed != needed:
            self.fail(ins, f'ABI or dataflow does not define {name}[{shift}:{shift + bits}]')

    def read_operand(self, ins, state, operand):
        if operand.type == X86_OP_REG:
            self.check_register(ins, state, *self.reg(ins, operand))
        elif operand.type == X86_OP_MEM:
            checked_stack.region(self, ins, state, operand)
            checked_stack.pointer(self, ins, state, operand)
            mem = operand.mem
            if ins.mnemonic != 'lea' and ins.addr_size != 8:
                self.fail(ins, '32-bit memory addressing requires pointer reconstruction')
            if mem.segment and ins.mnemonic != 'lea' and ins.reg_name(mem.segment) != 'fs':
                self.fail(ins, 'segment-relative addressing needs TLS lowering')
            for register in (mem.base, mem.index):
                name = ins.reg_name(register)
                if name and name != 'rip':
                    self.check_register(ins, state, *ALIASES[name])
            base_name = ins.reg_name(mem.base)
            index_name = ins.reg_name(mem.index)
            if not self.uniform and ins.mnemonic != 'lea' and state.get('constants', {}).get(base_name, 0) != 0 and not (index_name in state['pointers'] and mem.scale == 1):
                self.fail(ins, 'literal-derived memory address requires an instruction-bound pointer contract')
            if not self.uniform and ins.mnemonic != 'lea' and base_name not in ('', 'rip') and base_name not in state['native_pointers'] and not (index_name in state['native_pointers'] and mem.scale == 1) and not (checked_stack.lookup(self, ins, operand) or {}).get('dynamic_base', False) and checked_pointers.base_record(self, ins, operand) is None:
                self.fail_pointer(ins, 'memory address has no proven native pointer origin')
            frame = state['pointers'].get(base_name)
            if base_name in ('rsp', 'rbp') or (frame and frame[0] == 'frame'):
                base = state[base_name] if base_name in ('rsp', 'rbp') else frame[2]
                if base is None:
                    if not self.uniform:
                        self.fail(ins, 'dynamic frame offset')
                else:
                    offset = base + mem.disp
                    if not mem.index and ins.mnemonic != 'lea' and offset + operand.size > 0:
                        valid = any(loc['kind'] == 'stack' and loc['offset'] <= offset and offset + operand.size <= loc['offset'] + loc['bits'] // 8 for loc in self.argument_locations)
                        if not valid and not self.uniform:
                            self.fail(ins, 'read or write of return address or undeclared stack arguments')
                    self.depth = max(self.depth, -(base + mem.disp) + 128)
        elif operand.type != X86_OP_IMM:
            self.fail(ins, 'unsupported operand')

    def define(self, ins, state, operand):
        if operand.type == X86_OP_REG:
            name, bits, shift = self.reg(ins, operand)
            state['known'][name] = MASK64 if bits >= 32 else state['known'].get(name, 0) | (((1 << bits) - 1) << shift)
            state['pointers'].pop(name, None)
            state['native_pointers'].discard(name)
            state.setdefault('constants', {}).pop(name, None)
        elif operand.type == X86_OP_MEM:
            self.memory_writes[ins.address] = (operand,)
            self.read_operand(ins, state, operand)
            region = self.memory_write_region(ins, state, operand)
            if region is not None and region[0] == 'image' and immutable_data.overlaps(self.image, region[1], region[2]):
                self.fail(ins, 'write overlaps immutable image data')
            clean = state.get('tail_stack_clean', frozenset())
            base_name = ins.reg_name(operand.mem.base)
            frame = state['pointers'].get(base_name)
            begin = state[base_name] if base_name in ('rsp', 'rbp') else (frame[2] if frame and frame[0] == 'frame' else None)
            self.invalidate_stack_aliases(state)
            if begin is not None and not operand.mem.index:
                begin += operand.mem.disp
                state['tail_stack_clean'] = frozenset(loc['offset'] for loc in self.argument_locations if loc['kind'] == 'stack' and loc['offset'] in clean and not (begin < loc['offset'] + loc['bits'] // 8 and loc['offset'] < begin + operand.size))
            elif base_name == 'rip' and not operand.mem.index:
                state['tail_stack_clean'] = clean
            if base_name in ('rsp', 'rbp') and not operand.mem.index and state[base_name] is not None:
                begin = state[base_name] + operand.mem.disp
                for offset, saved in list(state['saved'].items()):
                    low, high = max(begin, offset), min(begin + operand.size, offset + 8)
                    if low < high:
                        defined = ((1 << ((high - low) * 8)) - 1) << ((low - offset) * 8)
                        state['saved'][offset] = (saved[0], saved[1] | defined, None, None)
        else:
            self.fail(ins, 'invalid destination')

    def invalidate_stack_aliases(self, state):
        state['saved'] = {offset: (saved[0], saved[1], None, None) for offset, saved in state['saved'].items()}
        state['tail_stack_clean'] = frozenset()

    def check_immutable_call(self, ins, callee, state, writes):
        if writes is not None:
            if any(kind == 'image' and immutable_data.overlaps(self.image, begin, end) for kind, begin, end in writes.writes):
                self.fail(ins, 'call writes immutable image data')
            return
        for index, kind in enumerate(callee['parameters']):
            if kind != 'ptr':
                continue
            pointer = effects.argument_pointer(self, ins, callee, index, state)
            if pointer and pointer[0] == 'image' and immutable_data.overlaps(self.image, pointer[2], pointer[2] + 1):
                self.fail(ins, 'immutable image pointer passed to a call with unknown effects')

    def check_tail_call(self, ins, state):
        callee, slot = self.tail_calls[ins.address]
        self.check_immutable_call(ins, callee, state, effects.call_writes(self, ins, state))
        if not effects.required_bindings(self, ins) <= state['import_bindings']:
            self.fail(ins, 'native callee requires original provider bindings')
        if slot is not None and slot not in state['image_pointers'] and not self.image.contracts.get('allow_unimplemented'):
            # A whole-title build keeps the import binding installed by native_image_init even after
            # the dataflow lost track of the GOT slot.
            self.fail(ins, 'import target has no proven native pointer origin')
        balanced = state['rsp'] == 0 and not state['saved']
        branch = ins.mnemonic in ('call', 'jmp') or ins.mnemonic.startswith('j')
        if not balanced and not (self.uniform and branch):
            self.fail(ins, 'tail call requires a balanced native frame')
        if not self.uniform and (
                abi.result_type(callee['result']) != abi.result_type(self.contract['result'])
                or abi.return_register(callee['result']) != abi.return_register(self.contract['result'])):
            self.fail(ins, 'tail-call return ABI is incompatible with the owner')
        incoming = {loc['offset']: loc for loc in self.argument_locations if loc['kind'] == 'stack'}
        for loc in abi.locations(callee['parameters']):
            if loc['kind'] == 'register':
                self.check_register(ins, state, loc['name'], loc['bits'])
                if loc['type'] == 'ptr' and loc['name'] not in state['native_pointers'] and state['constants'].get(loc['name']) != 0 and not self.uniform:
                    self.fail_pointer(ins, 'pointer argument has no proven native pointer origin')
            else:
                if self.uniform:
                    continue
                original = incoming.get(loc['offset'])
                if original is None or abi.parameter_type(original['type']) != abi.parameter_type(loc['type']):
                    self.fail(ins, 'tail stack argument lacks a compatible declared incoming slot')
                if loc['offset'] not in state['tail_stack_clean']:
                    self.fail(ins, 'tail stack argument may have been rewritten or escaped')

    def transfer_unchecked(self, ins, original):
        state = {'known': original['known'].copy(), 'rsp': original['rsp'], 'rbp': original['rbp'],
                 'saved': original['saved'].copy(), 'flags': set(original['flags']), 'pointers': original['pointers'].copy(),
                 'register_aliases': original.get('register_aliases', frozenset()),
                 'parameter_pointers': original.get('parameter_pointers', {}).copy(),
                 'zero_vectors': original.get('zero_vectors', set()).copy(),
                 'pending_outputs': original.get('pending_outputs', frozenset()),
                 'constants': original.get('constants', {}).copy(), 'tail_stack_clean': original['tail_stack_clean'],
                 'native_pointers': original['native_pointers'].copy(), 'stack_pointers': original['stack_pointers'],
                 'stack_origins': original['stack_origins'].copy(), 'stack_values': original['stack_values'].copy(),
                 'image_pointers': original['image_pointers'], 'import_bindings': original['import_bindings'].copy(), 'callback_memory_unmodified': original['callback_memory_unmodified']}
        op, args = ins.mnemonic, ins.operands
        if fma.analyze(self, ins, state) or avx.analyze(self, ins, state) or vector.analyze(self, ins, state) or x87.analyze(self, ins, state):
            return state
        if integer.analyze(self, ins, state) or bmi.analyze(self, ins, state) or system.analyze(self, ins, state):
            for register in ins.regs_access()[1]:
                name = ins.reg_name(register)
                if name in ALIASES:
                    state['constants'].pop(ALIASES[name][0], None)
            if ins.mnemonic in ('inc', 'dec') and args[0].type == X86_OP_REG and args[0].size == 8:
                name = self.reg(ins, args[0])[0]
                pointer = original['pointers'].get(name)
                if pointer:
                    kind, index, offset = pointer
                    state['pointers'][name] = (kind, index, None if offset is None else offset + (1 if ins.mnemonic == 'inc' else -1))
            return state
        if atomics.analyze(self, ins, state):
            for register in ins.regs_access()[1]:
                name = ins.reg_name(register)
                if name in ALIASES:
                    state['constants'].pop(ALIASES[name][0], None)
            return state
        if op == 'nop':
            return state
        if op == 'leave':
            # `mov rsp, rbp; pop rbp`.
            state['rsp'] = state['rbp']
            self.release_saved(state, original['rsp'], 'rsp')
            self.stack_pop(ins, state, 'rbp')
            return state
        if op == 'popfq':
            # Restore the tracked flags from the slot at the guest rsp and advance it.
            if state['rsp'] is None:
                if not self.uniform:
                    self.fail(ins, 'unknown stack transfer')
                state['flags'] = set()
                return state
            state['saved'].pop(state['rsp'], None)
            state['rsp'] += 8
            state['flags'] = set(FLAGS)
            return state
        if op in ('push', 'pop'):
            if args[0].size != 8 or (op == 'pop' and args[0].type not in (X86_OP_REG, X86_OP_MEM)):
                self.fail(ins, 'unsupported stack transfer')
            name = self.reg(ins, args[0])[0] if args[0].type == X86_OP_REG else None
            if op == 'push':
                if args[0].type == X86_OP_MEM:
                    self.read_operand(ins, state, args[0])
                if state['rsp'] is None:
                    # A dynamic frame. The uniform ABI keeps the guest rsp in the register file, so the
                    # slot is a real address the lowering can store to; only its value is unknown.
                    if not self.uniform:
                        self.fail(ins, 'unknown stack transfer')
                    return state
                state['rsp'] -= 8
                state['saved'][state['rsp']] = (name, state['known'].get(name, 0) if name else MASK64, state['rbp'] if name == 'rbp' else None, state['pointers'].get(name))
                self.depth = max(self.depth, -state['rsp'] + 128)
            elif args[0].type == X86_OP_MEM:
                # `pop m64`: the slot at the guest rsp is the source and an ordinary memory
                # operand is the destination; only the rsp advance is shared with a register pop.
                self.read_operand(ins, state, args[0])
                self.define(ins, state, args[0])
                if state['rsp'] is not None:
                    state['saved'].pop(state['rsp'], None)
                    state['rsp'] += 8
            else:
                self.stack_pop(ins, state, name)
            return state
        if ins.address in self.dispatch_jumps:
            return state
        if op == 'jmp' and ins.address in self.image.finite_tables:
            self.read_operand(ins, state, args[0])
            return state
        if ins.address in self.tail_calls:
            self.check_tail_call(ins, state)
            return state
        if op == 'call':
            if ins.address in self.dispatch_calls:
                for reg in VOLATILE | set(VECTOR_STORAGE):
                    state['known'].pop(reg, None)
                    state['pointers'].pop(reg, None)
                    state['constants'].pop(reg, None)
                for reg in VOLATILE | set(VECTOR_STORAGE):
                    state['known'][reg] = (1 << 128) - 1 if reg in VECTOR_STORAGE else MASK64
                state['flags'] = set()
                return state
            callee, slot = self.image.call(ins, self.contract)
            if callee.get('tls_resolver'):
                pointer = effects.argument_pointer(self, ins, callee, 0, original)
                if pointer is None or pointer[0] != 'image' or pointer[2] not in self.image.tls_indexes:
                    self.fail(ins, 'TLS resolver argument is not a qualified immutable index')
            if not effects.required_bindings(self, ins) <= state['import_bindings']:
                self.fail(ins, 'native callee requires original provider bindings')
            if slot == 'operand':
                self.read_operand(ins, state, args[0])
                if ins.address in self.image.finite_tables:
                    pass
                elif not self.uniform and (args[0].type == X86_OP_REG or self.memory_origin(ins, state, args[0]) is not None) and not self.pointer_operand(ins, state, args[0]):
                    self.fail(ins, 'indirect call target has no proven native pointer origin')
                if ins.address not in self.image.finite_tables and not self.uniform and args[0].type == X86_OP_MEM and self.memory_origin(ins, state, args[0]) is None:
                    base, index = ins.reg_name(args[0].mem.base), ins.reg_name(args[0].mem.index)
                    provenance = state['pointers'].get(base)
                    if not provenance or provenance[0] != 'parameter' or index in state['native_pointers']:
                        self.fail(ins, 'indirect call memory lacks an external native pointer-cell contract')
                    if not state['callback_memory_unmodified']:
                        self.fail(ins, 'indirect call target memory may have been rewritten')
            elif slot is not None and slot not in state['image_pointers']:
                self.fail(ins, 'import target has no proven native pointer origin')
            for index, loc in enumerate(abi.locations(callee['parameters'])):
                if loc['kind'] == 'register':
                    self.check_register(ins, state, loc['name'], loc['bits'])
                    if loc['type'] == 'ptr' and loc['name'] not in state['native_pointers'] and state['constants'].get(loc['name']) != 0 and not checked_pointers.argument_allowed(self, ins, index) and not self.uniform:
                        self.fail_pointer(ins, 'pointer argument has no proven native pointer origin')
                elif state['rsp'] is None:
                    # A runtime-sized frame: the outgoing slots live at the runtime guest rsp, which
                    # the analysis cannot name, so the static allocation check does not apply.
                    continue
                else:
                    offset = state['rsp'] + loc['offset'] - 8
                    if offset + 8 > 0:
                        self.fail(ins, 'outgoing stack argument is not allocated')
                    if loc['type'] == 'ptr' and offset not in state['stack_pointers'] and stack_values.read(state, offset, 8) != 0 and not checked_pointers.argument_allowed(self, ins, index) and not self.uniform:
                        self.fail_pointer(ins, 'stack pointer argument has no proven native pointer origin')
            passed_upper = {reg: state['known'].get(reg, 0) for reg in VECTOR_STORAGE if reg.startswith('ymm_hi')}
            for reg in VOLATILE | set(VECTOR_STORAGE):
                state['known'].pop(reg, None)
                state['pointers'].pop(reg, None)
                state['constants'].pop(reg, None)
            memory_effects = effects.call_writes(self, ins, original)
            self.check_immutable_call(ins, callee, original, memory_effects)
            if memory_effects is None or memory_effects.parameter_writes or any(kind == 'frame' for kind, _, _ in memory_effects.writes):
                self.invalidate_stack_aliases(state)
            state['flags'] = set()
            if abi.uniform(callee):
                for reg in VOLATILE | set(VECTOR_STORAGE):
                    if reg in passed_upper:
                        # The upper halves are passed to and returned from the callee through the
                        # register file; the callee can only define them further, so the value the
                        # caller passed is a sound lower bound rather than assuming them defined.
                        state['known'][reg] = passed_upper[reg]
                    else:
                        state['known'][reg] = (1 << 128) - 1 if reg in VECTOR_STORAGE else MASK64
            elif callee['result'] != 'void':
                state['known'][abi.return_register(callee['result'])] = (1 << abi.bits(callee['result'])) - 1
            return state
        if op == 'ret':
            # `ret imm16` is callee stack cleanup; in the uniform ABI the caller restores its own
            # rsp around a call, so the immediate is redundant and can be ignored.
            if state['rsp'] != 0 or state['saved']:
                # The uniform ABI keeps the guest rsp in the register file and the native frame is the
                # compiler's own alloca, so a runtime-sized guest rsp at the return unbalances nothing
                # natively and the saved-slot bookkeeping for it is stale; the scalar ABI's native frame
                # is the guest frame, so it still must balance.
                if not (self.uniform and state['rsp'] is None):
                    self.fail(ins, 'unbalanced native frame')
            if self.contract['result'] != 'void':
                self.check_register(ins, state, abi.return_register(self.contract['result']), abi.bits(self.contract['result']))
                if self.contract['result'] == 'ptr' and 'rax' not in state['native_pointers'] and state['constants'].get('rax') != 0:
                    self.fail_pointer(ins, 'pointer return has no proven native pointer origin')
            return state
        if op in ('ud2', 'int3', 'int'):
            return state
        if op.startswith('j'):
            if op != 'jmp' and op[1:] not in CONDITIONS:
                self.fail(ins, 'unsupported branch condition')
            if op != 'jmp' and not CONDITIONS[op[1:]] <= state['flags']:
                self.fail(ins, 'undefined branch flags')
            return state
        if op in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea'):
            if op == 'lea' and args[1].type != X86_OP_MEM:
                self.fail(ins, 'invalid address expression')
            if not register_values.transport(self, ins, original, state):
                self.read_operand(ins, state, args[1])
                self.define(ins, state, args[0])
            if args[0].type == X86_OP_REG:
                dest = self.reg(ins, args[0])[0]
                if op in ('mov', 'movabs'):
                    constant = self.constant_operand(ins, original, args[1])
                    if constant is not None:
                        self.constant_write(ins, original, state, args[0], constant)
                if args[0].size == 8 and op == 'mov' and args[1].type == X86_OP_REG:
                    source_name = self.reg(ins, args[1])[0]
                    source = original['pointers'].get(source_name)
                    if source_name in ('rsp', 'rbp'):
                        source = ('frame', 0, original[source_name]) if original[source_name] is not None else None
                    if source is not None:
                        state['pointers'][dest] = source
                if op == 'lea' and args[0].size == 8:
                    base = ins.reg_name(args[1].mem.base)
                    indexed = bool(args[1].mem.index)
                    if base == 'rip' and not indexed:
                        state['pointers'][dest] = ('image', 0, ins.address + ins.size + args[1].mem.disp)
                    elif base in ('rsp', 'rbp'):
                        if indexed or original[base] is None:
                            # A runtime index (or an already runtime-sized frame) makes the pointer
                            # frame-derived but not a known offset.
                            if not self.uniform:
                                self.fail(ins, 'dynamic frame offset')
                            state['pointers'][dest] = ('frame', 0, None)
                        else:
                            state['pointers'][dest] = ('frame', 0, original[base] + args[1].mem.disp)
                    elif base in original['pointers'] and not indexed:
                        kind, index, offset = original['pointers'][base]
                        state['pointers'][dest] = (kind, index, None if offset is None else offset + args[1].mem.disp)
                if dest in ('rsp', 'rbp'):
                    source = self.reg(ins, args[1])[0] if args[1].type == X86_OP_REG else None
                    frame = self.frame_relative(original, source)
                    if op == 'lea' and args[0].size == 8 and not args[1].mem.index and ins.reg_name(args[1].mem.base) in ('rsp', 'rbp'):
                        base = original[ins.reg_name(args[1].mem.base)]
                        if base is None:
                            # Releasing a dynamic frame keeps it dynamic; only the uniform ABI keeps
                            # the guest rsp in the register file.
                            if not self.uniform:
                                self.fail(ins, 'dynamic frame offset')
                            state[dest] = None
                        else:
                            state[dest] = base + args[1].mem.disp
                            self.release_saved(state, original[dest], dest)
                    elif op == 'mov' and args[0].size == 8 and source in ('rsp', 'rbp'):
                        state[dest] = original[source]
                        self.release_saved(state, original[dest], dest)
                    elif op == 'mov' and args[0].size == 8 and frame is not None:
                        state[dest] = frame
                    elif (self.uniform and op == 'lea' and args[0].size == 8 and args[1].type == X86_OP_MEM
                          and not args[1].mem.index):
                        # `lea rsp, [reg + disp]`: the uniform ABI keeps the guest rsp in the
                        # register file, so a frame restored through any register is representable
                        # as a runtime value.
                        state[dest] = None
                    elif self.uniform and (dest == 'rbp' or args[1].type == X86_OP_REG):
                        # The uniform ABI keeps the guest rsp in the register file, so a frame the
                        # analysis cannot pin down is representable and `and rsp, -32` / `sub rsp, rax`
                        # already take this path; a register source is the same runtime-sized frame
                        # restored through a register.
                        state[dest] = None
                    elif (self.uniform and op == 'lea' and args[0].size == 8 and args[1].type == X86_OP_MEM
                          and (args[1].mem.index or ins.reg_name(args[1].mem.base) in ('rsp', 'rbp'))):
                        # An indexed adjustment of the guest rsp, e.g. the `lea rsp, [rsp + rcx*8 + 8]`
                        # a dynamic-allocation thunk uses to give the stack back: still a dynamic frame.
                        state[dest] = None
                    elif self.uniform and op == 'mov' and args[0].size == 8 and args[1].type == X86_OP_MEM:
                        # Loading a frame pointer back from memory. The loaded value is a runtime value,
                        # so the frame is runtime-sized from here on; the load itself is read_operand's
                        # business and does not need a known frame offset.
                        state[dest] = None
                    else:
                        self.fail(ins, 'unsupported frame manipulation')
            return state
        if op in ('add', 'sub', 'and', 'or', 'xor', 'cmp', 'test'):
            zero = op == 'xor' and args[0].type == args[1].type == X86_OP_REG and args[0].reg == args[1].reg
            if not zero:
                self.read_operand(ins, state, args[0])
                self.read_operand(ins, state, args[1])
            if op not in ('cmp', 'test'):
                self.define(ins, state, args[0])
                if op in ('add', 'sub') and args[0].type == X86_OP_REG and args[0].size == 8 and args[1].type == X86_OP_IMM:
                    dest = self.reg(ins, args[0])[0]
                    pointer = original['pointers'].get(dest)
                    if pointer:
                        kind, index, offset = pointer
                        state['pointers'][dest] = (kind, index, None if offset is None else offset + args[1].imm * (1 if op == 'add' else -1))
                left, right = self.constant_operand(ins, original, args[0]), self.constant_operand(ins, original, args[1])
                if zero:
                    self.constant_write(ins, original, state, args[0], 0)
                elif left is not None and right is not None:
                    value = {'add': lambda: left + right, 'sub': lambda: left - right, 'and': lambda: left & right,
                             'or': lambda: left | right, 'xor': lambda: left ^ right}[op]()
                    self.constant_write(ins, original, state, args[0], value)
                if args[0].type == X86_OP_REG and self.reg(ins, args[0])[0] in ('rsp', 'rbp'):
                    dest = self.reg(ins, args[0])[0]
                    if op in ('add', 'sub') and args[1].type == X86_OP_IMM and state[dest] is not None:
                        state[dest] += args[1].imm * (1 if op == 'add' else -1)
                        self.release_saved(state, original[dest], dest)
                        self.depth = max(self.depth, -state[dest] + 128)
                    elif self.uniform:
                        state[dest] = None
                    else:
                        self.fail(ins, 'dynamic frame allocation')
            state['flags'] = set(FLAGS)
            return state
        self.fail(ins, 'instruction semantics are not implemented')

    def stack_slot_value(self, state):
        """The value of the slot at the current guest rsp, for a pop to memory. A slot this
        function pushed is a frame location; a declared caller window slot is one too; anything
        else (the guest return-address slot) is not modelled, so it freezes."""
        if state['rsp'] is None:
            slot = self.emit(f'inttoptr i64 {self.load("rsp")} to ptr')
            return self.emit(f'load i64, ptr {slot}, align 1')
        if abi.UNIFORM_STACK_BASE <= state['rsp'] < abi.uniform_stack_end() or state['rsp'] in state['saved']:
            return self.emit(f"load i64, ptr {self.frame_pointer(state['rsp'])}, align 1")
        return self.emit('freeze i64 poison')

    def stack_pop(self, ins, state, name):
        """Model `pop name` (also the rbp restore of `leave`): read the slot at the guest rsp and
        advance it. A slot this function never pushed reads a caller-pushed frame slot or freezes."""
        if state['rsp'] is None:
            # Same as push: the transfer happens at the guest rsp, which is a real address in this
            # ABI. The lowering loads the slot there, so the destination is a defined value; only
            # its provenance and (for rbp) its frame offset are unknown.
            if not self.uniform:
                self.fail(ins, 'unknown stack transfer')
            for table in ('constants', 'pointers'):
                state[table].pop(name, None)
            state['native_pointers'].discard(name)
            state['known'][name] = MASK64
            if name == 'rbp':
                state['rbp'] = None
            return
        saved = state['saved'].pop(state['rsp'], None)
        if saved is None:
            if not self.uniform:
                self.fail(ins, 'unknown stack transfer')
            # The uniform ABI keeps the guest stack in the local frame: the caller's window at
            # offsets [8, 264) and the guest return-address slot below it. A pop of a slot this
            # function never pushed therefore reads a caller-pushed slot (a defined frame location)
            # or the return-address slot (not modelled). The lowering loads the defined slot or
            # freezes an arbitrary but defined value, so the destination is defined either way;
            # only its provenance and (for rbp) its frame offset are unknown.
            state['constants'].pop(name, None)
            state['pointers'].pop(name, None)
            state['native_pointers'].discard(name)
            state['known'][name] = MASK64
            if name == 'rbp':
                state['rbp'] = None
            state['rsp'] += 8
            return
        state['known'][name] = saved[1]
        state['constants'].pop(name, None)
        if name == 'rbp':
            state['rbp'] = saved[2]
        if saved[3] is None:
            state['pointers'].pop(name, None)
        else:
            state['pointers'][name] = saved[3]
        state['rsp'] += 8

    def release_saved(self, state, previous, name):
        """Drop saved-slot bookkeeping below the guest rsp after the frame is released.

        A `lea rsp, [rsp + n]`, `mov rsp, rbp` or `add rsp, imm` gives stack space back; any slot
        that was pushed below the new rsp is outside the frame and its bookkeeping is stale, which
        otherwise makes two paths into the same block disagree on the saved keys.
        """
        if name != 'rsp' or state['rsp'] is None or previous is None or state['rsp'] <= previous:
            return
        state['saved'] = {offset: saved for offset, saved in state['saved'].items() if offset >= state['rsp']}

    def frame_relative(self, state, name):
        """The frame offset a register holds, when it is provably frame-relative.

        `lea reg, [rsp + n]` and `mov reg, rsp` record a frame pointer for their destination, so a
        later `mov rsp, reg` restores the frame from a value the analysis still tracks. A register
        whose value came from memory or an untracked computation has no such record and is rejected.
        """
        if name is None:
            return None
        if name in ('rsp', 'rbp'):
            return state[name]
        pointer = state['pointers'].get(name)
        return pointer[2] if pointer is not None and pointer[0] == 'frame' else None

    def memory_origin(self, ins, state, operand):
        if operand.type != X86_OP_MEM or operand.mem.index:
            return None
        base, displacement = ins.reg_name(operand.mem.base), operand.mem.disp
        if base == 'rip':
            return 'image', ins.address + ins.size + displacement
        if not base:
            return 'image', displacement
        if base in ('rsp', 'rbp') and state[base] is not None:
            return 'frame', state[base] + displacement
        pointer = state['pointers'].get(base)
        if pointer and pointer[0] in ('image', 'frame') and pointer[2] is not None:
            return pointer[0], pointer[2] + displacement
        return None

    def memory_write_region(self, ins, state, operand):
        if frame_exclusion.applies(self, ins, operand):
            known = self.memory_origin(ins, state, operand)
            if known is not None:
                if known[0] == 'frame':
                    self.fail(ins, 'frame exclusion contradicts a known frame write')
                return known[0], known[1], known[1] + operand.size
            return 'outside_frame', 0, 0
        checked = checked_stack.region(self, ins, state, operand)
        if checked is not None:
            return checked
        if operand.mem.index:
            return loop_ranges.frame_write(self, ins, state, operand)
        origin = self.memory_origin(ins, state, operand)
        return None if origin is None else (origin[0], origin[1], origin[1] + operand.size)

    def pointer_origin(self, ins, state, operand):
        if operand.size != 8 or not self.pointer_operand(ins, state, operand):
            return None
        if operand.type == X86_OP_REG:
            name = self.reg(ins, operand)[0]
            if name in ('rsp', 'rbp') and state[name] is not None:
                return 'frame', 0, state[name]
            return state['pointers'].get(name)
        origin = self.memory_origin(ins, state, operand)
        if origin is not None and origin[0] == 'frame':
            return state['stack_origins'].get(origin[1])
        return None

    def pointer_operand(self, ins, state, operand):
        if checked_stack.pointer(self, ins, state, operand):
            return True
        if operand.size != 8:
            return False
        if operand.type == X86_OP_REG:
            return self.reg(ins, operand)[0] in state['native_pointers']
        origin = self.memory_origin(ins, state, operand)
        if origin is None:
            parameter = effects.parameter_write(self, ins, state, operand)
            return parameter is not None and bool(state.get('parameter_pointers', {}).get((parameter[0], parameter[1]), 0) & 1)
        kind, offset = origin
        if kind == 'frame':
            return offset in state['stack_pointers']
        return offset in state['image_pointers']

    def transfer(self, ins, original):
        state = self.transfer_unchecked(ins, original)
        native = original['native_pointers'].copy()
        native.update(checked_pointers.validated_bases(self, ins, original))
        for register in ins.regs_access()[1]:
            name = ins.reg_name(register)
            if name in ALIASES:
                native.discard(ALIASES[name][0])
        stack = original['stack_pointers'].copy()
        origins = original['stack_origins'].copy()
        op, args = ins.mnemonic, ins.operands
        call_writes = effects.call_writes(self, ins, original) if op == 'call' else None
        # image_pointers (~250k entries) and import_bindings are usually unchanged by an
        # instruction; copy each one only when this instruction actually changes it.
        image = original['image_pointers']
        bindings = original['import_bindings']

        def image_discard(begin, end):
            nonlocal image
            removed = [offset for offset in range(begin - 7, end) if offset in image]
            if not removed:
                return
            if image is original['image_pointers']:
                image = image.copy()
            for offset in removed:
                image.discard(offset)

        def image_add(offset):
            nonlocal image
            if offset in image:
                return
            if image is original['image_pointers']:
                image = image.copy()
            image.add(offset)

        def image_clear():
            nonlocal image
            image = set()

        def import_bindings():
            nonlocal bindings
            if bindings is original['import_bindings']:
                bindings = bindings.copy()
            return bindings

        def bindings_clear():
            nonlocal bindings
            bindings = set()

        callback_memory_unmodified = original['callback_memory_unmodified']
        for operand in self.memory_writes.get(ins.address, ()):
            origin = self.memory_write_region(ins, original, operand)
            if origin is None or origin[0] != 'frame':
                callback_memory_unmodified = False
            if origin is not None and origin[0] == 'outside_frame':
                image_clear()
                bindings_clear()
                continue
            if origin is None:
                stack.clear()
                origins.clear()
                image_clear()
                bindings_clear()
            else:
                begin, end = origin[1], origin[2]
                add_cell = (op == 'mov' and checked_stack.lookup(self, ins, operand) is None and not operand.mem.index
                            and operand is args[0] and self.pointer_operand(ins, original, args[1]))
                if origin[0] == 'frame':
                    for offset in range(begin - 7, end):
                        stack.discard(offset)
                    origins = {offset: pointer for offset, pointer in origins.items() if not (begin < offset + 8 and offset < end)}
                    if add_cell:
                        stack.add(begin)
                        pointer = self.pointer_origin(ins, original, args[1])
                        if pointer is not None:
                            origins[begin] = pointer
                else:
                    image_discard(begin, end)
                    bindings = import_bindings()
                    for offset in range(begin - 7, end):
                        bindings.discard(offset)
                    if add_cell:
                        image_add(begin)
        if op in ('push', 'pop') and original['rsp'] is None:
            # A dynamic frame: the transfer happens at the guest rsp value, not at a frame slot, so
            # there is no slot bookkeeping and the popped destination loses its provenance.
            if op == 'pop' and args[0].type == X86_OP_REG:
                state['pointers'].pop(self.reg(ins, args[0])[0], None)
            native.add('rsp')
        elif op == 'push':
            offset = original['rsp'] - 8
            stack = {saved for saved in stack if not (offset < saved + 8 and saved < offset + 8)}
            origins = {saved: pointer for saved, pointer in origins.items() if not (offset < saved + 8 and saved < offset + 8)}
            pointer = self.pointer_origin(ins, original, args[0])
            if pointer is not None:
                origins[offset] = pointer
            if self.pointer_operand(ins, original, args[0]):
                stack.add(offset)
            native.add('rsp')
        elif op == 'pop':
            # A pop to memory has no destination register to track, but it still consumes the slot.
            if args[0].type == X86_OP_REG:
                name = self.reg(ins, args[0])[0]
                pointer = original['stack_origins'].get(original['rsp'])
                state['pointers'].pop(name, None)
                if pointer is not None:
                    state['pointers'][name] = pointer
                if original['rsp'] in original['stack_pointers']:
                    native.add(name)
            origins.pop(original['rsp'], None)
            stack.discard(original['rsp'])
            native.add('rsp')
        elif op == 'call':
            native.update(checked_pointers.validated_registers(self, ins, original))
            state['pending_outputs'] = pointer_outputs.capture(self, ins, original)
            native.difference_update(VOLATILE | set(VECTOR_STORAGE))
            if call_writes is None or call_writes.parameter_writes:
                stack.clear()
                origins.clear()
                image_clear()
                bindings_clear()
                callback_memory_unmodified = False
            else:
                for kind, begin, end in call_writes.writes:
                    if kind == 'frame':
                        for offset in range(begin - 7, end):
                            stack.discard(offset)
                        origins = {offset: pointer for offset, pointer in origins.items() if not (begin < offset + 8 and offset < end)}
                    else:
                        image_discard(begin, end)
                        bindings = import_bindings()
                        for offset in range(begin - 7, end):
                            bindings.discard(offset)
                        callback_memory_unmodified = False
            for _, predicate, kind, offset in state['pending_outputs']:
                if predicate == 'always':
                    if kind == 'frame':
                        stack.add(offset)
                    else:
                        image_add(offset)
            if ins.address not in self.dispatch_calls:
                callee, _ = self.image.call(ins, self.contract)
                if callee['result'] == 'ptr':
                    native.add('rax')
            native.add('rsp')
        elif args and args[0].type == X86_OP_REG and args[0].size == 8:
            destination = self.reg(ins, args[0])[0]
            proven = False
            if op in ('mov', 'movabs'):
                proven = self.pointer_operand(ins, original, args[1])
                pointer = self.pointer_origin(ins, original, args[1])
                if pointer is not None:
                    state['pointers'][destination] = pointer
            elif op == 'lea':
                memory = args[1].mem
                base, index = ins.reg_name(memory.base), ins.reg_name(memory.index)
                proven = ((base == 'rip' or base in original['native_pointers']) and index not in original['native_pointers']) or (base not in original['native_pointers'] and index in original['native_pointers'] and memory.scale == 1)
            elif op in ('add', 'sub'):
                left, right = (self.pointer_operand(ins, original, operand) for operand in args)
                proven = (left and not right) or (op == 'add' and right and not left)
            elif op in ('inc', 'dec'):
                proven = destination in original['native_pointers']
            elif op.startswith('cmov'):
                proven = all(self.pointer_operand(ins, original, operand) for operand in args)
            if proven:
                native.add(destination)
        if ins.address in getattr(self, 'checked_pointer_loads', {}):
            native.add(self.reg(ins, args[0])[0])
            checked_cell = self.memory_origin(ins, original, args[1])
            if checked_cell is not None:
                if checked_cell[0] == 'frame':
                    stack.add(checked_cell[1])
                else:
                    image_add(checked_cell[1])
        if self.image.immutable_cells:
            missing = self.image.immutable_cells - image
            if missing:
                image = image.copy() if image is original['image_pointers'] else image
                image.update(missing)
        if self.image.immutable_bindings:
            missing = self.image.immutable_bindings - bindings
            if missing:
                bindings = bindings.copy() if bindings is original['import_bindings'] else bindings
                bindings.update(missing)
        state['native_pointers'], state['stack_pointers'], state['image_pointers'] = native, stack, image
        state['callback_memory_unmodified'] = callback_memory_unmodified
        state['import_bindings'] = bindings
        state['stack_origins'] = origins
        stack_values.transfer(self, ins, original, state)
        parameter_pointers.transfer(self, ins, original, state)
        register_aliases.transfer(self, ins, original, state, VOLATILE, ALIASES)
        return state

    def constant_operand(self, ins, state, operand):
        if operand.type == X86_OP_IMM:
            return operand.imm & ((1 << (operand.size * 8)) - 1)
        if operand.type == X86_OP_REG:
            name, width, shift = self.reg(ins, operand)
            value = state.get('constants', {}).get(name)
            if value is not None:
                return (value >> shift) & ((1 << width) - 1)
        return None

    def constant_write(self, ins, original, state, operand, value):
        if operand.type != X86_OP_REG:
            return
        name, width, shift = self.reg(ins, operand)
        value &= (1 << width) - 1
        if width >= 32:
            state['constants'][name] = value
        elif name in original.get('constants', {}):
            mask = ((1 << width) - 1) << shift
            state['constants'][name] = (original['constants'][name] & ~mask) | (value << shift)

    def analyze(self):
        """Dataflow the contract, widening the extent across a false function start if needed.

        A fragment that only balances against its neighbour is not a standalone function: when
        the declared extent fails a frame-balance check, retry with the neighbouring fragments
        merged. The retry cannot change a contract that already balances, and the extent only
        ever grows, so the loop terminates.
        """
        while True:
            try:
                self.dataflow()
            except Rejected as error:
                if not self.uniform or 'native frame' not in str(error):
                    raise
                wider = self.widen_extent()
                if wider is None:
                    raise
                self.start, self.end = wider
                self.prepare()
                continue
            return

    def widen_extent(self):
        """The next-wider contract extent, or None.

        A false function start splits one real function into fragments: a fragment's epilogue pops
        registers an earlier fragment pushed, or its branch reaches the middle of a neighbouring
        declared function. Merge the fragments the declared extent touches and retry. A fragment
        the discovery had to borrow is merged whole, and a fall-through boundary on either side is
        crossed, until the extent stops growing. The extent only grows, so the loop terminates.
        """
        start, end = self.start, self.end
        for _ in range(64):
            previous, last = self.image.function_ends.get(start), self.image.function_ends.get(end)
            following = self.image.functions.get(end)
            if last is not None and following is not None and self.image.falls_through(last):
                end = following['address'] + following['size']
                continue
            if previous is not None and self.image.falls_through(previous):
                start = previous['address']
                continue
            if previous is not None and self.image.branches_into(previous, start):
                start = previous['address']
                continue
            merged = [self.image.functions[address] for address in sorted(self.borrowed)
                      if address < start or address + self.image.functions[address]['size'] > end]
            if merged:
                start = min([start] + [function['address'] for function in merged])
                end = max([end] + [function['address'] + function['size'] for function in merged])
                continue
            overlapping = [self.image.functions[callee['address']] for callee, _ in self.tail_calls.values()
                           if callee.get('address') in self.image.functions
                           and not (start <= callee['address'] and callee['address'] + callee['size'] <= end)]
            if overlapping:
                start = min([start] + [function['address'] for function in overlapping])
                end = max([end] + [function['address'] + function['size'] for function in overlapping])
                continue
            break
        if (start, end) == (self.start, self.end):
            return None
        return start, end

    def dataflow(self):
        known = {'rsp': MASK64}
        for loc in self.argument_locations:
            if loc['kind'] == 'register':
                known[loc['name']] = (1 << loc['bits']) - 1
        pointers = {loc['name']: ('uniform' if self.uniform else 'parameter', index, 0) for index, loc in enumerate(self.argument_locations) if loc['kind'] == 'register' and loc['type'] == 'ptr'}
        initial = {'known': known, 'rsp': 0, 'rbp': None, 'saved': {}, 'flags': set(), 'pointers': pointers, 'constants': {},
                   'tail_stack_clean': frozenset(loc['offset'] for loc in self.argument_locations if loc['kind'] == 'stack'),
                   'native_pointers': {'rsp'} | set(pointers),
                   'stack_pointers': {loc['offset'] for loc in self.argument_locations if loc['kind'] == 'stack' and loc['type'] == 'ptr'},
                   'stack_origins': {loc['offset']: ('parameter', index, 0) for index, loc in enumerate(self.argument_locations) if loc['kind'] == 'stack' and loc['type'] == 'ptr'},
                   'image_pointers': set(self.image.import_slots) | set(self.image.data_import_slots) | {slot for slot, _ in self.image.relocations},
                   'register_aliases': frozenset(), 'stack_values': {}, 'pending_outputs': frozenset(), 'parameter_pointers': {}, 'zero_vectors': set(),
                   'import_bindings': set(self.image.import_slots), 'callback_memory_unmodified': True}
        entry = self.start
        self.states[entry] = initial
        self.collecting = True
        pending = deque([entry])
        while pending:
            address = pending.popleft()
            transferred = self.transfer(self.instructions[address], self.states[address])
            for target in self.successors[address]:
                state = pointer_outputs.refine(self, self.instructions[address], transferred, target)
                old = self.states.get(target)
                if old is None:
                    new = state
                else:
                    same_frame = old['rsp'] == state['rsp'] and old['rbp'] == state['rbp']
                    if not same_frame and not self.uniform:
                        raise Rejected(f'incompatible native frames at 0x{target:x}')
                    new = dict(state)
                    if not same_frame:
                        # Two paths reach this block with different guest frames: a runtime number of
                        # pushes, or a frame the analysis could pin down on only one side. The
                        # uniform ABI keeps the guest rsp in the register file, so the block stays
                        # lowerable with a runtime-sized frame.
                        new['rsp'] = state['rsp'] if old['rsp'] == state['rsp'] else None
                        new['rbp'] = state['rbp'] if old['rbp'] == state['rbp'] else None
                    new['saved'] = {}
                    if old['saved'].keys() == state['saved'].keys():
                        for offset, saved in state['saved'].items():
                            before = old['saved'][offset]
                            # The two paths may have pushed different things at this offset: a saved
                            # register on one side, a stack argument or an immediate on the other. No
                            # single register can be restored from the merged slot, so keep the name
                            # only when both paths agree; `repair_frame` already skips a nameless slot.
                            # The other fields already merge by agreement below.
                            name = saved[0] if saved[0] == before[0] else None
                            new['saved'][offset] = (name, saved[1] & before[1], saved[2] if saved[2] == before[2] else None, saved[3] if saved[3] == before[3] else None)
                    new['known'] = {name: old['known'].get(name, 0) & state['known'].get(name, 0) for name in REGISTERS + VECTOR_STORAGE}
                    new['register_aliases'] = old.get('register_aliases', frozenset()) & state.get('register_aliases', frozenset())
                    new['parameter_pointers'] = {cell: kind | old.get('parameter_pointers', {})[cell] for cell, kind in state.get('parameter_pointers', {}).items() if cell in old.get('parameter_pointers', {})}
                    new['zero_vectors'] = old.get('zero_vectors', set()) & state.get('zero_vectors', set())
                    new['pending_outputs'] = old.get('pending_outputs', frozenset()) & state.get('pending_outputs', frozenset())
                    new['flags'] = old['flags'] & state['flags']
                    new['tail_stack_clean'] = old['tail_stack_clean'] & state['tail_stack_clean']
                    new['native_pointers'] = (old['native_pointers'] & state['native_pointers']) | {name for name in old['native_pointers'] if state.get('constants', {}).get(name) == 0} | {name for name in state['native_pointers'] if old.get('constants', {}).get(name) == 0}
                    new['stack_pointers'] = old['stack_pointers'] & state['stack_pointers']
                    new['stack_origins'] = {offset: pointer for offset, pointer in state['stack_origins'].items() if old['stack_origins'].get(offset) == pointer}
                    new['stack_values'] = {offset: value for offset, value in state['stack_values'].items() if old['stack_values'].get(offset) == value}
                    new['image_pointers'] = (old['image_pointers'] if old['image_pointers'] is state['image_pointers']
                                             else old['image_pointers'] & state['image_pointers'])
                    new['import_bindings'] = old['import_bindings'] & state['import_bindings']
                    new['callback_memory_unmodified'] = old['callback_memory_unmodified'] and state['callback_memory_unmodified']
                    if not same_frame:
                        # Offset-keyed incoming-window facts no longer name the incoming window once
                        # the guest rsp is a runtime value.
                        new['tail_stack_clean'] = frozenset()
                        new['stack_origins'] = {}
                        new['stack_values'] = {}
                        new['stack_pointers'] = set()
                    new['pointers'] = {name: pointer for name, pointer in state['pointers'].items() if old['pointers'].get(name) == pointer}
                    new['constants'] = {name: value for name, value in state['constants'].items() if old['constants'].get(name) == value}
                if old != new:
                    self.states[target] = new
                    pending.append(target)
        self.collecting = False
        for address, state in self.states.items():
            self.transfer(self.instructions[address], state)
        require(self.depth <= 1024 * 1024, 'native frame exceeds current allocation limit')
        alignments = self.contract.get('stack_objects', [])
        for padding in range(16):
            if all((self.depth + padding + obj['offset']) % obj['alignment'] == 0 for obj in alignments):
                self.depth += padding
                break
        else:
            raise Rejected('stack object alignments require incompatible entry stack addresses')

    def trap(self, ins, kind):
        report = [f'  call void @NativeAotReportGuardFailure_nid_no_patch(i64 {ins.address}, i32 {kind})'] if self.image.contracts.get('guard_diagnostics', False) else []
        return report + ['  call void @llvm.trap()', '  unreachable']

    def emit(self, expression):
        self.serial += 1
        value = f'%v{self.serial}'
        self.lines.append(f'  {value} = {expression}')
        return value

    def register_width(self, name):
        return 128 if name in VECTOR_STORAGE else 64

    def load(self, name, bits=64, shift=0):
        """The current value of a guest register, as an SSA value inside this block."""
        width = self.register_width(name)
        value = self.values.get(name) if REGISTER_SSA and self.values is not None else None
        if value is None:
            value = self.emit(f'load i{width}, ptr %{name}, align 8')
            if REGISTER_SSA and self.values is not None:
                self.values[name] = value
        if shift:
            value = self.emit(f'lshr i{width} {value}, {shift}')
        return value if bits == width else self.emit(f'trunc i{width} {value} to i{bits}')

    def write_register(self, name, value):
        """Record a register write. Inside a block it stays an SSA value; at a boundary
        `flush_registers` materializes it into the register's spill alloca."""
        if REGISTER_SSA and self.values is not None:
            self.values[name] = value
            self.dirty.add(name)
        else:
            width = self.register_width(name)
            align = 16 if width == 128 else 8
            self.lines.append(f'  store i{width} {value}, ptr %{name}, align {align}')

    def flush_registers(self):
        """Materialize the block's SSA register values so the next block can reload them.

        A value loaded from the register file and never written is still only in the SSA map, so
        every mapped register is spilled, not just the ones written in this block.
        """
        if not REGISTER_SSA or self.values is None:
            return
        for name in sorted(self.dirty, key=lambda name: SLOT_INDEX[name]):
            width = self.register_width(name)
            align = 16 if width == 128 else 8
            self.lines.append(f'  store i{width} {self.values[name]}, ptr %{name}, align {align}')
        self.dirty.clear()
        self.values.clear()

    def store_vector(self, name, value, bits=128, zero_upper=False):
        if bits != 128:
            value = self.emit(f'zext i{bits} {value} to i128')
            if not zero_upper:
                old = self.load(name, 128)
                high = self.emit(f'and i128 {old}, {((1 << 128) - 1) ^ ((1 << bits) - 1)}')
                value = self.emit(f'or i128 {high}, {value}')
        self.write_register(name, value)

    def store(self, name, value, bits=64, shift=0):
        if bits != 64:
            value = self.emit(f'zext i{bits} {value} to i64')
        if bits < 32:
            old = self.load(name)
            masked = self.emit(f'and i64 {old}, {MASK64 ^ (((1 << bits) - 1) << shift)}')
            if shift:
                value = self.emit(f'shl i64 {value}, {shift}')
            value = self.emit(f'or i64 {value}, {masked}')
        self.write_register(name, value)

    def frame_pointer(self, offset):
        return self.emit(f'getelementptr i8, ptr %frame, i64 {self.depth + offset}')

    def effective_integer(self, ins, operand):
        mem = operand.mem
        base, index = ins.reg_name(mem.base), ins.reg_name(mem.index)
        if base == 'rip' or base in ('rsp', 'rbp') or base in self.states[ins.address]['pointers']:
            value = self.emit(f'ptrtoint ptr {self.address(ins, operand)} to i64')
        else:
            value = str(mem.disp & MASK64)
            for name, scale in ((base, 1), (index, mem.scale)):
                if name:
                    parent, width, shift = ALIASES[name]
                    source = self.load(parent, width, shift)
                    if width != 64:
                        source = self.emit(f'zext i{width} {source} to i64')
                    if scale != 1:
                        source = self.emit(f'mul i64 {source}, {scale}')
                    value = self.emit(f'add i64 {value}, {source}')
        if ins.addr_size == 4:
            value = self.emit(f'trunc i64 {value} to i32')
            value = self.emit(f'zext i32 {value} to i64')
        return value

    def address(self, ins, operand):
        checked_pointers.emit_base(self, ins, operand)
        mem = operand.mem
        state = self.states[ins.address]
        base = ins.reg_name(mem.base)
        index = ins.reg_name(mem.index)
        if mem.segment and ins.reg_name(mem.segment) == 'fs':
            pointer = self.emit('call ptr @NativeAotTlsBase_nid_no_patch()')
            offset = str(mem.disp)
            if index:
                value = self.load(index)
                if mem.scale != 1:
                    value = self.emit(f'mul i64 {value}, {mem.scale}')
                offset = self.emit(f'add i64 {value}, {offset}')
            address = self.emit(f'getelementptr i8, ptr {pointer}, i64 {offset}') if offset != '0' else pointer
            return checked_stack.guard(self, ins, operand, address)
        if base == 'rip':
            require(not index, 'invalid RIP-relative index')
            displacement = ins.address + ins.size + mem.disp
            if ins.mnemonic == 'lea' and displacement in self.image.functions:
                # A `lea` computes a guest-visible function pointer, and the value a relocated
                # vtable slot holds and the runtime dispatch table is keyed by is
                # `guest_base + vaddr`, not the native body that `pointer()` names for a call
                # target. Returning the native symbol made the guest compare and dispatch on a
                # host address (REPORT24 n12).
                return f"inttoptr (i64 {self.image.guest_base + displacement} to ptr)"
            return self.image.pointer(displacement, 1 if ins.mnemonic == 'lea' else operand.size)
        if base not in state['pointers'] and index in state['pointers'] and mem.scale == 1:
            base, index = index, base
        if base in ('rsp', 'rbp') and state[base] is not None:
            pointer = self.frame_pointer(state[base] + mem.disp)
            offset = '0'
        elif base in ('rsp', 'rbp'):
            pointer = self.emit(f'inttoptr i64 {self.load(base)} to ptr')
            offset = str(mem.disp)
        elif base in state['pointers']:
            kind, argument, displacement = state['pointers'][base]
            if kind == 'image':
                pointer = self.image.pointer(displacement)
                offset = str(mem.disp)
            elif kind == 'frame':
                if displacement is None:
                    # A runtime-sized frame pointer: the value lives in the register, not at a
                    # known frame offset.
                    pointer = self.emit(f'inttoptr i64 {self.load(base)} to ptr')
                    offset = str(mem.disp)
                else:
                    pointer = self.frame_pointer(displacement)
                    offset = str(mem.disp)
            elif kind == 'uniform':
                # The uniform ABI keeps every GPR in its own alloca; a pointer in
                # a register is the loaded guest pointer, not a typed %argN.
                pointer = self.emit(f'inttoptr i64 {self.load(base)} to ptr')
                offset = str(mem.disp)
            else:
                pointer = f'%arg{argument}'
                offset = str(mem.disp + displacement)
        elif base:
            pointer = self.emit(f'inttoptr i64 {self.load(base)} to ptr')
            offset = str(mem.disp)
        else:
            pointer = self.image.pointer(mem.disp)
            offset = '0'
        if index:
            value = self.load(index)
            if mem.scale != 1:
                value = self.emit(f'mul i64 {value}, {mem.scale}')
            offset = self.emit(f'add i64 {value}, {offset}')
        address = self.emit(f'getelementptr i8, ptr {pointer}, i64 {offset}') if offset != '0' else pointer
        return checked_stack.guard(self, ins, operand, address)

    def memory_alignment(self, ins, operand):
        """The alignment proven for a scalar memory operand, or None when it cannot be proven.

        `atomics.ordered_load`/`ordered_store` claim this alignment in the IR, and a release or
        acquire atomic whose address is not naturally aligned lowers to `stlr`/`ldar`, which fault
        on a misaligned address (a packed guest field is stored at one). A constant address
        (RIP-relative or an image pointer) and a frame-relative address are inspected; an address
        the compiler cannot place keeps the natural form, the pre-existing policy.
        """
        if operand.type != X86_OP_MEM:
            return None
        mem = operand.mem
        state = self.states[ins.address]
        if mem.segment or mem.index:
            return None
        base = ins.reg_name(mem.base)
        if base == 'rip':
            return alignment_of(ins.address + ins.size + mem.disp)
        if base in ('rsp', 'rbp') and state[base] is not None:
            return alignment_of(self.depth + state[base] + mem.disp, 16)
        if base in state['pointers']:
            kind, argument, displacement = state['pointers'][base]
            if kind == 'image':
                return alignment_of(displacement + mem.disp)
            if kind == 'frame':
                return alignment_of(self.depth + displacement + mem.disp, 16)
        return None

    def read(self, ins, operand, bits=None):
        bits = operand.size * 8 if bits is None else bits
        if operand.type == X86_OP_REG:
            name, width, shift = self.reg(ins, operand)
            return self.load(name, min(width, bits), shift)
        if operand.type == X86_OP_IMM:
            return str(operand.imm & ((1 << bits) - 1))
        value = self.emit(atomics.ordered_load(bits, self.address(ins, operand), self.memory_alignment(ins, operand)))
        return checked_pointers.emit(self, ins, operand, value)

    def write(self, ins, operand, value):
        if operand.type == X86_OP_REG:
            name, bits, shift = self.reg(ins, operand)
            self.store(name, value, bits, shift)
        else:
            pointer = frame_exclusion.guard(self, ins, operand, self.address(ins, operand))
            self.lines.append(atomics.ordered_store(operand.size * 8, value, pointer, self.memory_alignment(ins, operand)))

    def guest_stack_flags(self, ins, args, state, right):
        """(left, right, value) from the guest rsp for a flag-setting stack adjustment, else None.

        The frame pointer stands in for the guest stack pointer, but a host address has different
        low bits, so PF (and AF) from `add/sub/cmp rsp, imm` would be wrong. The analysis tracks the
        guest rsp as an offset from its entry value, so the guest operand is `rsp_guest + offset`.
        """
        if self.rsp_guest is None or state['rsp'] is None:
            return None
        if args[0].type != X86_OP_REG or args[0].size != 8 or self.reg(ins, args[0])[0] != 'rsp':
            return None
        if args[1].type != X86_OP_IMM or ins.mnemonic not in ('add', 'sub', 'cmp'):
            return None
        guest = self.emit(f'load i64, ptr {self.rsp_guest}')
        left = self.emit(f'add i64 {guest}, {state["rsp"]}')
        instruction = 'sub' if ins.mnemonic == 'cmp' else ins.mnemonic
        value = self.emit(f'{instruction} i64 {left}, {right}')
        return left, right, value

    def flags(self, operation, bits, left, right, value):
        zf = self.emit(f'icmp eq i{bits} {value}, 0')
        sf = self.emit(f'icmp slt i{bits} {value}, 0')
        low = value if bits == 8 else self.emit(f'trunc i{bits} {value} to i8')
        parity = self.emit(f'call i8 @llvm.ctpop.i8(i8 {low})')
        parity = self.emit(f'and i8 {parity}, 1')
        pf = self.emit(f'icmp eq i8 {parity}, 0')
        if operation in ('sub', 'cmp'):
            cf = self.emit(f'icmp ult i{bits} {left}, {right}')
            different = self.emit(f'xor i{bits} {left}, {right}')
            changed = self.emit(f'xor i{bits} {left}, {value}')
            overflow = self.emit(f'and i{bits} {different}, {changed}')
            of = self.emit(f'icmp slt i{bits} {overflow}, 0')
        elif operation == 'add':
            cf = self.emit(f'icmp ult i{bits} {value}, {left}')
            different = self.emit(f'xor i{bits} {left}, {right}')
            same = self.emit(f'xor i{bits} {different}, -1')
            changed = self.emit(f'xor i{bits} {left}, {value}')
            overflow = self.emit(f'and i{bits} {same}, {changed}')
            of = self.emit(f'icmp slt i{bits} {overflow}, 0')
        else:
            cf = of = 'false'
        for name, value in [('zf', zf), ('sf', sf), ('cf', cf), ('of', of), ('pf', pf)]:
            self.lines.append(f'  store i1 {value}, ptr %{name}, align 1')

    def condition(self, operation):
        flags = {name: self.emit(f'load i1, ptr %{name}, align 1') for name in ('zf', 'sf', 'cf', 'of', 'pf')}
        inverse = lambda value: self.emit(f'xor i1 {value}, true')
        signed = lambda: self.emit(f"xor i1 {flags['sf']}, {flags['of']}")
        if operation == 'je': return flags['zf']
        if operation == 'jne': return inverse(flags['zf'])
        if operation == 'jb': return flags['cf']
        if operation == 'jae': return inverse(flags['cf'])
        if operation == 'js': return flags['sf']
        if operation == 'jns': return inverse(flags['sf'])
        if operation == 'jp': return flags['pf']
        if operation == 'jnp': return inverse(flags['pf'])
        if operation == 'jo': return flags['of']
        if operation == 'jno': return inverse(flags['of'])
        if operation in ('ja', 'jbe'):
            value = self.emit(f"or i1 {flags['cf']}, {flags['zf']}")
            return value if operation == 'jbe' else inverse(value)
        if operation == 'jl': return signed()
        if operation == 'jge': return inverse(signed())
        value = self.emit(f"or i1 {signed()}, {flags['zf']}")
        return value if operation == 'jle' else inverse(value)

    def native_value(self, typ, value):
        if typ == 'ptr':
            return self.emit(f'inttoptr i64 {value} to ptr')
        if typ in abi.FLOAT_TYPES:
            return self.emit(f'bitcast i{abi.bits(typ)} {value} to {abi.llvm_type(typ)}')
        return value

    def machine_value(self, typ, value):
        if typ == 'ptr':
            return self.emit(f'ptrtoint ptr {value} to i64')
        if typ in abi.FLOAT_TYPES:
            return self.emit(f'bitcast {abi.llvm_type(typ)} {value} to i{abi.bits(typ)}')
        return value

    def uniform_gep(self, block, bank, index):
        return self.emit(f'getelementptr inbounds %regfile, ptr {block}, i64 0, i32 {bank}, i64 {index}')

    def uniform_load_registers(self, block, slots=None, skip=()):
        def selected(name):
            return name not in skip and (slots is None or name in slots)
        for index, reg in enumerate(REGISTERS):
            if not selected(reg):
                continue
            gep = self.uniform_gep(block, 0, index)
            value = self.emit(f'load i64, ptr {gep}, align 8')
            self.write_register(reg, value)
        for index, reg in enumerate(VECTOR_REGISTERS):
            if not selected(reg):
                continue
            gep = self.uniform_gep(block, 1, index)
            value = self.emit(f'load i128, ptr {gep}, align 16')
            self.write_register(reg, value)
        for index in range(16):
            if not selected(f'ymm_hi{index}'):
                continue
            gep = self.uniform_gep(block, 2, index)
            value = self.emit(f'load i128, ptr {gep}, align 16')
            self.write_register(f'ymm_hi{index}', value)

    def uniform_store_registers(self, block, slots=None, rsp=None):
        for index, reg in enumerate(REGISTERS):
            # The rsp slot carries the guest stack pointer, which the frame pointer only stands in
            # for locally: publishing the frame address would hand a callee a host address, and its
            # own `add/sub rsp, imm` flags would then follow that address (see `outgoing_rsp`). The
            # slot is published even when the callee summary does not name rsp, because the callee's
            # prologue always copies the incoming guest rsp out of it.
            if reg != 'rsp' and slots is not None and reg not in slots:
                continue
            value = rsp if reg == 'rsp' and rsp is not None else self.load(reg)
            gep = self.uniform_gep(block, 0, index)
            self.lines.append(f'  store i64 {value}, ptr {gep}, align 8')
        for index, reg in enumerate(VECTOR_REGISTERS):
            if slots is not None and reg not in slots:
                continue
            value = self.load(reg, 128)
            gep = self.uniform_gep(block, 1, index)
            self.lines.append(f'  store i128 {value}, ptr {gep}, align 16')
        for index in range(16):
            if slots is not None and f'ymm_hi{index}' not in slots:
                continue
            value = self.load(f'ymm_hi{index}', 128)
            gep = self.uniform_gep(block, 2, index)
            self.lines.append(f'  store i128 {value}, ptr {gep}, align 16')

    def uniform_load_state(self, block):
        """Load the integer flags and the x87 stack from the register file (entry only)."""
        gep = self.uniform_gep(block, 3, 0)
        flags = self.emit(f'load i64, ptr {gep}, align 8')
        for name, bit in FLAG_BITS.items():
            value = self.emit(f'lshr i64 {flags}, {bit}')
            value = self.emit(f'trunc i64 {value} to i1')
            self.lines.append(f'  store i1 {value}, ptr %{name}, align 1')
        gep = self.uniform_gep(block, 5, 0)
        stored = self.emit(f'load i64, ptr {gep}, align 8')
        stored = self.emit(f'trunc i64 {stored} to i32')
        entries = [('x87', None, f'  store i32 {stored}, ptr %x87_top, align 4')]
        top = self.emit('load i32, ptr %x87_top, align 4')
        for index in range(8):
            # The register file holds st(0)..st(7); the native stack is a ring indexed by the top.
            value = self.emit(f'load double, ptr {self.uniform_gep(block, 4, index)}, align 8')
            entries.append(('x87', None, f'  store double {value}, ptr {self.x87_slot(top, index)}, align 8'))
        self.emit_group('state-load', entries)

    def x87_slot(self, top, index):
        offset = self.emit(f'add i32 {top}, {index}')
        offset = self.emit(f'and i32 {offset}, 7')
        return self.emit(f'getelementptr [8 x double], ptr %x87, i32 0, i32 {offset}')

    def uniform_store_state(self, block, defined):
        """Store the integer flags and the x87 stack to the register file (return only).

        Only the flags the analysis marks defined are published; the rest are zero and the
        companion mask records which bits are meaningful, so a consumer (or the differential
        harness) never treats an undefined flag as a real result.
        """
        result = mask = '0'
        for name, bit in FLAG_BITS.items():
            if name not in defined:
                continue
            value = self.emit(f'load i1, ptr %{name}, align 1')
            value = self.emit(f'zext i1 {value} to i64')
            value = self.emit(f'shl i64 {value}, {bit}')
            result = self.emit(f'or i64 {result}, {value}')
            mask = self.emit(f'or i64 {mask}, {1 << bit}')
        gep = self.uniform_gep(block, 3, 0)
        self.lines.append(f'  store i64 {result}, ptr {gep}, align 8')
        gep = self.uniform_gep(block, 3, 1)
        self.lines.append(f'  store i64 {mask}, ptr {gep}, align 8')
        top = self.emit('load i32, ptr %x87_top, align 4')
        entries = []
        for index in range(8):
            value = self.emit(f'load double, ptr {self.x87_slot(top, index)}, align 8')
            gep = self.uniform_gep(block, 4, index)
            entries.append(('x87', None, f'  store double {value}, ptr {gep}, align 8'))
        top = self.emit(f'load i32, ptr %x87_top, align 4')
        top = self.emit(f'zext i32 {top} to i64')
        gep = self.uniform_gep(block, 5, 0)
        entries.append(('x87', None, f'  store i64 {top}, ptr {gep}, align 8'))
        self.emit_group('state-store', entries)

    def emit_group(self, kind, entries):
        """Append a register-file transfer and remember which line carries which register.

        The load that feeds a store is part of the group: it reads a native alloca, and a native
        alloca is only written where the compiler writes it, so leaving the load out of the group
        would not make the register look used -- it is the store that publishes the value.
        """
        group = []
        for register, source, line in entries:
            if source is not None:
                group.append((source, None))
            group.append((len(self.lines), register))
            self.lines.append(line)
        self.groups.append((kind, group))

    def prune_regfile_traffic(self):
        """Drop the x87 rotation for a function that never executes an x87 instruction.

        The uniform ABI imports the x87 stack at the entry and publishes it at every return. A
        function that never reads or writes an x87 register cannot have changed the stack, so the
        entry import only copies the incoming values into natives nobody reads, and re-publishing
        them writes those same values back. Dropping the publish is not just a saving: a function
        that calls one that *does* use the stack must not overwrite what the callee published.
        """
        if not self.uniform or self.uses_x87 or not self.groups:
            return
        drop = set()
        for kind, entries in self.groups:
            if kind not in ('state-load', 'state-store'):
                continue
            for line_index, register in entries:
                if register == 'x87':
                    drop.add(line_index)
        self.lines = [line for index, line in enumerate(self.lines) if index not in drop]

    def uniform_copy_state(self, target, source):
        """Publish the callee's flags and definedness mask into `target`.

        A tail call is a `call`+`ret` on x86, and `ret` does not restore flags, so the flags the
        root's own caller finally sees are the *callee's*. The tail-call epilogue used to publish
        the caller's analysis flags instead, which disagreed with the reference whenever the
        callee's last flag write differed from the caller's (REPORT24). The x87 stack is not part
        of the uniform call ABI (a caller never reloads it from `%rf_out`), so it is left alone.
        """
        for index in range(2):
            value = self.emit(f'load i64, ptr {self.uniform_gep(source, 3, index)}, align 8')
            self.lines.append(f'  store i64 {value}, ptr {self.uniform_gep(target, 3, index)}, align 8')

    def outgoing_rsp(self, state, shift):
        """The guest rsp the callee sees: the call site's rsp, less the return-address slot that a
        `call` pushes and a tail `jmp` does not (`shift` is 8 for a jump). None when the guest rsp is
        not tracked, which leaves the frame pointer in the slot as before."""
        if self.rsp_guest is None or state['rsp'] is None:
            return None
        base = self.emit(f'load i64, ptr {self.rsp_guest}')
        return self.emit(f'add i64 {base}, {state["rsp"] + shift - 8}')

    def uniform_stack_out(self, block, rsp, shift=0):
        if rsp is None:
            # A runtime-sized frame: the outgoing window is the guest stack at the runtime rsp,
            # which the register file holds. Reading it there is the same window a known offset
            # would read, just at a value the analysis could not pin down.
            base = self.load('rsp')
            if shift:
                base = self.emit(f'add i64 {base}, {shift}')
            for index in range(abi.UNIFORM_STACK_SLOTS):
                address = base if not index else self.emit(f'add i64 {base}, {8 * index}')
                pointer = self.emit(f'inttoptr i64 {address} to ptr')
                value = self.emit(f'load i64, ptr {pointer}, align 1')
                gep = self.uniform_gep(block, 6, index)
                self.lines.append(f'  store i64 {value}, ptr {gep}, align 8')
            return
        for index in range(abi.UNIFORM_STACK_SLOTS):
            offset = abi.UNIFORM_STACK_BASE + 8 * index
            value = self.emit(f'load i64, ptr {self.frame_pointer(rsp + shift + offset - 8)}, align 1')
            gep = self.uniform_gep(block, 6, index)
            self.lines.append(f'  store i64 {value}, ptr {gep}, align 8')

    def uniform_stack_in(self, block):
        for index in range(abi.UNIFORM_STACK_SLOTS):
            offset = abi.UNIFORM_STACK_BASE + 8 * index
            gep = self.uniform_gep(block, 6, index)
            value = self.emit(f'load i64, ptr {gep}, align 8')
            self.lines.append(f'  store i64 {value}, ptr {self.frame_pointer(offset)}, align 1')

    def lower_dispatch(self, ins, state, jump, result):
        value = self.dispatch_value(ins, ins.operands[0])
        native = self.emit(f'call ptr @NativeAotDispatch_nid_no_patch(i64 {value})')
        ok = self.emit(f'icmp ne ptr {native}, null')
        label = f'dispatch_{ins.address:x}'
        self.lines.append(f'  br i1 {ok}, label %{label}_ok, label %{label}_trap')
        self.lines.append(f'{label}_trap:')
        self.lines.append(f'  call void @NativeAotReportDispatchFailure_nid_no_patch(i64 {ins.address}, i64 {value})')
        self.lines.append('  call void @llvm.trap()')
        self.lines.append('  unreachable')
        self.lines.append(f'{label}_ok:')
        self.uniform_store_registers('%rf_out', self.outgoing_rsp(state, 8 if jump else 0))
        self.uniform_stack_out('%rf_out', state['rsp'], 8 if jump else 0)
        self.lines.append(f'  call void {native}(ptr %rf_out)')
        self.uniform_load_registers('%rf_out', skip=('rsp',))
        if jump:
            self.uniform_copy_state('%rf', '%rf_out')
            self.uniform_store_registers('%rf')
            self.lines.append('  ret void')

    def lower_switch(self, ins, state, address):
        targets = self.switch_jumps[address]
        value = self.dispatch_value(ins, ins.operands[0])
        label = f'switch_{address:x}'
        for index, target in enumerate(targets):
            match = self.emit(f'icmp eq i64 {value}, {target}')
            if index + 1 < len(targets):
                self.lines.append(f'  br i1 {match}, label %b{target:x}, label %{label}_{index}')
                self.lines.append(f'{label}_{index}:')
            else:
                self.lines.append(f'  br i1 {match}, label %b{target:x}, label %{label}_trap')
        self.lines.append(f'{label}_trap:')
        self.lines.append(f'  call void @NativeAotReportDispatchFailure_nid_no_patch(i64 {address}, i64 {value})')
        self.lines.append('  call void @llvm.trap()')
        self.lines.append('  unreachable')

    def repair_frame(self, state):
        """Restore the saved guest registers and rsp so a tail call sees a balanced frame."""
        if state['rsp'] == 0 and not state['saved']:
            return state
        for offset in sorted(state['saved'], reverse=True):
            name = state['saved'][offset][0]
            if name is None:
                continue
            value = self.emit(f"load i64, ptr {self.frame_pointer(offset)}, align 1")
            self.store(name, value, 64)
        repaired = dict(state)
        if repaired['rsp'] is not None:
            repaired['rsp'] = 0
        repaired['saved'] = {}
        return repaired

    def call_masks(self, ins, callee, slot):
        """The (store, load) register masks a uniform call site needs.

        A direct call uses its callee's summary; an indirect site unions the summaries over its
        declared target set. A site the contract does not annotate (the runtime dispatch
        fallback) stays full, so no register is ever skipped without a proof.
        """
        if slot == 'operand':
            site = self.image.annotated_calls(self.contract).get(ins.address)
            if site is None:
                return registers.FULL, registers.FULL
            # A pool target set is shared by thousands of sites and can hold tens of thousands of
            # addresses; the summary pass already unioned it once.
            index = site.get('target_set')
            if index is not None:
                masks = registers.pool_mask(self.image, index)
                if masks is not None:
                    return masks
            store = load = 0
            for target in site['target_addresses']:
                target_store, target_load = registers.summary(self.image, target)
                store |= target_store
                load |= target_load
            return store, load
        return registers.summary(self.image, callee.get('address'))

    def uniform_call(self, ins, callee, slot, state, tail, result):
        store, load = self.call_masks(ins, callee, slot)
        # The callee's read set goes into the outgoing file, and the rsp slot always carries the
        # guest stack pointer (see `outgoing_rsp`), not the caller's frame address.
        self.uniform_store_registers('%rf_out', registers.names(store),
                                     self.outgoing_rsp(state, 8 if tail else 0))
        # A tail jmp leaves the guest return address at [rsp], so the callee's window starts one slot
        # above the caller's rsp; a `call` pushes that return address itself, so its window starts at
        # the rsp the args were pushed to.
        self.uniform_stack_out('%rf_out', state['rsp'], 8 if tail else 0)
        if slot == 'operand':
            if ins.address in self.image.finite_tables:
                target = finite_tables.emit_target(self, ins, self.image.finite_tables[ins.address])
            else:
                target = self.emit(f'inttoptr i64 {self.read(ins, ins.operands[0], 64)} to ptr')
            if ins.address in self.image.annotated_calls(self.contract):
                finite_tables.emit_membership(self, ins, target, ['@' + name for name in self.image.annotated_calls(self.contract)[ins.address]['targets']])
        else:
            target = '@' + callee['name']
        self.lines.append(f'  call void {target}(ptr %rf_out)')
        self.uniform_load_registers('%rf_out', registers.names(load), skip=('rsp',))
        if tail:
            self.uniform_copy_state('%rf', '%rf_out')
            self.uniform_store_registers('%rf')
            self.lines.append('  ret void')

    def block_boundaries(self):
        """The addresses that start an emitted basic block, and the instructions that end one.

        A block starts at the entry, at a branch target, and after a terminator; between two
        boundaries the guest registers stay SSA values, so only the boundaries spill them. The
        first emitted block always needs a label even when it is not reachable (a dead fragment).
        """
        ordered = sorted(self.instructions)
        terminators = {address for address, ins in self.instructions.items()
                       if ins.mnemonic.startswith('j') or ins.mnemonic in ('ret', 'ud2', 'int3')
                       or not self.successors[address]}
        leaders = {self.start, ordered[0]}
        for address in terminators:
            leaders.update(self.successors[address])
        for previous, address in zip(ordered, ordered[1:]):
            if previous in terminators:
                leaders.add(address)
        return leaders, terminators

    def lower(self):
        result, parameters = signature(self.contract)
        name = self.contract['name']
        self.values = {}
        self.dirty = set()
        if self.uniform:
            self.lines = [f'define void @{name}(ptr %rf) uwtable {{', 'entry:']
            if getattr(self, 'entry_index', None) is not None:
                index = self.entry_index
                self.lines.append(f'  %count_ptr_{index} = getelementptr i64, ptr @__aps5_aot_counts, i64 {index}')
                self.lines.append(f'  %count_old_{index} = atomicrmw add ptr %count_ptr_{index}, i64 1 monotonic')
        else:
            args = ', '.join(f'{abi.parameter_type(typ)} %arg{i}' for i, typ in enumerate(parameters))
            self.lines = [f'define {abi.result_type(result)} @{name}({args}) uwtable {{', 'entry:']
        for reg in REGISTERS:
            self.lines.append(f'  %{reg} = alloca i64, align 8')
            unknown = self.emit('freeze i64 poison')
            self.lines.append(f'  store i64 {unknown}, ptr %{reg}, align 8')
        for reg in VECTOR_STORAGE:
            self.lines.append(f'  %{reg} = alloca i128, align 16')
            unknown = self.emit('freeze i128 poison')
            self.lines.append(f'  store i128 {unknown}, ptr %{reg}, align 16')
        for flag in ('zf', 'sf', 'cf', 'of', 'pf'):
            self.lines.append(f'  %{flag} = alloca i1, align 1')
        self.lines.append(f'  %frame = alloca [{self.depth + self.stack_end} x i8], align 16')
        self.rsp_guest = None
        if self.uniform:
            # The guest rsp is an x86 stack pointer; the frame below is a host address. An
            # `add/sub rsp, imm` flag result is defined by the guest value, so the entry copies the
            # incoming rsp here before the frame pointer replaces it in %rsp.
            self.lines.append('  %rsp_guest = alloca i64, align 8')
            self.lines.append('  %rf_out = alloca %regfile, align 16')
            self.lines.append('  %x87 = alloca [8 x double], align 16')
            self.lines.append('  %x87_top = alloca i32, align 4')
            self.lines.append('  store i32 0, ptr %x87_top, align 4')
            for flag in ('c0', 'c1', 'c2', 'c3'):
                self.lines.append(f'  %{flag} = alloca i1, align 1')
                self.lines.append(f'  store i1 false, ptr %{flag}, align 1')
            self.uniform_load_registers('%rf')
            self.uniform_load_state('%rf')
            self.uniform_stack_in('%rf')
            incoming = self.load('rsp')
            self.lines.append(f'  store i64 {incoming}, ptr %rsp_guest, align 8')
            self.rsp_guest = '%rsp_guest'
            self.store('rsp', self.emit(f'ptrtoint ptr {self.frame_pointer(0)} to i64'))
        else:
            self.store('rsp', self.emit(f'ptrtoint ptr {self.frame_pointer(0)} to i64'))
            for i, loc in enumerate(self.argument_locations):
                value = self.machine_value(loc['type'], f'%arg{i}')
                if loc['kind'] == 'stack':
                    self.lines.append(f"  store i{loc['bits']} {value}, ptr {self.frame_pointer(loc['offset'])}, align 1")
                elif loc['name'] in VECTOR_REGISTERS:
                    self.store_vector(loc['name'], value, loc['bits'], zero_upper=True)
                else:
                    self.store(loc['name'], value, loc['bits'])
        if getattr(self, 'floating_point_checked', False):
            # Only functions that actually used a floating-point instruction need the host
            # FPCR validated (the profile is declared once for the image or per function).
            control = self.emit('call i64 asm sideeffect "mrs $0, FPCR", "=r"()')
            mask = (3 << 22) | (1 << 24) | 0x9f03
            control = self.emit(f'and i64 {control}, {mask}')
            valid = self.emit(f'icmp eq i64 {control}, 0')
            self.lines.extend([f'  br i1 {valid}, label %native_fp_valid, label %native_fp_invalid',
                               'native_fp_invalid:', '  call void @llvm.trap()', '  unreachable', 'native_fp_valid:'])
        # The prologue's register values must reach the entry block's allocas before the branch
        # that leaves the prologue; the entry block then reloads them like any other block.
        self.flush_registers()
        self.lines.append(f"  br label %b{self.start:x}")
        leaders, terminators = self.block_boundaries()
        for address in sorted(self.instructions):
            ins = self.instructions[address]
            args, op = ins.operands, ins.mnemonic
            if address in leaders:
                self.flush_registers()
                self.lines.append(f'b{address:x}:')
            if address in terminators and self.successors[address]:
                # The terminator's own lowering emits the branch, so the spill must happen first.
                self.flush_registers()
            state = self.states[address]
            terminal = False
            if fma.lower(self, ins) or avx.lower(self, ins) or vector.lower(self, ins) or x87.lower(self, ins):
                pass
            elif integer.lower(self, ins) or bmi.lower(self, ins) or system.lower(self, ins):
                pass
            elif atomics.lower(self, ins):
                pass
            elif op == 'leave':
                # `mov rsp, rbp; pop rbp`.
                rbp = state['rbp']
                rsp_value = self.load('rbp')
                self.store('rsp', rsp_value)
                if rbp is None:
                    slot = self.emit(f'inttoptr i64 {rsp_value} to ptr')
                    self.store('rbp', self.emit(f'load i64, ptr {slot}, align 1'))
                    self.store('rsp', self.emit(f'add i64 {rsp_value}, 8'))
                else:
                    entry = state['saved'].get(rbp)
                    if entry is None:
                        if abi.UNIFORM_STACK_BASE <= rbp < abi.uniform_stack_end():
                            value = self.emit(f'load i64, ptr {self.frame_pointer(rbp)}, align 1')
                        else:
                            value = self.emit('freeze i64 poison')
                        self.store('rbp', value, 64)
                    elif entry[1]:
                        self.store('rbp', self.emit(f'load i64, ptr {self.frame_pointer(rbp)}, align 1'))
                    self.store('rsp', self.emit(f'ptrtoint ptr {self.frame_pointer(rbp + 8)} to i64'))
            elif op == 'popfq':
                # Restore the tracked flags from the slot at the guest rsp.
                stack_address = self.load('rsp') if state['rsp'] is None else self.emit(f'ptrtoint ptr {self.frame_pointer(state["rsp"])} to i64')
                slot = self.emit(f'inttoptr i64 {stack_address} to ptr')
                value = self.emit(f'load i64, ptr {slot}, align 1')
                for name, bit in (('cf', 0), ('pf', 2), ('zf', 6), ('sf', 7), ('of', 11)):
                    shifted = self.emit(f'lshr i64 {value}, {bit}')
                    integer.store_flag(self, name, self.emit(f'trunc i64 {shifted} to i1'))
                self.store('rsp', self.emit(f'add i64 {stack_address}, 8'))
            elif op in ('push', 'pop'):
                reg = self.reg(ins, args[0])[0] if args[0].type == X86_OP_REG else None
                if state['rsp'] is None:
                    # A dynamic frame: transfer at the guest rsp value, which this ABI keeps in the
                    # register file, rather than at a frame offset.
                    rsp = self.load('rsp')
                    if op == 'push':
                        if reg is None or state['known'].get(reg, 0):
                            value = self.read(ins, args[0], 64)
                            rsp = self.emit(f'sub i64 {rsp}, 8')
                            slot = self.emit(f'inttoptr i64 {rsp} to ptr')
                            self.lines.append(f'  store i64 {value}, ptr {slot}, align 1')
                        else:
                            rsp = self.emit(f'sub i64 {rsp}, 8')
                    else:
                        slot = self.emit(f'inttoptr i64 {rsp} to ptr')
                        value = self.emit(f'load i64, ptr {slot}, align 1')
                        if args[0].type == X86_OP_MEM:
                            self.write(ins, args[0], value)
                        else:
                            self.store(reg, value)
                        rsp = self.emit(f'add i64 {rsp}, 8')
                    self.store('rsp', rsp)
                elif op == 'push':
                    if reg is None or state['known'].get(reg, 0):
                        value = self.read(ins, args[0], 64)
                        self.lines.append(f"  store i64 {value}, ptr {self.frame_pointer(state['rsp'] - 8)}, align 1")
                    offset = state['rsp'] - 8
                elif args[0].type == X86_OP_MEM:
                    # `pop m64`: the slot value goes to the memory operand (addressed with the rsp
                    # this pop has not advanced yet), then the rsp advances.
                    self.write(ins, args[0], self.stack_slot_value(state))
                    offset = state['rsp'] + 8
                else:
                    entry = state['saved'].get(state['rsp'])
                    if entry is None:
                        # A pop of a slot this function never pushed: a declared caller-pushed slot
                        # is a real frame location, anything else (the guest return-address slot) is
                        # not modelled, so the value is an arbitrary but well-defined one.
                        if abi.UNIFORM_STACK_BASE <= state['rsp'] < abi.uniform_stack_end():
                            value = self.emit(f"load i64, ptr {self.frame_pointer(state['rsp'])}, align 1")
                        else:
                            value = self.emit('freeze i64 poison')
                        self.store(reg, value, 64)
                    elif entry[1]:
                        self.store(reg, self.emit(f"load i64, ptr {self.frame_pointer(state['rsp'])}, align 1"))
                    offset = state['rsp'] + 8
                if state['rsp'] is not None:
                    self.store('rsp', self.emit(f'ptrtoint ptr {self.frame_pointer(offset)} to i64'))
            elif op in ('mov', 'movabs'):
                self.write(ins, args[0], self.read(ins, args[1], args[0].size * 8))
            elif op in ('movzx', 'movsx', 'movsxd'):
                value = self.read(ins, args[1])
                value = self.emit(f"{'zext' if op == 'movzx' else 'sext'} i{args[1].size * 8} {value} to i{args[0].size * 8}")
                self.write(ins, args[0], value)
            elif op == 'lea':
                value = self.effective_integer(ins, args[1])
                if args[0].size != 8:
                    value = self.emit(f'trunc i64 {value} to i{args[0].size * 8}')
                self.write(ins, args[0], value)
            elif op in ('add', 'sub', 'and', 'or', 'xor', 'cmp', 'test'):
                bits = args[0].size * 8
                zero = op == 'xor' and args[0].type == args[1].type == X86_OP_REG and args[0].reg == args[1].reg
                left = '0' if zero else self.read(ins, args[0])
                right = '0' if zero else self.read(ins, args[1], bits)
                instruction = {'cmp': 'sub', 'test': 'and'}.get(op, op)
                value = self.emit(f'{instruction} i{bits} {left}, {right}')
                if op not in ('cmp', 'test'):
                    self.write(ins, args[0], value)
                # A stack adjustment's flags follow the guest stack pointer, not the frame pointer
                # that stands in for it (REPORT22 n11).
                guest = self.guest_stack_flags(ins, args, state, right)
                self.flags(op, bits, *(guest or (left, right, value)))
            elif op == 'call' and address in self.dispatch_calls:
                self.lower_dispatch(ins, state, False, result)
            elif address in self.dispatch_jumps:
                self.lower_dispatch(ins, state, True, result)
                terminal = True
            elif address in self.switch_jumps:
                self.lower_switch(ins, state, address)
                terminal = True
            elif address in self.tail_calls and ins.mnemonic.startswith('j') and ins.mnemonic != 'jmp':
                # Conditional tail call (jcc): taken -> tail call, not-taken -> fall through.
                # A fall-through continuation (a non-branch last instruction) is unconditional
                # and is handled by the tail-call branch below, not as a condition.
                callee, slot = self.tail_calls[address]
                require(abi.uniform(callee), 'conditional tail call requires a uniform callee')
                label = f'ctc_{address:x}'
                self.lines.append(f'  br i1 {self.condition(op)}, label %{label}, label %b{address + ins.size:x}')
                self.lines.append(f'{label}:')
                self.uniform_call(ins, callee, slot, self.repair_frame(state), True, result)
                terminal = True
            elif op == 'call' or address in self.tail_calls:
                tail = address in self.tail_calls
                callee, slot = self.tail_calls[address] if tail else self.image.call(ins, self.contract)
                if abi.uniform(callee):
                    self.uniform_call(ins, callee, slot, self.repair_frame(state) if tail else state, tail, result)
                    terminal = tail
                else:
                    arguments = []
                    native_arguments = []
                    parameter_locations = abi.locations(callee['parameters'])
                    for index, loc in enumerate(parameter_locations):
                        if loc['kind'] == 'stack':
                            if tail:
                                value = self.emit(f"load i{loc['bits']}, ptr {self.frame_pointer(loc['offset'])}, align 1")
                            elif state['rsp'] is None:
                                # The outgoing slot is at the runtime guest rsp, the same window the
                                # known-offset form reads.
                                base = self.emit(f"add i64 {self.load('rsp')}, {loc['offset'] - 8}")
                                pointer = self.emit(f'inttoptr i64 {base} to ptr')
                                value = self.emit(f"load i{loc['bits']}, ptr {pointer}, align 1")
                            else:
                                offset = state['rsp'] + loc['offset'] - 8
                                value = self.emit(f"load i{loc['bits']}, ptr {self.frame_pointer(offset)}, align 1")
                        else:
                            value = self.load(loc['name'], loc['bits'])
                        value = self.native_value(loc['type'], value)
                        if not tail and loc['type'] == 'ptr':
                            checked_pointers.emit_argument(self, ins, index, callee, value)
                        arguments.append(f"{abi.parameter_type(loc['type'])} {value}")
                        native_arguments.append(value)
                    hle_sequence = None
                    if self.image.hle_log and not tail:
                        hle_name = callee['name']
                        if hle_name not in self.image.hle_names:
                            self.image.hle_names[hle_name] = len(self.image.hle_names)
                        hle_index = self.image.hle_names[hle_name]
                        hle_args = []
                        for index in range(6):
                            if index >= len(native_arguments):
                                hle_args.append('0')
                                continue
                            typ = parameter_locations[index]['type']
                            if typ == 'ptr':
                                hle_args.append(self.emit(f'ptrtoint ptr {native_arguments[index]} to i64'))
                            elif typ in ('f32', 'f64'):
                                hle_args.append('0')
                            elif abi.bits(typ) == 64:
                                hle_args.append(native_arguments[index])
                            else:
                                hle_args.append(self.emit(f'zext i{abi.bits(typ)} {native_arguments[index]} to i64'))
                        hle_sequence = self.emit(f"call i64 @HleLogCall(ptr @__aps5_hle_name_{hle_index}, {', '.join('i64 ' + item for item in hle_args)})")
                    if slot == 'operand':
                        if address in self.image.finite_tables:
                            target = finite_tables.emit_target(self, ins, self.image.finite_tables[address])
                        else:
                            target = self.emit(f'inttoptr i64 {self.read(ins, args[0], 64)} to ptr')
                        if address in self.image.annotated_calls(self.contract):
                            names = self.image.annotated_calls(self.contract)[address]['targets']
                            finite_tables.emit_membership(self, ins, target, ['@' + name for name in names])
                    else:
                        target = '@' + callee['name'] if slot is None else self.emit(f'load ptr, ptr {self.image.pointer(slot, 8)}, align 1')
                    expression = f"call {abi.result_type(callee['result'])} {target}({', '.join(arguments)})"
                    if callee['result'] == 'void':
                        self.lines.append('  ' + expression)
                        value = None
                    else:
                        value = self.emit(expression)
                    if hle_sequence is not None:
                        if value is None:
                            self.lines.append(f'  call void @HleLogReturn(i64 {hle_sequence}, i64 0)')
                        elif callee['result'] in ('i8', 'u8', 'i16', 'u16', 'i32', 'u32'):
                            widened = self.emit(f"zext i{abi.bits(callee['result'])} {value} to i64")
                            self.lines.append(f'  call void @HleLogReturn(i64 {hle_sequence}, i64 {widened})')
                        elif callee['result'] == 'ptr':
                            widened = self.emit(f'ptrtoint ptr {value} to i64')
                            self.lines.append(f'  call void @HleLogReturn(i64 {hle_sequence}, i64 {widened})')
                        elif abi.bits(callee['result']) == 64:
                            self.lines.append(f'  call void @HleLogReturn(i64 {hle_sequence}, i64 {value})')
                        else:
                            self.lines.append(f'  call void @HleLogReturn(i64 {hle_sequence}, i64 0)')
                    if value is not None and not callee.get('noreturn'):
                        pointer_outputs.emit_checks(self, ins, callee, native_arguments, value)
                    if callee.get('noreturn'):
                        self.lines.append('  unreachable')
                        terminal = True
                    elif tail:
                        if self.uniform:
                            if value is not None:
                                value = self.machine_value(callee['result'], value)
                                if callee['result'] in abi.FLOAT_TYPES:
                                    self.store_vector('xmm0', value, abi.bits(callee['result']), zero_upper=True)
                                else:
                                    self.store('rax', value, abi.bits(callee['result']))
                            self.uniform_store_state('%rf', state['flags'])
                            self.uniform_store_registers('%rf')
                            self.lines.append('  ret void')
                        else:
                            self.lines.append('  ret void' if value is None else f"  ret {abi.llvm_type(result)} {value}")
                        terminal = True
                    elif value is not None:
                        value = self.machine_value(callee['result'], value)
                        if callee['result'] in abi.FLOAT_TYPES:
                            self.store_vector('xmm0', value, abi.bits(callee['result']), zero_upper=True)
                        else:
                            self.store('rax', value, abi.bits(callee['result']))
            elif op == 'ret':
                if self.uniform:
                    self.uniform_store_state('%rf', state['flags'])
                    self.uniform_store_registers('%rf')
                    self.lines.append('  ret void')
                elif result == 'void':
                    self.lines.append('  ret void')
                else:
                    value = self.load(abi.return_register(result), abi.bits(result))
                    value = self.native_value(result, value)
                    self.lines.append(f'  ret {abi.llvm_type(result)} {value}')
                terminal = True
            elif op == 'jmp' and address in self.image.finite_tables:
                descriptor = self.image.finite_tables[address]
                target = finite_tables.emit_target(self, ins, descriptor)
                targets = list(dict.fromkeys(descriptor['targets']))
                finite_tables.emit_membership(self, ins, target, [self.image.pointer(value) for value in targets])
                labels = ', '.join(f'label %b{value:x}' for value in targets)
                self.lines.append(f'  indirectbr ptr {target}, [{labels}]')
                terminal = True
            elif op.startswith('j'):
                target = args[0].imm
                if op == 'jmp': self.lines.append(f'  br label %b{target:x}')
                else: self.lines.append(f'  br i1 {self.condition(op)}, label %b{target:x}, label %b{address + ins.size:x}')
                terminal = True
            elif op in ('ud2', 'int3', 'int'):
                self.lines.extend(['  call void @llvm.trap()', '  unreachable'])
                terminal = True
            elif op != 'nop':
                self.fail(ins, 'missing lowering')
            if not terminal and address in self.tail_calls:
                # A fall-through into another function is a tail call: the instruction was lowered
                # above, then the frame is repaired and control transfers to the callee.
                callee, slot = self.tail_calls[address]
                require(abi.uniform(callee), 'fall-through tail call requires a uniform callee')
                self.uniform_call(ins, callee, slot, self.repair_frame(state), True, result)
                terminal = True
            if terminal:
                # The lowering already emitted the terminator; a value written after the spill
                # belongs to the terminating edge, not to the successor blocks.
                self.values.clear()
                self.dirty.clear()
            elif address + ins.size in leaders:
                self.flush_registers()
                self.lines.append(f'  br label %b{address + ins.size:x}')
        self.prune_regfile_traffic()
        self.lines.append('}')
        return '\n'.join(self.lines)


_EXTERN = re.compile(r'^(@[A-Za-z_][A-Za-z_0-9]*) = (?:private )?(constant|global) (\[[^\]]*\])')


def extern_declaration(line):
    """Turn a module-global definition into the external declaration a chunk module needs."""
    match = _EXTERN.match(line)
    if match is None:
        return None
    align = re.search(r'align \d+$', line)
    return (f'{match.group(1)} = external {match.group(2)} {match.group(3)}'
            + (f', {align.group(0)}' if align else ''))


def _reason_histogram(stubs):
    counts = {}
    for _, reason in stubs:
        key = re.sub(r'0x[0-9a-f]+', '0xADDR', reason.split('\n', 1)[0])[:160]
        counts[key] = counts.get(key, 0) + 1
    return [{'reason': key, 'count': count} for key, count in sorted(counts.items(), key=lambda item: -item[1])[:20]]


def stub_function(spec, reason):
    """Native entry for a function the lifter rejected: report its guest address and trap.

    The image keeps every declared function so direct and dispatch calls still resolve; a rejected
    body becomes this stub, so a title run reports the first function the lifter cannot lower
    instead of failing the whole build.
    """
    result, parameters = signature(spec)
    name = spec['name']
    if abi.uniform(spec):
        head = f'define void @{name}(ptr %rf) uwtable {{'
    else:
        args = ', '.join(f'{abi.parameter_type(typ)} %arg{i}' for i, typ in enumerate(parameters))
        head = f'define {abi.result_type(result)} @{name}({args}) uwtable {{'
    return '\n'.join([head, 'entry:',
                      f'  call void @NativeAotReportUnimplemented_nid_no_patch(i64 {spec["address"]})',
                      '  call void @llvm.trap()', '  unreachable', '}'])


def compile_image(image, sink=None, emit_bodies=True, analyze=True):
    """Lower the whole image to LLVM IR.

    With `sink`, the preamble, each body and each stub are written out as they are produced and
    the IR is not returned; a title's module is far too large to assemble in memory. With
    `emit_bodies` false only the preamble (plus the shared tables and helper) is emitted, which a
    partitioned build links against one module of per-chunk bodies; `analyze` false also skips
    discovery and dataflow, which the preamble does not need.
    """
    # A whole-title build sets allow_unimplemented so a rejected body becomes a reporting trap
    # stub instead of failing the image; the SDK samples keep the strict default.
    tolerant = bool(image.contracts.get('allow_unimplemented'))
    registers.prepare(image)
    functions, stubs = [], []
    if analyze:
        for spec in image.functions.values():
            if spec.get('stub'):
                stubs.append((spec, 'declared stub'))
                continue
            if spec.get('external'):
                # A function the image declares but does not contain: the differential harness
                # supplies its native body (a recorded-call replay stub). Emit a declaration only.
                continue
            try:
                functions.append(Function(image, spec))
            except Rejected as error:
                if not tolerant:
                    raise
                stubs.append((spec, str(error)))
        def reject(function, error):
            stubs.append((function.contract, str(error)))
            function.rejected = True
        # effects.analyze calls analyze() in callee order, which the pointer/effect summaries need.
        effects.analyze(functions, reject=reject if tolerant else None)
        functions = [function for function in functions if not getattr(function, 'rejected', False)]
    try:
        descriptor = native_image.describe(image) if image.contracts.get('native_runtime_registration') else None
    except ValueError as error:
        raise Rejected(str(error)) from error
    lines = [f'target triple = "{image.target_spec["triple"]}"', 'declare void @llvm.trap()', 'declare i8 @llvm.ctpop.i8(i8)']
    for width in (16, 32, 64):
        lines.append(f'declare i{width} @llvm.ctpop.i{width}(i{width})')
        lines.append(f'declare i{width} @llvm.ctlz.i{width}(i{width}, i1)')
        lines.append(f'declare i{width} @llvm.cttz.i{width}(i{width}, i1)')
        lines.append(f'declare i{width} @llvm.bswap.i{width}(i{width})')
    # Rotates: rol/ror on the operand width, rcl/rcr on the carry-extended width + 1.
    for width in (8, 16, 32, 64, 9, 17, 33, 65):
        lines.append(f'declare i{width} @llvm.fshl.i{width}(i{width}, i{width}, i{width})')
        lines.append(f'declare i{width} @llvm.fshr.i{width}(i{width}, i{width}, i{width})')
    for lanes in (2, 4, 8):
        lines.append(f'declare <{lanes} x float> @llvm.fma.v{lanes}f32(<{lanes} x float>, <{lanes} x float>, <{lanes} x float>)')
    for lanes in (2, 4):
        lines.append(f'declare <{lanes} x double> @llvm.fma.v{lanes}f64(<{lanes} x double>, <{lanes} x double>, <{lanes} x double>)')
    lines.append('declare float @llvm.fma.f32(float, float, float)')
    lines.append('declare double @llvm.fma.f64(double, double, double)')
    lines.append('declare i64 @llvm.readcyclecounter()')
    lines.append('declare ptr @NativeAotTlsBase_nid_no_patch()')
    lines.append('declare double @llvm.fabs.f64(double)')
    lines.append('declare double @llvm.sqrt.f64(double)')
    # The x87 fprem lowering uses fmod; a title may also import it, so declare it once.
    if 'fmod' not in {contract['name'] for contract in image.imports.values()}:
        lines.append('declare double @fmod(double, double)')
    lines.extend(d for d in avx.INTRINSIC_DECLARATIONS + integer.INTRINSIC_DECLARATIONS if d not in lines)
    if any(abi.uniform(spec) for spec in image.functions.values()):
        lines.append('%%regfile = type { [16 x i64], [16 x i128], [16 x i128], [2 x i64], [8 x double], [1 x i64], [%d x i64] }' % abi.UNIFORM_STACK_SLOTS)
    dispatch_enabled = bool(image.contracts.get('dispatch'))
    # The dispatch table is keyed by host address: a relocated vtable entry already holds guest_base + target.
    dispatch_entries = sorted((image.guest_base + spec['address'], spec['name']) for spec in image.functions.values()) if dispatch_enabled else []
    if dispatch_enabled:
        table = ', '.join(f'{{ i64, ptr }} {{ i64 {address}, ptr @{name} }}' for address, name in dispatch_entries)
        lines.append(f'@__aps5_aot_dispatch = private constant [{len(dispatch_entries)} x {{ i64, ptr }}] [{table}], align 8')
        lines.append('declare ptr @NativeAotDispatch_nid_no_patch(i64)')
        lines.append('declare void @NativeAotReportDispatchFailure_nid_no_patch(i64, i64)')
        lines.append('declare void @NativeAotRegisterDispatch_nid_no_patch(ptr, i64)')
    if stubs:
        lines.append('declare void @NativeAotReportUnimplemented_nid_no_patch(i64)')
    process_parameters = image.contracts.get('title_process_parameters')
    if process_parameters:
        lines.append('declare void @NativeAotBindAllocator_nid_no_patch(ptr, i64, i64)')
        # The heap is initialised from main, not this constructor: the title's allocator init calls
        # runtime HLE whose namespace-scope containers are not constructed until after the ctors.
        lines.append('declare void @NativeAotSetProcessParameters_nid_no_patch(ptr)')
    if image.contracts.get('count_entries'):
        ordered = sorted(image.functions.values(), key=lambda spec: spec['address'])
        addresses = ', '.join(f'i64 {image.guest_base + spec["address"]}' for spec in ordered)
        lines.append(f'@__aps5_aot_counts = global [{len(ordered)} x i64] zeroinitializer, align 8')
        lines.append(f'@__aps5_aot_count_addresses = private constant [{len(ordered)} x i64] [{addresses}], align 8')
        lines.append('declare void @NativeAotRegisterEntryCounts_nid_no_patch(ptr, i64, ptr)')
        for index, spec in enumerate(ordered):
            spec['entry_index'] = index
    lines.extend(module_tls.declarations(image))
    if image.contracts.get('guard_diagnostics', False):
        lines.append('declare void @NativeAotReportGuardFailure_nid_no_patch(i64, i32)')
    if any(f.checked_pointer_loads or f.checked_pointer_arguments or f.checked_pointer_bases for f in functions):
        lines.append(f'declare zeroext i1 @{checked_pointers.SYMBOL}(ptr, i64, i1 zeroext)')
    names = {spec['name'] for spec in image.functions.values()}
    for spec in image.functions.values():
        if not spec.get('external'):
            continue
        require(abi.uniform(spec), 'external function requires the uniform register-file ABI')
        lines.append(f'declare void @{spec["name"]}(ptr)')
    for contract in image.imports.values():
        result, parameters = signature(contract)
        require(contract['name'] not in names, 'duplicate native name')
        names.add(contract['name'])
        argument_types = ', '.join(abi.parameter_type(t) for t in parameters)
        if contract.get('stub'):
            if result == 'void':
                lines.append(f"define void @{contract['name']}({argument_types}) {{ entry: ret void }}")
            elif result == 'ptr':
                lines.append(f"define ptr @{contract['name']}({argument_types}) {{ entry: ret ptr null }}")
            elif result in abi.FLOAT_TYPES:
                lines.append(f"define {abi.result_type(result)} @{contract['name']}({argument_types}) {{ entry: ret {abi.llvm_type(result)} 0.0 }}")
            else:
                lines.append(f"define {abi.result_type(result)} @{contract['name']}({argument_types}) {{ entry: ret i{abi.bits(result)} 0 }}")
        else:
            suffix = ' noreturn' if contract.get('noreturn') else ''
            lines.append(f"declare {abi.result_type(result)} @{contract['name']}({argument_types}){suffix}")
    for binding in image.data_imports.values():
        require(binding['name'] not in names, 'duplicate native data symbol')
        names.add(binding['name'])
        lines.append(f"@{binding['name']} = external global [{binding['size']} x i8]")
    if image.guest_data:
        require(not image.immutable_regions, 'guest data cannot also declare immutable regions')
        segments = ', '.join(f"{{ i64, i64, i64, i64, i64 }} {{ i64 {image.guest_base + spec['p_vaddr']}, i64 {spec['p_offset']}, i64 {spec['p_filesz']}, i64 {spec['p_memsz']}, i64 {spec['p_flags']} }}" for spec in image.segments)
        lines.append(f'@__aps5_aot_segments = private constant [{len(image.segments)} x {{ i64, i64, i64, i64, i64 }}] [{segments}], align 8')
        lines.append('declare void @NativeAotMapImage_nid_no_patch(ptr, i64)')
    for spec in image.data:
        if image.guest_data:
            continue
        if spec['address'] in image.immutable_initializers:
            lines.append(immutable_data.declaration(image, spec))
            continue
        raw = image.read(spec['address'], spec['size'])
        value = ''.join(f'\\{byte:02X}' for byte in raw)
        writable = image.segment(spec['address'])['p_flags'] & 2 or any(spec['address'] <= slot < spec['address'] + spec['size'] for slot in [*image.import_slots, *(slot for slot, _ in image.relocations)])
        lines.append(f"@{image.namespace}data_{spec['address']:x} = {'global' if writable else 'constant'} [{len(raw)} x i8] c\"{value}\", align 16")
    for name, binding in image.data_bindings.items():
        lines.append(f"@{binding['name']} = global [{binding['size']} x i8] zeroinitializer, align 16")
    if descriptor is not None:
        lines.extend(native_image.declarations(image, descriptor))
    if image.immutable_regions:
        lines.extend(immutable_data.declarations(image))
    unresolved_relocations = []
    # A whole-title image has hundreds of thousands of pointer slots; one store per slot makes
    # clang's initializer codegen pathologically slow and memory-hungry. Above a threshold the
    # slots go into a constant table the runtime applies in a loop instead.
    pointer_stores = []
    for slot, target in image.relocations:
        if slot in image.immutable_cells:
            continue
        try:
            value = image.pointer(target)
        except Rejected:
            # A pointer into the middle of a function (jump-table entries) has no native
            # function to name; leave the slot zero and report it instead of failing the image.
            unresolved_relocations.append(hex(target))
            continue
        pointer_stores.append((image.pointer(slot, 8), value))
    for slot, contract in image.import_slots.items():
        if slot not in image.immutable_cells:
            pointer_stores.append((image.pointer(slot, 8), f"@{contract['name']}"))
    for slot, binding in image.data_import_slots.items():
        if slot not in image.immutable_cells:
            pointer_stores.append((image.pointer(slot, 8), f"@{binding['name']}"))
    relocation_table = len(pointer_stores) > 1024
    if relocation_table:
        entries = ', '.join(f'{{ ptr, ptr }} {{ ptr {slot}, ptr {value} }}' for slot, value in pointer_stores)
        lines.append(f'@__aps5_aot_relocations = private constant [{len(pointer_stores)} x {{ ptr, ptr }}] [{entries}], align 8')
        lines.append('declare void @NativeAotApplyRelocations_nid_no_patch(ptr, i64)')
    if image.tls_layout or image.relocations or image.import_slots or image.data_import_slots or descriptor is not None or image.immutable_regions or dispatch_enabled:
        lines.extend(['@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }] [{ i32, ptr, ptr } { i32 101, ptr @native_image_init, ptr null }]',
                      'define internal void @native_image_init() {'])
        if image.guest_data:
            lines.append(f'  call void @NativeAotMapImage_nid_no_patch(ptr @__aps5_aot_segments, i64 {len(image.segments)})')
        if relocation_table:
            lines.append(f'  call void @NativeAotApplyRelocations_nid_no_patch(ptr @__aps5_aot_relocations, i64 {len(pointer_stores)})')
        else:
            for slot, value in pointer_stores:
                lines.append(f'  store ptr {value}, ptr {slot}, align 1')
        if dispatch_enabled:
            lines.append(f'  call void @NativeAotRegisterDispatch_nid_no_patch(ptr @__aps5_aot_dispatch, i64 {len(dispatch_entries)})')
        if image.contracts.get('count_entries'):
            lines.append(f'  call void @NativeAotRegisterEntryCounts_nid_no_patch(ptr @__aps5_aot_counts, i64 {len(image.functions)}, ptr @__aps5_aot_count_addresses)')
        if process_parameters:
            # Replace the title's allocator table entries with typed wrappers over its natively
            # compiled guest functions, then let the runtime heap read the mapped parameters.
            for binding in process_parameters['bindings']:
                lines.append(f'  call void @NativeAotBindAllocator_nid_no_patch(ptr inttoptr (i64 {binding["slot"]} to ptr), i64 {binding["target"]}, i64 {binding["index"]})')
            lines.append(f'  call void @NativeAotSetProcessParameters_nid_no_patch(ptr inttoptr (i64 {process_parameters["address"]} to ptr))')
        if image.tls_layout:
            lines.append(f"  call void @{module_tls.REGISTER}(ptr @{image.tls_layout['name']})")
        if image.immutable_regions:
            lines.append(f'  call void @NativeAotRequireReadOnly_nid_no_patch(ptr @__aps5_aot_readonly_ranges, i64 {len(image.immutable_regions)})')
        if descriptor is not None:
            lines.append('  call void @NativeAotRegisterImage_nid_no_patch(ptr @__aps5_aot_image)')
        lines.extend(['  ret void', '}'])
    for function in functions:
        function.entry_index = function.contract.get('entry_index')
    # A partitioned build reuses these: the header carries the declarations a chunk module needs,
    # and the extern list names the module globals it references from the preamble module.
    image.module_header = [line for line in lines if line.startswith(('target triple', 'declare ', '%regfile = type'))]
    image.module_externs = [extern for extern in (extern_declaration(line) for line in lines) if extern]
    bodies = []
    late_stubs = []
    if sink is not None:
        sink('\n\n'.join(lines))
    for function in (functions if emit_bodies else ()):
        try:
            body = function.lower()
        except Rejected as error:
            if not tolerant:
                raise
            # The stub is the body here; do not emit it a second time below.
            late_stubs.append((function.contract, str(error)))
            body = stub_function(function.contract, str(error))
        if sink is None:
            bodies.append(body)
        else:
            sink('\n\n' + body)
    if sink is None:
        lines.extend(bodies)
        lines.extend(stub_function(spec, reason) for spec, reason in stubs)
        lines.extend(finite_tables.module_declarations(image))
    else:
        for spec, reason in stubs:
            sink('\n\n' + stub_function(spec, reason))
        for declaration in finite_tables.module_declarations(image):
            sink('\n\n' + declaration)
        sink('\n')
    stubs.extend(late_stubs)
    if image.hle_log:
        lines.append('declare i64 @HleLogCall(ptr, i64, i64, i64, i64, i64, i64)')
        lines.append('declare void @HleLogReturn(i64, i64)')
        for hle_name, hle_index in image.hle_names.items():
            raw = hle_name.encode() + b'\0'
            encoded = ''.join(f'\\{byte:02X}' for byte in raw)
            lines.append(f'@__aps5_hle_name_{hle_index} = private constant [{len(raw)} x i8] c"{encoded}", align 1')
    report = {'schema': 1, 'target': image.target, 'status': 'experimental_native_ir', 'input_sha256': hashlib.sha256(image.bytes).hexdigest(),
              'functions': [{'name': f.contract['name'], 'address': f.contract['address'], 'instructions': len(f.instructions),
                             'native_tail_calls': len(f.tail_calls),
                             'bounded_loops': f.loop_proofs,
                             'checked_stack_accesses': list(f.checked_accesses.values()),
                             'checked_frame_exclusion': sorted(f.frame_exclusions),
                             'checked_pointer_loads': list(f.checked_pointer_loads.values()),
                             'checked_pointer_arguments': list(f.checked_pointer_arguments.values()),
                             'checked_pointer_bases': list(f.checked_pointer_bases.values()),
                             'memory_effects': effects.report(image.memory_effects.get(f.contract['address'])),
                             'native_frame_bytes_before_optimization': f.depth} for f in functions],
              'native_image': descriptor,
              'immutable_data': image.contracts.get('immutable_data', []),
              'required_provider_bindings': {image.functions[address]['name']: sorted(slots) for address, slots in image.provider_requirements.items() if slots},
              'inferred_pointer_outputs': {image.functions[address]['name']: sorted(fields) for address, fields in image.pointer_output_summaries.items() if fields},
              'provider_pointer_outputs': {name: contract['pointer_outputs'] for name, contract in image.imports.items() if 'pointer_outputs' in contract},
              'provider_effect_contracts': {name: contract['memory_effects'] for name, contract in image.imports.items() if 'memory_effects' in contract},
              'imports': len(image.import_slots), 'pointer_relocations': len(image.relocations),
              'unimplemented_functions': len(stubs),
              'unresolved_relocations': unresolved_relocations,
              'unimplemented_reasons': _reason_histogram(stubs),
              'tls': image.tls_layout, 'tls_indexes': sorted(image.tls_indexes),
              'module_lifecycle': image.module_lifecycle,
              'finite_tables': list(image.finite_tables.values()),
              'indirect_calls': [site for sites in image.call_contracts.values() for site in sites.values()],
              'limitations': ['declared function boundaries and ABIs', 'declared scalar, SSE and AVX instruction subsets', 'no guest exception or TLS recovery', 'computed jumps limited to immutable absolute relocation tables', 'other indirect call target sets remain declared with runtime membership checks',
                              'no game compatibility or performance qualification']}
    if sink is not None:
        return None, report
    return '\n\n'.join(lines) + '\n', report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('--contracts', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--object', type=Path)
    parser.add_argument('--stream', action='store_true',
                        help='write the IR to --output as it is produced instead of assembling it in memory')
    parser.add_argument('--target', choices=TARGETS, default='apple-arm64')
    args = parser.parse_args()
    try:
        image = Image(args.input, json.loads(args.contracts.read_text()), args.target)
        if args.stream:
            if args.object:
                parser.error('--stream cannot be combined with --object')
            with open(args.output, 'w') as output:
                _, report = compile_image(image, sink=output.write)
            args.output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')
            return
        ir, report = compile_image(image)
        if args.object:
            from toolchain import build_native_object
            report['native_object'] = build_native_object(ir, args.object, args.target)
    except (Rejected, KeyError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(2, f'Native AOT rejected: {error}\n')
    args.output.write_text(ir)
    args.output.with_suffix('.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()

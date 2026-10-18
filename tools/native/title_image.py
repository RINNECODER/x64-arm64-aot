#!/usr/bin/env python3
"""Compile a bounded, entry-reachable subset of a title eboot into one native image.

The contract set declares every function of the title. The functions reachable from the ELF entry
and the module initializer (following direct calls, the contracts' indirect-call target sets and
the annotated indirect jumps) are compiled natively; every other function becomes a reporting trap
stub, so a title run reports the first function the lifter cannot lower instead of failing the
build. Title-derived output stays in the lane work dir.

usage: title_image.py --elf eboot.elf --contracts title.contracts.json --output title.ll
       [--object title.o] [--limit N] [--stride N]
"""
import argparse
import json
import os
import sys
import time
from collections import deque

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "core" / "aot"))
from compiler import Image, compile_image, Rejected  # noqa: E402
from toolchain import build_native_object  # noqa: E402
import abi  # noqa: E402
import guest_layout  # noqa: E402


def default_guest_base():
    """The slide the native runtime will place the whole guest address space at.

    The launcher exports the same value as ANYPS5_GUEST_BASE; exporting it for the build too keeps
    the compiler's address translation and the HLE arena in step.
    """
    value = os.environ.get('ANYPS5_GUEST_BASE')
    return int(value, 0) if value else guest_layout.NATIVE_GUEST_BASE


def title_process_parameters(image):
    """The title's process-parameter block with its allocator table resolved to guest addresses.

    The SCE relative relocations that fill the libc parameters and the allocator replacement table
    are part of the pointer-relocation contract, so ``image.relocations`` resolves them here.
    """
    if not image.process_parameters:
        return None
    address, size = image.process_parameters[0]
    relocations = dict(image.relocations)

    libc = relocations.get(address + 0x38, 0)
    if not libc:
        return None
    replacement = relocations.get(libc + 0x30, 0)
    if not replacement:
        return None
    heap_api = replacement + 0x20
    bindings = []
    # 0..9: the heap API. 10/11: the table's initialize/finalize callbacks.
    for index in range(10):
        target = relocations.get(heap_api + index * 8, 0)
        if target:
            bindings.append({'slot': image.guest_base + heap_api + index * 8,
                             'target': image.guest_base + target, 'index': index})
    for index, offset in ((10, 0x10), (11, 0x18)):
        target = relocations.get(replacement + offset, 0)
        if target:
            bindings.append({'slot': image.guest_base + replacement + offset,
                             'target': image.guest_base + target, 'index': index})
    return {'address': image.guest_base + address, 'bytes': size, 'bindings': bindings}


def reachable(image, entry_addresses, limit, exclude=()):
    starts = {spec['address']: spec for spec in image.functions.values()}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    seen, order, frontier = set(exclude), [], set()
    pending = deque(address for address in entry_addresses if address in starts and address not in seen)
    seen.update(pending)
    while pending and len(order) < limit:
        address = pending.popleft()
        spec = starts[address]
        order.append(address)
        targets = set()
        for insn in decoder.disasm(image.read(address, spec['size']), address):
            if insn.mnemonic in ('call', 'jmp') and insn.operands and insn.operands[0].type == X86_OP_IMM:
                targets.add(insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF)
        for record in spec.get('indirect_calls', []) + spec.get('indirect_jumps', []):
            targets.update(record.get('targets', []))
        for target in sorted(targets):
            if target in starts and target not in seen:
                seen.add(target)
                pending.append(target)
    native = set(order)
    # Only the callees of the native subset need a stub; the rest of the eboot is out of reach for
    # this prototype, and keeping 277k stubs would make the IR (and clang) unusable.
    for address in order:
        spec = starts[address]
        targets = set()
        for insn in decoder.disasm(image.read(address, spec['size']), address):
            if insn.mnemonic in ('call', 'jmp') and insn.operands and insn.operands[0].type == X86_OP_IMM:
                targets.add(insn.operands[0].imm & 0xFFFFFFFFFFFFFFFF)
        for record in spec.get('indirect_calls', []) + spec.get('indirect_jumps', []):
            targets.update(record.get('targets', []))
        frontier |= (targets - native) & set(starts)
    return order, frontier


def relocation_table(cells, functions, slot):
    """The contiguous run of pointer relocation cells around a slot, when every cell names a
    declared function. A register loaded from the slot is one entry of that run."""
    if slot not in cells:
        return []
    run = set()
    cursor = slot
    while cursor in cells:
        run.add(cells[cursor])
        cursor -= 8
    cursor = slot + 8
    while cursor in cells:
        run.add(cells[cursor])
        cursor += 8
    if not run or len(run) > 65536 or not all(target in functions for target in run):
        return []
    return sorted(run)


def recover_pointer_slot_calls(image, native):
    """Declare the target set of every register-form indirect call whose operand register was
    loaded from a pointer relocation slot.

    A lifecycle loop (or any dispatch loop) loads a function pointer out of a relocation table
    into a register and calls the register, so recovery records the site with no target set and the
    bounded image leaves the slot holding a raw guest address. Resolving the loaded slot to its
    contiguous relocation run gives the call its closed-world target set. Returns every target the
    recovered sets name, so the caller can keep them in the image as reporting stubs.
    """
    cells = dict(image.relocations)
    functions = image.functions
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    added = set()
    for address in native:
        spec = functions.get(address)
        if spec is None:
            continue
        records = spec.setdefault('indirect_calls', [])
        known_sites = {record['address'] for record in records}
        known = {}
        for insn in decoder.disasm(image.read(address, spec['size']), address):
            operands = insn.operands
            if insn.mnemonic in ('call', 'jmp'):
                if len(operands) == 1 and operands[0].type == X86_OP_REG:
                    state = known.get(insn.reg_name(operands[0].reg))
                    if state is not None and state[0] == 'load' and insn.address not in known_sites:
                        targets = relocation_table(cells, functions, state[1])
                        if targets:
                            records.append({'address': insn.address, 'targets': targets})
                            known_sites.add(insn.address)
                            added.update(targets)
                if insn.mnemonic == 'call':
                    # A call clobbers the caller-saved registers; keep the callee-saved base.
                    for volatile in ('rax', 'rcx', 'rdx', 'rsi', 'rdi') + tuple(f'r{i}' for i in range(8, 12)):
                        known.pop(volatile, None)
                continue
            if not operands:
                continue
            destination = operands[0] if operands[0].access & CS_AC_WRITE else None
            if destination is None or destination.type != X86_OP_REG:
                continue
            name = insn.reg_name(destination.reg)
            previous = known.pop(name, None)
            if insn.mnemonic == 'lea' and len(operands) == 2 and operands[1].type == X86_OP_MEM:
                mem = operands[1].mem
                if insn.reg_name(mem.base) == 'rip' and not mem.index and not mem.segment:
                    known[name] = ('base', insn.address + insn.size + mem.disp)
            elif insn.mnemonic == 'mov' and len(operands) == 2 and operands[1].type == X86_OP_MEM:
                mem = operands[1].mem
                base = known.get(insn.reg_name(mem.base)) if mem.base else None
                if base is not None and base[0] == 'base' and not mem.index and not mem.segment:
                    known[name] = ('load', base[1] + mem.disp)
            elif insn.mnemonic in ('add', 'sub') and len(operands) == 2 and operands[1].type == X86_OP_IMM:
                if previous is not None and previous[0] == 'base':
                    delta = operands[1].imm if insn.mnemonic == 'add' else -operands[1].imm
                    known[name] = ('base', previous[1] + delta)
    return added


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--elf', required=True)
    parser.add_argument('--contracts', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--object')
    parser.add_argument('--limit', type=int, default=600)
    parser.add_argument('--entries', default='entry,init')
    parser.add_argument('--nid-symbols', help='file of runtime symbol names (one per line, underscore stripped)')
    parser.add_argument('--guest-base', type=lambda value: int(value, 0), default=default_guest_base(),
                        help='slide added to every guest vaddr; the native arm64 placement above the macOS hole by default')
    parser.add_argument('--hle-log', action='store_true',
                        help='log every import call and its return through HleLogCall/HleLogReturn')
    parser.add_argument('--abi', help='ABI annotations the contracts were generated from; a stale '
                                      'contracts/ABI pair is rejected instead of stubbing a verified import')
    args = parser.parse_args()
    contracts = json.loads(open(args.contracts).read())
    if args.abi:
        abi.validate_import_annotations(contracts, json.loads(open(args.abi).read()))
    # The slide must be set before the first Image so the process-parameter bindings carry it.
    contracts['guest_base'] = args.guest_base
    image = Image(args.elf, contracts)
    entries = []
    if 'entry' in args.entries:
        entries.append(image.elf['e_entry'])
    if 'init' in args.entries:
        init = image.contracts.get('lifecycle', {}).get('init')
        if init:
            entries.append(init)
    process_parameters = title_process_parameters(image)
    if process_parameters:
        # The allocator callbacks are reachable only from data, so they are explicit entry roots;
        # the walk then compiles their callees instead of leaving dispatch misses behind them.
        entries += [binding['target'] - image.guest_base for binding in process_parameters['bindings']]
    start = time.time()
    lifecycle = contracts.get('lifecycle', {})
    # DT_INIT/DT_FINI are init-array loops; their body can run past the next declared start (a
    # spurious interior label), which makes the compiler reject them for escaping the contract.
    # Extend each lifecycle contract to its decoded body and drop the interior starts it covers,
    # before the walk, so the recovery pass and the closure see the whole loop.
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    for address in sorted({lifecycle.get('init'), lifecycle.get('fini')} - {None}):
        spec = next((item for item in contracts['functions'] if item['address'] == address), None)
        if spec is None:
            continue
        end = address
        for insn in decoder.disasm(image.read(address, min(0x400, 0x44AC1CC - address)), address):
            end = insn.address + insn.size
            if insn.mnemonic in ('ret', 'ud2', 'int3'):
                break
        if end <= address + spec['size']:
            continue
        spec['size'] = end - address
        dropped = [item['address'] for item in contracts['functions']
                   if item is not spec and address < item['address'] < end]
        contracts['functions'] = [item for item in contracts['functions'] if item['address'] not in dropped]
        for item in dropped:
            image.functions.pop(item, None)
        print('extended lifecycle 0x%x to 0x%x, dropped %s' % (address, end, [hex(a) for a in dropped]), flush=True)
    # The walk follows direct calls and the target sets recovery declared. A register-form indirect
    # call whose operand came from a pointer relocation slot has no declared set; recover it and keep
    # the run of named functions in the image as reporting stubs, so the call resolves to a named
    # trap instead of a dispatch miss (the bounded walk itself does not widen).
    order, frontier = reachable(image, entries, args.limit)
    native = set(order) | ({lifecycle.get('init'), lifecycle.get('fini')} - {None})
    # Follow the pointer-slot call targets with the remaining budget, after the direct closure, so
    # a bounded limit keeps the entry/heap-init subtree native instead of letting the recovered run
    # enqueue ahead of it. Targets past the budget stay reporting stubs.
    while len(order) < args.limit:
        recovered = recover_pointer_slot_calls(image, native) - native
        if not recovered:
            break
        extra, extra_frontier = reachable(image, sorted(recovered), args.limit - len(order), exclude=native)
        if not extra:
            break
        order += extra
        frontier |= extra_frontier
        native |= set(extra)
    keep = native | frontier
    contracts['functions'] = [spec for spec in image.functions.values() if spec['address'] in keep]
    for spec in contracts['functions']:
        if spec['address'] in native:
            spec.pop('stub', None)
        else:
            spec['stub'] = True
    contracts['allow_unimplemented'] = True
    contracts['guest_data'] = True
    contracts['count_entries'] = True
    contracts['hle_log'] = args.hle_log
    if process_parameters:
        contracts['title_process_parameters'] = process_parameters
    # HLE NID binding: point a typed import at the runtime's <name>_nid_postfix symbol when
    # that exists (the arm64 libs define every guest entry point with that suffix).
    if args.nid_symbols:
        known = set(open(args.nid_symbols).read().split())
        for contract in contracts['imports'].values():
            if contract['name'] + '_nid_postfix' in known:
                contract['name'] = contract['name'] + '_nid_postfix'
            elif contract['name'] not in known:
                # A guest import the runtime does not define must not be emitted under a name the
                # host C library defines: a global stub would interpose over libSystem for the whole
                # process. Namespace it so the stub generator can trampoline it to the host function.
                contract['name'] = '__aps5_guest_' + contract['name']
    image = Image(args.elf, contracts)
    print('native %d stub %d entries %s native_has %s (%.1fs)' % (len(order), len(frontier), [hex(e) for e in entries], [hex(a) in [hex(x) for x in native] for a in entries], time.time() - start), flush=True)
    start = time.time()
    ir, report = compile_image(image)
    open(args.output, 'w').write(ir)
    print(f'ir {len(ir) / 1e6:.1f} MB in {time.time() - start:.1f}s; '
          f'unimplemented {report["unimplemented_functions"]}', flush=True)
    if report['unimplemented_reasons']:
        print('top reasons:', json.dumps(report['unimplemented_reasons'][:5]), flush=True)
    if args.object:
        # The prototype keeps the machine-state allocas the strict SDK-sample guard rejects.
        report['native_object'] = build_native_object(ir, args.object, strict=False)
        print('object', report['native_object'], flush=True)
    open(args.output + '.json', 'w').write(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()

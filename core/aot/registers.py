"""Per-function register summaries for the uniform register-file ABI.

Every uniform function loads the whole guest register file from its `%rf` argument, so a caller
that stores only the registers the callee may read is correct, and a caller that reads back only
the registers the callee may write is correct, provided the summary is a conservative
over-approximation. The summary is computed structurally from the function's own instructions
(capstone's register access) unioned over every uniform callee it can call, so a register a
nested callee reads is copied even when the function itself never touches it.

Two masks per function:

* ``store`` - the slots the caller must put into the outgoing register file. It is the union of
  the function's own reads and writes plus every callee's store set, so a slot that is only
  written on some path (or written partially, which reads the entry value) still has a defined
  value at the callee. A caller never skips a register unless the whole reachable set proves it
  unused.
* ``load`` - the slots the caller must read back after the call: the function's own writes plus
  every callee's load set.

An indirect call site unions the summary over its declared target set; a site with no declared
target set (the runtime dispatch fallback) is full.
"""
from collections import deque

from capstone.x86 import X86_OP_IMM, X86_OP_MEM

import abi

GPRS = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'] + [f'r{i}' for i in range(8, 16)]
VECTORS = [f'xmm{i}' for i in range(16)]
UPPER = [f'ymm_hi{i}' for i in range(16)]
SLOTS = GPRS + VECTORS + UPPER
INDEX = {name: index for index, name in enumerate(SLOTS)}
FULL = (1 << len(SLOTS)) - 1
# The registers a SysV import call may read: the integer and vector argument registers plus al
# (a variadic call publishes the vector count there), and the registers it may write back.
IMPORT_READS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9') + tuple(f'xmm{i}' for i in range(8)) + ('rax',)
IMPORT_WRITES = ('rax', 'xmm0')
IMPORT_READ_MASK = sum(1 << INDEX[name] for name in IMPORT_READS)
IMPORT_WRITE_MASK = sum(1 << INDEX[name] for name in IMPORT_WRITES)

_ALIASES = {}
for _full, _dword, _word, _low in zip(GPRS[:8], ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'),
                                      ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'),
                                      ('al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil')):
    for _name in (_full, _dword, _word, _low):
        _ALIASES[_name] = _full
for _index, _name in enumerate(('ah', 'ch', 'dh', 'bh')):
    _ALIASES[_name] = GPRS[_index]
for _full in GPRS[8:]:
    for _suffix in ('', 'd', 'w', 'b'):
        _ALIASES[_full + _suffix] = _full


def slot_mask(name):
    """The mask of storage slots a capstone register name names (a ymm names its xmm and upper)."""
    if name in _ALIASES:
        return 1 << INDEX[_ALIASES[name]]
    if name.startswith('xmm') and name[3:].isdigit() and 0 <= int(name[3:]) < 16:
        return 1 << INDEX[name]
    if name.startswith('ymm') and name[3:].isdigit() and 0 <= int(name[3:]) < 16:
        return (1 << INDEX[name.replace('ymm', 'xmm')]) | (1 << INDEX['ymm_hi' + name[3:]])
    return 0


def names(mask):
    """The storage-slot names a mask selects."""
    return {name for index, name in enumerate(SLOTS) if mask >> index & 1}


def _import_effects(contract, reads, writes):
    """The registers a call to a non-uniform callee reads (arguments) and writes (result)."""
    result, parameters = abi.signature(contract)
    for location in abi.locations(parameters):
        if location['kind'] == 'register':
            reads |= 1 << INDEX[location['name']]
    register = abi.return_register(result)
    if register is not None:
        writes |= 1 << INDEX[register]
    return reads, writes


def _record_targets(image, record):
    """The declared target addresses of an indirect call/jump, or None when the contract has no
    annotation (the runtime dispatch fallback, which stays full)."""
    if record is None:
        return None
    targets = record.get('targets')
    if targets is None and 'target_set' in record:
        index = record['target_set']
        pool = image.contracts.get('target_sets')
        if not isinstance(pool, list) or not isinstance(index, int) or not 0 <= index < len(pool):
            return None
        targets = pool[index]
    if not isinstance(targets, list) or not targets:
        return None
    return targets


def _group_key(record):
    """A key that shares one group between every site naming the same target set.

    A pool target set is referenced by thousands of sites and can hold tens of thousands of
    addresses; keying on the shared list object (or the pool index) means the union is computed
    once instead of once per site.
    """
    if record.get('targets') is not None:
        return ('i', id(record['targets']))
    return ('p', record.get('target_set'))


def structural(image, spec):
    """(store, load, direct callees, indirect groups) for one function, before the fixed point.

    Decodes the function's whole FDE range linearly. Any instruction capstone cannot classify as
    a resolved uniform call is treated conservatively: a direct call outside the function table
    is an import (its argument and result registers), an indirect site without a declared target
    set is full. `indirect groups` is one (group key, target list) per annotated indirect site;
    the key shares a group between sites naming the same target set.
    """
    start, size = spec['address'], spec.get('size') or 0
    if size <= 0:
        return FULL, FULL, set(), []
    try:
        code = image.read(start, size)
    except Exception:
        return FULL, FULL, set(), []
    reads = writes = 0
    callees = set()
    groups = []
    sites = {}
    for record in spec.get('indirect_calls') or ():
        if isinstance(record, dict):
            sites.setdefault((record.get('address'), 'call'), record)
    for record in spec.get('indirect_jumps') or ():
        if isinstance(record, dict):
            sites.setdefault((record.get('address'), 'jmp'), record)
    for ins in image.decoder.disasm(code, start):
        if ins.mnemonic == 'vzeroupper':
            # The lowering zeroes only the ymm upper halves; capstone reports all sixteen ymm as
            # written, which would also mark every xmm lane and blow up the store set.
            writes |= sum(1 << INDEX[f'ymm_hi{index}'] for index in range(16))
            continue
        for register in ins.regs_access()[0]:
            reads |= slot_mask(ins.reg_name(register))
        for register in ins.regs_access()[1]:
            writes |= slot_mask(ins.reg_name(register))
        if ins.mnemonic not in ('call', 'jmp') or not ins.operands:
            continue
        operand = ins.operands[0]
        direct = None
        if operand.type == X86_OP_IMM:
            direct = operand.imm  # capstone resolves a relative branch to its absolute target
            if ins.mnemonic == 'jmp' and start <= direct < start + size:
                continue  # a local branch, not a tail call
        elif operand.type == X86_OP_MEM and ins.reg_name(operand.mem.base) == 'rip' and not operand.mem.index:
            direct = ins.address + ins.size + operand.mem.disp  # a GOT/PLT import slot
        if direct is None:
            record = sites.get((ins.address, 'call' if ins.mnemonic == 'call' else 'jmp'))
            targets = _record_targets(image, record)
            if targets is None:
                return FULL, FULL, set(), []
            groups.append((_group_key(record), targets))
            continue
        contract = image.functions.get(direct)
        if contract is not None and abi.uniform(contract):
            callees.add(direct)
        elif contract is not None:
            reads, writes = _import_effects(contract, reads, writes)
        else:
            reads |= IMPORT_READ_MASK
            writes |= IMPORT_WRITE_MASK
    return reads | writes, writes, callees, groups


def _absorb(address, grew_store, grew_load, store, load, pending, queued):
    if store[address] | grew_store != store[address] or load[address] | grew_load != load[address]:
        store[address] |= grew_store
        load[address] |= grew_load
        if address not in queued:
            pending.append(address)
            queued.add(address)


def prepare(image):
    """Compute every function's (store, load) mask and cache them on the image.

    store(F) = own reads and writes unioned with every uniform callee's store; load(F) = own
    writes unioned with every callee's load. A worklist propagates a callee's growth to its
    callers, so recursion converges without a topological order.

    Indirect sites depend on a whole target set at once. The sets are shared dispatch tables
    with up to millions of entries, so the union over each set is a single graph node (a
    "group") instead of one edge per target; a target's growth reaches a group's dependents
    through two hops. Without the grouping the caller graph holds hundreds of millions of
    edges and does not fit in memory.
    """
    if getattr(image, 'register_summaries_ready', False):
        return image.register_summaries
    store, load = {}, {}
    direct_callers = {}
    dependents = {}
    group_targets = []
    group_keys = {}
    group_pool = {}
    for address, spec in image.functions.items():
        reads, writes, direct, groups = structural(image, spec)
        store[address], load[address] = reads, writes
        for target in direct:
            direct_callers.setdefault(target, set()).add(address)
        for key, targets in groups:
            gid = group_keys.get(key)
            if gid is None:
                gid = len(group_targets)
                group_keys[key] = gid
                group_targets.append(targets)
                if key[0] == 'p':
                    group_pool[key[1]] = gid
            dependents.setdefault(gid, set()).add(address)
    target_groups = {}
    for gid, targets in enumerate(group_targets):
        for target in targets:
            target_groups.setdefault(target, set()).add(gid)
    group_store = [0] * len(group_targets)
    group_load = [0] * len(group_targets)
    for gid, targets in enumerate(group_targets):
        grew_store = grew_load = 0
        for target in targets:
            current = store.get(target)
            if current is None:
                # Not a uniform function in this image: the call reads the argument registers
                # and writes the result registers, exactly as a direct import call does.
                grew_store |= IMPORT_READ_MASK | IMPORT_WRITE_MASK
                grew_load |= IMPORT_WRITE_MASK
            else:
                grew_store |= current
                grew_load |= load[target]
        group_store[gid], group_load[gid] = grew_store, grew_load
    pending = deque()
    queued = set()
    for address in image.functions:
        pending.append(address)
        queued.add(address)
    for gid in range(len(group_targets)):
        pending.append(-(gid + 1))
        queued.add(-(gid + 1))
    while pending:
        item = pending.popleft()
        queued.discard(item)
        if item >= 0:
            address = item
            grew_store, grew_load = store[address], load[address]
            for caller in direct_callers.get(address, ()):
                _absorb(caller, grew_store, grew_load, store, load, pending, queued)
            for gid in target_groups.get(address, ()):
                if (group_store[gid] | grew_store != group_store[gid]
                        or group_load[gid] | grew_load != group_load[gid]):
                    group_store[gid] |= grew_store
                    group_load[gid] |= grew_load
                    if -(gid + 1) not in queued:
                        pending.append(-(gid + 1))
                        queued.add(-(gid + 1))
        else:
            gid = -item - 1
            grew_store, grew_load = group_store[gid], group_load[gid]
            for caller in dependents.get(gid, ()):
                _absorb(caller, grew_store, grew_load, store, load, pending, queued)
    image.register_summaries = {address: (store[address], load[address]) for address in image.functions}
    image.register_pool_masks = {index: (group_store[gid], group_load[gid])
                                 for index, gid in group_pool.items()}
    image.register_summaries_ready = True
    return image.register_summaries


def summary(image, address):
    return image.register_summaries.get(address, (FULL, FULL))


def pool_mask(image, index):
    """The (store, load) union of a shared pool target set, or None when it was never seen."""
    return image.register_pool_masks.get(index)

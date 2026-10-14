from capstone.x86 import X86_OP_MEM, X86_OP_REG

import hashlib

from calls import structural_signature


def require(condition, message):
    if not condition:
        raise ValueError(message)


def discover(image):
    cells = dict(image.relocations)
    require(len(cells) == len(image.relocations), 'duplicate finite-table relocation')
    records = image.contracts.get('immutable_data', [])
    if not isinstance(records, list) or not all(isinstance(r, dict) and type(r.get('address')) is int for r in records):
        return {}, {}
    regions = {record['address'] for record in records}
    if not regions:
        # No immutable-data region means no finite table can be qualified, so skip the whole-image
        # disassembly scan (it dominated Image construction on a title with none).
        return {}, {}
    result, labels = {}, {}
    for owner in image.functions.values():
        bases = {}
        end = owner['address'] + owner['size']
        instructions = list(image.decoder.disasm(image.read(owner['address'], owner['size']), owner['address']))
        for ins in instructions:
            args = ins.operands
            if ins.mnemonic in ('call', 'jmp') and len(args) == 1 and args[0].type == X86_OP_MEM:
                operand, mem = args[0], args[0].mem
                base = ins.reg_name(mem.base)
                if base in bases and operand.size == 8 and ins.addr_size == 8 and not mem.segment and mem.scale == 8:
                    table = bases[base] + mem.disp
                    spec = next((spec for spec in image.data if spec['address'] in regions
                                 and spec['address'] <= table < spec['address'] + spec['size']), None)
                    if spec is not None and table % 8 == 0 and table in cells:
                        targets = []
                        cursor = table
                        while cursor in cells and cursor + 8 <= spec['address'] + spec['size']:
                            require(len(targets) < 256, 'finite table exceeds bounded target limit')
                            targets.append(cells[cursor])
                            cursor += 8
                        descriptor = {'address': ins.address, 'table': table, 'size': cursor - table,
                                      'targets': targets, 'kind': ins.mnemonic,
                                      'qualification': 'immutable-relative-relocations-with-runtime-bounds-and-membership'}
                        if ins.mnemonic == 'call':
                            require(all(target in image.functions for target in targets), 'finite call table requires internal function entries')
                            contracts = [image.functions[target] for target in targets]
                            require(all(structural_signature(c) == structural_signature(contracts[0]) for c in contracts),
                                    'finite call table has incompatible target ABIs')
                            descriptor['contract'] = {key: contracts[0][key] for key in
                                ('result', 'parameters', 'guest_calling_convention', 'guest_locations', 'guest_return_register')
                                if key in contracts[0]}
                            descriptor['contract']['name'] = f'finite_{ins.address:x}'
                            if all(c.get('noreturn') for c in contracts):
                                descriptor['contract']['noreturn'] = True
                        else:
                            require(all(owner['address'] < target < end for target in targets), 'finite jump target escapes owner')
                            for target in targets:
                                require(target not in labels or labels[target] == owner['name'], 'ambiguous native jump label')
                                labels[target] = owner['name']
                        result[ins.address] = descriptor
            _, written = ins.regs_access()
            for reg in written:
                name = ins.reg_name(reg)
                for root in list(bases):
                    aliases = {root, root + 'd', root + 'w', root + 'b'}
                    if root in ('rax', 'rbx', 'rcx', 'rdx'):
                        aliases.update({'e' + root[1:], root[1:], root[1] + 'l', root[1] + 'h'})
                    elif root in ('rsi', 'rdi', 'rbp', 'rsp'):
                        aliases.update({'e' + root[1:], root[1:], root[1:] + 'l'})
                    if name in aliases:
                        bases.pop(root)
            if ins.mnemonic == 'lea' and len(args) == 2 and args[0].type == X86_OP_REG and args[0].size == 8:
                mem = args[1].mem
                if ins.reg_name(mem.base) == 'rip' and not mem.index and not mem.segment:
                    bases[ins.reg_name(args[0].reg)] = ins.address + ins.size + mem.disp
            if ins.mnemonic.startswith('j') or ins.mnemonic in ('call', 'ret', 'ud2'):
                bases.clear()
    return result, labels


def emit_target(function, ins, descriptor):
    address = function.effective_integer(ins, ins.operands[0])
    base = function.emit(f'ptrtoint ptr {function.image.pointer(descriptor["table"], descriptor["size"])} to i64')
    relative = function.emit(f'sub i64 {address}, {base}')
    bounded = function.emit(f'icmp ule i64 {relative}, {descriptor["size"] - 8}')
    residue = function.emit(f'and i64 {relative}, 7')
    aligned = function.emit(f'icmp eq i64 {residue}, 0')
    valid = function.emit(f'and i1 {bounded}, {aligned}')
    continuation = f'table_read_{ins.address:x}'
    invalid = f'table_invalid_{ins.address:x}'
    function.lines.extend([f'  br i1 {valid}, label %{continuation}, label %{invalid}', invalid + ':',
                           '  call void @llvm.trap()', '  unreachable', continuation + ':'])
    pointer = function.emit(f'inttoptr i64 {address} to ptr')
    return function.emit(f'load ptr, ptr {pointer}, align 1')


MEMBER = '__aps5_aot_target_member'
MEMBER_HELPER = f'''define internal i1 @{MEMBER}(ptr %table, i64 %count, ptr %target) {{\nentry:\n  br label %loop\nloop:\n  %index = phi i64 [ 0, %entry ], [ %next, %body ]\n  %end = icmp uge i64 %index, %count\n  br i1 %end, label %missing, label %body\nbody:\n  %slot = getelementptr inbounds ptr, ptr %table, i64 %index\n  %candidate = load ptr, ptr %slot, align 8\n  %hit = icmp eq ptr %candidate, %target\n  %next = add i64 %index, 1\n  br i1 %hit, label %found, label %loop\nfound:\n  ret i1 true\nmissing:\n  ret i1 false\n}}'''


def target_table(image, pointers):
    """Name of the shared constant table for `pointers`, registering it on first use.

    Sites share their declared target sets, so one table per distinct set replaces a
    per-site chain of compares; membership is order-independent and duplicates are dropped.
    The name is content-addressed so a function's IR does not depend on the order in which
    other functions registered their tables.
    """
    key = tuple(dict.fromkeys(pointers))
    tables = getattr(image, 'target_tables', None)
    if tables is None:
        tables = image.target_tables = {}
    name = '__aps5_aot_targets_' + hashlib.sha256('\x00'.join(key).encode()).hexdigest()[:16]
    if name not in tables:
        tables[name] = key
    return name


def emit_membership(function, ins, target, pointers):
    names = list(dict.fromkeys(pointers))
    table = target_table(function.image, names)
    allowed = function.emit(f'call i1 @{MEMBER}(ptr @{table}, i64 {len(names)}, ptr {target})')
    continuation, invalid = f'target_valid_{ins.address:x}', f'target_invalid_{ins.address:x}'
    function.lines.extend([f'  br i1 {allowed}, label %{continuation}, label %{invalid}', invalid + ':',
                           '  call void @llvm.trap()', '  unreachable', continuation + ':'])


def module_declarations(image):
    """Constant target tables and the membership helper the lowered bodies call."""
    tables = getattr(image, 'target_tables', None)
    if not tables:
        return []
    lines = [f'@{name} = private constant [{len(pointers)} x ptr] '
             f'[{ ", ".join("ptr " + pointer for pointer in pointers)}], align 8'
             for name, pointers in sorted(tables.items())]
    lines.append(MEMBER_HELPER)
    return lines

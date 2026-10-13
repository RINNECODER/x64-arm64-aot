from capstone.x86 import X86_OP_IMM, X86_OP_REG


def written_registers(ins, aliases):
    return {aliases[name][0] for register in ins.regs_access()[1] if (name := ins.reg_name(register)) in aliases}


def initial_value(function, address, register, predecessors, members, aliases, volatile):
    visited = set(members)
    while address not in visited:
        visited.add(address)
        ins = function.instructions[address]
        if ins.mnemonic == 'call' and register in volatile:
            return None
        if register in written_registers(ins, aliases):
            args = ins.operands
            if len(args) != 2 or args[0].type != X86_OP_REG or args[0].size not in (4, 8) or function.reg(ins, args[0])[0] != register:
                return None
            if ins.mnemonic in ('mov', 'movabs') and args[1].type == X86_OP_IMM:
                return args[1].imm & ((1 << (args[0].size * 8)) - 1)
            if ins.mnemonic == 'xor' and args[1].type == X86_OP_REG and args[0].reg == args[1].reg:
                return 0
            return None
        incoming = predecessors[address]
        if len(incoming) != 1:
            return None
        address = next(iter(incoming))
    return None


def discover(function, aliases, volatile):
    predecessors = {address: set() for address in function.instructions}
    for address, successors in function.successors.items():
        for successor in successors:
            predecessors[successor].add(address)
    ranges, proofs = {}, []
    for latch, branch in sorted(function.instructions.items()):
        if branch.mnemonic != 'jmp' or latch in function.tail_calls or branch.operands[0].type != X86_OP_IMM:
            continue
        header = branch.operands[0].imm
        if header >= latch or header not in function.instructions:
            continue
        path, guard, address, visited = [], None, header, set()
        while address not in visited:
            visited.add(address)
            ins = function.instructions[address]
            if address == latch:
                path.append(address)
                break
            successors = function.successors[address]
            if ins.mnemonic == 'je' and guard is None and path and function.instructions[path[-1]].mnemonic == 'cmp':
                guard = (address, path[-1], ins.operands[0].imm)
            elif len(successors) != 1 or ins.mnemonic in ('call', 'jmp'):
                break
            if address + ins.size not in successors:
                break
            path.append(address)
            address += ins.size
        if not path or path[-1] != latch or guard is None:
            continue
        members = set(path)
        if function.contract['address'] in members or guard[2] in members:
            continue
        external = predecessors[header] - members
        if len(external) != 1 or any(predecessors[node] - members for node in path[1:]):
            continue
        compare = function.instructions[guard[1]]
        args = compare.operands
        if len(args) != 2 or args[0].type != X86_OP_REG or args[0].size != 8 or args[1].type != X86_OP_IMM:
            continue
        register = function.reg(compare, args[0])[0]
        if register in ('rsp', 'rbp'):
            continue
        writes = [node for node in path if register in written_registers(function.instructions[node], aliases)]
        if len(writes) != 1 or path.index(writes[0]) <= path.index(guard[0]):
            continue
        increment = function.instructions[writes[0]]
        operands = increment.operands
        if increment.mnemonic != 'add' or len(operands) != 2 or operands[0].type != X86_OP_REG or operands[0].size != 8 or operands[1].type != X86_OP_IMM:
            continue
        step, limit = operands[1].imm, args[1].imm
        start = initial_value(function, next(iter(external)), register, predecessors, members, aliases, volatile)
        if start is None or step <= 0 or not 0 <= start <= limit < 1 << 64 or (limit - start) % step:
            continue
        for node in path:
            ranges.setdefault(node, {})[register] = (start, limit)
        proofs.append({'header': header, 'latch': latch, 'register': register, 'minimum': start, 'maximum': limit, 'step': step})
    return ranges, proofs


def frame_write(function, ins, state, operand):
    memory = operand.mem
    if ins.addr_size != 8 or memory.segment:
        return None
    index, base = ins.reg_name(memory.index), ins.reg_name(memory.base)
    bounds = function.index_ranges.get(ins.address, {}).get(index)
    if bounds is None:
        return None
    displacement = state[base] if base in ('rsp', 'rbp') else None
    if displacement is None:
        pointer = state['pointers'].get(base)
        if pointer is None or pointer[0] != 'frame':
            return None
        displacement = pointer[2]
    begin = displacement + memory.disp + bounds[0] * memory.scale
    end = displacement + memory.disp + bounds[1] * memory.scale + operand.size
    if not -function.depth <= begin < end <= 0:
        return None
    return 'frame', begin, end

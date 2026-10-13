from capstone.x86 import X86_OP_REG

import effects


def transfer(function, ins, original, state):
    cells = original.get('parameter_pointers', {}).copy()
    zeros = original.get('zero_vectors', set()).copy()
    for register in ins.regs_access()[1]:
        name = ins.reg_name(register)
        if name.startswith(('xmm', 'ymm')):
            zeros.discard('xmm'+name[3:])
            zeros.discard('ymm'+name[3:])
    args = ins.operands
    if ins.mnemonic in ('xorps', 'xorpd', 'pxor', 'vpxor', 'vxorps', 'vxorpd') and all(op.type == X86_OP_REG for op in args):
        sources = args if len(args) == 2 else args[1:]
        if len(sources) == 2 and sources[0].reg == sources[1].reg:
            zeros.add(ins.reg_name(args[0].reg))
    for operand in function.memory_writes.get(ins.address, ()):
        region = function.memory_write_region(ins, original, operand)
        if region is not None and region[0] == 'frame':
            continue
        parameter = effects.parameter_write(function, ins, original, operand)
        if parameter is None:
            cells.clear()
            continue
        index, begin, end = parameter
        cells = {(p, offset): kind for (p, offset), kind in cells.items() if p == index and not (begin < offset + 8 and offset < end)}
        source = args[1] if len(args) == 2 and operand is args[0] else None
        if source is None:
            continue
        scalar = ins.mnemonic in ('mov', 'movabs') and operand.size == 8 and (
            function.pointer_operand(ins, original, source) or function.constant_operand(ins, original, source) == 0)
        vector_zero = ins.mnemonic in ('movups', 'movaps', 'movupd', 'movapd', 'movdqu', 'movdqa', 'vmovups', 'vmovaps', 'vmovdqu', 'vmovdqa') and source.type == X86_OP_REG and ins.reg_name(source.reg) in original.get('zero_vectors', set())
        if scalar:
            cells[index, begin] = 1 if function.pointer_operand(ins, original, source) else 2
        elif vector_zero:
            cells.update({(index, offset): 2 for offset in range(begin, end - 7, 8)})
    if ins.mnemonic == 'call':
        zeros.clear()
        writes = effects.call_writes(function, ins, original)
        if writes is None or any(kind == 'image' for kind, _, _ in writes.writes):
            cells.clear()
        elif writes.parameter_writes:
            for index, begin, end in writes.parameter_writes:
                cells = {(p, offset): kind for (p, offset), kind in cells.items() if p == index and not (begin < offset + 8 and offset < end)}
    state['parameter_pointers'] = cells
    state['zero_vectors'] = zeros


def summarize(function):
    if function.tail_calls:
        return frozenset()
    returns = [state.get('parameter_pointers', {}) for address, state in function.states.items()
               if function.instructions[address].mnemonic == 'ret']
    if not returns:
        return frozenset()
    shared = set.intersection(*(set(cells) for cells in returns))
    return frozenset(cell for cell in shared if any(cells[cell] & 1 for cells in returns))

from capstone.x86 import X86_OP_MEM, X86_OP_REG

import effects


def read(state, offset, size):
    values = state['stack_values']
    if not all(offset + index in values for index in range(size)):
        return None
    return sum(values[offset + index] << (index * 8) for index in range(size))


def operand_value(function, ins, state, operand):
    value = function.constant_operand(ins, state, operand)
    if value is not None:
        return value
    if operand.type != X86_OP_MEM or operand.size > 8:
        return None
    origin = function.memory_origin(ins, state, operand)
    return read(state, origin[1], operand.size) if origin is not None and origin[0] == 'frame' else None


def transfer(function, ins, original, state):
    values = original['stack_values'].copy()

    def invalidate(begin, end):
        for offset in list(values):
            if begin <= offset < end:
                del values[offset]

    def store(begin, size, value):
        invalidate(begin, begin + size)
        if value is not None:
            values.update({begin + index: (value >> (index * 8)) & 255 for index in range(size)})

    for operand in function.memory_writes.get(ins.address, ()):
        region = function.memory_write_region(ins, original, operand)
        if region is None:
            values.clear()
        elif region[0] == 'frame':
            invalidate(region[1], region[2])
        if ins.mnemonic in ('mov', 'movabs') and operand is ins.operands[0]:
            origin = function.memory_origin(ins, original, operand)
            if origin is not None and origin[0] == 'frame':
                store(origin[1], operand.size, operand_value(function, ins, original, ins.operands[1]))
    if ins.mnemonic == 'push':
        if original['rsp'] is None:
            values.clear()  # a dynamic frame: the slot is not a known frame offset
        else:
            store(original['rsp'] - 8, 8, operand_value(function, ins, original, ins.operands[0]))
    elif ins.mnemonic == 'pop':
        if original['rsp'] is None:
            values.clear()
        else:
            value = read(original, original['rsp'], 8)
            if value is not None:
                state['constants'][function.reg(ins, ins.operands[0])[0]] = value
            invalidate(original['rsp'], original['rsp'] + 8)
    elif ins.mnemonic == 'call':
        writes = effects.call_writes(function, ins, original)
        if writes is None or writes.parameter_writes:
            values.clear()
        else:
            for kind, begin, end in writes.writes:
                if kind == 'frame':
                    invalidate(begin, end)
    elif ins.mnemonic in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd') and ins.operands[0].type == X86_OP_REG:
        source = ins.operands[1]
        value = operand_value(function, ins, original, source)
        if value is not None:
            bits = source.size * 8
            if ins.mnemonic in ('movsx', 'movsxd') and value & (1 << (bits - 1)):
                value -= 1 << bits
            function.constant_write(ins, original, state, ins.operands[0], value)
    state['stack_values'] = values

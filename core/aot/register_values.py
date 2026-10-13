from capstone.x86 import X86_OP_MEM, X86_OP_REG


MASK64 = (1 << 64) - 1


def low_prefix(mask):
    count = 0
    while count < 64 and mask & (1 << count):
        count += 1
    return count


def transport(function, ins, original, state):
    args = ins.operands
    if len(args) != 2 or args[0].type != X86_OP_REG:
        return False
    destination, width, shift = function.reg(ins, args[0])
    if destination in ('rsp', 'rbp'):
        return False
    if ins.mnemonic == 'mov' and args[1].type == X86_OP_REG:
        source, source_width, source_shift = function.reg(ins, args[1])
        if source_width != width:
            return False
        known = (original['known'].get(source, 0) >> source_shift) & ((1 << width) - 1)
    elif ins.mnemonic == 'lea' and args[1].type == X86_OP_MEM and ins.addr_size == 8 and not args[1].mem.segment:
        memory = args[1].mem
        base, index = ins.reg_name(memory.base), ins.reg_name(memory.index)
        if base in ('rsp', 'rbp', 'rip') or base in original['native_pointers'] or index in original['native_pointers']:
            return False
        base_bits = 64 if base in (None, '', 'rip') else low_prefix(original['known'].get(base, 0))
        index_bits = 64 if not index else min(64, low_prefix(original['known'].get(index, 0)) + (memory.scale.bit_length() - 1))
        known = (1 << min(width, base_bits, index_bits)) - 1
    else:
        return False
    function.define(ins, state, args[0])
    field = ((1 << width) - 1) << shift
    retained = (MASK64 ^ ((1 << 32) - 1)) if width == 32 else original['known'].get(destination, 0) & ~field
    state['known'][destination] = retained | (known << shift)
    return True

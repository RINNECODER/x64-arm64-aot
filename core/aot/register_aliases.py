from capstone.x86 import X86_OP_REG


REGISTERS = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}


def equivalents(state, name):
    result = {name}
    for pair in state.get('register_aliases', frozenset()):
        if name in pair:
            result.update(pair)
    return result


def transfer(function, ins, original, state, volatile, aliases_by_name):
    aliases = original.get('register_aliases', frozenset())
    written = {aliases_by_name[ins.reg_name(register)][0] for register in ins.regs_access()[1]
               if ins.reg_name(register) in aliases_by_name and aliases_by_name[ins.reg_name(register)][0] in REGISTERS}
    if ins.mnemonic == 'call':
        written.update(volatile)
    result = {pair for pair in aliases if not written.intersection(pair)}
    args = ins.operands
    if ins.mnemonic == 'mov' and len(args) == 2 and all(arg.type == X86_OP_REG and arg.size == 8 for arg in args):
        destination, source = (function.reg(ins, arg)[0] for arg in args)
        result.update(tuple(sorted((destination, other))) for other in equivalents(original, source) if other != destination)
    state['register_aliases'] = frozenset(result)

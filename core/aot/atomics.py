"""x86-64 atomics and the TSO memory-ordering policy for the native ARM64 target.

Locked read-modify-write instructions become LLVM atomic operations with `seq_cst` ordering, which
is the strongest ordering and matches x86's `lock` prefix (a full barrier). Plain guest loads and
stores become `acquire`/`release` atomic accesses (see `ordered_load`/`ordered_store`): that is
exactly x86 TSO on top of ARM's weak model, because

  * an acquire load cannot move after a later access    -> LoadLoad and LoadStore are ordered;
  * a release store cannot move before an earlier access -> LoadStore and StoreStore are ordered;
  * StoreLoad stays reorderable, which TSO also allows.

Locked RMW and the fence instructions add the full `dmb ish` (seq_cst) that TSO needs for
StoreLoad. This is deliberately conservative: every scalar guest access is ordered, including
stack and thread-local ones.

Later narrowing pass (planned, not implemented here): prove that accesses which cannot escape the
thread use plain loads and stores. The compiler already tracks stack offsets (`state['pointers']`
with `frame` origins), the native frame alloca, and TLS (`%fs:` is rejected today), so the pass
would classify each memory operand as frame / thread-local / image / unknown and emit plain
accesses for the first two. It must also keep the natural alignment of the atomic forms, since
`ldapr`/`stlr` assume it (Apple silicon tolerates a misaligned runtime address; other ARM64 does
not), which is a second reason to narrow to provably aligned, non-escaping cells first.
"""
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

LOCKED_RMW = {
    'lock xadd': 'add', 'lock add': 'add', 'lock sub': 'sub', 'lock and': 'and',
    'lock or': 'or', 'lock xor': 'xor', 'xadd': 'add',
}
LOCKED_STEP = {'lock inc': ('add', 1), 'lock dec': ('sub', 1)}
LOCKED_BIT = {'lock bts': 'or', 'lock btr': 'and', 'lock btc': 'xor'}
CMPXCHG = {'lock cmpxchg', 'cmpxchg'}
FENCES = {'mfence': 'seq_cst', 'lfence': 'acquire', 'sfence': 'release'}
EXCHANGE = {'xchg', 'lock xchg'}
ATOMIC = set(LOCKED_RMW) | set(LOCKED_STEP) | set(LOCKED_BIT) | CMPXCHG | set(FENCES) | EXCHANGE
ATOMIC_WIDTHS = (1, 2, 4, 8)


def ordered_load(bits, pointer, align=None):
    """The TSO load of a guest scalar: acquire, so later accesses cannot move before it.

    `align` is the alignment the caller proved for `pointer`. A release/acquire atomic whose
    address is not naturally aligned lowers to `stlr`/`ldar`, which fault on a misaligned address,
    so an under-aligned access keeps its true alignment and orders with a fence instead. An unknown
    alignment (`None`) keeps the natural form, the compiler's pre-existing policy.
    """
    if bits not in (8, 16, 32, 64):
        return f'load i{bits}, ptr {pointer}, align 1'
    width = bits // 8
    if align is None or align >= width:
        return f'load atomic i{bits}, ptr {pointer} acquire, align {width}'
    return f'load i{bits}, ptr {pointer}, align {align}\n  fence acquire'


def ordered_store(bits, value, pointer, align=None):
    """The TSO store of a guest scalar: release, so earlier accesses cannot move after it.

    `align` is the alignment the caller proved for `pointer`; see `ordered_load`.
    """
    if bits not in (8, 16, 32, 64):
        return f'store i{bits} {value}, ptr {pointer}, align 1'
    width = bits // 8
    if align is None or align >= width:
        return f'store atomic i{bits} {value}, ptr {pointer} release, align {width}'
    return f'  fence release\n  store i{bits} {value}, ptr {pointer}, align {align}'


def _operands(ins):
    memory = register = None
    for operand in ins.operands:
        if operand.type == X86_OP_MEM:
            memory = operand
        elif operand.type == X86_OP_REG:
            register = operand
    return memory, register


def _accumulator(size):
    """cmpxchg's implicit accumulator: AL / AX / EAX / RAX for 1 / 2 / 4 / 8 bytes."""
    return ('rax', size * 8, 0)


def _load_carry(function):
    return function.emit('load i1, ptr %cf, align 1')


def _store_carry(function, value):
    function.lines.append(f'  store i1 {value}, ptr %cf, align 1')


def analyze(function, ins, state):
    op = ins.mnemonic
    if op not in ATOMIC:
        return False
    if op in FENCES:
        if ins.operands:
            function.fail(ins, 'fence takes no operands')
        return True
    memory, register = _operands(ins)
    if op in CMPXCHG:
        if memory is None or register is None or len(ins.operands) != 2 or ins.operands[0].type != X86_OP_MEM:
            function.fail(ins, 'compare-exchange requires a memory destination and a register source')
        if memory.size not in ATOMIC_WIDTHS:
            function.fail(ins, 'compare-exchange width is not implemented')
        function.read_operand(ins, state, register)
        name, bits, _ = _accumulator(memory.size)
        function.check_register(ins, state, name, bits)
        function.define(ins, state, memory)
        state['known'][name] = (1 << bits) - 1
        state['flags'] = {'zf', 'sf', 'cf', 'of', 'pf'}
        return True
    if memory is None:
        if op not in EXCHANGE or len(ins.operands) != 2 or ins.operands[0].type != X86_OP_REG or ins.operands[1].type != X86_OP_REG:
            function.fail(ins, f'{op} requires a memory destination or two register operands')
        for operand in ins.operands:
            function.read_operand(ins, state, operand)
        for operand in ins.operands:
            function.define(ins, state, operand)
        return True
    if memory.size not in ATOMIC_WIDTHS:
        function.fail(ins, 'atomic read-modify-write requires a scalar memory destination')
    if op in LOCKED_STEP:
        if len(ins.operands) != 1:
            function.fail(ins, f'{op} takes a single memory operand')
        function.define(ins, state, memory)
        state['flags'] = {'zf', 'sf', 'of', 'pf'} | (state['flags'] & {'cf'})
        return True
    if op in LOCKED_RMW:
        source = ins.operands[1] if len(ins.operands) == 2 else None
        if source is None or source.type not in (X86_OP_REG, X86_OP_IMM):
            function.fail(ins, f'{op} requires a memory destination and a register or immediate source')
        if op in ('lock xadd', 'xadd') and source.type != X86_OP_REG:
            function.fail(ins, f'{op} requires a register source')
        if source.type == X86_OP_REG:
            function.read_operand(ins, state, source)
        function.define(ins, state, memory)
        if op in ('lock xadd', 'xadd'):
            function.define(ins, state, source)
        state['flags'] = {'zf', 'sf', 'cf', 'of', 'pf'}
        return True
    if op in LOCKED_BIT:
        if len(ins.operands) != 2 or ins.operands[1].type not in (X86_OP_REG, X86_OP_IMM):
            function.fail(ins, f'{op} requires a memory destination and a register or immediate bit index')
        if ins.operands[1].type == X86_OP_REG:
            function.read_operand(ins, state, ins.operands[1])
        function.define(ins, state, memory)
        state['flags'] = {'cf'}
        return True
    if op in EXCHANGE:
        if register is None or len(ins.operands) != 2:
            function.fail(ins, 'exchange requires a memory operand and a register operand')
        function.read_operand(ins, state, register)
        function.define(ins, state, memory)
        function.define(ins, state, register)
        return True
    function.fail(ins, 'atomic operation is not implemented')
    return True


def _bit_target(function, ins, memory, index):
    """x86 bit-string addressing: the bit index selects a word and a bit inside it."""
    bits = memory.size * 8
    if index.type == X86_OP_IMM:
        # The immediate form masks the offset to the operand width; only the register form
        # adjusts the address (bit-string addressing).
        bit = index.imm % bits
        return function.address(ins, memory), str(bit)
    raw = function.read(ins, index)
    width = index.size * 8
    if width < bits:
        raw = function.emit(f'zext i{width} {raw} to i{bits}')
    word = function.emit(f'lshr i{bits} {raw}, {bits.bit_length() - 1}')
    pointer = function.address(ins, memory)
    offset = function.emit(f'mul i{bits} {word}, {memory.size}')
    pointer = function.emit(f'getelementptr i8, ptr {pointer}, i{bits} {offset}')
    bit = function.emit(f'and i{bits} {raw}, {bits - 1}')
    return pointer, bit


def lower(function, ins):
    op, args = ins.mnemonic, ins.operands
    if op not in ATOMIC:
        return False
    if op in FENCES:
        function.lines.append(f'  fence {FENCES[op]}')
        return True
    memory, register = _operands(ins)
    if memory is None:
        left, right = function.read(ins, args[0]), function.read(ins, args[1])
        function.write(ins, args[0], right)
        function.write(ins, args[1], left)
        return True
    bits, align = memory.size * 8, memory.size
    if op in CMPXCHG:
        name, width, _ = _accumulator(memory.size)
        expected = function.load(name, width)
        replacement = function.read(ins, register, width)
        pointer = function.address(ins, memory)
        pair = function.emit(f'cmpxchg ptr {pointer}, i{width} {expected}, i{width} {replacement} seq_cst seq_cst, align {align}')
        old = function.emit(f'extractvalue {{ i{width}, i1 }} {pair}, 0')
        success = function.emit(f'extractvalue {{ i{width}, i1 }} {pair}, 1')
        function.store(name, old, width)
        # x86 sets the flags from `destination - accumulator`, like `cmp [mem], acc`.
        difference = function.emit(f'sub i{width} {old}, {expected}')
        function.flags('sub', width, old, expected, difference)
        function.lines.append(f'  store i1 {success}, ptr %zf, align 1')
        return True
    if op in LOCKED_STEP:
        operation = LOCKED_STEP[op][0]
        pointer = function.address(ins, memory)
        old = function.emit(f'atomicrmw {operation} ptr {pointer}, i{bits} 1 seq_cst, align {align}')
        new = function.emit(f'{operation} i{bits} {old}, 1')
        carry = _load_carry(function) if 'cf' in function.states[ins.address]['flags'] else 'false'
        function.flags(operation, bits, old, '1', new)
        _store_carry(function, carry)
        return True
    if op in LOCKED_RMW:
        operation = LOCKED_RMW[op]
        value = function.read(ins, args[1], bits)
        pointer = function.address(ins, memory)
        old = function.emit(f'atomicrmw {operation} ptr {pointer}, i{bits} {value} seq_cst, align {align}')
        new = function.emit(f'{operation} i{bits} {old}, {value}')
        function.flags(operation, bits, old, value, new)
        if op in ('lock xadd', 'xadd'):
            function.write(ins, register, old)
        return True
    if op in LOCKED_BIT:
        pointer, bit = _bit_target(function, ins, memory, args[1])
        operation = LOCKED_BIT[op]
        mask = function.emit(f'shl i{bits} 1, {bit}')
        if operation == 'and':
            mask = function.emit(f'xor i{bits} {mask}, -1')
        old = function.emit(f'atomicrmw {operation} ptr {pointer}, i{bits} {mask} seq_cst, align {align}')
        shifted = function.emit(f'lshr i{bits} {old}, {bit}')
        _store_carry(function, function.emit(f'trunc i{bits} {shifted} to i1'))
        return True
    if op in EXCHANGE:
        value = function.read(ins, register, bits)
        pointer = function.address(ins, memory)
        old = function.emit(f'atomicrmw xchg ptr {pointer}, i{bits} {value} seq_cst, align {align}')
        function.write(ins, register, old)
        return True
    function.fail(ins, 'atomic operation is not implemented')
    return True

"""x87 FPU lowering (Phase 2 lifter slice 3).

The title's x87 usage (measured over the executable segment): fstp/fld/fxch/fldz/fld1/
fprem/fnstsw/fucomi/fmul/fild/fucompi/fcmove/fmulp/fadd/fchs/fst/fisttp/fisub/fdivrp/
fdivp/fcmovnb. The stack is modelled as eight f64 slots with a top index.

Precision decision: the measured usage contains 29 80-bit (tbyte) transfers and 17 fprem.
Those transfers are compiler stack spills of values already computed as f64, so an f64
stack is exact for them; fprem is approximated by f64 fmod (last-bit differences possible).
A full soft-float f80 is recorded as a follow-up rather than implemented here.
"""
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

OPERATIONS = {
    'fld', 'fldz', 'fld1', 'fldpi', 'fst', 'fstp', 'fild', 'fistp', 'fisttp',
    'fadd', 'faddp', 'fsub', 'fsubp', 'fsubr', 'fsubrp', 'fmul', 'fmulp', 'fdiv', 'fdivp',
    'fdivr', 'fdivrp', 'fchs', 'fabs', 'fsqrt', 'fxch', 'fcom', 'fcomp', 'fcompp',
    'fucom', 'fucomp', 'fucompp', 'fcomi', 'fcomip', 'fucomi', 'fucomip', 'fucompi',
    'fiadd', 'fisub', 'fisubr', 'fimul', 'fidiv', 'fidivr',
    'fnstsw', 'fnstcw', 'fldcw', 'fcmove', 'fcmovne', 'fcmovb', 'fcmovbe', 'fcmovnb',
    'fcmovnbe', 'fcmovu', 'fcmovnu', 'fprem', 'fprem1', 'frndint', 'fwait',
}
# fcmovcc reads the stored EFLAGS set by a previous fcomi/fucomi (or integer compare), not a
# fresh st(0)/st(1) comparison: predicate name and the flags it needs.
FCMOV = {'fcmove': ('je', {'zf'}), 'fcmovne': ('jne', {'zf'}), 'fcmovb': ('jb', {'cf'}),
         'fcmovbe': ('jbe', {'cf', 'zf'}), 'fcmovnb': ('jae', {'cf'}),
         'fcmovnbe': ('ja', {'cf', 'zf'}), 'fcmovu': ('jp', {'pf'}), 'fcmovnu': ('jnp', {'pf'})}


def analyze(function, ins, state):
    op = ins.mnemonic
    if op not in OPERATIONS:
        return False
    if op in ('fcomi', 'fcomip', 'fucomi', 'fucomip', 'fucompi'):
        # These set the integer EFLAGS (CF/PF/ZF), which a following fcmovcc/conditional reads.
        state['flags'] = {'zf', 'pf', 'cf', 'of', 'sf'}
    if op in FCMOV and not FCMOV[op][1] <= state['flags']:
        function.fail(ins, 'undefined floating-point condition flags')
    if ins.operands and ins.operands[-1].type == X86_OP_MEM:
        function.read_operand(ins, state, ins.operands[-1])
    return True


def _top(function):
    return function.emit('load i32, ptr %x87_top, align 4')


def _slot(function, top, index):
    offset = function.emit(f'add i32 {top}, {index}')
    offset = function.emit(f'and i32 {offset}, 7')
    return function.emit(f'getelementptr [8 x double], ptr %x87, i32 0, i32 {offset}')


def _push(function, value):
    top = _top(function)
    new_top = function.emit(f'sub i32 {top}, 1')
    new_top = function.emit(f'and i32 {new_top}, 7')
    function.lines.append(f'  store i32 {new_top}, ptr %x87_top, align 4')
    slot = _slot(function, new_top, 0)
    function.lines.append(f'  store double {value}, ptr {slot}, align 8')


def _pop(function):
    top = _top(function)
    new_top = function.emit(f'add i32 {top}, 1')
    new_top = function.emit(f'and i32 {new_top}, 7')
    function.lines.append(f'  store i32 {new_top}, ptr %x87_top, align 4')


def _st(function, index):
    top = _top(function)
    slot = _slot(function, top, index)
    return function.emit(f'load double, ptr {slot}, align 8')


def _set_st(function, index, value):
    top = _top(function)
    slot = _slot(function, top, index)
    function.lines.append(f'  store double {value}, ptr {slot}, align 8')


def _status_word(function):
    result = '0'
    for name, bit in (('c0', 8), ('c1', 9), ('c2', 10), ('c3', 14)):
        value = function.emit(f'load i1, ptr %{name}, align 1')
        value = function.emit(f'zext i1 {value} to i32')
        value = function.emit(f'shl i32 {value}, {bit}')
        result = function.emit(f'or i32 {result}, {value}')
    return result


def lower(function, ins):
    op, args = ins.mnemonic, ins.operands
    if op not in OPERATIONS:
        return False
    if op in ('fwait', 'frndint'):
        return True
    if op == 'fldz':
        _push(function, '0.0')
        return True
    if op == 'fld1':
        _push(function, '1.0')
        return True
    if op == 'fldpi':
        _push(function, '0x400921FB54442D18')
        return True
    if op == 'fld':
        if args[0].type == X86_OP_REG:
            _push(function, _st(function, _index(ins, args[0])))
        else:
            _push(function, _memory(function, ins, args[0]))
        return True
    if op == 'fild':
        value = _integer_memory(function, ins, args[0])
        _push(function, function.emit(f'sitofp i{args[0].size * 8} {value} to double'))
        return True
    if op in ('fiadd', 'fisub', 'fisubr', 'fimul', 'fidiv', 'fidivr'):
        if not args or args[0].type != X86_OP_MEM:
            function.fail(ins, 'integer arithmetic requires a memory operand')
        value = function.read(ins, args[0], args[0].size * 8)
        other = function.emit(f'sitofp i{args[0].size * 8} {value} to double')
        left, right = _st(function, 0), other
        if op in ('fisubr', 'fidivr'):
            left, right = right, left
        operation = 'fadd' if op == 'fiadd' else ('fsub' if op.startswith('fisub') else ('fmul' if op == 'fimul' else 'fdiv'))
        _set_st(function, 0, function.emit(f'{operation} double {left}, {right}'))
        return True
    if op in ('fst', 'fstp'):
        if args[0].type == X86_OP_REG:
            _set_st(function, _index(ins, args[0]), _st(function, 0))
        else:
            width = args[0].size * 8
            value = _st(function, 0)
            if width == 32:
                narrowed = function.emit(f'fptrunc double {value} to float')
                stored = function.emit(f'bitcast float {narrowed} to i32')
            elif width == 80:
                stored = _extended(function, value)
            else:
                stored = function.emit(f'bitcast double {value} to i64')
            function.write(ins, args[0], stored)
        if op == 'fstp':
            _pop(function)
        return True
    if op in ('fistp', 'fisttp'):
        value = _st(function, 0)
        width = args[0].size * 8
        converted = function.emit(f'fptosi double {value} to i{width}') if op == 'fistp' else function.emit(f'fptoui double {value} to i{width}')
        function.write(ins, args[0], converted)
        _pop(function)
        return True
    if op in ('fadd', 'faddp', 'fsub', 'fsubp', 'fsubr', 'fsubrp', 'fmul', 'fmulp', 'fdiv', 'fdivp', 'fdivr', 'fdivrp'):
        popping = op.endswith('p')
        reverse = op.startswith('fsubr') or op.startswith('fdivr')
        if args and args[0].type == X86_OP_MEM:
            other, index = _memory(function, ins, args[0]), 1
        else:
            index = 1
            for operand in args:
                if operand.type == X86_OP_REG and _index(ins, operand) != 0:
                    index = _index(ins, operand)
                    break
            other = _st(function, index)
        if popping:
            left, right = other, _st(function, 0)
        else:
            left, right = _st(function, 0), other
        if reverse:
            left, right = right, left
        operation = 'fadd' if op.startswith('fadd') else ('fsub' if op.startswith('fsub') else ('fmul' if op.startswith('fmul') else 'fdiv'))
        result = function.emit(f'{operation} double {left}, {right}')
        if popping:
            _set_st(function, index, result)
            _pop(function)
        else:
            _set_st(function, 0, result)
        return True
    if op in ('fchs', 'fabs', 'fsqrt'):
        value = _st(function, 0)
        if op == 'fchs':
            value = function.emit(f'fneg double {value}')
        elif op == 'fabs':
            value = function.emit(f'call double @llvm.fabs.f64(double {value})')
        else:
            value = function.emit(f'call double @llvm.sqrt.f64(double {value})')
        _set_st(function, 0, value)
        return True
    if op == 'fxch':
        index = _index(ins, args[-1])
        a, b = _st(function, 0), _st(function, index)
        _set_st(function, 0, b)
        _set_st(function, index, a)
        return True
    if op in ('fcom', 'fcomp', 'fucom', 'fucomp', 'fcompp', 'fucompp', 'fcomi', 'fcomip',
              'fucomi', 'fucomip', 'fucompi'):
        # Capstone spells the explicit operand form (FUCOMIP ST(0), ST(i)) as `fucompi st(i)`;
        # use it when present so `fucompi st(0)` compares ST(0) with itself rather than ST(1).
        index = _index(ins, args[-1]) if args and args[-1].type == X86_OP_REG else 1
        left, right = _st(function, 0), _st(function, index)
        unordered = function.emit(f'fcmp uno double {left}, {right}')
        below = function.emit(f'fcmp olt double {left}, {right}')
        equal = function.emit(f'fcmp oeq double {left}, {right}')
        function.lines.append(f'  store i1 {unordered}, ptr %c0, align 1')
        function.lines.append(f'  store i1 {below}, ptr %c2, align 1')
        function.lines.append(f'  store i1 {equal}, ptr %c3, align 1')
        if op in ('fcomi', 'fcomip', 'fucomi', 'fucomip', 'fucompi'):
            zf = function.emit(f'or i1 {unordered}, {equal}')
            function.lines.append(f'  store i1 {zf}, ptr %zf, align 1')
            function.lines.append(f'  store i1 {unordered}, ptr %pf, align 1')
            function.lines.append(f'  store i1 {below}, ptr %cf, align 1')
            function.lines.append('  store i1 false, ptr %of, align 1')
            function.lines.append('  store i1 false, ptr %sf, align 1')
        if op in ('fcomp', 'fcompp', 'fucomp', 'fucompp', 'fcomip', 'fucomip', 'fucompi'):
            _pop(function)
        if op in ('fcompp', 'fucompp'):
            _pop(function)
        return True
    if op == 'fnstsw':
        function.write(ins, args[0], _status_word(function))
        return True
    if op in ('fnstcw', 'fldcw'):
        return True
    if op in FCMOV:
        predicate = function.condition(FCMOV[op][0])
        index = _index(ins, args[-1])
        old, new = _st(function, 0), _st(function, index)
        _set_st(function, 0, function.emit(f'select i1 {predicate}, double {new}, double {old}'))
        return True
    if op in ('fprem', 'fprem1'):
        result = function.emit(f'call double @fmod(double {_st(function, 0)}, double {_st(function, 1)})')
        _set_st(function, 0, result)
        return True
    return False


def _index(ins, operand):
    name = ins.reg_name(operand.reg)
    if name.startswith('st'):
        digits = ''.join(ch for ch in name if ch.isdigit())
        return int(digits) if digits else 0
    return 0


def _memory(function, ins, operand):
    width = operand.size * 8
    if width == 32:
        raw = function.read(ins, operand, 32)
        single = function.emit(f'bitcast i32 {raw} to float')
        return function.emit(f'fpext float {single} to double')
    if width == 80:
        return _double(function, function.read(ins, operand, 80))
    value = function.read(ins, operand, 64)
    return function.emit(f'bitcast i64 {value} to double')


def _extended(function, value):
    """The x87 80-bit extended bit pattern of a double, as an i80 (ARM64 has no x86_fp80)."""
    bits = function.emit(f'bitcast double {value} to i64')
    sign = function.emit(f'and i64 {bits}, {1 << 63}')
    magnitude = function.emit(f'and i64 {bits}, {(1 << 63) - 1}')
    exponent = function.emit(f'lshr i64 {magnitude}, 52')
    fraction = function.emit(f'and i64 {magnitude}, {(1 << 52) - 1}')
    zero = function.emit(f'icmp eq i64 {magnitude}, 0')
    biased = function.emit(f'add i64 {exponent}, 15360')
    biased = function.emit(f'select i1 {zero}, i64 0, i64 {biased}')
    significand = function.emit(f'shl i64 {fraction}, 11')
    significand = function.emit(f'or i64 {significand}, {1 << 63}')
    significand = function.emit(f'select i1 {zero}, i64 0, i64 {significand}')
    result = function.emit(f'zext i64 {significand} to i80')
    high = function.emit(f'zext i64 {biased} to i80')
    high = function.emit(f'shl i80 {high}, 64')
    result = function.emit(f'or i80 {result}, {high}')
    sign80 = function.emit(f'zext i64 {sign} to i80')
    sign80 = function.emit(f'shl i80 {sign80}, 16')
    return function.emit(f'or i80 {result}, {sign80}')


def _double(function, raw):
    """The double value of an x87 80-bit extended i80."""
    sign = function.emit(f'lshr i80 {raw}, 79')
    sign = function.emit(f'trunc i80 {sign} to i64')
    sign = function.emit(f'shl i64 {sign}, 63')
    exponent = function.emit(f'lshr i80 {raw}, 64')
    exponent = function.emit(f'trunc i80 {exponent} to i64')
    exponent = function.emit(f'and i64 {exponent}, 32767')
    significand = function.emit(f'trunc i80 {raw} to i64')
    zero = function.emit(f'icmp eq i64 {exponent}, 0')
    biased = function.emit(f'sub i64 {exponent}, 15360')
    fraction = function.emit(f'lshr i64 {significand}, 11')
    fraction = function.emit(f'and i64 {fraction}, {(1 << 52) - 1}')
    magnitude = function.emit(f'shl i64 {biased}, 52')
    magnitude = function.emit(f'or i64 {magnitude}, {fraction}')
    magnitude = function.emit(f'select i1 {zero}, i64 0, i64 {magnitude}')
    bits = function.emit(f'or i64 {sign}, {magnitude}')
    return function.emit(f'bitcast i64 {bits} to double')


def _integer_memory(function, ins, operand):
    return function.read(ins, operand, operand.size * 8)

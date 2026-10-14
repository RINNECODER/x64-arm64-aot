"""BMI2 and scalar-tail integer lowering (Phase 2 lifter slice 3).

andn, bextr, bzhi, shlx, shrx, sarx, mulx, rorx, popcnt, lzcnt, tzcnt, movbe, rol, ror.
FMA, x87, system and TLS live in their own modules. Kept separate from integer.py so the
lane that owns avx/vector is not touched.
"""
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

import integer

OPERATIONS = {'andn', 'bextr', 'bzhi', 'shlx', 'shrx', 'sarx', 'mulx', 'rorx',
              'popcnt', 'lzcnt', 'tzcnt', 'movbe', 'rol', 'ror'}
BIT_COUNT = {'popcnt', 'lzcnt', 'tzcnt'}
SHIFT = {'shlx': 'shl', 'shrx': 'lshr', 'sarx': 'ashr'}


def _general(function, ins, state, operand, label):
    if operand.type != X86_OP_REG:
        function.fail(ins, f'{label} requires a general-purpose register')
    name = function.reg(ins, operand)[0]
    if name in ('rsp', 'rbp'):
        # The scalar ABI's native frame is the guest frame, so an arbitrary value there is not
        # representable. The uniform ABI keeps the guest frame registers in the register file, where
        # the destination is an ordinary slot that simply loses its frame meaning.
        if not function.uniform:
            function.fail(ins, f'{label} requires a general-purpose register')
        state[name] = None
    return name


def analyze(function, ins, state):
    op, args = ins.mnemonic, ins.operands
    if op not in OPERATIONS:
        return False
    width = args[0].size * 8 if args and args[0].size else 0
    if op in ('andn', 'bextr', 'bzhi') or op in SHIFT:
        if len(args) != 3 or args[0].type != X86_OP_REG:
            function.fail(ins, f'{op} requires three operands')
        _general(function, ins, state, args[0], op)
        for operand in args[1:]:
            function.read_operand(ins, state, operand)
        function.define(ins, state, args[0])
        if op == 'andn':
            state['flags'] = {'zf', 'sf'}
        elif op == 'bextr':
            state['flags'] = {'zf'}
        elif op == 'bzhi':
            state['flags'] = {'zf', 'sf', 'cf'}
        return True
    if op == 'mulx':
        if len(args) != 3 or args[0].type != X86_OP_REG or args[1].type != X86_OP_REG:
            function.fail(ins, 'mulx requires two register destinations')
        _general(function, ins, state, args[0], op)
        _general(function, ins, state, args[1], op)
        function.check_register(ins, state, 'rdx', width)
        function.read_operand(ins, state, args[2])
        function.define(ins, state, args[0])
        function.define(ins, state, args[1])
        return True
    if op == 'rorx':
        if len(args) != 3 or args[0].type != X86_OP_REG or args[2].type != X86_OP_IMM:
            function.fail(ins, 'rorx requires a register destination and an immediate count')
        _general(function, ins, state, args[0], op)
        function.read_operand(ins, state, args[1])
        function.define(ins, state, args[0])
        return True
    if op in BIT_COUNT:
        if len(args) != 2 or args[0].type != X86_OP_REG:
            function.fail(ins, f'{op} requires a register destination')
        _general(function, ins, state, args[0], op)
        function.read_operand(ins, state, args[1])
        function.define(ins, state, args[0])
        state['flags'] = {'zf', 'cf'} if op in ('lzcnt', 'tzcnt') else {'zf'}
        return True
    if op == 'movbe':
        if len(args) != 2 or args[0].size not in (2, 4, 8):
            function.fail(ins, 'movbe requires a 2/4/8-byte operand')
        if args[0].type == X86_OP_REG and args[1].type == X86_OP_MEM:
            function.read_operand(ins, state, args[1])
            function.define(ins, state, args[0])
        elif args[1].type == X86_OP_REG and args[0].type == X86_OP_MEM:
            function.read_operand(ins, state, args[1])
            function.define(ins, state, args[0])
        else:
            function.fail(ins, 'unsupported movbe operands')
        return True
    if op in ('rol', 'ror'):
        if len(args) != 2 or args[0].type != X86_OP_REG or args[0].size not in (1, 2, 4, 8):
            function.fail(ins, f'unsupported {op} operands')
        _general(function, ins, state, args[0], op)
        function.read_operand(ins, state, args[0])
        function.read_operand(ins, state, args[1])
        function.define(ins, state, args[0])
        mask = width - 1
        flags = {'cf'}
        if args[1].type == X86_OP_IMM and (args[1].imm & mask) == 1:
            flags.add('of')
        state['flags'] = flags
        return True
    return False


def _shift_amount(function, ins, operand, width, wide):
    mask = 63 if width == 64 else 31
    if operand.type == X86_OP_IMM:
        return str(operand.imm & mask)
    source_width = operand.size * 8
    value = function.read(ins, operand, source_width)
    value = function.emit(f'and i{source_width} {value}, {mask}')
    return integer.extension(function, value, source_width, wide)


def _rotate_right(function, value, count, width):
    right = function.emit(f'lshr i{width} {value}, {count}')
    complement = function.emit(f'sub i{width} {width}, {count}')
    complement = function.emit(f'and i{width} {complement}, {width - 1}')
    left = function.emit(f'shl i{width} {value}, {complement}')
    return function.emit(f'or i{width} {right}, {left}')


def lower(function, ins):
    op, args = ins.mnemonic, ins.operands
    if op not in OPERATIONS:
        return False
    if op == 'andn':
        width = args[0].size * 8
        value = function.emit(f'xor i{width} {function.read(ins, args[1], width)}, -1')
        value = function.emit(f'and i{width} {value}, {function.read(ins, args[2], width)}')
        integer.store_flag(function, 'zf', function.emit(f'icmp eq i{width} {value}, 0'))
        integer.store_flag(function, 'sf', function.emit(f'icmp slt i{width} {value}, 0'))
        integer.store_flag(function, 'cf', 'false')
        integer.store_flag(function, 'of', 'false')
        function.write(ins, args[0], value)
        return True
    if op == 'bextr':
        width = args[0].size * 8
        wide = 128 if width == 64 else 64
        source = integer.extension(function, function.read(ins, args[1], width), width, wide)
        control_width = args[2].size * 8
        control = function.read(ins, args[2], control_width)
        start = function.emit(f'and i{control_width} {control}, 255')
        length = function.emit(f'lshr i{control_width} {control}, 8')
        length = function.emit(f'and i{control_width} {length}, 255')
        start = integer.extension(function, start, control_width, wide)
        length = integer.extension(function, length, control_width, wide)
        start_ok = function.emit(f'icmp ult i{wide} {start}, {width}')
        length_ok = function.emit(f'icmp ne i{wide} {length}, 0')
        valid = function.emit(f'and i1 {start_ok}, {length_ok}')
        shifted = function.emit(f'lshr i{wide} {source}, {start}')
        clamped = function.emit(f'icmp ult i{wide} {length}, {width}')
        length = function.emit(f'select i1 {clamped}, i{wide} {length}, i{wide} {width}')
        mask = function.emit(f'shl i{wide} 1, {length}')
        mask = function.emit(f'sub i{wide} {mask}, 1')
        masked = function.emit(f'and i{wide} {shifted}, {mask}')
        masked = function.emit(f'trunc i{wide} {masked} to i{width}')
        value = function.emit(f'select i1 {valid}, i{width} {masked}, i{width} 0')
        integer.store_flag(function, 'zf', function.emit(f'icmp eq i{width} {value}, 0'))
        function.write(ins, args[0], value)
        return True
    if op == 'bzhi':
        width = args[0].size * 8
        wide = width + 1
        source = integer.extension(function, function.read(ins, args[1], width), width, wide)
        index_width = args[2].size * 8
        index = function.read(ins, args[2], index_width)
        index = function.emit(f'and i{index_width} {index}, {width - 1}')
        index = integer.extension(function, index, index_width, wide)
        one = function.emit(f'shl i{wide} 1, {index}')
        mask = function.emit(f'sub i{wide} {one}, 1')
        masked = function.emit(f'and i{wide} {source}, {mask}')
        masked = function.emit(f'trunc i{wide} {masked} to i{width}')
        value = function.emit(f'select i1 {function.emit(f"icmp uge i{width} {function.read(ins, args[2], width)}, {width}")}, i{width} {function.read(ins, args[1], width)}, i{width} {masked}')
        integer.store_flag(function, 'zf', function.emit(f'icmp eq i{width} {value}, 0'))
        integer.store_flag(function, 'sf', function.emit(f'icmp slt i{width} {value}, 0'))
        integer.store_flag(function, 'cf', function.emit(f'icmp uge i{width} {function.read(ins, args[2], width)}, {width}'))
        integer.store_flag(function, 'of', 'false')
        function.write(ins, args[0], value)
        return True
    if op in SHIFT:
        width = args[0].size * 8
        wide = 128 if width == 64 else 64
        count = _shift_amount(function, ins, args[2], width, wide)
        source = integer.extension(function, function.read(ins, args[1], width), width, wide, op == 'sarx')
        shifted = function.emit(f'{SHIFT[op]} i{wide} {source}, {count}')
        function.write(ins, args[0], function.emit(f'trunc i{wide} {shifted} to i{width}'))
        return True
    if op == 'mulx':
        width = args[1].size * 8
        wide = width * 2
        left = integer.extension(function, function.load('rdx', width), width, wide)
        right = integer.extension(function, function.read(ins, args[2], width), width, wide)
        product = function.emit(f'mul i{wide} {left}, {right}')
        function.write(ins, args[1], function.emit(f'trunc i{wide} {product} to i{width}'))
        high = function.emit(f'lshr i{wide} {product}, {width}')
        function.write(ins, args[0], function.emit(f'trunc i{wide} {high} to i{width}'))
        return True
    if op == 'rorx':
        width = args[0].size * 8
        count = args[2].imm & (width - 1)
        value = function.read(ins, args[1], width)
        if count == 0:
            function.write(ins, args[0], value)
        else:
            function.write(ins, args[0], _rotate_right(function, value, str(count), width))
        return True
    if op in BIT_COUNT:
        width = args[0].size * 8
        value = function.read(ins, args[1], width)
        if op == 'popcnt':
            result = function.emit(f'call i{width} @llvm.ctpop.i{width}(i{width} {value})')
            integer.store_flag(function, 'zf', function.emit(f'icmp eq i{width} {result}, 0'))
            integer.store_flag(function, 'cf', 'false')
            integer.store_flag(function, 'of', 'false')
        else:
            intrinsic = 'ctlz' if op == 'lzcnt' else 'cttz'
            result = function.emit(f'call i{width} @llvm.{intrinsic}.i{width}(i{width} {value}, i1 false)')
            integer.store_flag(function, 'zf', function.emit(f'icmp eq i{width} {result}, 0'))
            integer.store_flag(function, 'cf', function.emit(f'icmp eq i{width} {value}, 0'))
        function.write(ins, args[0], result)
        return True
    if op == 'movbe':
        width = args[0].size * 8
        value = function.read(ins, args[1], width)
        function.write(ins, args[0], function.emit(f'call i{width} @llvm.bswap.i{width}(i{width} {value})'))
        return True
    if op in ('rol', 'ror'):
        width = args[0].size * 8
        mask = width - 1
        count = _shift_amount(function, ins, args[1], width, width)
        if args[1].type == X86_OP_IMM:
            count = str(args[1].imm & mask)
        else:
            count = function.emit(f'and i{width} {count}, {mask}')
        value = function.read(ins, args[0], width)
        if args[1].type == X86_OP_IMM and (args[1].imm & mask) == 0:
            return True
        if op == 'ror':
            complement = function.emit(f'sub i{width} {width}, {count}')
            complement = function.emit(f'and i{width} {complement}, {width - 1}')
            right = function.emit(f'lshr i{width} {value}, {count}')
            left = function.emit(f'shl i{width} {value}, {complement}')
            result = function.emit(f'or i{width} {right}, {left}')
            position = function.emit(f'sub i{width} {count}, 1')
            position = function.emit(f'and i{width} {position}, {width - 1}')
            carry = function.emit(f'lshr i{width} {value}, {position}')
            carry = function.emit(f'and i{width} {carry}, 1')
        else:
            complement = function.emit(f'sub i{width} {width}, {count}')
            complement = function.emit(f'and i{width} {complement}, {width - 1}')
            right = function.emit(f'lshr i{width} {value}, {complement}')
            left = function.emit(f'shl i{width} {value}, {count}')
            result = function.emit(f'or i{width} {right}, {left}')
            position = function.emit(f'sub i{width} {width}, {count}')
            position = function.emit(f'and i{width} {position}, {width - 1}')
            carry = function.emit(f'lshr i{width} {value}, {position}')
            carry = function.emit(f'and i{width} {carry}, 1')
        function.write(ins, args[0], result)
        previous = function.states[ins.address]['flags']
        old_cf = integer.load_flag(function, 'cf') if 'cf' in previous else 'false'
        carry = function.emit(f'trunc i{width} {carry} to i1')
        nonzero = function.emit(f'icmp ne i{width} {count}, 0')
        carry = function.emit(f'select i1 {nonzero}, i1 {carry}, i1 {old_cf}')
        top = function.emit(f'lshr i{width} {result}, {width - 1}')
        top = function.emit(f'trunc i{width} {top} to i1')
        if op == 'rol':
            overflow = function.emit(f'xor i1 {top}, {carry}')
        else:
            second = function.emit(f'lshr i{width} {result}, {width - 2}')
            second = function.emit(f'trunc i{width} {second} to i1')
            overflow = function.emit(f'xor i1 {top}, {second}')
        one = function.emit(f'icmp eq i{width} {count}, 1')
        integer.store_flag(function, 'cf', carry)
        integer.store_flag(function, 'of', function.emit(f'select i1 {one}, i1 {overflow}, i1 false'))
        return True
    return False

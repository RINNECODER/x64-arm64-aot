from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


FLAGS = {'cf', 'zf', 'sf', 'of', 'pf'}
CONDITIONS = {
    'e': {'zf'}, 'ne': {'zf'}, 'a': {'cf', 'zf'}, 'ae': {'cf'}, 'b': {'cf'}, 'be': {'cf', 'zf'},
    'g': {'zf', 'sf', 'of'}, 'ge': {'sf', 'of'}, 'l': {'sf', 'of'}, 'le': {'zf', 'sf', 'of'},
    's': {'sf'}, 'ns': {'sf'}, 'o': {'of'}, 'no': {'of'}, 'p': {'pf'}, 'np': {'pf'},
}
ALIASES = {'z': 'e', 'nz': 'ne', 'c': 'b', 'nc': 'ae', 'na': 'be', 'nbe': 'a',
           'nb': 'ae', 'nae': 'b', 'ng': 'le', 'nge': 'l', 'nl': 'ge', 'nle': 'g', 'pe': 'p', 'po': 'np'}
ROTATES = {'rol', 'ror', 'rcl', 'rcr'}
SHIFTS = {'shl', 'sal', 'shr', 'sar'}
OPERATIONS = {'inc', 'dec', 'imul', 'sbb', 'adc', 'cdqe', 'cdq', 'cwd', 'cqo', 'neg', 'not', 'div', 'idiv', 'blsr', 'blsi', 'blsmsk', 'bt', 'bts', 'btr', 'btc', 'bsf', 'bsr', 'mul', 'cwde', 'bswap',
              'shld', 'shrd', 'cld', 'std',
              'prefetchnta', 'prefetcht0', 'prefetcht1', 'prefetcht2', 'prefetchw'} | SHIFTS | ROTATES


# x86 CRC32 is the CRC32C (Castagnoli) accumulator; AArch64 has it as one instruction per width.
CRC32_INTRINSICS = {8: 'crc32cb', 16: 'crc32ch', 32: 'crc32cw', 64: 'crc32cx'}
INTRINSIC_DECLARATIONS = [
    'declare i32 @llvm.aarch64.crc32cb(i32, i32)',
    'declare i32 @llvm.aarch64.crc32ch(i32, i32)',
    'declare i32 @llvm.aarch64.crc32cw(i32, i32)',
    'declare i32 @llvm.aarch64.crc32cx(i32, i64)',
]


def condition(ins):
    suffix = ins.mnemonic[4:] if ins.mnemonic.startswith('cmov') else ins.mnemonic[3:]
    return ALIASES.get(suffix, suffix)


def implicit_define(state, name, width, shift=0):
    mask = ((1 << width) - 1) << shift
    state['known'][name] = (1 << 64) - 1 if width >= 32 else state['known'].get(name, 0) | mask
    state['pointers'].pop(name, None)


def analyze(function, ins, state):
    op, args = ins.mnemonic, ins.operands
    if op.startswith('stos') or op.startswith('rep stos'):
        width = 8 if op.endswith('b') else 16 if op.endswith('w') else 32 if op.endswith('d') else 64
        function.check_register(ins, state, 'rax', width)
        function.check_register(ins, state, 'rdi', 64)
        if op.startswith('rep'):
            function.check_register(ins, state, 'rcx', 64)
        # The store destination is implicit (rdi); rdi advances and, for rep, rcx counts down.
        implicit_define(state, 'rdi', 64)
        if op.startswith('rep'):
            implicit_define(state, 'rcx', 64)
        return True
    conditional = op.startswith(('cmov', 'set'))
    if op == 'crc32':
        if len(args) != 2 or args[0].type != X86_OP_REG or args[0].size not in (4, 8) or args[1].type not in (X86_OP_REG, X86_OP_MEM):
            function.fail(ins, 'crc32 requires a 32- or 64-bit register destination and a register or memory source')
        function.read_operand(ins, state, args[1])
        function.define(ins, state, args[0])
        return True
    if op not in OPERATIONS and not conditional:
        return False
    if conditional:
        if args and args[0].type == X86_OP_REG and function.reg(ins, args[0])[0] in ('rsp', 'rbp') and not getattr(function, 'uniform', False):
            function.fail(ins, 'conditional operation cannot reconstruct a dynamic native frame')
        suffix = condition(ins)
        if suffix not in CONDITIONS:
            function.fail(ins, 'unsupported integer condition')
        if not CONDITIONS[suffix] <= state['flags']:
            function.fail(ins, 'undefined integer condition flags')
        if op.startswith('cmov'):
            if len(args) != 2 or args[0].type != X86_OP_REG or args[0].size not in (2, 4, 8):
                function.fail(ins, 'unsupported conditional move operands')
            for operand in args:
                function.read_operand(ins, state, operand)
        elif len(args) != 1 or args[0].size != 1:
            function.fail(ins, 'unsupported conditional set operands')
        function.define(ins, state, args[0])
        return True
    if op == 'bswap':
        if len(args) != 1 or args[0].type != X86_OP_REG or args[0].size not in (4, 8):
            function.fail(ins, 'byte swap requires a 32-bit or 64-bit register')
        if function.reg(ins, args[0])[0] in ('rsp', 'rbp'):
            function.fail(ins, 'byte swap cannot reconstruct a dynamic native frame')
        function.read_operand(ins, state, args[0])
        function.define(ins, state, args[0])
        return True
    if op in ('blsr', 'blsi', 'blsmsk', 'bt'):
        if op == 'bt' and args and args[0].type == X86_OP_MEM:
            # `bt m, r/imm` tests a bit of a bit string that may cross the operand: the byte is
            # `index // width` bytes into memory and the bit is `index % width`.
            if args[1].type not in (X86_OP_REG, X86_OP_IMM):
                function.fail(ins, 'unsupported memory bit test')
            for operand in args:
                function.read_operand(ins, state, operand)
            state['flags'] = {'cf'} | (state['flags'] & {'zf'})
            return True
        if len(args) != 2 or args[0].type != X86_OP_REG:
            function.fail(ins, 'bit operation requires a register destination')
        if op == 'bt':
            if args[0].size not in (2, 4, 8) or args[1].type not in (X86_OP_REG, X86_OP_IMM):
                function.fail(ins, 'unsupported register bit test')
            for operand in args:
                function.read_operand(ins, state, operand)
            state['flags'] = {'cf'} | (state['flags'] & {'zf'})
        else:
            if args[0].size not in (4, 8) or args[1].size != args[0].size:
                function.fail(ins, 'unsupported reset-lowest-bit width')
            if function.reg(ins, args[0])[0] in ('rsp', 'rbp') and not getattr(function, 'uniform', False):
                function.fail(ins, 'bit operation cannot reconstruct a dynamic native frame')
            function.read_operand(ins, state, args[1])
            function.define(ins, state, args[0])
            state['flags'] = {'cf', 'zf', 'sf', 'of'}
        return True
    if op in ('bts', 'btr', 'btc'):
        if len(args) != 2 or args[0].size not in (2, 4, 8) or args[1].type not in (X86_OP_REG, X86_OP_IMM):
            function.fail(ins, 'unsupported bit set/reset operands')
        for operand in args:
            function.read_operand(ins, state, operand)
        function.define(ins, state, args[0])
        state['flags'] = {'cf'}
        return True
    if op in ('bsf', 'bsr'):
        if len(args) != 2 or args[0].type != X86_OP_REG or args[0].size != args[1].size:
            function.fail(ins, 'unsupported bit scan operands')
        function.read_operand(ins, state, args[0])
        function.read_operand(ins, state, args[1])
        function.define(ins, state, args[0])
        state['flags'] = {'zf'}
        return True
    if op in ('cld', 'std') or op.startswith('prefetch'):
        return True
    if op == 'cwde':
        function.check_register(ins, state, 'rax', 16)
        implicit_define(state, 'rax', 32)
        return True
    if op == 'bswap':
        width = args[0].size * 8
        if width not in (32, 64):
            function.fail(ins, 'unsupported byte swap width')
        function.read_operand(ins, state, args[0])
        function.define(ins, state, args[0])
        return True
    if op in ('shld', 'shrd'):
        width = args[0].size * 8
        if width not in (16, 32, 64) or len(args) != 3:
            function.fail(ins, 'unsupported double shift operands')
        for operand in args[:2]:
            function.read_operand(ins, state, operand)
        if args[2].type == X86_OP_IMM:
            function.read_operand(ins, state, args[2])
        function.define(ins, state, args[0])
        state['flags'] = {'cf', 'of', 'zf', 'sf', 'pf'}
        return True
    if op == 'mul' and len(args) == 1:
        width = args[0].size * 8
        function.read_operand(ins, state, args[0])
        function.check_register(ins, state, 'rax', width)
        implicit_define(state, 'rax', width)
        implicit_define(state, 'rdx', width)
        state['flags'] = {'cf', 'of'}
        return True
    if op in ('cdqe', 'cdq', 'cwd', 'cqo'):
        width = {'cdqe': 32, 'cdq': 32, 'cwd': 16, 'cqo': 64}[op]
        function.check_register(ins, state, 'rax', width)
        implicit_define(state, 'rax' if op == 'cdqe' else 'rdx', 64 if op == 'cdqe' else width)
        return True
    if op in ('div', 'idiv'):
        width = args[0].size * 8
        function.read_operand(ins, state, args[0])
        function.check_register(ins, state, 'rax', 16 if width == 8 else width)
        if width != 8:
            function.check_register(ins, state, 'rdx', width)
        implicit_define(state, 'rax', 16 if width == 8 else width)
        if width != 8:
            implicit_define(state, 'rdx', width)
        state['flags'] = set()
        return True
    if args[0].type == X86_OP_REG and function.reg(ins, args[0])[0] in ('rsp', 'rbp'):
        if not getattr(function, 'uniform', False):
            function.fail(ins, 'integer operation cannot reconstruct a dynamic native frame')
        state[function.reg(ins, args[0])[0]] = None
    if op == 'imul' and len(args) == 1:
        width = args[0].size * 8
        function.read_operand(ins, state, args[0])
        function.check_register(ins, state, 'rax', width)
        implicit_define(state, 'rax', width)
        implicit_define(state, 'rdx', width)
        state['flags'] = {'cf', 'of'}
        return True
    if op == 'imul' and len(args) not in (2, 3):
        function.fail(ins, 'one-operand signed multiplication is not implemented')
    reads = args[1:] if op == 'imul' and len(args) == 3 else args
    for operand in reads:
        function.read_operand(ins, state, operand)
    if op in ('adc', 'sbb') and 'cf' not in state['flags']:
        function.fail(ins, 'carry input is not defined')
    if op in ROTATES:
        width = args[0].size * 8
        if len(args) != 2 or width not in (8, 16, 32, 64):
            function.fail(ins, 'unsupported rotate operands')
        dynamic = args[1].type == X86_OP_REG
        if op in ('rcl', 'rcr') and 'cf' not in state['flags']:
            # The carry is an input to the rotation itself, so the destination depends on it.
            function.fail(ins, 'rotate carry input is not defined')
        if args[1].type == X86_OP_IMM:
            count = args[1].imm & (63 if width == 64 else 31)
            if count:
                # ROL/ROR define OF only for a count of one; RCL/RCR are left undefined here.
                defined = {'of'} if count == 1 and op in ('rol', 'ror') else set()
                state['flags'] = (state['flags'] - {'cf', 'of'}) | {'cf'} | defined
        elif dynamic and function.reg(ins, args[1])[0] == 'rcx':
            # A dynamic count is zero sometimes, which leaves CF unchanged, so CF stays defined
            # only if it already was; OF is defined only when the masked count is one.
            function.read_operand(ins, state, args[1])
            state['flags'] = (state['flags'] - {'of'}) | ({'cf'} if 'cf' in state['flags'] else set())
        else:
            function.fail(ins, f'{op} requires an immediate or cl count')
        function.define(ins, state, args[0])
        return True
    if op in SHIFTS:
        width = args[0].size * 8
        if len(args) != 2 or width not in (8, 16, 32, 64):
            function.fail(ins, 'unsupported shift operands')
        if args[1].type == X86_OP_IMM:
            count = args[1].imm & (63 if width == 64 else 31)
            if count == 0:
                if width == 32:
                    function.define(ins, state, args[0])
                return True
            state['flags'] = {'zf', 'sf', 'pf'}
            if count < width or op == 'sar':
                state['flags'].add('cf')
            if count == 1:
                state['flags'].add('of')
        else:
            available = {'zf', 'sf', 'pf'}
            if width >= 32 or op == 'sar':
                available.add('cf')
            state['flags'] = state['flags'] & available
    elif op in ('inc', 'dec'):
        state['flags'] = {'zf', 'sf', 'of', 'pf'} | (state['flags'] & {'cf'})
    elif op == 'imul':
        state['flags'] = {'cf', 'of'}
    elif op != 'not':
        state['flags'] = FLAGS.copy()
    function.define(ins, state, args[0])
    return True


def load_flag(function, name):
    return function.emit(f'load i1, ptr %{name}, align 1')


def store_flag(function, name, value):
    function.lines.append(f'  store i1 {value}, ptr %{name}, align 1')


def extension(function, value, source_width, target_width, signed=False):
    if source_width == target_width:
        return value
    return function.emit(f'{"sext" if signed else "zext"} i{source_width} {value} to i{target_width}')


def lower_shift(function, ins):
    args, op = ins.operands, ins.mnemonic
    width = args[0].size * 8
    mask = 63 if width == 64 else 31
    if args[1].type == X86_OP_IMM and args[1].imm & mask == 0:
        if width == 32:
            function.write(ins, args[0], function.read(ins, args[0]))
        return
    previous = function.states[ins.address]['flags']
    old = {name: load_flag(function, name) if name in previous else 'false' for name in sorted(FLAGS)}
    value = function.read(ins, args[0])
    raw_count = function.read(ins, args[1])
    count_width = args[1].size * 8
    raw_count = function.emit(f'and i{count_width} {raw_count}, {mask}')
    wide = 128 if width == 64 else 64
    count = extension(function, raw_count, count_width, wide)
    zero = function.emit(f'icmp eq i{wide} {count}, 0')
    extended = extension(function, value, width, wide, op == 'sar')
    instruction = {'shl': 'shl', 'sal': 'shl', 'shr': 'lshr', 'sar': 'ashr'}[op]
    shifted = function.emit(f'{instruction} i{wide} {extended}, {count}')
    result = function.emit(f'trunc i{wide} {shifted} to i{width}')
    function.flags('and', width, value, '0', result)
    high = function.emit(f'icmp ult i{wide} {count}, {width + 1}')
    if op in ('shl', 'sal'):
        position = function.emit(f'sub i{wide} {width}, {count}')
        position = function.emit(f'select i1 {high}, i{wide} {position}, i{wide} 0')
        carry_value = function.emit(f'lshr i{wide} {extended}, {position}')
    else:
        position = function.emit(f'sub i{wide} {count}, 1')
        position = function.emit(f'select i1 {zero}, i{wide} 0, i{wide} {position}')
        carry_value = function.emit(f'{instruction} i{wide} {extended}, {position}')
    carry = function.emit(f'trunc i{wide} {carry_value} to i1')
    if op in ('shl', 'sal'):
        sign = function.emit(f'icmp slt i{width} {result}, 0')
        overflow = function.emit(f'xor i1 {sign}, {carry}')
    elif op == 'shr':
        overflow = function.emit(f'icmp slt i{width} {value}, 0')
    else:
        overflow = 'false'
    store_flag(function, 'cf', carry)
    store_flag(function, 'of', overflow)
    for name in sorted(FLAGS):
        current = load_flag(function, name)
        store_flag(function, name, function.emit(f'select i1 {zero}, i1 {old[name]}, i1 {current}'))
    function.write(ins, args[0], result)


def lower_rotate(function, ins):
    args, op = ins.operands, ins.mnemonic
    width = args[0].size * 8
    mask = 63 if width == 64 else 31
    if args[1].type == X86_OP_IMM:
        fixed = args[1].imm & mask
        count = str(fixed)
    else:
        loaded = function.read(ins, args[1], 8)
        loaded = function.emit(f'and i8 {loaded}, {mask}')
        count = loaded if width == 8 else function.emit(f'zext i8 {loaded} to i{width}')
        fixed = None
    value = function.read(ins, args[0])
    if fixed == 0:
        # A zero count is a no-op for the operand and every flag.
        function.write(ins, args[0], value)
        return
    if op in ('rol', 'ror'):
        # A funnel shift is a rotate and takes the count modulo the width, including 0.
        name = 'fshl' if op == 'rol' else 'fshr'
        result = function.emit(f'call i{width} @llvm.{name}.i{width}(i{width} {value}, i{width} {value}, i{width} {count})')
        high = function.emit(f'icmp slt i{width} {result}, 0')
        carry = function.emit(f'trunc i{width} {result} to i1') if op == 'rol' else high
        if fixed is None:
            previous = load_flag(function, 'cf')
            zero = function.emit(f'icmp eq i{width} {count}, 0')
            carry = function.emit(f'select i1 {zero}, i1 {previous}, i1 {carry}')
        store_flag(function, 'cf', carry)
        # OF is defined only for a count of one; the analysis drops it otherwise.
        other = carry if op == 'rol' else function.emit(f'icmp ne i{width} ' +
            function.emit(f'and i{width} {result}, {1 << (width - 2)}') + ', 0')
        store_flag(function, 'of', function.emit(f'xor i1 {high}, {other}'))
    else:
        # Rotate the (width + 1)-bit value (carry:value); CF is the bit rotated back out.
        wide = width + 1
        carry_in = load_flag(function, 'cf')
        extended = function.emit(f'zext i{width} {value} to i{wide}')
        bit = function.emit(f'zext i1 {carry_in} to i{wide}')
        bit = function.emit(f'shl i{wide} {bit}, {width}')
        joined = function.emit(f'or i{wide} {extended}, {bit}')
        wide_count = count if wide == 8 else function.emit(f'zext i{width} {count} to i{wide}')
        name = 'fshl' if op == 'rcl' else 'fshr'
        rotated = function.emit(f'call i{wide} @llvm.{name}.i{wide}(i{wide} {joined}, i{wide} {joined}, i{wide} {wide_count})')
        result = function.emit(f'trunc i{wide} {rotated} to i{width}')
        carry_out = function.emit(f'lshr i{wide} {rotated}, {width}')
        store_flag(function, 'cf', function.emit(f'trunc i{wide} {carry_out} to i1'))
    function.write(ins, args[0], result)


def lower_divide(function, ins):
    operand = ins.operands[0]
    width = operand.size * 8
    signed = ins.mnemonic == 'idiv'
    wide = width * 2
    denominator = function.read(ins, operand)
    low = function.load('rax', 16 if width == 8 else width)
    if width == 8:
        numerator = low
        high = function.emit(f'lshr i16 {low}, 8')
        high = function.emit(f'trunc i16 {high} to i8')
    else:
        high = function.load('rdx', width)
        upper = extension(function, high, width, wide)
        upper = function.emit(f'shl i{wide} {upper}, {width}')
        low = extension(function, low, width, wide)
        numerator = function.emit(f'or i{wide} {upper}, {low}')
    label = f'integer_div_{ins.address:x}_{function.serial}'
    if signed:
        denominator = extension(function, denominator, width, wide, True)
        nonzero = function.emit(f'icmp ne i{wide} {denominator}, 0')
        quotient = function.emit(f'sdiv i{wide} {numerator}, {denominator}')
        truncated = function.emit(f'trunc i{wide} {quotient} to i{width}')
        back = extension(function, truncated, width, wide, True)
        fits = function.emit(f'icmp eq i{wide} {quotient}, {back}')
        valid = function.emit(f'and i1 {nonzero}, {fits}')
        remainder = function.emit(f'srem i{wide} {numerator}, {denominator}')
    else:
        valid = function.emit(f'icmp ult i{width} {high}, {denominator}')
        denominator = extension(function, denominator, width, wide)
        quotient = function.emit(f'udiv i{wide} {numerator}, {denominator}')
        remainder = function.emit(f'urem i{wide} {numerator}, {denominator}')
    function.lines.extend([f'  br i1 {valid}, label %{label}_ok, label %{label}_fault',
                           f'{label}_fault:', '  call void @llvm.trap()', '  unreachable', f'{label}_ok:'])
    quotient = function.emit(f'trunc i{wide} {quotient} to i{width}')
    remainder = function.emit(f'trunc i{wide} {remainder} to i{width}')
    function.store('rax', quotient, width)
    function.store('rax' if width == 8 else 'rdx', remainder, width, 8 if width == 8 else 0)


def lower_stos(function, ins):
    op = ins.mnemonic
    width = 8 if op.endswith('b') else 16 if op.endswith('w') else 32 if op.endswith('d') else 64
    value = function.load('rax', width)
    label = f'rep_{ins.address:x}'
    if op.startswith('rep'):
        function.lines.append(f'  br label %{label}_cond')
        function.lines.append(f'{label}_cond:')
        count = function.emit('load i64, ptr %rcx, align 8')
        done = function.emit(f'icmp eq i64 {count}, 0')
        function.lines.append(f'  br i1 {done}, label %{label}_done, label %{label}_body')
        function.lines.append(f'{label}_body:')
    pointer = function.emit('load i64, ptr %rdi, align 8')
    address = function.emit(f'inttoptr i64 {pointer} to ptr')
    function.lines.append(f'  store i{width} {value}, ptr {address}, align 1')
    advanced = function.emit(f'add i64 {pointer}, {width // 8}')
    function.lines.append(f'  store i64 {advanced}, ptr %rdi, align 8')
    if op.startswith('rep'):
        remaining = function.emit(f'sub i64 {count}, 1')
        function.lines.append(f'  store i64 {remaining}, ptr %rcx, align 8')
        function.lines.append(f'  br label %{label}_cond')
        function.lines.append(f'{label}_done:')
    return True


def lower(function, ins):
    op, args = ins.mnemonic, ins.operands
    conditional = op.startswith(('cmov', 'set'))
    if op == 'crc32':
        width = args[1].size * 8
        if width not in CRC32_INTRINSICS:
            function.fail(ins, 'unsupported crc32 source width')
        accumulator = function.read(ins, args[0], 32)
        source = function.read(ins, args[1], width)
        if width < 32:
            source = function.emit(f'zext i{width} {source} to i32')
        result = function.emit(f'call i32 @llvm.aarch64.{CRC32_INTRINSICS[width]}(i32 {accumulator}, i{max(width, 32)} {source})')
        function.write(ins, args[0], result if args[0].size == 4 else function.emit(f'zext i32 {result} to i64'))
        return True
    if op.startswith('stos') or op.startswith('rep stos'):
        return lower_stos(function, ins)
    if op not in OPERATIONS and not conditional:
        return False
    if conditional:
        predicate = function.condition('j' + condition(ins))
        if op.startswith('set'):
            value = function.emit(f'zext i1 {predicate} to i8')
        else:
            width = args[0].size * 8
            old, new = function.read(ins, args[0]), function.read(ins, args[1])
            value = function.emit(f'select i1 {predicate}, i{width} {new}, i{width} {old}')
        function.write(ins, args[0], value)
    elif op == 'bswap':
        width = args[0].size * 8
        source = function.read(ins, args[0])
        value = '0'
        for index in range(width // 8):
            byte = function.emit(f'lshr i{width} {source}, {index * 8}')
            byte = function.emit(f'and i{width} {byte}, 255')
            byte = function.emit(f'shl i{width} {byte}, {width - 8 - index * 8}')
            value = function.emit(f'or i{width} {value}, {byte}')
        function.write(ins, args[0], value)
    elif op == 'blsr':
        width = args[0].size * 8
        source = function.read(ins, args[1])
        previous = function.emit(f'sub i{width} {source}, 1')
        result = function.emit(f'and i{width} {previous}, {source}')
        function.flags('and', width, source, '0', result)
        store_flag(function, 'cf', function.emit(f'icmp eq i{width} {source}, 0'))
        function.write(ins, args[0], result)
    elif op in ('blsi', 'blsmsk'):
        width = args[0].size * 8
        source = function.read(ins, args[1])
        if op == 'blsi':
            other = function.emit(f'sub i{width} 0, {source}')
            result = function.emit(f'and i{width} {source}, {other}')
            carry = function.emit(f'icmp ne i{width} {source}, 0')
        else:
            other = function.emit(f'sub i{width} {source}, 1')
            result = function.emit(f'xor i{width} {other}, {source}')
            carry = function.emit(f'icmp eq i{width} {source}, 0')
        function.flags('and', width, source, '0', result)
        store_flag(function, 'cf', carry)
        function.write(ins, args[0], result)
    elif op == 'bt':
        width = args[0].size * 8
        if args[0].type == X86_OP_MEM:
            # Bit-string addressing: the operand spans `index // width` further bytes, exactly as
            # the set/reset/complement form below.
            pointer = function.address(ins, args[0])
            base = function.emit(f'ptrtoint ptr {pointer} to i64')
            raw = args[1].imm if args[1].type == X86_OP_IMM else function.read(ins, args[1])
            index = extension(function, raw, args[1].size * 8, 64) if args[1].type != X86_OP_IMM else raw
            shift = function.emit(f'lshr i64 {index}, {width.bit_length() - 1}')
            offset = function.emit(f'mul i64 {shift}, {width // 8}')
            target = function.emit(f'inttoptr i64 {function.emit(f"add i64 {base}, {offset}")} to ptr')
            source = function.emit(f'load i{width}, ptr {target}, align 1')
            masked = function.emit(f'and i64 {index}, {width - 1}')
            bit = masked if width == 64 else function.emit(f'trunc i64 {masked} to i{width}')
        else:
            source = function.read(ins, args[0])
            index = function.read(ins, args[1])
            index_width = args[1].size * 8
            index = function.emit(f'and i{index_width} {index}, {width - 1}')
            bit = extension(function, index, index_width, width)
        shifted = function.emit(f'lshr i{width} {source}, {bit}')
        store_flag(function, 'cf', function.emit(f'trunc i{width} {shifted} to i1'))
    elif op in ('bts', 'btr', 'btc'):
        width = args[0].size * 8
        target = None
        if args[0].type == X86_OP_MEM:
            pointer = function.address(ins, args[0])
            base = function.emit(f'ptrtoint ptr {pointer} to i64')
            raw = args[1].imm if args[1].type == X86_OP_IMM else function.read(ins, args[1])
            index = extension(function, raw, args[1].size * 8, 64) if args[1].type != X86_OP_IMM else raw
            shift = function.emit(f'lshr i64 {index}, {width.bit_length() - 1}')
            offset = function.emit(f'mul i64 {shift}, {width // 8}')
            target = function.emit(f'inttoptr i64 {function.emit(f"add i64 {base}, {offset}")} to ptr')
            source = function.emit(f'load i{width}, ptr {target}, align 1')
            masked = function.emit(f'and i64 {index}, {width - 1}')
            bit = masked if width == 64 else function.emit(f'trunc i64 {masked} to i{width}')
        else:
            source = function.read(ins, args[0])
            if args[1].type == X86_OP_IMM:
                bit = args[1].imm & (width - 1)
            else:
                bit = function.emit(f'and i{args[1].size * 8} {function.read(ins, args[1])}, {width - 1}')
                bit = extension(function, bit, args[1].size * 8, width)
        shifted = function.emit(f'lshr i{width} {source}, {bit}')
        store_flag(function, 'cf', function.emit(f'trunc i{width} {shifted} to i1'))
        mask = function.emit(f'shl i{width} 1, {bit}')
        if op == 'bts':
            result = function.emit(f'or i{width} {source}, {mask}')
        elif op == 'btr':
            result = function.emit(f'and i{width} {source}, {function.emit(f"xor i{width} {mask}, -1")}')
        else:
            result = function.emit(f'xor i{width} {source}, {mask}')
        if target is None:
            function.write(ins, args[0], result)
        else:
            function.lines.append(f'  store i{width} {result}, ptr {target}, align 1')
    elif op in ('bsf', 'bsr'):
        width = args[0].size * 8
        source = function.read(ins, args[1])
        zero = function.emit(f'icmp eq i{width} {source}, 0')
        if op == 'bsf':
            count = function.emit(f'call i{width} @llvm.cttz.i{width}(i{width} {source}, i1 false)')
        else:
            leading = function.emit(f'call i{width} @llvm.ctlz.i{width}(i{width} {source}, i1 false)')
            count = function.emit(f'sub i{width} {width - 1}, {leading}')
        previous = function.read(ins, args[0])
        result = function.emit(f'select i1 {zero}, i{width} {previous}, i{width} {count}')
        store_flag(function, 'zf', zero)
        function.write(ins, args[0], result)
    elif op in ('cld', 'std') or op.startswith('prefetch'):
        return True
    elif op == 'cwde':
        function.store('rax', function.emit(f'sext i16 {function.load("rax", 16)} to i32'), 32)
    elif op == 'bswap':
        width = args[0].size * 8
        function.write(ins, args[0], function.emit(f'call i{width} @llvm.bswap.i{width}(i{width} {function.read(ins, args[0], width)})'))
    elif op in ('shld', 'shrd'):
        width = args[0].size * 8
        mask = width - 1
        value = function.read(ins, args[0])
        source = function.read(ins, args[1])
        if args[2].type == X86_OP_IMM:
            count = args[2].imm & mask
        else:
            count = function.emit(f'and i{args[2].size * 8} {function.read(ins, args[2])}, {mask}')
            count = extension(function, count, args[2].size * 8, width)
        zero = function.emit(f'icmp eq i{width} {count}, 0')
        inverse = function.emit(f'sub i{width} {width}, {count}')
        if op == 'shld':
            shifted = function.emit(f'shl i{width} {value}, {count}')
            fill = function.emit(f'lshr i{width} {source}, {inverse}')
            carry = function.emit(f'lshr i{width} {value}, {inverse}')
        else:
            shifted = function.emit(f'lshr i{width} {value}, {count}')
            fill = function.emit(f'shl i{width} {source}, {inverse}')
            carry = function.emit(f'lshr i{width} {value}, {function.emit(f"sub i{width} {count}, 1")}')
        result = function.emit(f'select i1 {zero}, i{width} {value}, i{width} {function.emit(f"or i{width} {shifted}, {fill}")}')
        store_flag(function, 'cf', function.emit(f'trunc i{width} {carry} to i1'))
        store_flag(function, 'of', 'false')
        function.write(ins, args[0], result)
    elif op == 'mul':
        width = args[0].size * 8
        left = extension(function, function.load('rax', width), width, width * 2)
        right = extension(function, function.read(ins, args[0], width), width, width * 2)
        product = function.emit(f'mul i{width * 2} {left}, {right}')
        low = function.emit(f'trunc i{width * 2} {product} to i{width}')
        high = function.emit(f'trunc i{width * 2} {function.emit(f"lshr i{width * 2} {product}, {width}")} to i{width}')
        overflow = function.emit(f'icmp ne i{width} {high}, 0')
        store_flag(function, 'cf', overflow)
        store_flag(function, 'of', overflow)
        function.store('rax', low, width)
        function.store('rdx', high, width)
    elif op in ('cdqe', 'cdq', 'cwd', 'cqo'):
        width = {'cdqe': 32, 'cdq': 32, 'cwd': 16, 'cqo': 64}[op]
        value = function.load('rax', width)
        if op == 'cdqe':
            function.store('rax', extension(function, value, 32, 64, True))
        else:
            function.store('rdx', function.emit(f'ashr i{width} {value}, {width - 1}'), width)
    elif op in ('div', 'idiv'):
        lower_divide(function, ins)
    elif op in ROTATES:
        lower_rotate(function, ins)
    elif op in SHIFTS:
        lower_shift(function, ins)
    elif op == 'imul':
        width = args[0].size * 8
        if len(args) == 1:
            left = function.load('rax', width)
            right = function.read(ins, args[0], width)
            left = extension(function, left, width, width * 2, True)
            right = extension(function, right, width, width * 2, True)
            product = function.emit(f'mul i{width * 2} {left}, {right}')
            low = function.emit(f'trunc i{width * 2} {product} to i{width}')
            high = function.emit(f'lshr i{width * 2} {product}, {width}')
            high = function.emit(f'trunc i{width * 2} {high} to i{width}')
            sign = function.emit(f'ashr i{width} {low}, {width - 1}')
            overflow = function.emit(f'icmp ne i{width} {high}, {sign}')
            store_flag(function, 'cf', overflow)
            store_flag(function, 'of', overflow)
            function.store('rax', low, width)
            function.store('rdx', high, width)
            return True
        left, right = args if len(args) == 2 else args[1:]
        left = extension(function, function.read(ins, left), width, width * 2, True)
        right = extension(function, function.read(ins, right, width), width, width * 2, True)
        product = function.emit(f'mul i{width * 2} {left}, {right}')
        result = function.emit(f'trunc i{width * 2} {product} to i{width}')
        check = extension(function, result, width, width * 2, True)
        overflow = function.emit(f'icmp ne i{width * 2} {product}, {check}')
        store_flag(function, 'cf', overflow)
        store_flag(function, 'of', overflow)
        function.write(ins, args[0], result)
    else:
        width = args[0].size * 8
        left = function.read(ins, args[0])
        if op == 'not':
            value = function.emit(f'xor i{width} {left}, -1')
        elif op == 'neg':
            value = function.emit(f'sub i{width} 0, {left}')
            function.flags('sub', width, '0', left, value)
        elif op in ('inc', 'dec'):
            old = load_flag(function, 'cf') if 'cf' in function.states[ins.address]['flags'] else 'false'
            instruction = 'add' if op == 'inc' else 'sub'
            value = function.emit(f'{instruction} i{width} {left}, 1')
            function.flags(instruction, width, left, '1', value)
            store_flag(function, 'cf', old)
        else:
            right = function.read(ins, args[1], width)
            carry = load_flag(function, 'cf')
            wide = width + 1
            lhs = extension(function, left, width, wide)
            rhs = extension(function, right, width, wide)
            rhs = function.emit(f'add i{wide} {rhs}, {extension(function, carry, 1, wide)}')
            instruction = 'add' if op == 'adc' else 'sub'
            result = function.emit(f'{instruction} i{wide} {lhs}, {rhs}')
            value = function.emit(f'trunc i{wide} {result} to i{width}')
            if op == 'adc':
                new_carry = function.emit(f'lshr i{wide} {result}, {width}')
                new_carry = function.emit(f'trunc i{wide} {new_carry} to i1')
            else:
                new_carry = function.emit(f'icmp ult i{wide} {lhs}, {rhs}')
            function.flags(instruction, width, left, right, value)
            store_flag(function, 'cf', new_carry)
        function.write(ins, args[0], value)
    return True

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


FULL_MOVES = {'movups', 'movaps', 'movupd', 'movapd', 'movdqu', 'movdqa'}
BITWISE = {'xorps': 'xor', 'xorpd': 'xor', 'pxor': 'xor', 'andps': 'and', 'andpd': 'and',
           'pand': 'and', 'orps': 'or', 'orpd': 'or', 'por': 'or', 'pandn': 'andnot',
           'andnps': 'andnot', 'andnpd': 'andnot'}
FLOAT_OPS = {'addps': ('fadd', 128), 'mulps': ('fmul', 128), 'subps': ('fsub', 128),
             'addpd': ('fadd', 128), 'mulpd': ('fmul', 128), 'subpd': ('fsub', 128), 'divpd': ('fdiv', 128),
             'addss': ('fadd', 32), 'mulss': ('fmul', 32), 'subss': ('fsub', 32),
             'addsd': ('fadd', 64), 'mulsd': ('fmul', 64), 'subsd': ('fsub', 64),
             'divss': ('fdiv', 32), 'divsd': ('fdiv', 64)}
SQRT_OPS = {'sqrtss': 32, 'sqrtsd': 64}
CONVERTS = {'cvtsi2ss': 32, 'cvtsi2sd': 64, 'cvtsd2ss': 64, 'cvtss2sd': 32}
TO_INT = {'cvttss2si': 32, 'cvttsd2si': 64, 'cvtss2si': 32, 'cvtsd2si': 64}
COMPARES = {'comiss': 32, 'ucomiss': 32, 'comisd': 64, 'ucomisd': 64}
PACKED_CMPEQ = {'pcmpeqb': 8, 'pcmpeqw': 16, 'pcmpeqd': 32, 'pcmpeqq': 64}
PACKED_CMPGT = {'pcmpgtb': 8, 'pcmpgtw': 16, 'pcmpgtd': 32, 'pcmpgtq': 64}
PACKED_MINMAX = {'minps': (32, True), 'maxps': (32, False), 'minpd': (64, True), 'maxpd': (64, False),
                 'minss': (32, True), 'maxss': (32, False), 'minsd': (64, True), 'maxsd': (64, False)}
PACKED_UNPACKS = {'punpcklbw': (8, 0), 'punpckhbw': (8, 1), 'punpcklwd': (16, 0), 'punpckhwd': (16, 1),
                  'punpckldq': (32, 0), 'punpckhdq': (32, 1), 'punpcklqdq': (64, 0), 'punpckhqdq': (64, 1)}
CMP_PREDICATES = ['eq', 'lt', 'le', 'unord', 'neq', 'nlt', 'nle', 'ord', 'eq_uq', 'nge', 'ngt',
                  'false', 'neq_oq', 'ge', 'gt', 'true', 'eq_os', 'lt_oq', 'le_oq', 'unord_s',
                  'neq_us', 'nlt_uq', 'nle_uq', 'ord_s', 'eq_us', 'nge_uq', 'ngt_uq', 'false_os',
                  'neq_os', 'ge_oq', 'gt_oq', 'true_us']
CMP_LLVM = ['oeq', 'olt', 'ole', 'uno', 'une', 'uge', 'ugt', 'ord', 'ueq', 'ult', 'ule',
            'false', 'one', 'oge', 'ogt', 'true', 'oeq', 'olt', 'ole', 'uno', 'une', 'uge',
            'ugt', 'ord', 'ueq', 'ult', 'ule', 'false', 'one', 'oge', 'ogt', 'true']
CVT_PACKED = {'cvtdq2pd': (32, 64, 2, 'sitofp'), 'cvtpd2dq': (64, 32, 2, 'fptosi'),
              'cvttpd2dq': (64, 32, 2, 'trunc'), 'cvtpd2ps': (64, 32, 2, 'fptrunc'),
              'cvtps2pd': (32, 64, 2, 'fpext'), 'cvtdq2ps': (32, 32, 4, 'sitofp'),
              'cvtps2dq': (32, 32, 4, 'fptosi'), 'cvttps2dq': (32, 32, 4, 'trunc')}
CMP_GENERIC = {'cmpps': 32, 'cmppd': 64, 'cmpss': 32, 'cmpsd': 64}
CMP_MNEMONICS = {f'cmp{suffix}{kind}': (lane, index)
                 for index, suffix in enumerate(CMP_PREDICATES)
                 for kind, lane in (('ps', 32), ('pd', 64), ('ss', 32), ('sd', 64))}
SHUFFLES = {'shufps', 'pshufd', 'unpcklps', 'unpckhps', 'unpcklpd', 'unpckhpd',
            'punpcklqdq', 'punpckhqdq', 'movlhps', 'movhlps'}
SUPPORTED = (FULL_MOVES | set(BITWISE) | set(FLOAT_OPS) | SHUFFLES | set(SQRT_OPS)
             | set(CONVERTS) | set(TO_INT) | set(COMPARES) | set(PACKED_CMPEQ) | set(PACKED_CMPGT)
             | set(PACKED_MINMAX) | set(PACKED_UNPACKS) | set(CMP_MNEMONICS) | set(CMP_GENERIC)
             | set(CVT_PACKED) | {
    'movd', 'movq', 'movss', 'movsd', 'movlps', 'movlpd', 'psrld', 'paddd', 'pcmpgtd',
    'packuswb'})
FP_POLICY = {'rounding': 'nearest-even', 'subnormals': 'preserve', 'exceptions': 'masked',
             'status_flags': 'unobserved', 'nan_payloads': 'unobserved'}
MASK128 = (1 << 128) - 1


def _xmm(ins, operand):
    return operand.type == X86_OP_REG and ins.reg_name(operand.reg).startswith('xmm')


def _check(function, ins, state, operand, bits, shift=0):
    if operand.type == X86_OP_REG:
        name = ins.reg_name(operand.reg)
        if _xmm(ins, operand):
            function.check_register(ins, state, name, bits, shift)
        else:
            if bits > operand.size * 8 or shift:
                function.fail(ins, 'unsupported vector source register')
            function.read_operand(ins, state, operand)
    elif operand.type == X86_OP_MEM:
        function.read_operand(ins, state, operand)
    else:
        function.fail(ins, 'invalid vector source')


def _define(function, ins, state, operand, bits=128, zero_upper=False):
    if _xmm(ins, operand):
        name = ins.reg_name(operand.reg)
        state['known'][name] = MASK128 if zero_upper else state['known'].get(name, 0) | ((1 << bits) - 1)
    elif operand.type == X86_OP_MEM:
        function.define(ins, state, operand)
    elif operand.type == X86_OP_REG and bits <= 64:
        function.define(ins, state, operand)
    else:
        function.fail(ins, 'unsupported vector destination')


def _mask(function, ins, state, operand):
    if _xmm(ins, operand):
        return state['known'].get(ins.reg_name(operand.reg), 0)
    if operand.type == X86_OP_MEM:
        function.read_operand(ins, state, operand)
        return (1 << (operand.size * 8)) - 1
    _check(function, ins, state, operand, operand.size * 8)
    return (1 << (operand.size * 8)) - 1


def _copy_mask(ins, state, destination, source_mask, bits=128, zero_upper=False):
    name = ins.reg_name(destination.reg)
    low = (1 << bits) - 1
    high = MASK128 ^ low
    previous = MASK128 if zero_upper else state['known'].get(name, 0)
    state['known'][name] = (previous & high) | (source_mask & low)


def _complete_lanes(mask, width, result_width=None):
    result_width = width if result_width is None else result_width
    result = 0
    lane = (1 << width) - 1
    for index in range(128 // width):
        if (mask >> (index * width)) & lane == lane:
            result |= ((1 << result_width) - 1) << (index * result_width)
    return result


def _policy(function, ins):
    if any(function.contract.get('floating_point', {}).get(key) != value for key, value in FP_POLICY.items()):
        function.fail(ins, 'floating-point instructions require the validated native floating_point profile')


def _shuffle(ins):
    op, args = ins.mnemonic, ins.operands
    if op == 'shufps':
        control = args[2].imm
        return 32, [control & 3, (control >> 2) & 3, 4 + ((control >> 4) & 3), 4 + ((control >> 6) & 3)]
    if op == 'pshufd':
        return 32, [(args[2].imm >> (index * 2)) & 3 for index in range(4)]
    if op in ('unpcklps', 'unpckhps'):
        offset = 0 if op == 'unpcklps' else 2
        return 32, [offset, offset + 4, offset + 1, offset + 5]
    if op in ('unpcklpd', 'punpcklqdq', 'movlhps'):
        return 64, [0, 2]
    if op == 'movhlps':
        return 64, [3, 1]
    return 64, [1, 3]


def analyze(function, ins, state):
    op, args = ins.mnemonic, ins.operands
    if op not in SUPPORTED:
        return False
    if not any(_xmm(ins, operand) for operand in args):
        return False
    if op in FULL_MOVES:
        if _xmm(ins, args[0]):
            _copy_mask(ins, state, args[0], _mask(function, ins, state, args[1]))
        else:
            _check(function, ins, state, args[1], 128)
            _define(function, ins, state, args[0])
    elif op in ('movd', 'movq', 'movss', 'movsd', 'movlps', 'movlpd'):
        bits = 32 if op in ('movd', 'movss') else 64
        zero = op in ('movd', 'movq') or (op in ('movss', 'movsd') and args[1].type == X86_OP_MEM)
        if _xmm(ins, args[0]):
            _copy_mask(ins, state, args[0], _mask(function, ins, state, args[1]), bits, zero)
        else:
            _check(function, ins, state, args[1], bits)
            _define(function, ins, state, args[0], bits, zero)
    elif op in BITWISE:
        zero = BITWISE[op] in ('xor', 'andnot') and args[0].type == args[1].type == X86_OP_REG and args[0].reg == args[1].reg
        known = MASK128 if zero else _mask(function, ins, state, args[0]) & _mask(function, ins, state, args[1])
        _copy_mask(ins, state, args[0], known)
    elif op in SHUFFLES:
        width, mask = _shuffle(ins)
        count = 128 // width
        sources = [_mask(function, ins, state, args[1] if op == 'pshufd' else args[0]),
                   _mask(function, ins, state, args[1])]
        lane_mask = (1 << width) - 1
        known = 0
        for lane, index in enumerate(mask):
            source_mask = sources[1 if index >= count else 0]
            known |= ((source_mask >> ((index % count) * width)) & lane_mask) << (lane * width)
        _copy_mask(ins, state, args[0], known)
    elif op == 'psrld':
        known = _mask(function, ins, state, args[0])
        if args[1].type == X86_OP_IMM:
            count = args[1].imm
            if count > 31:
                known = MASK128
            else:
                lane = (1 << 32) - 1
                result = 0
                for index in range(4):
                    defined = ((known >> (index * 32)) & lane) >> count
                    result |= (defined | (lane ^ (lane >> count))) << (index * 32)
                known = result
        else:
            _check(function, ins, state, args[1], 64)
            known = _complete_lanes(known, 32)
        _copy_mask(ins, state, args[0], known)
    elif op in ('paddd', 'pcmpgtd', 'packuswb'):
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        if op == 'packuswb':
            known = _complete_lanes(left, 16, 8) | (_complete_lanes(right, 16, 8) << 64)
        else:
            known = _complete_lanes(left & right, 32)
        _copy_mask(ins, state, args[0], known)
    elif op in PACKED_CMPEQ or op in PACKED_CMPGT:
        lane = (PACKED_CMPEQ | PACKED_CMPGT)[op]
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        _copy_mask(ins, state, args[0], _complete_lanes(left & right, lane, lane))
    elif op in PACKED_UNPACKS:
        width, high = PACKED_UNPACKS[op]
        count = 128 // width
        sources = [_mask(function, ins, state, args[0]), _mask(function, ins, state, args[1])]
        lane_mask = (1 << width) - 1
        known = 0
        for lane in range(count):
            source = 1 if lane % 2 else 0
            source_lane = (count // 2 + lane // 2) if high else (lane // 2)
            known |= ((sources[source] >> (source_lane * width)) & lane_mask) << (lane * width)
        _copy_mask(ins, state, args[0], known)
    elif op in PACKED_MINMAX:
        lane, _is_min = PACKED_MINMAX[op]
        if op.endswith(('ss', 'sd')):
            _policy(function, ins)
            _check(function, ins, state, args[0], lane)
            _check(function, ins, state, args[1], lane)
            _define(function, ins, state, args[0], lane)
        else:
            left, right = (_mask(function, ins, state, operand) for operand in args[:2])
            _copy_mask(ins, state, args[0], _complete_lanes(left & right, lane))
    elif op in CVT_PACKED:
        _policy(function, ins)
        source_bits, target_bits, count, _kind = CVT_PACKED[op]
        _check(function, ins, state, args[1], count * source_bits)
        _define(function, ins, state, args[0], count * target_bits, zero_upper=(count * target_bits < 128))
    elif op in CMP_MNEMONICS or op in CMP_GENERIC:
        _policy(function, ins)
        lane = CMP_GENERIC[op] if op in CMP_GENERIC else CMP_MNEMONICS[op][0]
        if op.endswith(('ss', 'sd')):
            _check(function, ins, state, args[0], lane)
            _check(function, ins, state, args[1], lane)
            _define(function, ins, state, args[0], lane)
        else:
            left, right = (_mask(function, ins, state, operand) for operand in args[:2])
            _copy_mask(ins, state, args[0], _complete_lanes(left & right, lane, lane))
    elif op in FLOAT_OPS:
        _policy(function, ins)
        bits = FLOAT_OPS[op][1]
        if bits == 128:
            left, right = (_mask(function, ins, state, operand) for operand in args[:2])
            _copy_mask(ins, state, args[0], _complete_lanes(left & right, 64 if op.endswith(('pd', 'sd')) else 32))
        else:
            _check(function, ins, state, args[0], bits)
            _check(function, ins, state, args[1], bits)
            _define(function, ins, state, args[0], bits)
    elif op in SQRT_OPS:
        _policy(function, ins)
        _check(function, ins, state, args[1], SQRT_OPS[op])
        _define(function, ins, state, args[0], SQRT_OPS[op])
    elif op in CONVERTS:
        _policy(function, ins)
        if op in ('cvtsi2ss', 'cvtsi2sd'):
            _check(function, ins, state, args[1], args[1].size * 8)
            _define(function, ins, state, args[0], CONVERTS[op])
        elif op == 'cvtsd2ss':
            _check(function, ins, state, args[1], 64)
            _define(function, ins, state, args[0], 32)
        else:
            _check(function, ins, state, args[1], 32)
            _define(function, ins, state, args[0], 64)
    elif op in TO_INT:
        _policy(function, ins)
        _check(function, ins, state, args[1], TO_INT[op])
        function.define(ins, state, args[0])
    elif op in COMPARES:
        _policy(function, ins)
        _check(function, ins, state, args[0], COMPARES[op])
        _check(function, ins, state, args[1], COMPARES[op])
        state['flags'] = {'cf', 'zf', 'pf', 'of', 'sf'}
    return True


def _write(function, ins, operand, value, bits=128, zero_upper=False):
    if _xmm(ins, operand):
        function.store_vector(ins.reg_name(operand.reg), value, bits, zero_upper)
    else:
        function.write(ins, operand, value)


def _cast(function, value, bits, kind):
    return function.emit(f'bitcast i{bits} {value} to {kind}')


def _unpack(function, value, width=32):
    return _cast(function, value, 128, f'<{128 // width} x i{width}>')


def _pack(function, value, width=32):
    return function.emit(f'bitcast <{128 // width} x i{width}> {value} to i128')


def lower(function, ins):
    op, args = ins.mnemonic, ins.operands
    if op not in SUPPORTED or not any(_xmm(ins, operand) for operand in args):
        return False
    read = lambda operand, bits=128: function.read(ins, operand, bits)
    if op in ('movaps', 'movapd', 'movdqa'):
        for operand in args:
            if operand.type == X86_OP_MEM:
                address = function.emit(f'ptrtoint ptr {function.address(ins, operand)} to i64')
                low = function.emit(f'and i64 {address}, 15')
                aligned = function.emit(f'icmp eq i64 {low}, 0')
                label = aligned[1:]
                function.lines.extend([f'  br i1 {aligned}, label %{label}_aligned, label %{label}_misaligned',
                                       f'{label}_misaligned:', '  call void @llvm.trap()', '  unreachable', f'{label}_aligned:'])
    if op in FULL_MOVES:
        _write(function, ins, args[0], read(args[1]))
    elif op in ('movd', 'movq', 'movss', 'movsd', 'movlps', 'movlpd'):
        bits = 32 if op in ('movd', 'movss') else 64
        zero = op in ('movd', 'movq') or (op in ('movss', 'movsd') and args[1].type == X86_OP_MEM)
        _write(function, ins, args[0], read(args[1], bits), bits, zero)
    elif op in BITWISE:
        instruction = BITWISE[op]
        zero = instruction in ('xor', 'andnot') and args[0].type == args[1].type == X86_OP_REG and args[0].reg == args[1].reg
        if zero:
            value = '0'
        else:
            left, right = read(args[0]), read(args[1])
            if instruction == 'andnot':
                left = function.emit(f'xor i128 {left}, -1')
                instruction = 'and'
            value = function.emit(f'{instruction} i128 {left}, {right}')
        _write(function, ins, args[0], value)
    elif op in SHUFFLES:
        width, mask = _shuffle(ins)
        count = 128 // width
        left = _unpack(function, read(args[1] if op == 'pshufd' else args[0]), width)
        right = left if op == 'pshufd' else _unpack(function, read(args[1]), width)
        indices = ', '.join(f'i32 {index}' for index in mask)
        result = function.emit(f'shufflevector <{count} x i{width}> {left}, <{count} x i{width}> {right}, <{count} x i32> <{indices}>')
        _write(function, ins, args[0], _pack(function, result, width))
    elif op == 'psrld':
        left = _unpack(function, read(args[0]))
        count = str(args[1].imm) if args[1].type == X86_OP_IMM else read(args[1], 64)
        valid = function.emit(f'icmp ult i64 {count}, 32')
        limited = function.emit(f'and i64 {count}, 31')
        narrow = function.emit(f'trunc i64 {limited} to i32')
        lane = function.emit(f'insertelement <4 x i32> zeroinitializer, i32 {narrow}, i32 0')
        counts = function.emit(f'shufflevector <4 x i32> {lane}, <4 x i32> zeroinitializer, <4 x i32> zeroinitializer')
        shifted = function.emit(f'lshr <4 x i32> {left}, {counts}')
        result = function.emit(f'select i1 {valid}, <4 x i32> {shifted}, <4 x i32> zeroinitializer')
        _write(function, ins, args[0], _pack(function, result))
    elif op in ('paddd', 'pcmpgtd'):
        left, right = (_unpack(function, read(operand)) for operand in args[:2])
        if op == 'paddd':
            result = function.emit(f'add <4 x i32> {left}, {right}')
        else:
            mask = function.emit(f'icmp sgt <4 x i32> {left}, {right}')
            result = function.emit(f'sext <4 x i1> {mask} to <4 x i32>')
        _write(function, ins, args[0], _pack(function, result))
    elif op in PACKED_CMPEQ or op in PACKED_CMPGT:
        lane = (PACKED_CMPEQ | PACKED_CMPGT)[op]
        count = 128 // lane
        kind = f'<{count} x i{lane}>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        compare = function.emit(f'icmp {"eq" if op in PACKED_CMPEQ else "sgt"} {kind} {left}, {right}')
        result = function.emit(f'sext <{count} x i1> {compare} to {kind}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op in PACKED_UNPACKS:
        width, high = PACKED_UNPACKS[op]
        count = 128 // width
        kind = f'<{count} x i{width}>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        indices = []
        for lane in range(count):
            source_lane = (count // 2 + lane // 2) if high else (lane // 2)
            indices.append(source_lane + (0 if lane % 2 == 0 else count))
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {kind} {left}, {kind} {right}, <{count} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op in PACKED_MINMAX:
        lane, is_min = PACKED_MINMAX[op]
        predicate = 'olt' if is_min else 'ogt'
        if op.endswith(('ss', 'sd')):
            kind = 'float' if lane == 32 else 'double'
            left = function.emit(f'bitcast i{lane} {read(args[0], lane)} to {kind}')
            right = function.emit(f'bitcast i{lane} {read(args[1], lane)} to {kind}')
            compare = function.emit(f'fcmp {predicate} {kind} {left}, {right}')
            result = function.emit(f'select i1 {compare}, {kind} {left}, {kind} {right}')
            _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i{lane}'), lane)
        else:
            count = 128 // lane
            kind = f'<{count} x {"float" if lane == 32 else "double"}>'
            left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
            right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
            compare = function.emit(f'fcmp {predicate} {kind} {left}, {right}')
            result = function.emit(f'select <{count} x i1> {compare}, {kind} {left}, {kind} {right}')
            _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op in CVT_PACKED:
        source_bits, target_bits, count, kind = CVT_PACKED[op]
        source = f'<{count} x {"float" if source_bits == 32 else "double"}>' if source_bits in (32, 64) else None
        if kind == 'sitofp':
            source = f'<{count} x i{source_bits}>'
            value = function.emit(f'bitcast i{count * source_bits} {read(args[1], count * source_bits)} to {source}')
            result = function.emit(f'sitofp {source} {value} to <{count} x {"float" if target_bits == 32 else "double"}>')
            packed = function.emit(f'bitcast <{count} x {"float" if target_bits == 32 else "double"}> {result} to i{count * target_bits}')
        elif kind == 'fpext':
            value = function.emit(f'bitcast i{count * source_bits} {read(args[1], count * source_bits)} to <{count} x float>')
            result = function.emit(f'fpext <{count} x float> {value} to <{count} x double>')
            packed = function.emit(f'bitcast <{count} x double> {result} to i{count * target_bits}')
        elif kind == 'fptrunc':
            value = function.emit(f'bitcast i{count * source_bits} {read(args[1], count * source_bits)} to <{count} x double>')
            result = function.emit(f'fptrunc <{count} x double> {value} to <{count} x float>')
            packed = function.emit(f'bitcast <{count} x float> {result} to i{count * target_bits}')
        else:
            source_kind = 'float' if source_bits == 32 else 'double'
            value = function.emit(f'bitcast i{count * source_bits} {read(args[1], count * source_bits)} to <{count} x {source_kind}>')
            if kind == 'fptosi':
                value = function.emit(f'call <{count} x {source_kind}> @llvm.rint.v{count}f{source_bits}(<{count} x {source_kind}> {value})')
            low, high = -2147483648.0, 2147483648.0
            below = function.emit(f'fcmp oge <{count} x {source_kind}> {value}, <{", ".join([f"{source_kind} {low}"] * count)}>')
            above = function.emit(f'fcmp olt <{count} x {source_kind}> {value}, <{", ".join([f"{source_kind} {high}"] * count)}>')
            in_range = function.emit(f'and <{count} x i1> {below}, {above}')
            clamped = function.emit(f'select <{count} x i1> {in_range}, <{count} x {source_kind}> {value}, <{count} x {source_kind}> zeroinitializer')
            converted = function.emit(f'fptosi <{count} x {source_kind}> {clamped} to <{count} x i32>')
            indefinite = '<' + ', '.join(['i32 -2147483648'] * count) + '>'
            result = function.emit(f'select <{count} x i1> {in_range}, <{count} x i32> {converted}, <{count} x i32> {indefinite}')
            packed = function.emit(f'bitcast <{count} x i32> {result} to i{count * target_bits}')
        _write(function, ins, args[0], packed, count * target_bits, zero_upper=(count * target_bits < 128))
    elif op in CMP_MNEMONICS or op in CMP_GENERIC:
        _policy(function, ins)
        if op in CMP_GENERIC:
            lane, index = CMP_GENERIC[op], args[2].imm & 0x07
        else:
            lane, index = CMP_MNEMONICS[op]
        predicate = CMP_LLVM[index]
        if op.endswith(('ss', 'sd')):
            kind = 'float' if lane == 32 else 'double'
            left = function.emit(f'bitcast i{lane} {read(args[0], lane)} to {kind}')
            right = function.emit(f'bitcast i{lane} {read(args[1], lane)} to {kind}')
            compare = function.emit(f'fcmp {predicate} {kind} {left}, {right}')
            mask = function.emit(f'sext i1 {compare} to i{lane}')
            base = function.emit(f'bitcast i128 {read(args[0])} to <{128 // lane} x i{lane}>')
            merged = function.emit(f'insertelement <{128 // lane} x i{lane}> {base}, i{lane} {mask}, i32 0')
            _write(function, ins, args[0], function.emit(f'bitcast <{128 // lane} x i{lane}> {merged} to i128'))
        else:
            count = 128 // lane
            kind = f'<{count} x {"float" if lane == 32 else "double"}>'
            left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
            right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
            compare = function.emit(f'fcmp {predicate} {kind} {left}, {right}')
            result = function.emit(f'sext <{count} x i1> {compare} to <{count} x i{lane}>')
            _write(function, ins, args[0], function.emit(f'bitcast <{count} x i{lane}> {result} to i128'))
    elif op == 'packuswb':
        values = []
        limit = '<' + ', '.join(['i16 255'] * 8) + '>'
        for operand in args[:2]:
            value = _unpack(function, read(operand), 16)
            negative = function.emit(f'icmp slt <8 x i16> {value}, zeroinitializer')
            above = function.emit(f'icmp sgt <8 x i16> {value}, {limit}')
            low = function.emit(f'select <8 x i1> {negative}, <8 x i16> zeroinitializer, <8 x i16> {value}')
            clipped = function.emit(f'select <8 x i1> {above}, <8 x i16> {limit}, <8 x i16> {low}')
            values.append(function.emit(f'trunc <8 x i16> {clipped} to <8 x i8>'))
        indices = ', '.join(f'i32 {i}' for i in range(16))
        combined = function.emit(f'shufflevector <8 x i8> {values[0]}, <8 x i8> {values[1]}, <16 x i32> <{indices}>')
        _write(function, ins, args[0], function.emit(f'bitcast <16 x i8> {combined} to i128'))
    elif op in FLOAT_OPS:
        instruction, bits = FLOAT_OPS[op]
        element = 'double' if op.endswith(('pd', 'sd')) else 'float'
        kind = f'<{bits // (64 if element == "double" else 32)} x {element}>' if bits == 128 else element
        left, right = (_cast(function, read(operand, bits), bits, kind) for operand in args[:2])
        result = function.emit(f'{instruction} {kind} {left}, {right}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in SQRT_OPS:
        lane = SQRT_OPS[op]
        kind = 'float' if lane == 32 else 'double'
        scalar = function.emit(f'bitcast i{lane} {read(args[1], lane)} to {kind}')
        root = function.emit(f'call {kind} @llvm.sqrt.{"f32" if lane == 32 else "f64"}({kind} {scalar})')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {root} to i{lane}'), lane)
    elif op in CONVERTS:
        if op in ('cvtsi2ss', 'cvtsi2sd'):
            bits = args[1].size * 8
            lane = CONVERTS[op]
            kind = 'float' if lane == 32 else 'double'
            value = function.emit(f'sitofp i{bits} {read(args[1], bits)} to {kind}')
            _write(function, ins, args[0], function.emit(f'bitcast {kind} {value} to i{lane}'), lane)
        elif op == 'cvtsd2ss':
            value = function.emit(f'fptrunc double {function.emit(f"bitcast i64 {read(args[1], 64)} to double")} to float')
            _write(function, ins, args[0], function.emit(f'bitcast float {value} to i32'), 32)
        else:
            value = function.emit(f'fpext float {function.emit(f"bitcast i32 {read(args[1], 32)} to float")} to double')
            _write(function, ins, args[0], function.emit(f'bitcast double {value} to i64'), 64)
    elif op in TO_INT:
        lane = TO_INT[op]
        kind = 'float' if lane == 32 else 'double'
        dest_bits = args[0].size * 8
        scalar = function.emit(f'bitcast i{lane} {read(args[1], lane)} to {kind}')
        if op in ('cvtss2si', 'cvtsd2si'):
            scalar = function.emit(f'call {kind} @llvm.rint.{"f32" if lane == 32 else "f64"}({kind} {scalar})')
        low, high = (-2147483648.0, 2147483648.0) if dest_bits == 32 else (-9223372036854775808.0, 9223372036854775808.0)
        above = function.emit(f'fcmp oge {kind} {scalar}, {low}')
        below = function.emit(f'fcmp olt {kind} {scalar}, {high}')
        in_range = function.emit(f'and i1 {above}, {below}')
        clamped = function.emit(f'select i1 {in_range}, {kind} {scalar}, {kind} 0.000000e+00')
        converted = function.emit(f'fptosi {kind} {clamped} to i{dest_bits}')
        result = function.emit(f'select i1 {in_range}, i{dest_bits} {converted}, i{dest_bits} {-2 ** (dest_bits - 1)}')
        _write(function, ins, args[0], result, dest_bits)
    elif op in COMPARES:
        lane = COMPARES[op]
        kind = 'float' if lane == 32 else 'double'
        left, right = (_cast(function, read(operand, lane), lane, kind) for operand in args[:2])
        flags = {name: function.emit(f'fcmp {predicate} {kind} {left}, {right}')
                 for name, predicate in [('zf', 'ueq'), ('pf', 'uno'), ('cf', 'ult')]}
        flags.update({'of': 'false', 'sf': 'false'})
        for name, value in flags.items():
            function.lines.append(f'  store i1 {value}, ptr %{name}, align 1')
    return True

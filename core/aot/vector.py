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
PACKED_BINARY = {'paddb': ('add', 8), 'paddw': ('add', 16), 'paddq': ('add', 64), 'psubw': ('sub', 16),
                 'psubd': ('sub', 32), 'psubq': ('sub', 64)}
PACKED_MINMAX_INT = {'pmaxub': (8, False), 'pminub': (8, True), 'pmaxuw': (16, False), 'pminuw': (16, True)}
PACKED_MUL = {'pmuludq': False, 'pmuldq': True}
MADD = {'pmaddwd'}
PEXTR = {'pextrb': 8, 'pextrw': 16, 'pextrd': 32, 'pextrq': 64}
PINS = {'pinsrb': 8, 'pinsrw': 16, 'pinsrd': 32, 'pinsrq': 64}
BLENDS_IMM = {'pblendw': 16, 'blendps': 32, 'blendpd': 64}
PACKS = {'packsswb': (16, 8), 'packssdw': (32, 16)}
SHUF_WORDS = {'pshuflw', 'pshufhw'}
DUPS = {'movshdup': 32, 'movsldup': 32, 'movddup': 64}
PACKED_SHIFTS = {'psrlw': ('lshr', 16), 'psrld': ('lshr', 32), 'psrlq': ('lshr', 64),
                 'psraw': ('ashr', 16), 'psrad': ('ashr', 32), 'psllw': ('shl', 16),
                 'pslld': ('shl', 32), 'psllq': ('shl', 64)}
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
            'punpcklbw', 'punpcklwd', 'punpcklqdq', 'punpckhqdq', 'movlhps', 'movhlps'}
PACKED_SAT = {'paddsb': ('sadd.sat', 8), 'paddsw': ('sadd.sat', 16),
              'paddusb': ('uadd.sat', 8), 'paddusw': ('uadd.sat', 16),
              'psubsb': ('ssub.sat', 8), 'psubsw': ('ssub.sat', 16),
              'psubusb': ('usub.sat', 8), 'psubusw': ('usub.sat', 16)}
SUPPORTED = (FULL_MOVES | set(BITWISE) | set(FLOAT_OPS) | SHUFFLES | set(SQRT_OPS)
             | set(CONVERTS) | set(TO_INT) | set(COMPARES) | set(PACKED_SHIFTS) | set(PACKED_BINARY) | set(PACKED_MINMAX_INT) | set(PACKED_MUL)
             | set(PACKS) | SHUF_WORDS | set(PACKED_CMPEQ) | set(PACKED_CMPGT)
             | set(PACKED_MINMAX) | set(PACKED_UNPACKS) | set(CMP_MNEMONICS) | set(CMP_GENERIC)
             | set(CVT_PACKED) | set(DUPS) | set(PACKED_SAT) | {
    'movhpd', 'pshufb', 'pmaddubsw', 'pmaddwd', 'pblendw', 'blendps', 'blendpd',
    'pextrb', 'pextrw', 'pextrd', 'pextrq', 'pinsrb', 'pinsrw', 'pinsrd', 'pinsrq',
    'movd', 'movq', 'movss', 'movsd', 'movlps', 'movlpd', 'psrld', 'paddd', 'pcmpgtd',
    'packuswb', 'ucomiss', 'cvtsi2ss', 'paddb', 'pmaxub', 'pcmpeqb', 'pcmpeqd', 'psrad', 'movmskps',
    'pextrw', 'pmulhw', 'psadbw', 'phminposuw', 'pslldq', 'psrldq'})
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
    # The profile may be declared per function or once for the whole image.
    profile = function.contract.get('floating_point')
    if profile is None:
        image = getattr(function, 'image', None)
        profile = image.contracts.get('floating_point') if image is not None else None
    if any((profile or {}).get(key) != value for key, value in FP_POLICY.items()):
        function.fail(ins, 'floating-point instructions require the validated native floating_point profile')
    function.floating_point_checked = True


def _shuffle(ins):
    op, args = ins.mnemonic, ins.operands
    if op in ('punpcklbw', 'punpcklwd'):
        width = 8 if op == 'punpcklbw' else 16
        count = 128 // width
        return width, [value for i in range(count // 2) for value in (i, i + count)]
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
    if not any(_xmm(ins, operand) for operand in args) and op not in TO_INT:
        # A scalar conversion may read memory and write a GPR, with no xmm operand at all.
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
    elif op == 'movmskps':
        _check(function, ins, state, args[1], 128)
        _define(function, ins, state, args[0], 32)
    elif op in PEXTR:
        _check(function, ins, state, args[1], 128)
        function.define(ins, state, args[0])
    elif op in ('pmulhw', 'psadbw'):
        _check(function, ins, state, args[0], 128)
        _check(function, ins, state, args[1], 128)
        _copy_mask(ins, state, args[0], MASK128)
    elif op == 'phminposuw':
        _check(function, ins, state, args[1], 128)
        _copy_mask(ins, state, args[0], MASK128)
    elif op in ('pslldq', 'psrldq'):
        _check(function, ins, state, args[0], 128)
        _copy_mask(ins, state, args[0], _mask(function, ins, state, args[0]))
    elif op in SHUF_WORDS:
        source = _mask(function, ins, state, args[1])
        control = args[2].imm
        known = 0
        for lane in range(8):
            if op == 'pshuflw':
                index = ((control >> (lane * 2)) & 3) if lane < 4 else lane
            else:
                index = lane if lane < 4 else 4 + ((control >> ((lane - 4) * 2)) & 3)
            known |= ((source >> (index * 16)) & 0xffff) << (lane * 16)
        _copy_mask(ins, state, args[0], known)
    elif op in DUPS:
        lane = DUPS[op]
        source = _mask(function, ins, state, args[1])
        lane_mask = (1 << lane) - 1
        indices = [0, 0] if op == 'movddup' else ([1, 1, 3, 3] if op == 'movshdup' else [0, 0, 2, 2])
        known = 0
        for destination, source_index in enumerate(indices):
            known |= ((source >> (source_index * lane)) & lane_mask) << (destination * lane)
        _copy_mask(ins, state, args[0], known)
    elif op in PACKED_BINARY:
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        _copy_mask(ins, state, args[0], _complete_lanes(left & right, PACKED_BINARY[op][1]))
    elif op in PACKED_SAT:
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        _copy_mask(ins, state, args[0], _complete_lanes(left & right, PACKED_SAT[op][1]))
    elif op in PINS:
        width = PINS[op]
        lane = args[2].imm & (128 // width - 1)
        source = _mask(function, ins, state, args[1]) & ((1 << width) - 1)
        mask = (MASK128 ^ (((1 << width) - 1) << (lane * width))) | (source << (lane * width))
        _copy_mask(ins, state, args[0], mask)
    elif op == 'movhpd':
        if _xmm(ins, args[0]):
            source = _mask(function, ins, state, args[1]) & 0xffffffffffffffff
            mask = (_mask(function, ins, state, args[0]) & 0xffffffffffffffff) | (source << 64)
            _copy_mask(ins, state, args[0], mask)
        else:
            _check(function, ins, state, args[1], 64)
            _define(function, ins, state, args[0])
    elif op == 'pshufb':
        # An index byte with its high bit set selects a zero; any other index selects the source
        # byte, so only the selected bytes of the source have to be defined.
        source = _mask(function, ins, state, args[0])
        index = _mask(function, ins, state, args[1])
        known = 0
        for lane in range(16):
            selector = (index >> (lane * 8)) & 0xff
            if selector & 0x80:
                known |= 0xff << (lane * 8)
            else:
                known |= ((source >> ((selector & 15) * 8)) & 0xff) << (lane * 8)
        _copy_mask(ins, state, args[0], known)
    elif op == 'pmaddubsw':
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        _copy_mask(ins, state, args[0], _complete_lanes(left & right, 16))
    elif op in PACKED_MINMAX_INT:
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        _copy_mask(ins, state, args[0], _complete_lanes(left & right, PACKED_MINMAX_INT[op][0]))
    elif op in PACKED_MUL:
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        _copy_mask(ins, state, args[0], _complete_lanes(left & right, 32, 64))
    elif op in MADD:
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        _copy_mask(ins, state, args[0], _complete_lanes(left & right, 16, 32))
    elif op in BLENDS_IMM:
        width, control = BLENDS_IMM[op], args[2].imm
        source = _mask(function, ins, state, args[1])
        destination = _mask(function, ins, state, args[0])
        lane = (1 << width) - 1
        known = 0
        for index in range(128 // width):
            pick = source if (control >> index) & 1 else destination
            known |= (pick & lane) << (index * width)
        _copy_mask(ins, state, args[0], known)
    elif op in PACKED_SHIFTS:
        instruction, width = PACKED_SHIFTS[op]
        known = _mask(function, ins, state, args[0])
        if args[1].type == X86_OP_IMM:
            count = args[1].imm
            if count > width - 1:
                known = MASK128
            else:
                lane = (1 << width) - 1
                result = 0
                for index in range(128 // width):
                    defined = ((known >> (index * width)) & lane) >> count
                    result |= (defined | (lane ^ (lane >> count))) << (index * width)
                known = result
        else:
            _check(function, ins, state, args[1], 64)
            known = _complete_lanes(known, 32)
        _copy_mask(ins, state, args[0], known)
    elif op in ('paddd', 'pcmpgtd', 'packuswb') or op in PACKS:
        left, right = (_mask(function, ins, state, operand) for operand in args[:2])
        if op == 'packuswb':
            known = _complete_lanes(left, 16, 8) | (_complete_lanes(right, 16, 8) << 64)
        elif op in PACKS:
            source, target = PACKS[op]
            known = _complete_lanes(left, source, target) | (_complete_lanes(right, source, target) << 64)
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
    if op not in SUPPORTED or (not any(_xmm(ins, operand) for operand in args) and op not in TO_INT):
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
    elif op == 'movmskps':
        source = read(args[1])
        value = '0'
        for lane in range(4):
            bit = function.emit(f'lshr i128 {source}, {lane * 32 + 31}')
            bit = function.emit(f'trunc i128 {bit} to i32')
            bit = function.emit(f'and i32 {bit}, 1')
            bit = function.emit(f'shl i32 {bit}, {lane}')
            value = function.emit(f'or i32 {value}, {bit}')
        function.write(ins, args[0], value)
    elif op in PEXTR:
        width = PEXTR[op]
        count = 128 // width
        kind = f'<{count} x i{width}>'
        source = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        element = function.emit(f'extractelement {kind} {source}, i32 {args[2].imm & (count - 1)}')
        dest_bits = args[0].size * 8
        if dest_bits > width:
            element = function.emit(f'zext i{width} {element} to i{dest_bits}')
        function.write(ins, args[0], element)
    elif op in PACKED_SAT:
        operation, lane = PACKED_SAT[op]
        count = 128 // lane
        kind = f'<{count} x i{lane}>'
        left, right = (_cast(function, read(operand), 128, kind) for operand in args[:2])
        result = function.emit(f'call {kind} @llvm.{operation}.v{count}i{lane}({kind} {left}, {kind} {right})')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op in PINS:
        width = PINS[op]
        count = 128 // width
        kind = f'<{count} x i{width}>'
        base = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        source = read(args[1], width)
        result = function.emit(f'insertelement {kind} {base}, i{width} {source}, i32 {args[2].imm & (count - 1)}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op == 'movhpd':
        if _xmm(ins, args[0]):
            base = function.emit(f'bitcast i128 {read(args[0])} to <2 x i64>')
            source = read(args[1], 64)
            result = function.emit(f'insertelement <2 x i64> {base}, i64 {source}, i32 1')
            _write(function, ins, args[0], function.emit(f'bitcast <2 x i64> {result} to i128'))
        else:
            base = function.emit(f'bitcast i128 {read(args[1])} to <2 x i64>')
            high = function.emit(f'extractelement <2 x i64> {base}, i32 1')
            function.write(ins, args[0], high)
    elif op == 'pshufb':
        kind = '<16 x i8>'
        source = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        index = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        result = 'zeroinitializer'
        for lane in range(16):
            selector = function.emit(f'extractelement {kind} {index}, i32 {lane}')
            high = function.emit(f'icmp slt i8 {selector}, 0')
            offset = function.emit(f'and i8 {selector}, 15')
            offset = function.emit(f'zext i8 {offset} to i32')
            byte = function.emit(f'extractelement {kind} {source}, i32 {offset}')
            byte = function.emit(f'select i1 {high}, i8 0, i8 {byte}')
            result = function.emit(f'insertelement {kind} {result}, i8 {byte}, i32 {lane}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op == 'pmaddubsw':
        bytes_kind, words_kind = '<16 x i8>', '<16 x i16>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {bytes_kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {bytes_kind}')
        left = function.emit(f'zext {bytes_kind} {left} to {words_kind}')
        right = function.emit(f'sext {bytes_kind} {right} to {words_kind}')
        product = function.emit(f'mul {words_kind} {left}, {right}')
        product32 = function.emit(f'sext {words_kind} {product} to <16 x i32>')
        evens = ', '.join(f'i32 {lane}' for lane in range(0, 16, 2))
        odds = ', '.join(f'i32 {lane}' for lane in range(1, 16, 2))
        low = function.emit(f'shufflevector <16 x i32> {product32}, <16 x i32> zeroinitializer, <8 x i32> <{evens}>')
        high = function.emit(f'shufflevector <16 x i32> {product32}, <16 x i32> zeroinitializer, <8 x i32> <{odds}>')
        total = function.emit(f'add <8 x i32> {low}, {high}')
        bottom = ', '.join(['i32 -32768'] * 8)
        top = ', '.join(['i32 32767'] * 8)
        below = function.emit(f'icmp slt <8 x i32> {total}, <{bottom}>')
        above = function.emit(f'icmp sgt <8 x i32> {total}, <{top}>')
        clipped = function.emit(f'select <8 x i1> {below}, <8 x i32> <{bottom}>, <8 x i32> {total}')
        clipped = function.emit(f'select <8 x i1> {above}, <8 x i32> <{top}>, <8 x i32> {clipped}')
        result = function.emit(f'trunc <8 x i32> {clipped} to <8 x i16>')
        _write(function, ins, args[0], function.emit(f'bitcast <8 x i16> {result} to i128'))
    elif op == 'pmulhw':
        kind = '<8 x i16>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        left32 = function.emit(f'sext {kind} {left} to <8 x i32>')
        right32 = function.emit(f'sext {kind} {right} to <8 x i32>')
        product = function.emit(f'mul <8 x i32> {left32}, {right32}')
        splat = ', '.join(['i32 16'] * 8)
        high = function.emit(f'lshr <8 x i32> {product}, <{splat}>')
        result = function.emit(f'trunc <8 x i32> {high} to {kind}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op == 'psadbw':
        kind = '<16 x i8>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        below = function.emit(f'icmp ugt {kind} {left}, {right}')
        forward = function.emit(f'sub {kind} {left}, {right}')
        backward = function.emit(f'sub {kind} {right}, {left}')
        difference = function.emit(f'select <16 x i1> {below}, {kind} {forward}, {kind} {backward}')
        sums = []
        for group in (0, 8):
            total = '0'
            for lane in range(8):
                element = function.emit(f'extractelement {kind} {difference}, i32 {group + lane}')
                element = function.emit(f'zext i8 {element} to i64')
                total = function.emit(f'add i64 {total}, {element}')
            sums.append(total)
        low = function.emit(f'zext i64 {sums[0]} to i128')
        high = function.emit(f'zext i64 {sums[1]} to i128')
        high = function.emit(f'shl i128 {high}, 64')
        _write(function, ins, args[0], function.emit(f'or i128 {low}, {high}'))
    elif op in ('pslldq', 'psrldq'):
        shift = args[1].imm * 8
        if shift >= 128:
            _write(function, ins, args[0], '0')
        else:
            value = read(args[0])
            _write(function, ins, args[0], function.emit(f'{"shl" if op == "pslldq" else "lshr"} i128 {value}, {shift}'))
    elif op == 'phminposuw':
        kind = '<8 x i16>'
        source = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        best = function.emit(f'extractelement {kind} {source}, i32 0')
        index = '0'
        for lane in range(1, 8):
            element = function.emit(f'extractelement {kind} {source}, i32 {lane}')
            less = function.emit(f'icmp ult i16 {element}, {best}')
            best = function.emit(f'select i1 {less}, i16 {element}, i16 {best}')
            index = function.emit(f'select i1 {less}, i32 {lane}, i32 {index}')
        value = function.emit(f'zext i16 {best} to i32')
        shifted = function.emit(f'shl i32 {index}, 16')
        value = function.emit(f'or i32 {value}, {shifted}')
        _write(function, ins, args[0], function.emit(f'zext i32 {value} to i128'))
    elif op in SHUF_WORDS:
        source = function.emit(f'bitcast i128 {read(args[1])} to <8 x i16>')
        control = args[2].imm
        indices = []
        for lane in range(8):
            if op == 'pshuflw':
                indices.append(((control >> (lane * 2)) & 3) if lane < 4 else lane)
            else:
                indices.append(lane if lane < 4 else 4 + ((control >> ((lane - 4) * 2)) & 3))
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector <8 x i16> {source}, <8 x i16> zeroinitializer, <8 x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast <8 x i16> {result} to i128'))
    elif op in DUPS:
        lane = DUPS[op]
        count = 128 // lane
        kind = f'<{count} x i{lane}>'
        value = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        indices = [0, 0] if op == 'movddup' else ([1, 1, 3, 3] if op == 'movshdup' else [0, 0, 2, 2])
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {kind} {value}, {kind} zeroinitializer, <{count} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op in PACKED_BINARY:
        instruction, width = PACKED_BINARY[op]
        count = 128 // width
        kind = f'<{count} x i{width}>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        result = function.emit(f'{instruction} {kind} {left}, {right}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op in PACKED_MINMAX_INT:
        width, is_min = PACKED_MINMAX_INT[op]
        count = 128 // width
        kind = f'<{count} x i{width}>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {kind}')
        compare = function.emit(f'icmp {"ult" if is_min else "ugt"} {kind} {left}, {right}')
        result = function.emit(f'select <{count} x i1> {compare}, {kind} {left}, {kind} {right}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))
    elif op in BLENDS_IMM:
        width, control = BLENDS_IMM[op], args[2].imm
        count = 128 // width
        kind = f'<{count} x i{width}>'
        left = _cast(function, read(args[0]), 128, kind)
        right = _cast(function, read(args[1]), 128, kind)
        indices = [count + index if (control >> index) & 1 else index for index in range(count)]
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {kind} {left}, {kind} {right}, <{count} x i32> <{mask}>')
        _write(function, ins, args[0], _pack(function, result, width))
    elif op in MADD:
        words_kind, dwords_kind = '<8 x i16>', '<8 x i32>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {words_kind}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {words_kind}')
        left = function.emit(f'sext {words_kind} {left} to {dwords_kind}')
        right = function.emit(f'sext {words_kind} {right} to {dwords_kind}')
        product = function.emit(f'mul {dwords_kind} {left}, {right}')
        evens = ', '.join(f'i32 {lane}' for lane in range(0, 8, 2))
        odds = ', '.join(f'i32 {lane}' for lane in range(1, 8, 2))
        low = function.emit(f'shufflevector {dwords_kind} {product}, {dwords_kind} zeroinitializer, <4 x i32> <{evens}>')
        high = function.emit(f'shufflevector {dwords_kind} {product}, {dwords_kind} zeroinitializer, <4 x i32> <{odds}>')
        total = function.emit(f'add <4 x i32> {low}, {high}')
        _write(function, ins, args[0], function.emit(f'bitcast <4 x i32> {total} to i128'))
    elif op in PACKED_MUL:
        signed = PACKED_MUL[op]
        count = 2
        kind32 = '<4 x i32>'
        kind64 = '<2 x i64>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind32}')
        right = function.emit(f'bitcast i128 {read(args[1])} to {kind32}')
        left_even = function.emit(f'shufflevector {kind32} {left}, {kind32} zeroinitializer, <2 x i32> <i32 0, i32 2>')
        right_even = function.emit(f'shufflevector {kind32} {right}, {kind32} zeroinitializer, <2 x i32> <i32 0, i32 2>')
        extension = 'sext' if signed else 'zext'
        left64 = function.emit(f'{extension} <2 x i32> {left_even} to {kind64}')
        right64 = function.emit(f'{extension} <2 x i32> {right_even} to {kind64}')
        product = function.emit(f'mul {kind64} {left64}, {right64}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind64} {product} to i128'))
    elif op in PACKED_SHIFTS:
        instruction, width = PACKED_SHIFTS[op]
        count = 128 // width
        kind = f'<{count} x i{width}>'
        left = function.emit(f'bitcast i128 {read(args[0])} to {kind}')
        if args[1].type == X86_OP_IMM:
            amount = args[1].imm
            if amount >= width:
                if instruction == 'ashr':
                    splat = ', '.join([f'i{width} {width - 1}'] * count)
                    result = function.emit(f'ashr {kind} {left}, <{splat}>')
                else:
                    result = 'zeroinitializer'
            else:
                splat = ', '.join([f'i{width} {amount}'] * count)
                result = function.emit(f'{instruction} {kind} {left}, <{splat}>')
        else:
            shift = read(args[1], 64)
            valid = function.emit(f'icmp ult i64 {shift}, {width}')
            limited = function.emit(f'and i64 {shift}, {width - 1}')
            narrow = limited if width == 64 else function.emit(f'trunc i64 {limited} to i{width}')
            lane = function.emit(f'insertelement <{count} x i{width}> zeroinitializer, i{width} {narrow}, i32 0')
            counts = function.emit(f'shufflevector <{count} x i{width}> {lane}, <{count} x i{width}> zeroinitializer, <{count} x i32> zeroinitializer')
            shifted = function.emit(f'{instruction} {kind} {left}, {counts}')
            if instruction == 'ashr':
                splat = ', '.join([f'i{width} {width - 1}'] * count)
                saturated = function.emit(f'ashr {kind} {left}, <{splat}>')
                result = function.emit(f'select i1 {valid}, {kind} {shifted}, {kind} {saturated}')
            else:
                result = function.emit(f'select i1 {valid}, {kind} {shifted}, {kind} zeroinitializer')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'))

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
    elif op in PACKS:
        source_width, target_width = PACKS[op]
        count = 128 // source_width
        kind = f'<{count} x i{source_width}>'
        target = f'<{count} x i{target_width}>'
        low_limit = '<' + ', '.join([f'i{source_width} {-((1 << (target_width - 1)))}'] * count) + '>'
        high_limit = '<' + ', '.join([f'i{source_width} {(1 << (target_width - 1)) - 1}'] * count) + '>'
        values = []
        for operand in args[:2]:
            value = function.emit(f'bitcast i128 {read(operand)} to {kind}')
            below = function.emit(f'icmp slt {kind} {value}, {low_limit}')
            above = function.emit(f'icmp sgt {kind} {value}, {high_limit}')
            low = function.emit(f'select <{count} x i1> {below}, {kind} {low_limit}, {kind} {value}')
            high = function.emit(f'select <{count} x i1> {above}, {kind} {high_limit}, {kind} {low}')
            values.append(function.emit(f'trunc {kind} {high} to {target}'))
        indices = ', '.join(f'i32 {index}' for index in [*range(count), *range(count, 2 * count)])
        combined_kind = f'<{2 * count} x i{target_width}>'
        combined = function.emit(f'shufflevector {target} {values[0]}, {target} {values[1]}, <{2 * count} x i32> <{indices}>')
        _write(function, ins, args[0], function.emit(f'bitcast {combined_kind} {combined} to i128'))
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

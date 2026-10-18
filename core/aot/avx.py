from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG


MOVES = {'vmovups', 'vmovaps', 'vmovdqa', 'vmovdqu', 'vmovupd', 'vmovapd'}
BITWISE = {'vpand': 'and', 'vpor': 'or', 'vpxor': 'xor', 'vxorps': 'xor', 'vxorpd': 'xor',
           'vandps': 'and', 'vandpd': 'and', 'vorps': 'or', 'vorpd': 'or'}
ANDNOT = {'vpandn', 'vandnps', 'vandnpd'}
SCALAR_MOVES = {'vmovss', 'vmovsd'}
BROADCASTS = {'vbroadcastss': 32, 'vbroadcastsd': 64, 'vpbroadcastb': 8, 'vpbroadcastw': 16, 'vpbroadcastq': 64}
INT_CONVERSIONS = {'vcvtsi2ss': (32, 'ss'), 'vcvtsi2sd': (64, 'sd'),
                   'vcvtss2sd': (32, 'extend'), 'vcvtsd2ss': (64, 'truncate')}
PACKED_FLOAT = {'vaddps': ('fadd', 32), 'vsubps': ('fsub', 32), 'vmulps': ('fmul', 32), 'vdivps': ('fdiv', 32),
                'vaddpd': ('fadd', 64), 'vsubpd': ('fsub', 64), 'vmulpd': ('fmul', 64), 'vdivpd': ('fdiv', 64)}
PACKED_MINMAX = {'vminps': (32, True), 'vmaxps': (32, False), 'vminpd': (64, True), 'vmaxpd': (64, False)}
SCALAR_FLOAT = {'vaddss': ('fadd', 32), 'vsubss': ('fsub', 32), 'vmulss': ('fmul', 32), 'vdivss': ('fdiv', 32),
                'vaddsd': ('fadd', 64), 'vsubsd': ('fsub', 64), 'vmulsd': ('fmul', 64), 'vdivsd': ('fdiv', 64)}
SCALAR_MINMAX = {'vminss': (32, True), 'vmaxss': (32, False), 'vminsd': (64, True), 'vmaxsd': (64, False)}
PACKED_INT = {'vpaddb': ('add', 8), 'vpaddw': ('add', 16), 'vpaddd': ('add', 32), 'vpaddq': ('add', 64),
              'vpsubb': ('sub', 8), 'vpsubw': ('sub', 16), 'vpsubd': ('sub', 32), 'vpsubq': ('sub', 64),
              'vpmullw': ('mul', 16), 'vpmulld': ('mul', 32)}
PACKED_CMPEQ = {'vpcmpeqb': 8, 'vpcmpeqw': 16, 'vpcmpeqd': 32, 'vpcmpeqq': 64}
PACKED_CMPGT = {'vpcmpgtb': 8, 'vpcmpgtw': 16, 'vpcmpgtd': 32, 'vpcmpgtq': 64}
PACKED_MINMAX_INT = {'vpminsb': (8, True, True), 'vpminsw': (16, True, True), 'vpminsd': (32, True, True),
                     'vpminub': (8, False, True), 'vpminuw': (16, False, True), 'vpminud': (32, False, True),
                     'vpmaxsb': (8, True, False), 'vpmaxsw': (16, True, False), 'vpmaxsd': (32, True, False),
                     'vpmaxub': (8, False, False), 'vpmaxuw': (16, False, False), 'vpmaxud': (32, False, False)}
UNPACKS = {'vpunpcklbw': (8, 0), 'vpunpckhbw': (8, 1), 'vpunpcklwd': (16, 0), 'vpunpckhwd': (16, 1),
           'vpunpckldq': (32, 0), 'vpunpckhdq': (32, 1), 'vpunpcklqdq': (64, 0), 'vpunpckhqdq': (64, 1),
           'vunpcklps': (32, 0), 'vunpckhps': (32, 1), 'vunpcklpd': (64, 0), 'vunpckhpd': (64, 1)}
SHUF_IMM = {'vshufps': (32, 2), 'vshufpd': (64, 1)}
MOVLHPS = {'vmovlhps', 'vmovhlps'}
SHIFTS_IMM = {'vpsllw': ('shl', 16), 'vpslld': ('shl', 32), 'vpsllq': ('shl', 64),
              'vpsrlw': ('lshr', 16), 'vpsrld': ('lshr', 32), 'vpsrlq': ('lshr', 64),
              'vpsraw': ('ashr', 16), 'vpsrad': ('ashr', 32), 'vpsraq': ('ashr', 64)}
SHIFTS_VAR = {'vpsllvd': ('shl', 32), 'vpsllvq': ('shl', 64), 'vpsrlvd': ('lshr', 32),
              'vpsrlvq': ('lshr', 64), 'vpsravd': ('ashr', 32)}
BYTE_SHIFTS = {'vpslldq': 'shl', 'vpsrldq': 'lshr'}
PACKS = {'vpackuswb': (16, 8, False), 'vpacksswb': (16, 8, True),
         'vpackssdw': (32, 16, True), 'vpackusdw': (32, 16, False)}
SHUF_WORDS = {'vpshuflw', 'vpshufhw'}
MUL64 = {'vpmuludq': False, 'vpmuldq': True}
EXTENDS = {'vpmovsxbw': (8, 16, True), 'vpmovzxbw': (8, 16, False),
           'vpmovsxwd': (16, 32, True), 'vpmovzxwd': (16, 32, False),
           'vpmovsxdq': (32, 64, True), 'vpmovzxdq': (32, 64, False),
           'vpmovsxbd': (8, 32, True), 'vpmovzxbd': (8, 32, False),
           'vpmovsxwq': (16, 64, True), 'vpmovzxwq': (16, 64, False),
           'vpmovsxbq': (8, 64, True), 'vpmovzxbq': (8, 64, False)}
ABS = {'vpabsb': 8, 'vpabsw': 16, 'vpabsd': 32}
PTEST = {'vptest'}
BLENDS_IMM = {'vblendps': 32, 'vblendpd': 64, 'vpblendw': 16, 'vpblendd': 32}
BLENDS_VAR = {'vblendvps': 32, 'vblendvpd': 64, 'vpblendvb': 8}
PERMIL_IMM = {'vpermilps': 32, 'vpermilpd': 64}
PERMS = {'vperm2f128', 'vperm2i128', 'vinsertf128', 'vextractf128', 'vpermq', 'vpermd', 'vpermpd', 'vpermps'}
DUPS = {'vmovshdup': 32, 'vmovsldup': 32, 'vmovddup': 64}
PACKED_ODDS = {'vpmulhw', 'vpmulhuw', 'vpsadbw', 'vphminposuw'}
# Saturating packed integer arithmetic: the LLVM saturating intrinsics lower to the NEON
# saturating add/sub instructions, so these stay single instructions.
PACKED_SAT = {'vpaddsb': ('sadd.sat', 8), 'vpaddsw': ('sadd.sat', 16),
              'vpaddusb': ('uadd.sat', 8), 'vpaddusw': ('uadd.sat', 16),
              'vpsubsb': ('ssub.sat', 8), 'vpsubsw': ('ssub.sat', 16),
              'vpsubusb': ('usub.sat', 8), 'vpsubusw': ('usub.sat', 16)}
# Horizontal adds: PHADDD/PHADDW/VHADDPS/VHADDPD add adjacent lanes within each 128-bit lane.
HORIZONTAL = {'vphaddw': (16, False), 'vphaddd': (32, False),
              'vhaddps': (32, True), 'vhaddpd': (64, True)}
MXCSR = {'vstmxcsr', 'vldmxcsr'}
# AVX2 gather: vgatherdps takes dword indices and 32-bit lanes, so the index and data vectors
# have the same element count. The other gather forms (qword indices, 64-bit lanes) differ.
GATHER = {'vgatherdps': (32, 'float')}
AES = {'aesimc', 'vaesimc'}
PCLMUL = {'pclmulqdq'}
MASKED = {'vmaskmovps', 'vmaskmovpd', 'vpmaskmovd', 'vpmaskmovq'}
BROADCAST128 = {'vbroadcastf128', 'vbroadcasti128'}
ADDSUB = {'vaddsubps': 32, 'vaddsubpd': 64}
MADD = {'vpmaddwd'}
CMP_PREDICATES = ['oeq', 'olt', 'ole', 'uno', 'une', 'uge', 'ugt', 'ord',
                  'ueq', 'ult', 'ule', 'false', 'one', 'oge', 'ogt', 'true',
                  'oeq', 'olt', 'ole', 'uno', 'une', 'uge', 'ugt', 'ord',
                  'ueq', 'ult', 'ule', 'false', 'one', 'oge', 'ogt', 'true']
CMP_SUFFIXES = ['eq', 'lt', 'le', 'unord', 'neq', 'nlt', 'nle', 'ord', 'eq_uq', 'nge', 'ngt',
                'false', 'neq_oq', 'ge', 'gt', 'true', 'eq_os', 'lt_oq', 'le_oq', 'unord_s',
                'neq_us', 'nlt_uq', 'nle_uq', 'ord_s', 'eq_us', 'nge_uq', 'ngt_uq', 'false_os',
                'neq_os', 'ge_oq', 'gt_oq', 'true_us']
CMP = {f'vcmp{suffix}{kind}': (lane, index)
       for index, suffix in enumerate(CMP_SUFFIXES)
       for kind, lane in (('ps', 32), ('pd', 64), ('ss', 32), ('sd', 64))}
FLAGS_COMPARE = {'vucomiss': 32, 'vucomisd': 64, 'vcomiss': 32, 'vcomisd': 64}
MOVMSK = {'vmovmskps': 32, 'vmovmskpd': 64, 'movmskps': 32, 'movmskpd': 64,
          'pmovmskb': 8, 'vpmovmskb': 8}
LEGACY = {'movmskps', 'movmskpd', 'pmovmskb', 'aesimc', 'pclmulqdq'}
VTEST = {'vtestps': 32, 'vtestpd': 64}
ROUNDS = {'vroundps': 32, 'vroundpd': 64, 'vroundss': 32, 'vroundsd': 64}
SQRT = {'vsqrtps': 32, 'vsqrtpd': 64, 'vsqrtss': 32, 'vsqrtsd': 64}
RECIP = {'vrcpps': 32, 'vrcpss': 32, 'vrsqrtps': 32, 'vrsqrtss': 32}
CVT_ROUND = {'vcvtps2dq': 32, 'vcvttps2dq': 32, 'vcvtpd2dq': 64, 'vcvttpd2dq': 64,
             'vcvtdq2ps': 32, 'vcvtpd2ps': 64, 'vcvtps2pd': 32, 'vcvtdq2pd': 32}
TO_INT = {'vcvttss2si': 32, 'vcvttsd2si': 64, 'vcvtss2si': 32, 'vcvtsd2si': 64}
EXTRACT_ELEM = {'vpextrb': 8, 'vpextrw': 16, 'vpextrd': 32, 'vpextrq': 64, 'vextractps': 32}
INSERT_ELEM = {'vpinsrb': 8, 'vpinsrw': 16, 'vpinsrd': 32, 'vpinsrq': 64, 'vinsertps': 32}
EXTRACT128 = {'vextracti128'}
INSERT128 = {'vinserti128'}
PSHUFB = {'vpshufb'}
PALIGNR = {'vpalignr'}
HALF = {'vcvtph2ps', 'vcvtps2ph'}
LEGACY_MOVES = {'vmovlps', 'vmovhps', 'vmovlpd', 'vmovhpd'}
SUPPORTED = (MOVES | set(BITWISE) | ANDNOT | SCALAR_MOVES | set(BROADCASTS)
             | {'vmovd', 'vmovq', 'vpbroadcastd', 'vpshufd', 'vpsllvd', 'vzeroupper'}
             | set(INT_CONVERSIONS) | set(PACKED_FLOAT) | set(PACKED_MINMAX) | set(SCALAR_FLOAT)
             | set(SCALAR_MINMAX) | set(PACKED_INT) | set(PACKED_CMPEQ) | set(PACKED_CMPGT)
             | set(PACKED_MINMAX_INT) | set(UNPACKS) | set(SHUF_IMM) | MOVLHPS | set(SHIFTS_IMM)
             | set(SHIFTS_VAR) | set(BYTE_SHIFTS) | set(PACKS) | set(EXTENDS) | set(ABS) | PTEST
             | set(BLENDS_IMM) | set(BLENDS_VAR) | set(PERMIL_IMM) | PERMS
             | set(FLAGS_COMPARE) | set(MOVMSK) | set(VTEST) | set(ROUNDS) | set(SQRT)
             | set(RECIP) | set(CVT_ROUND) | set(TO_INT) | set(EXTRACT_ELEM) | set(INSERT_ELEM)
             | EXTRACT128 | INSERT128 | set(PSHUFB) | set(PALIGNR) | HALF | set(LEGACY_MOVES)
             | set(DUPS) | BROADCAST128 | set(CMP) | set(SHUF_WORDS) | set(MUL64)
             | set(ADDSUB) | set(MADD) | set(PACKED_ODDS) | set(MASKED)
             | set(PACKED_SAT) | set(HORIZONTAL) | MXCSR | set(GATHER) | AES | PCLMUL)
MASK128 = (1 << 128) - 1
MASK256 = (1 << 256) - 1

INTRINSIC_DECLARATIONS = [
    'declare <4 x float> @llvm.sqrt.v4f32(<4 x float>)',
    'declare <8 x float> @llvm.sqrt.v8f32(<8 x float>)',
    'declare <2 x double> @llvm.sqrt.v2f64(<2 x double>)',
    'declare <4 x double> @llvm.sqrt.v4f64(<4 x double>)',
    'declare float @llvm.sqrt.f32(float)',
    'declare double @llvm.sqrt.f64(double)',
    'declare <4 x float> @llvm.rint.v4f32(<4 x float>)',
    'declare <8 x float> @llvm.rint.v8f32(<8 x float>)',
    'declare <2 x double> @llvm.rint.v2f64(<2 x double>)',
    'declare <4 x double> @llvm.rint.v4f64(<4 x double>)',
    'declare float @llvm.rint.f32(float)',
    'declare double @llvm.rint.f64(double)',
    'declare <4 x float> @llvm.floor.v4f32(<4 x float>)',
    'declare <8 x float> @llvm.floor.v8f32(<8 x float>)',
    'declare <2 x double> @llvm.floor.v2f64(<2 x double>)',
    'declare <4 x double> @llvm.floor.v4f64(<4 x double>)',
    'declare float @llvm.floor.f32(float)',
    'declare double @llvm.floor.f64(double)',
    'declare <4 x float> @llvm.ceil.v4f32(<4 x float>)',
    'declare <8 x float> @llvm.ceil.v8f32(<8 x float>)',
    'declare <2 x double> @llvm.ceil.v2f64(<2 x double>)',
    'declare <4 x double> @llvm.ceil.v4f64(<4 x double>)',
    'declare float @llvm.ceil.f32(float)',
    'declare double @llvm.ceil.f64(double)',
    'declare <4 x float> @llvm.trunc.v4f32(<4 x float>)',
    'declare <8 x float> @llvm.trunc.v8f32(<8 x float>)',
    'declare <2 x double> @llvm.trunc.v2f64(<2 x double>)',
    'declare <4 x double> @llvm.trunc.v4f64(<4 x double>)',
    'declare float @llvm.trunc.f32(float)',
    'declare double @llvm.trunc.f64(double)',
    'declare <4 x float> @llvm.round.v4f32(<4 x float>)',
    'declare <8 x float> @llvm.round.v8f32(<8 x float>)',
    'declare <2 x double> @llvm.round.v2f64(<2 x double>)',
    'declare <4 x double> @llvm.round.v4f64(<4 x double>)',
    'declare float @llvm.round.f32(float)',
    'declare double @llvm.round.f64(double)',
    'declare <4 x i32> @llvm.masked.load.v4i32.p0(ptr, i32, <4 x i1>, <4 x i32>)',
] + [f'declare <{count} x i{width}> @llvm.{operation}.v{count}i{width}(<{count} x i{width}>, <{count} x i{width}>)'
     for operation in ('uadd.sat', 'sadd.sat', 'usub.sat', 'ssub.sat')
     for width, count in ((8, 16), (8, 32), (16, 8), (16, 16))] + [
    'declare <8 x i32> @llvm.masked.load.v8i32.p0(ptr, i32, <8 x i1>, <8 x i32>)',
    'declare <8 x float> @llvm.masked.gather.v8f32.v8p0(<8 x ptr>, i32, <8 x i1>, <8 x float>)',
    'declare <4 x float> @llvm.masked.gather.v4f32.v4p0(<4 x ptr>, i32, <4 x i1>, <4 x float>)',
    'declare <4 x double> @llvm.masked.gather.v4f64.v4p0(<4 x ptr>, i32, <4 x i1>, <4 x double>)',
    'declare <2 x double> @llvm.masked.gather.v2f64.v2p0(<2 x ptr>, i32, <2 x i1>, <2 x double>)',
    'declare <16 x i8> @llvm.aarch64.crypto.aesimc(<16 x i8>)',
    'declare i128 @llvm.aarch64.neon.pmull64(i64, i64)',
    'declare void @llvm.masked.store.v4i32.p0(<4 x i32>, ptr, i32, <4 x i1>)',
    'declare void @llvm.masked.store.v8i32.p0(<8 x i32>, ptr, i32, <8 x i1>)',
]


def _register(ins, operand):
    if operand.type != X86_OP_REG:
        return None
    name = ins.reg_name(operand.reg)
    if name.startswith(('xmm', 'ymm')) and name[3:].isdigit() and int(name[3:]) < 16:
        return 'xmm' + name[3:], 'ymm_hi' + name[3:], 128 if name.startswith('xmm') else 256
    return None


def _known(function, ins, state, operand, bits):
    register = _register(ins, operand)
    if register is not None:
        low, high, width = register
        if bits > width:
            function.fail(ins, 'AVX operand width exceeds its register')
        known = state['known'].get(low, 0)
        if bits > 128:
            known |= state['known'].get(high, 0) << 128
        return known & ((1 << bits) - 1)
    if operand.type == X86_OP_MEM:
        function.read_operand(ins, state, operand)
    elif operand.type == X86_OP_REG:
        function.read_operand(ins, state, operand)
    else:
        function.fail(ins, 'invalid AVX source')
    return (1 << bits) - 1


def _require(function, ins, state, operand, bits):
    if _known(function, ins, state, operand, bits) != (1 << bits) - 1:
        function.fail(ins, f'AVX source has undefined bits in its low {bits} bits')


def _define(function, ins, state, operand, known, bits):
    register = _register(ins, operand)
    if register is None:
        function.define(ins, state, operand)
        return
    low, high, width = register
    if bits > width:
        function.fail(ins, 'AVX result width exceeds its register')
    low_mask = (1 << min(bits, 128)) - 1
    state['known'][low] = (known & low_mask) | (MASK128 ^ low_mask)
    state['known'][high] = (known >> 128) & MASK128 if bits == 256 else MASK128


def _same(left, right):
    return left.type == right.type == X86_OP_REG and left.reg == right.reg


def _complete(mask, width, bits):
    result = 0
    lane = (1 << width) - 1
    for index in range(bits // width):
        if (mask >> (index * width)) & lane == lane:
            result |= lane << (index * width)
    return result


def _veckind(bits, lane_bits, is_float):
    count = bits // lane_bits
    if is_float:
        return f'<{count} x {"float" if lane_bits == 32 else "double"}>'
    return f'<{count} x i{lane_bits}>'


def _shuffle_indices(bits, width, selector):
    count = 128 // width
    indices = []
    for base in range(0, bits, 128):
        for lane in range(count):
            index = selector(lane)
            indices.append(base // width + index)
    return indices


def _binary_mask(function, ins, state, bits):
    return _known(function, ins, state, ins.operands[1], bits) & _known(function, ins, state, ins.operands[2], bits)


def analyze(function, ins, state):
    op, args = ins.mnemonic, ins.operands
    if op not in SUPPORTED:
        return False
    if ins.bytes[0] not in (0xc4, 0xc5) and op not in LEGACY:
        function.fail(ins, 'only VEX encodings are implemented; EVEX masking requires separate lowering')
    if op == 'vzeroupper':
        for index in range(16):
            state['known'][f'ymm_hi{index}'] = MASK128
        return True
    bits = args[0].size * 8
    if op in MOVES:
        if _register(ins, args[0]):
            known = _known(function, ins, state, args[1], bits)
        else:
            _require(function, ins, state, args[1], bits)
            known = (1 << bits) - 1
        _define(function, ins, state, args[0], known, bits)
    elif op in SCALAR_MOVES:
        lane = 32 if op == 'vmovss' else 64
        if _register(ins, args[0]):
            if len(args) == 2:
                # The two-operand form zeroes bits above the scalar lane, so those bits are
                # defined regardless of the previous contents of the destination.
                source = _known(function, ins, state, args[1], lane)
                known = (source & ((1 << lane) - 1)) | (MASK128 ^ ((1 << lane) - 1))
            else:
                previous = _known(function, ins, state, args[1], 128)
                source = _known(function, ins, state, args[2], lane)
                known = (previous & (MASK128 ^ ((1 << lane) - 1))) | (source & ((1 << lane) - 1))
            _define(function, ins, state, args[0], known, 128)
        else:
            _require(function, ins, state, args[1], lane)
            _define(function, ins, state, args[0], (1 << lane) - 1, 128)
    elif op in INT_CONVERSIONS:
        lane = 64 if op in ('vcvtsi2sd', 'vcvtss2sd') else 32
        src1 = args[1] if len(args) >= 3 else args[0]
        previous = _known(function, ins, state, src1, 128)
        _known(function, ins, state, args[-1], args[-1].size * 8)
        known = (previous & (MASK128 ^ ((1 << lane) - 1))) | ((1 << lane) - 1)
        _define(function, ins, state, args[0], known, 128)
    elif op in ('vmovd', 'vmovq'):
        width = 32 if op == 'vmovd' else 64
        if _register(ins, args[0]):
            known = _known(function, ins, state, args[1], width)
        else:
            _require(function, ins, state, args[1], width)
            known = (1 << width) - 1
        _define(function, ins, state, args[0], known, width)
    elif op in BROADCASTS:
        lane = BROADCASTS[op]
        scalar = _known(function, ins, state, args[1], lane)
        known = sum(scalar << offset for offset in range(0, bits, lane))
        _define(function, ins, state, args[0], known, bits)
    elif op in BITWISE or op in ANDNOT:
        zero = op in BITWISE and BITWISE[op] == 'xor' and _same(args[1], args[2])
        known = (1 << bits) - 1 if zero else _binary_mask(function, ins, state, bits)
        _define(function, ins, state, args[0], known, bits)
    elif op in PACKED_FLOAT:
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, bits), bits)
    elif op in PACKED_MINMAX:
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, bits), bits)
    elif op in SCALAR_FLOAT or op in SCALAR_MINMAX:
        lane = 32 if op.endswith('ss') else 64
        src1 = args[1] if len(args) >= 3 else args[0]
        known = (_known(function, ins, state, src1, 128) & (MASK128 ^ ((1 << lane) - 1))) \
            | _known(function, ins, state, args[-1], lane)
        _define(function, ins, state, args[0], known, 128)
    elif op in PACKED_INT:
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, bits), bits)
    elif op in PACKED_ODDS:
        for operand in args[1:]:
            _known(function, ins, state, operand, bits if op != 'vphminposuw' else 128)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in PACKED_SAT or op in HORIZONTAL:
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, bits), bits)
    elif op in MXCSR:
        function.read_operand(ins, state, args[0])
        if op == 'vstmxcsr':
            function.define(ins, state, args[0])
    elif op in GATHER:
        lane_bits, _element = GATHER[op]
        if len(args) != 3 or args[1].type != X86_OP_MEM or not args[1].mem.index:
            function.fail(ins, 'gather requires a memory operand with a vector index and a mask register')
        base = ins.reg_name(args[1].mem.base)
        if base:
            function.check_register(ins, state, *gpr_alias(base))
        mask = _known(function, ins, state, args[2], bits)
        destination = _known(function, ins, state, args[0], bits)
        selected = 0
        for lane in range(bits // lane_bits):
            if (mask >> (lane * 32 + 31)) & 1:
                selected |= ((1 << lane_bits) - 1) << (lane * lane_bits)
        _define(function, ins, state, args[0], destination | selected, bits)
        # The whole mask register is cleared once the gather completes without a fault.
        _define(function, ins, state, args[2], (1 << bits) - 1, bits)
    elif op in AES:
        _define(function, ins, state, args[0], _known(function, ins, state, args[1], 128), 128)
    elif op in PCLMUL:
        known = _known(function, ins, state, args[0], 128) & _known(function, ins, state, args[1], 128)
        _define(function, ins, state, args[0], known, 128)
    elif op in MASKED:
        register = args[0] if _register(ins, args[0]) is not None else args[2]
        mask_bits = register.size * 8
        _require(function, ins, state, args[1], mask_bits)
        if _register(ins, args[0]) is not None:
            _known(function, ins, state, args[2], mask_bits)
            _define(function, ins, state, args[0], (1 << mask_bits) - 1, mask_bits)
        else:
            _require(function, ins, state, args[2], mask_bits)
            function.define(ins, state, args[0])
    elif op in PACKED_CMPEQ or op in PACKED_CMPGT:
        lane = (PACKED_CMPEQ | PACKED_CMPGT)[op]
        _define(function, ins, state, args[0], _complete(_binary_mask(function, ins, state, bits), lane, bits), bits)
    elif op in PACKED_MINMAX_INT:
        lane = PACKED_MINMAX_INT[op][0]
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, bits), bits)
    elif op in UNPACKS:
        width = UNPACKS[op][0]
        source = _known(function, ins, state, args[1], bits) & _known(function, ins, state, args[2], bits)
        _define(function, ins, state, args[0], source, bits)
    elif op in SHUF_IMM or op in PERMIL_IMM:
        source = _known(function, ins, state, args[1], bits)
        if len(args) >= 3 and args[2].type != X86_OP_IMM:
            source &= _known(function, ins, state, args[2], bits)
        _define(function, ins, state, args[0], source, bits)
    elif op in MOVLHPS:
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, 128), 128)
    elif op in SHIFTS_IMM:
        lane = SHIFTS_IMM[op][1]
        _define(function, ins, state, args[0], _known(function, ins, state, args[1], bits), bits)
    elif op in SHIFTS_VAR:
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, bits), bits)
    elif op in BYTE_SHIFTS:
        _define(function, ins, state, args[0], _known(function, ins, state, args[1], bits), bits)
    elif op in PACKS:
        _define(function, ins, state, args[0], _binary_mask(function, ins, state, bits), bits)
    elif op in EXTENDS:
        source_width, target_width, _signed = EXTENDS[op]
        source_bits = (bits // target_width) * source_width
        _require(function, ins, state, args[1], source_bits)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in ABS:
        _define(function, ins, state, args[0], _known(function, ins, state, args[1], bits), bits)
    elif op in PTEST:
        _known(function, ins, state, args[0], bits)
        _known(function, ins, state, args[1], bits)
        state['flags'] = {'zf', 'cf'}
    elif op in BLENDS_IMM or op in BLENDS_VAR:
        left = _known(function, ins, state, args[1], bits)
        right = _known(function, ins, state, args[2], bits)
        _define(function, ins, state, args[0], left & right, bits)
    elif op in PERMS:
        for operand in args[1:]:
            if _register(ins, operand):
                _known(function, ins, state, operand, operand.size * 8)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in FLAGS_COMPARE:
        lane = FLAGS_COMPARE[op]
        _known(function, ins, state, args[0], lane)
        _known(function, ins, state, args[1], lane)
        state['flags'] = {'zf', 'pf', 'cf', 'of', 'sf'}
    elif op in MOVMSK:
        _known(function, ins, state, args[1], args[1].size * 8)
        function.define(ins, state, args[0])
    elif op in VTEST:
        _known(function, ins, state, args[0], bits)
        _known(function, ins, state, args[1], bits)
        state['flags'] = {'zf', 'cf'}
    elif op in DUPS:
        _known(function, ins, state, args[1], args[1].size * 8)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in BROADCAST128:
        _known(function, ins, state, args[1], 128)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in CMP:
        lane, _predicate = CMP[op]
        if op.endswith(('ss', 'sd')):
            src1 = args[1] if len(args) >= 3 else args[0]
            previous = _known(function, ins, state, src1, 128)
            _known(function, ins, state, args[2], lane)
            known = (previous & (MASK128 ^ ((1 << lane) - 1))) | ((1 << lane) - 1)
            _define(function, ins, state, args[0], known, 128)
        else:
            _known(function, ins, state, args[1], bits)
            _known(function, ins, state, args[2], bits)
            _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in ROUNDS or op in SQRT or op in RECIP:
        table = ROUNDS if op in ROUNDS else (SQRT if op in SQRT else RECIP)
        lane = table[op]
        if op.endswith('ss') or op.endswith('sd'):
            src1 = args[1] if len(args) >= 3 else args[0]
            previous = _known(function, ins, state, src1, 128)
            _known(function, ins, state, args[-2] if op in ROUNDS else args[-1], lane)
            known = (previous & (MASK128 ^ ((1 << lane) - 1))) | ((1 << lane) - 1)
            _define(function, ins, state, args[0], known, 128)
        else:
            _known(function, ins, state, args[1], bits)
            _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in CVT_ROUND:
        _known(function, ins, state, args[1], args[1].size * 8)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in TO_INT:
        _known(function, ins, state, args[1], TO_INT[op])
        function.define(ins, state, args[0])
    elif op in EXTRACT_ELEM:
        _known(function, ins, state, args[1], 128)
        function.define(ins, state, args[0])
    elif op in INSERT_ELEM:
        _known(function, ins, state, args[1], 128)
        if op == 'vinsertps':
            _known(function, ins, state, args[2], 128 if args[2].type == X86_OP_REG else 32)
        else:
            _known(function, ins, state, args[2], INSERT_ELEM[op])
        _define(function, ins, state, args[0], MASK128, 128)
    elif op in EXTRACT128 or op in INSERT128:
        for operand in args[1:]:
            if _register(ins, operand):
                _known(function, ins, state, operand, operand.size * 8)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in PSHUFB or op in PALIGNR:
        _known(function, ins, state, args[1], bits)
        _known(function, ins, state, args[2], bits)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in SHUF_WORDS:
        _known(function, ins, state, args[1], bits)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in MUL64:
        _known(function, ins, state, args[1], bits)
        _known(function, ins, state, args[2], bits)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in ADDSUB or op in MADD:
        _known(function, ins, state, args[1], bits)
        _known(function, ins, state, args[2], bits)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in HALF:
        _known(function, ins, state, args[1], args[1].size * 8)
        _define(function, ins, state, args[0], (1 << bits) - 1, bits)
    elif op in LEGACY_MOVES:
        lane = 64
        if len(args) >= 3:
            _known(function, ins, state, args[1], 128)
            _known(function, ins, state, args[2], lane)
            _define(function, ins, state, args[0], MASK128, 128)
        else:
            _known(function, ins, state, args[1], lane)
            _define(function, ins, state, args[0], MASK128, 128)
    elif op == 'vpbroadcastd':
        scalar = _known(function, ins, state, args[1], 32)
        known = sum(scalar << offset for offset in range(0, bits, 32))
        _define(function, ins, state, args[0], known, bits)
    elif op == 'vpshufd':
        if args[2].type != X86_OP_IMM:
            function.fail(ins, 'AVX dword shuffle requires an immediate control')
        source = _known(function, ins, state, args[1], bits)
        known = 0
        for lane in range(bits // 32):
            selected = (lane // 4) * 4 + ((args[2].imm >> ((lane % 4) * 2)) & 3)
            known |= ((source >> (selected * 32)) & 0xffffffff) << (lane * 32)
        _define(function, ins, state, args[0], known, bits)
    elif op == 'vpsllvd':
        both = _binary_mask(function, ins, state, bits)
        known = 0
        for offset in range(0, bits, 32):
            if (both >> offset) & 0xffffffff == 0xffffffff:
                known |= 0xffffffff << offset
        _define(function, ins, state, args[0], known, bits)
    return True


def _read(function, ins, operand, bits):
    register = _register(ins, operand)
    if register is None:
        return function.read(ins, operand, bits)
    low, high, _ = register
    value = function.load(low, min(bits, 128))
    if bits <= 128:
        return value
    value = function.emit(f'zext i128 {value} to i256')
    upper = function.emit(f'zext i128 {function.load(high, 128)} to i256')
    upper = function.emit(f'shl i256 {upper}, 128')
    return function.emit(f'or i256 {value}, {upper}')


def _write(function, ins, operand, value, bits):
    register = _register(ins, operand)
    if register is None:
        function.write(ins, operand, value)
        return
    low, high, _ = register
    if bits == 256:
        low_value = function.emit(f'trunc i256 {value} to i128')
        high_value = function.emit(f'lshr i256 {value}, 128')
        high_value = function.emit(f'trunc i256 {high_value} to i128')
        function.store_vector(low, low_value)
        function.store_vector(high, high_value)
    else:
        function.store_vector(low, value, bits, zero_upper=True)
        function.store_vector(high, '0')


def _aligned(function, ins, bits):
    for operand in ins.operands:
        if operand.type != X86_OP_MEM:
            continue
        pointer = function.address(ins, operand)
        address = function.emit(f'ptrtoint ptr {pointer} to i64')
        residue = function.emit(f'and i64 {address}, {bits // 8 - 1}')
        aligned = function.emit(f'icmp eq i64 {residue}, 0')
        label = aligned[1:]
        function.lines.extend([f'  br i1 {aligned}, label %{label}_aligned, label %{label}_misaligned',
                               f'{label}_misaligned:', '  call void @llvm.trap()', '  unreachable', f'{label}_aligned:'])


def _lower_binary(function, ins, bits, llvm_op, lane_bits, is_float):
    kind = _veckind(bits, lane_bits, is_float)
    left = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[1], bits)} to {kind}')
    right = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to {kind}')
    result = function.emit(f'{llvm_op} {kind} {left}, {right}')
    return function.emit(f'bitcast {kind} {result} to i{bits}')


def _lower_odd(function, ins, bits, op):
    """vpmulhw (signed word multiply high), vpsadbw (byte SAD per 8-byte group) and
    vphminposuw (minimum unsigned word and its index)."""
    if op == 'vphminposuw':
        source = function.emit(f'bitcast i128 {_read(function, ins, ins.operands[1], 128)} to <8 x i16>')
        best = function.emit(f'extractelement <8 x i16> {source}, i32 0')
        index = '0'
        for lane in range(1, 8):
            element = function.emit(f'extractelement <8 x i16> {source}, i32 {lane}')
            less = function.emit(f'icmp ult i16 {element}, {best}')
            best = function.emit(f'select i1 {less}, i16 {element}, i16 {best}')
            index = function.emit(f'select i1 {less}, i32 {lane}, i32 {index}')
        value = function.emit(f'zext i16 {best} to i32')
        value = function.emit(f'or i32 {value}, {function.emit(f"shl i32 {index}, 16")}')
        return function.emit(f'zext i32 {value} to i128')
    if op in ('vpmulhw', 'vpmulhuw'):
        count = bits // 16
        kind = f'<{count} x i16>'
        left = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[1], bits)} to {kind}')
        right = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to {kind}')
        extend = 'sext' if op == 'vpmulhw' else 'zext'
        left32 = function.emit(f'{extend} {kind} {left} to <{count} x i32>')
        right32 = function.emit(f'{extend} {kind} {right} to <{count} x i32>')
        product = function.emit(f'mul <{count} x i32> {left32}, {right32}')
        splat = ', '.join(['i32 16'] * count)
        high = function.emit(f'lshr <{count} x i32> {product}, <{splat}>')
        result = function.emit(f'trunc <{count} x i32> {high} to {kind}')
        return function.emit(f'bitcast {kind} {result} to i{bits}')
    count = bits // 8
    kind = f'<{count} x i8>'
    left = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[1], bits)} to {kind}')
    right = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to {kind}')
    below = function.emit(f'icmp ugt {kind} {left}, {right}')
    forward = function.emit(f'sub {kind} {left}, {right}')
    backward = function.emit(f'sub {kind} {right}, {left}')
    difference = function.emit(f'select <{count} x i1> {below}, {kind} {forward}, {kind} {backward}')
    result = '0'
    for group in range(bits // 64):
        total = '0'
        for lane in range(8):
            element = function.emit(f'extractelement {kind} {difference}, i32 {group * 8 + lane}')
            element = function.emit(f'zext i8 {element} to i64')
            total = function.emit(f'add i64 {total}, {element}')
        part = function.emit(f'zext i64 {total} to i{bits}')
        part = function.emit(f'shl i{bits} {part}, {group * 64}')
        result = function.emit(f'or i{bits} {result}, {part}')
    return result


def gpr_alias(name):
    """The canonical register, width and shift of a GPR name (the memory-operand path in
    compiler.py owns this table; a gather's index is a vector, so it cannot go through it)."""
    import compiler
    if name not in compiler.ALIASES:
        raise KeyError(name)
    return compiler.ALIASES[name]


def _lower_gather(function, ins, bits, op):
    """VGATHERDPS: a masked load per lane; the mask register is cleared afterwards. The mask's
    sign bit selects a lane, and unselected lanes keep the destination's previous value."""
    lane_bits, element = GATHER[op]
    count = bits // lane_bits
    memory = ins.operands[1].mem
    base = function.load(ins.reg_name(memory.base))
    index = function.emit(f'bitcast i{bits} {_vector_value(function, ins.reg_name(memory.index), bits)} to <{count} x i32>')
    mask = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to <{count} x i32>')
    previous = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[0], bits)} to <{count} x {element}>')
    active = function.emit(f'icmp slt <{count} x i32> {mask}, zeroinitializer')
    pointers = 'zeroinitializer'
    for lane in range(count):
        offset = function.emit(f'extractelement <{count} x i32> {index}, i32 {lane}')
        offset = function.emit(f'sext i32 {offset} to i64')
        scale = memory.scale or 1
        if scale != 1:
            offset = function.emit(f'mul i64 {offset}, {scale}')
        address = function.emit(f'add i64 {base}, {offset}')
        pointer = function.emit(f'inttoptr i64 {address} to ptr')
        pointers = function.emit(f'insertelement <{count} x ptr> {pointers}, ptr {pointer}, i32 {lane}')
    gathered = function.emit(f'call <{count} x {element}> @llvm.masked.gather.v{count}{"f32" if element == "float" else "f64"}.v{count}p0(<{count} x ptr> {pointers}, i32 {lane_bits // 8}, <{count} x i1> {active}, <{count} x {element}> {previous})')
    return function.emit(f'bitcast <{count} x {element}> {gathered} to i{bits}')


def _lower_pclmul(function, ins):
    """PCLMULQDQ: carry-less multiply of the selected 64-bit halves, AArch64 PMULL."""
    control = ins.operands[2].imm
    left = function.emit(f'bitcast i128 {_read(function, ins, ins.operands[0], 128)} to <2 x i64>')
    right = function.emit(f'bitcast i128 {_read(function, ins, ins.operands[1], 128)} to <2 x i64>')
    low = function.emit(f'extractelement <2 x i64> {left}, i32 {control & 1}')
    high = function.emit(f'extractelement <2 x i64> {right}, i32 {(control >> 4) & 1}')
    result = function.emit(f'call i128 @llvm.aarch64.neon.pmull64(i64 {low}, i64 {high})')
    return result


def _vector_value(function, name, bits):
    """The value of a named xmm/ymm register (a gather's index is a register, not an operand)."""
    base = 'xmm' + name[3:] if name.startswith('ymm') else name
    value = function.load(base, 128)
    if bits <= 128:
        return value
    wide = function.emit(f'zext i128 {value} to i{bits}')
    upper = function.emit(f'zext i128 {function.load("ymm_hi" + name[3:], 128)} to i{bits}')
    upper = function.emit(f'shl i{bits} {upper}, 128')
    return function.emit(f'or i{bits} {wide}, {upper}')


def _lower_saturating(function, ins, bits, operation, lane_bits):
    kind = _veckind(bits, lane_bits, False)
    count = bits // lane_bits
    left = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[1], bits)} to {kind}')
    right = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to {kind}')
    result = function.emit(f'call {kind} @llvm.{operation}.v{count}i{lane_bits}({kind} {left}, {kind} {right})')
    return function.emit(f'bitcast {kind} {result} to i{bits}')


def _lower_horizontal(function, ins, bits, lane_bits, is_float):
    """PHADDD/PHADDW/VHADDPS/VHADDPD: adjacent lanes are added within each 128-bit lane."""
    count = bits // lane_bits
    kind = _veckind(bits, lane_bits, is_float)
    left = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[1], bits)} to {kind}')
    right = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to {kind}')
    per_group = 128 // lane_bits
    evens, odds = [], []
    for group in range(bits // 128):
        base = group * per_group
        for start in (base, count + base):
            evens += [start + 2 * lane for lane in range(per_group // 2)]
            odds += [start + 2 * lane + 1 for lane in range(per_group // 2)]
    even_mask = ', '.join(f'i32 {index}' for index in evens)
    odd_mask = ', '.join(f'i32 {index}' for index in odds)
    low = function.emit(f'shufflevector {kind} {left}, {kind} {right}, <{count} x i32> <{even_mask}>')
    high = function.emit(f'shufflevector {kind} {left}, {kind} {right}, <{count} x i32> <{odd_mask}>')
    operation = 'fadd' if is_float else 'add'
    result = function.emit(f'{operation} {kind} {low}, {high}')
    return function.emit(f'bitcast {kind} {result} to i{bits}')


def _lower_minmax(function, ins, bits, lane_bits, is_float, is_min):
    kind = _veckind(bits, lane_bits, is_float)
    left = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[1], bits)} to {kind}')
    right = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to {kind}')
    if is_float:
        predicate = 'olt' if is_min else 'ogt'
        compare = function.emit(f'fcmp {predicate} {kind} {left}, {right}')
    else:
        _, signed, _ = PACKED_MINMAX_INT[ins.mnemonic]
        predicate = ('slt' if is_min else 'sgt') if signed else ('ult' if is_min else 'ugt')
        compare = function.emit(f'icmp {predicate} {kind} {left}, {right}')
    result = function.emit(f'select <{bits // lane_bits} x i1> {compare}, {kind} {left}, {kind} {right}')
    return function.emit(f'bitcast {kind} {result} to i{bits}')


def _lower_compare(function, ins, bits, lane_bits, predicate, is_float):
    kind = _veckind(bits, lane_bits, is_float)
    left = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[1], bits)} to {kind}')
    right = function.emit(f'bitcast i{bits} {_read(function, ins, ins.operands[2], bits)} to {kind}')
    compare = function.emit(f'{"fcmp" if is_float else "icmp"} {predicate} {kind} {left}, {right}')
    result = function.emit(f'sext <{bits // lane_bits} x i1> {compare} to {kind}')
    return function.emit(f'bitcast {kind} {result} to i{bits}')


def _lower_scalar_binary(function, ins, lane_bits, llvm_op):
    count = 128 // lane_bits
    kind = 'float' if lane_bits == 32 else 'double'
    src1 = ins.operands[1] if len(ins.operands) >= 3 else ins.operands[0]
    source = function.emit(f'bitcast i128 {_read(function, ins, src1, 128)} to <{count} x {kind}>')
    low = function.emit(f'extractelement <{count} x {kind}> {source}, i32 0')
    scalar = function.emit(f'bitcast i{lane_bits} {_read(function, ins, ins.operands[-1], lane_bits)} to {kind}')
    result = function.emit(f'{llvm_op} {kind} {low}, {scalar}')
    merged = function.emit(f'insertelement <{count} x {kind}> {source}, {kind} {result}, i32 0')
    return function.emit(f'bitcast <{count} x {kind}> {merged} to i128')


def _lower_scalar_minmax(function, ins, lane_bits, is_min):
    count = 128 // lane_bits
    kind = 'float' if lane_bits == 32 else 'double'
    src1 = ins.operands[1] if len(ins.operands) >= 3 else ins.operands[0]
    source = function.emit(f'bitcast i128 {_read(function, ins, src1, 128)} to <{count} x {kind}>')
    low = function.emit(f'extractelement <{count} x {kind}> {source}, i32 0')
    scalar = function.emit(f'bitcast i{lane_bits} {_read(function, ins, ins.operands[-1], lane_bits)} to {kind}')
    predicate = 'olt' if is_min else 'ogt'
    compare = function.emit(f'fcmp {predicate} {kind} {low}, {scalar}')
    result = function.emit(f'select i1 {compare}, {kind} {low}, {kind} {scalar}')
    merged = function.emit(f'insertelement <{count} x {kind}> {source}, {kind} {result}, i32 0')
    return function.emit(f'bitcast <{count} x {kind}> {merged} to i128')


def lower(function, ins):
    op, args = ins.mnemonic, ins.operands
    if op not in SUPPORTED:
        return False
    if op in avx_ext.LOWERED:
        return avx_ext.lower(function, ins)
    if op == 'vzeroupper':
        for index in range(16):
            function.store_vector(f'ymm_hi{index}', '0')
        return True
    bits = args[0].size * 8
    read = lambda operand, width=bits: _read(function, ins, operand, width)
    if op in ('vmovdqa', 'vmovaps', 'vmovapd'):
        _aligned(function, ins, bits)
    if op in MOVES:
        _write(function, ins, args[0], read(args[1]), bits)
    elif op in SCALAR_MOVES:
        lane = 32 if op == 'vmovss' else 64
        if _register(ins, args[0]):
            if len(args) == 2:
                value = function.emit(f'zext i{lane} {read(args[1], lane)} to i128')
            else:
                high = function.emit(f'and i128 {read(args[1], 128)}, {MASK128 ^ ((1 << lane) - 1)}')
                value = function.emit(f'or i128 {high}, {function.emit(f"zext i{lane} {read(args[2], lane)} to i128")}')
            _write(function, ins, args[0], value, 128)
        else:
            _write(function, ins, args[0], read(args[1], lane), lane)
    elif op in INT_CONVERSIONS:
        lane = 64 if op in ('vcvtsi2sd', 'vcvtss2sd') else 32
        src1 = args[1] if len(args) >= 3 else args[0]
        if op in ('vcvtsi2ss', 'vcvtsi2sd'):
            source_bits = args[-1].size * 8
        else:
            source_bits = 64 if op == 'vcvtsd2ss' else 32
        source_value = _read(function, ins, args[-1], source_bits)
        if op in ('vcvtsi2ss', 'vcvtsi2sd'):
            converted = function.emit(f'sitofp i{source_bits} {source_value} to {"float" if lane == 32 else "double"}')
        elif op == 'vcvtss2sd':
            converted = function.emit(f'fpext float {function.emit(f"bitcast i32 {source_value} to float")} to double')
        else:
            converted = function.emit(f'fptrunc double {function.emit(f"bitcast i64 {source_value} to double")} to float')
        scalar = function.emit(f'bitcast {"float" if lane == 32 else "double"} {converted} to i{lane}')
        vector_type = f'<{128 // lane} x i{lane}>'
        base = function.emit(f'bitcast i128 {read(src1, 128)} to {vector_type}')
        merged = function.emit(f'insertelement {vector_type} {base}, i{lane} {scalar}, i32 0')
        _write(function, ins, args[0], function.emit(f'bitcast {vector_type} {merged} to i128'), 128)
    elif op in ('vmovd', 'vmovq'):
        width = 32 if op == 'vmovd' else 64
        _write(function, ins, args[0], read(args[1], width), width)
    elif op in BROADCASTS:
        lane = BROADCASTS[op]
        count = bits // lane
        kind = f'<{count} x i{lane}>'
        scalar = read(args[1], lane)
        lane_vector = function.emit(f'insertelement {kind} zeroinitializer, i{lane} {scalar}, i32 0')
        value = function.emit(f'shufflevector {kind} {lane_vector}, {kind} zeroinitializer, <{count} x i32> zeroinitializer')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {value} to i{bits}'), bits)
    elif op in BITWISE:
        value = '0' if BITWISE[op] == 'xor' and _same(args[1], args[2]) else function.emit(f'{BITWISE[op]} i{bits} {read(args[1])}, {read(args[2])}')
        _write(function, ins, args[0], value, bits)
    elif op in ANDNOT:
        value = function.emit(f'xor i{bits} {read(args[1])}, -1')
        _write(function, ins, args[0], function.emit(f'and i{bits} {value}, {read(args[2])}'), bits)
    elif op in PACKED_FLOAT:
        llvm_op, lane = PACKED_FLOAT[op]
        _write(function, ins, args[0], _lower_binary(function, ins, bits, llvm_op, lane, True), bits)
    elif op in PACKED_MINMAX:
        lane, is_min = PACKED_MINMAX[op]
        _write(function, ins, args[0], _lower_minmax(function, ins, bits, lane, True, is_min), bits)
    elif op in SCALAR_FLOAT:
        llvm_op, lane = SCALAR_FLOAT[op]
        _write(function, ins, args[0], _lower_scalar_binary(function, ins, lane, llvm_op), 128)
    elif op in SCALAR_MINMAX:
        lane, is_min = SCALAR_MINMAX[op]
        _write(function, ins, args[0], _lower_scalar_minmax(function, ins, lane, is_min), 128)
    elif op in PACKED_INT:
        llvm_op, lane = PACKED_INT[op]
        _write(function, ins, args[0], _lower_binary(function, ins, bits, llvm_op, lane, False), bits)
    elif op in PACKED_ODDS:
        _write(function, ins, args[0], _lower_odd(function, ins, bits, op), bits)
    elif op in PACKED_SAT:
        _write(function, ins, args[0], _lower_saturating(function, ins, bits, *PACKED_SAT[op]), bits)
    elif op in HORIZONTAL:
        _write(function, ins, args[0], _lower_horizontal(function, ins, bits, *HORIZONTAL[op]), bits)
    elif op in MXCSR:
        # No MXCSR is modelled: the ABI's floating-point policy (round to nearest, subnormals
        # preserved, exceptions masked) is the architectural default, which is what a save/restore
        # pair round-trips. `vldmxcsr` is a no-op and `vstmxcsr` stores that default.
        if op == 'vstmxcsr':
            function.write(ins, args[0], '8064')
    elif op in GATHER:
        _write(function, ins, args[0], _lower_gather(function, ins, bits, op), bits)
        _write(function, ins, args[2], '0', 128)
    elif op in AES:
        kind = '<16 x i8>'
        source = function.emit(f'bitcast i128 {_read(function, ins, args[1], 128)} to {kind}')
        result = function.emit(f'call {kind} @llvm.aarch64.crypto.aesimc({kind} {source})')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'), 128)
    elif op in PCLMUL:
        _write(function, ins, args[0], _lower_pclmul(function, ins), 128)
    elif op in MASKED:
        register = args[0] if _register(ins, args[0]) is not None else args[2]
        lane_bits = register.size * 8
        lanes = lane_bits // 32
        kind = f'<{lanes} x i32>'
        source = function.emit(f'bitcast i{lane_bits} {_read(function, ins, args[1], lane_bits)} to {kind}')
        splat = ', '.join(['i32 31'] * lanes)
        shifted = function.emit(f'lshr {kind} {source}, <{splat}>')
        mask = function.emit(f'trunc {kind} {shifted} to <{lanes} x i1>')
        if _register(ins, args[0]) is not None:
            pointer = function.address(ins, args[2])
            loaded = function.emit(f'call {kind} @llvm.masked.load.v{lanes}i32.p0(ptr {pointer}, i32 1, <{lanes} x i1> {mask}, {kind} zeroinitializer)')
            _write(function, ins, args[0], function.emit(f'bitcast {kind} {loaded} to i{lane_bits}'), lane_bits)
        else:
            pointer = function.address(ins, args[0])
            value = function.emit(f'bitcast i{lane_bits} {_read(function, ins, args[2], lane_bits)} to {kind}')
            function.lines.append(f'  call void @llvm.masked.store.v{lanes}i32.p0({kind} {value}, ptr {pointer}, i32 1, <{lanes} x i1> {mask})')
    elif op in PACKED_CMPEQ or op in PACKED_CMPGT:
        lane = (PACKED_CMPEQ | PACKED_CMPGT)[op]
        predicate = 'eq' if op in PACKED_CMPEQ else 'sgt'
        _write(function, ins, args[0], _lower_compare(function, ins, bits, lane, predicate, False), bits)
    elif op in PACKED_MINMAX_INT:
        lane, signed, is_min = PACKED_MINMAX_INT[op]
        _write(function, ins, args[0], _lower_minmax(function, ins, bits, lane, False, is_min), bits)
    elif op in UNPACKS:
        width, high = UNPACKS[op]
        count = 128 // width
        total = bits // width
        left = read(args[1])
        right = read(args[2])
        indices = []
        for group in range(bits // 128):
            a_base = group * count
            b_base = total + group * count
            for lane in range(count):
                source_lane = (count // 2 + lane // 2) if high else (lane // 2)
                indices.append((a_base if lane % 2 == 0 else b_base) + source_lane)
        source = f'<{total} x i{width}>'
        left_v = function.emit(f'bitcast i{bits} {left} to {source}')
        right_v = function.emit(f'bitcast i{bits} {right} to {source}')
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {source} {left_v}, {source} {right_v}, <{total} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast {source} {result} to i{bits}'), bits)
    elif op in SHUF_IMM:
        width, bits_per_selector = SHUF_IMM[op]
        count = 128 // width
        total = bits // width
        control = args[3].imm
        indices = []
        for group in range(bits // 128):
            offset = group * count
            for lane in range(count):
                if op == 'vshufps':
                    selector = (control >> (lane * 2)) & 3
                else:
                    selector = (control >> (group * count + lane)) & 1
                source = 0 if lane < count // 2 else 1
                indices.append(offset + (selector % count) + source * total)
        source = f'<{total} x i{width}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {source}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {source}')
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {source} {left}, {source} {right}, <{total} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast {source} {result} to i{bits}'), bits)
    elif op in PERMIL_IMM:
        width = PERMIL_IMM[op]
        count = 128 // width
        total = bits // width
        source = f'<{total} x i{width}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {source}')
        if args[2].type == X86_OP_IMM:
            control = args[2].imm
            indices = []
            for group in range(bits // 128):
                offset = group * count
                for lane in range(count):
                    if width == 32:
                        selector = (control >> (lane * 2)) & 3
                    else:
                        selector = (control >> (group * count + lane)) & 1
                    indices.append(offset + selector)
            mask = ', '.join(f'i32 {index}' for index in indices)
            result = function.emit(f'shufflevector {source} {left}, {source} zeroinitializer, <{total} x i32> <{mask}>')
        else:
            right = function.emit(f'bitcast i{bits} {read(args[2])} to {source}')
            if width == 32:
                masked = function.emit(f'and {source} {right}, <{", ".join([f"i{width} 3"] * total)}>')
            else:
                shifted = function.emit(f'lshr {source} {right}, <{", ".join([f"i{width} 1"] * total)}>')
                masked = function.emit(f'and {source} {shifted}, <{", ".join([f"i{width} 1"] * total)}>')
            offsets = []
            for base in range(0, bits, 128):
                offsets.extend([base // width] * count)
            index_vector = function.emit(f'add {source} {masked}, <{", ".join(f"i{width} {offset}" for offset in offsets)}>')
            result = 'zeroinitializer'
            for lane in range(total):
                index = function.emit(f'extractelement {source} {index_vector}, i32 {lane}')
                selected = function.emit(f'extractelement {source} {left}, i{width} {index}')
                result = function.emit(f'insertelement {source} {result}, i{width} {selected}, i32 {lane}')
        _write(function, ins, args[0], function.emit(f'bitcast {source} {result} to i{bits}'), bits)
    elif op in MOVLHPS:
        left = read(args[1], 128)
        right = read(args[2], 128)
        if op == 'vmovlhps':
            indices = [0, 1, 4, 5]
        else:
            indices = [6, 7, 2, 3]
        left_v = function.emit(f'bitcast i128 {left} to <4 x i32>')
        right_v = function.emit(f'bitcast i128 {right} to <4 x i32>')
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector <4 x i32> {left_v}, <4 x i32> {right_v}, <4 x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast <4 x i32> {result} to i128'), 128)
    elif op in SHIFTS_IMM:
        llvm_op, lane = SHIFTS_IMM[op]
        count = bits // lane
        kind = f'<{count} x i{lane}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        if args[2].type == X86_OP_IMM:
            amount = args[2].imm
            if amount >= lane:
                if llvm_op == 'ashr':
                    splat = ', '.join([f'i{lane} {lane - 1}'] * count)
                    value = function.emit(f'{llvm_op} {kind} {left}, <{splat}>')
                else:
                    value = f'zeroinitializer'
            else:
                splat = ', '.join([f'i{lane} {amount}'] * count)
                value = function.emit(f'{llvm_op} {kind} {left}, <{splat}>')
        else:
            shift = read(args[2])
            lanes = bits // 128
            per_group = count // lanes
            count64 = 'zeroinitializer'
            for group in range(lanes):
                chunk = function.emit(f'lshr i{bits} {shift}, {group * 128}')
                chunk = function.emit(f'trunc i{bits} {chunk} to i64')
                for index in range(per_group):
                    count64 = function.emit(f'insertelement <{count} x i64> {count64}, i64 {chunk}, i32 {group * per_group + index}')
            valid = function.emit(f'icmp ult <{count} x i64> {count64}, <{", ".join([f"i64 {lane}"] * count)}>')
            masked = function.emit(f'and <{count} x i64> {count64}, <{", ".join([f"i64 {lane - 1}"] * count)}>')
            safe = function.emit(f'trunc <{count} x i64> {masked} to {kind}')
            shifted = function.emit(f'{llvm_op} {kind} {left}, {safe}')
            if llvm_op == 'ashr':
                splat = ', '.join([f'i{lane} {lane - 1}'] * count)
                saturated = function.emit(f'ashr {kind} {left}, <{splat}>')
                value = function.emit(f'select <{count} x i1> {valid}, {kind} {shifted}, {kind} {saturated}')
            else:
                value = function.emit(f'select <{count} x i1> {valid}, {kind} {shifted}, {kind} zeroinitializer')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {value} to i{bits}'), bits)
    elif op in SHIFTS_VAR:
        llvm_op, lane = SHIFTS_VAR[op]
        count = bits // lane
        kind = f'<{count} x i{lane}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        counts = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
        valid = function.emit(f'icmp ult {kind} {counts}, <{", ".join([f"i{lane} {lane}"] * count)}>')
        safe = function.emit(f'and {kind} {counts}, <{", ".join([f"i{lane} {lane - 1}"] * count)}>')
        shifted = function.emit(f'{llvm_op} {kind} {left}, {safe}')
        if llvm_op == 'ashr':
            splat = ', '.join([f'i{lane} {lane - 1}'] * count)
            saturated = function.emit(f'ashr {kind} {left}, <{splat}>')
            value = function.emit(f'select <{count} x i1> {valid}, {kind} {shifted}, {kind} {saturated}')
        else:
            value = function.emit(f'select <{count} x i1> {valid}, {kind} {shifted}, {kind} zeroinitializer')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {value} to i{bits}'), bits)
    elif op in BYTE_SHIFTS:
        count = bits // 8
        amount = args[2].imm
        source = f'<{count} x i8>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {source}')
        indices = []
        for base in range(0, bits, 128):
            offset = base // 8
            for lane in range(16):
                if op == 'vpslldq':
                    index = lane - amount
                    indices.append(offset + index if 0 <= index < 16 else count)
                else:
                    index = lane + amount
                    indices.append(offset + index if 0 <= index < 16 else count)
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {source} {left}, {source} zeroinitializer, <{count} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast {source} {result} to i{bits}'), bits)
    elif op in PACKS:
        source_width, target_width, signed = PACKS[op]
        count = bits // source_width
        total = bits // target_width
        half = count // (bits // 128)
        kind = f'<{count} x i{source_width}>'
        target = f'<{count} x i{target_width}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
        if signed:
            low_limit = '<' + ', '.join([f'i{source_width} {-((1 << (target_width - 1)))}'] * count) + '>'
            high_limit = '<' + ', '.join([f'i{source_width} {(1 << (target_width - 1)) - 1}'] * count) + '>'
        else:
            low_limit = 'zeroinitializer'
            high_limit = '<' + ', '.join([f'i{source_width} {(1 << target_width) - 1}'] * count) + '>'
        values = []
        for value in (left, right):
            below = function.emit(f'icmp slt {kind} {value}, {low_limit}')
            above = function.emit(f'icmp sgt {kind} {value}, {high_limit}')
            low = function.emit(f'select <{count} x i1> {below}, {kind} {low_limit}, {kind} {value}')
            high = function.emit(f'select <{count} x i1> {above}, {kind} {high_limit}, {kind} {low}')
            values.append(function.emit(f'trunc {kind} {high} to {target}'))
        indices = []
        for group in range(bits // 128):
            a_base = group * half
            b_base = count + group * half
            indices.extend(range(a_base, a_base + half))
            indices.extend(range(b_base, b_base + half))
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {target} {values[0]}, {target} {values[1]}, <{total} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast <{total} x i{target_width}> {result} to i{bits}'), bits)
    elif op in EXTENDS:
        source_width, target_width, signed = EXTENDS[op]
        count = bits // target_width
        source_bits = count * source_width
        source = f'<{count} x i{source_width}>'
        target = f'<{count} x i{target_width}>'
        value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {source}')
        extended = function.emit(f'{"sext" if signed else "zext"} {source} {value} to {target}')
        _write(function, ins, args[0], function.emit(f'bitcast {target} {extended} to i{bits}'), bits)
    elif op in ABS:
        width = ABS[op]
        count = bits // width
        kind = f'<{count} x i{width}>'
        value = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        negative = function.emit(f'icmp slt {kind} {value}, zeroinitializer')
        negated = function.emit(f'sub {kind} zeroinitializer, {value}')
        result = function.emit(f'select <{count} x i1> {negative}, {kind} {negated}, {kind} {value}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in PTEST:
        left = read(args[0])
        right = read(args[1])
        intersection = function.emit(f'and i{bits} {left}, {right}')
        zf = function.emit(f'icmp eq i{bits} {intersection}, 0')
        if op == 'vptest':
            difference = function.emit(f'and i{bits} {left}, {function.emit(f"xor i{bits} {right}, -1")}')
            cf = function.emit(f'icmp eq i{bits} {difference}, 0')
        else:
            cf = 'false'
        function.lines.append(f'  store i1 {zf}, ptr %zf, align 1')
        function.lines.append(f'  store i1 {cf}, ptr %cf, align 1')
    elif op in BLENDS_IMM:
        width = BLENDS_IMM[op]
        count = bits // width
        control = args[3].imm
        kind = f'<{count} x i{width}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
        per_lane = 8 if width == 16 else count
        condition = '<' + ', '.join(['i1 true' if (control >> (lane % per_lane)) & 1 else 'i1 false' for lane in range(count)]) + '>'
        result = function.emit(f'select <{count} x i1> {condition}, {kind} {right}, {kind} {left}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in BLENDS_VAR:
        width = BLENDS_VAR[op]
        count = bits // width
        kind = f'<{count} x i{width}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
        mask_bits = args[3].size * 8
        mask_value = function.emit(f'bitcast i{mask_bits} {read(args[3], mask_bits)} to <{count} x i{width}>')
        zero = '<' + ', '.join([f'i{width} 0'] * count) + '>'
        negative = function.emit(f'icmp slt <{count} x i{width}> {mask_value}, {zero}')
        result = function.emit(f'select <{count} x i1> {negative}, {kind} {right}, {kind} {left}')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in PERMS:
        _lower_perm(function, ins, bits)
    elif op in FLAGS_COMPARE:
        lane = FLAGS_COMPARE[op]
        kind = 'float' if lane == 32 else 'double'
        left = function.emit(f'bitcast i{lane} {read(args[0], lane)} to {kind}')
        right = function.emit(f'bitcast i{lane} {read(args[1], lane)} to {kind}')
        flags = {'zf': function.emit(f'fcmp ueq {kind} {left}, {right}'),
                 'pf': function.emit(f'fcmp uno {kind} {left}, {right}'),
                 'cf': function.emit(f'fcmp ult {kind} {left}, {right}'),
                 'of': 'false', 'sf': 'false'}
        for name, value in flags.items():
            function.lines.append(f'  store i1 {value}, ptr %{name}, align 1')
    elif op in MOVMSK:
        lane = MOVMSK[op]
        source_bits = args[1].size * 8
        count = source_bits // lane
        dest_bits = args[0].size * 8
        kind = f'<{count} x i{lane}>'
        value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
        result = '0'
        for index in range(count):
            element = function.emit(f'extractelement {kind} {value}, i32 {index}')
            sign = function.emit(f'lshr i{lane} {element}, {lane - 1}')
            bit = function.emit(f'and i{lane} {sign}, 1')
            if dest_bits == lane:
                wide = bit
            elif dest_bits > lane:
                wide = function.emit(f'zext i{lane} {bit} to i{dest_bits}')
            else:
                wide = function.emit(f'trunc i{lane} {bit} to i{dest_bits}')
            shifted = function.emit(f'shl i{dest_bits} {wide}, {index}')
            result = function.emit(f'or i{dest_bits} {result}, {shifted}')
        _write(function, ins, args[0], result, dest_bits)
    elif op in DUPS:
        lane = DUPS[op]
        per_lane = 128 // lane
        count = bits // lane
        kind = f'<{count} x i{lane}>'
        value = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        indices = []
        for group in range(bits // 128):
            base = group * per_lane
            if op == 'vmovddup':
                indices.extend([base, base])
            elif op == 'vmovshdup':
                indices.extend([base + 1, base + 1, base + 3, base + 3])
            else:
                indices.extend([base, base, base + 2, base + 2])
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {kind} {value}, {kind} zeroinitializer, <{count} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in BROADCAST128:
        value = function.emit(f'zext i128 {read(args[1], 128)} to i256')
        high = function.emit(f'shl i256 {value}, 128')
        _write(function, ins, args[0], function.emit(f'or i256 {value}, {high}'), 256)
    elif op in CMP:
        lane, _index = CMP[op]
        predicate = CMP_PREDICATES[_index]
        if op.endswith(('ss', 'sd')):
            kind = 'float' if lane == 32 else 'double'
            count = 128 // lane
            src1 = args[1] if len(args) >= 3 else args[0]
            src2 = args[2] if len(args) >= 3 else args[1]
            left = function.emit(f'bitcast i{lane} {read(src1, lane)} to {kind}')
            right = function.emit(f'bitcast i{lane} {read(src2, lane)} to {kind}')
            compare = function.emit(f'fcmp {predicate} {kind} {left}, {right}')
            mask = function.emit(f'sext i1 {compare} to i{lane}')
            base = function.emit(f'bitcast i128 {read(src1, 128)} to <{count} x i{lane}>')
            merged = function.emit(f'insertelement <{count} x i{lane}> {base}, i{lane} {mask}, i32 0')
            _write(function, ins, args[0], function.emit(f'bitcast <{count} x i{lane}> {merged} to i128'), 128)
        else:
            count = bits // lane
            kind = f'<{count} x {"float" if lane == 32 else "double"}>'
            left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
            right = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
            compare = function.emit(f'fcmp {predicate} {kind} {left}, {right}')
            result = function.emit(f'sext <{count} x i1> {compare} to <{count} x i{lane}>')
            _write(function, ins, args[0], function.emit(f'bitcast <{count} x i{lane}> {result} to i{bits}'), bits)
    elif op in VTEST:
        lane = VTEST[op]
        count = bits // lane
        kind = f'<{count} x i{lane}>'
        left = function.emit(f'bitcast i{bits} {read(args[0])} to {kind}')
        right = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        left_negative = function.emit(f'icmp slt {kind} {left}, zeroinitializer')
        right_negative = function.emit(f'icmp slt {kind} {right}, zeroinitializer')
        zero_any = 'false'
        one_any = 'false'
        for index in range(count):
            ln = function.emit(f'extractelement <{count} x i1> {left_negative}, i32 {index}')
            rn = function.emit(f'extractelement <{count} x i1> {right_negative}, i32 {index}')
            both = function.emit(f'and i1 {ln}, {rn}')
            only = function.emit(f'and i1 {function.emit(f"xor i1 {ln}, true")}, {rn}')
            zero_any = function.emit(f'or i1 {zero_any}, {both}')
            one_any = function.emit(f'or i1 {one_any}, {only}')
        zf = function.emit(f'xor i1 {zero_any}, true')
        cf = function.emit(f'xor i1 {one_any}, true')
        function.lines.append(f'  store i1 {zf}, ptr %zf, align 1')
        function.lines.append(f'  store i1 {cf}, ptr %cf, align 1')
    elif op in EXTRACT_ELEM:
        lane = EXTRACT_ELEM[op]
        source_bits = 128
        count = source_bits // lane
        kind = f'<{count} x i{lane}>'
        value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
        element = function.emit(f'extractelement {kind} {value}, i32 {args[2].imm}')
        dest_bits = args[0].size * 8
        if dest_bits > lane:
            element = function.emit(f'zext i{lane} {element} to i{dest_bits}')
        _write(function, ins, args[0], element, dest_bits)
    elif op in INSERT_ELEM:
        if op == 'vinsertps':
            imm = args[3].imm
            base = function.emit(f'bitcast i128 {read(args[1], 128)} to <4 x i32>')
            if args[2].type == X86_OP_REG:
                source = function.emit(f'bitcast i128 {read(args[2], 128)} to <4 x i32>')
                value = function.emit(f'extractelement <4 x i32> {source}, i32 {(imm >> 6) & 3}')
            else:
                value = read(args[2], 32)
            result = function.emit(f'insertelement <4 x i32> {base}, i32 {value}, i32 {(imm >> 4) & 3}')
            condition = '<' + ', '.join(['i1 true' if (imm >> lane) & 1 else 'i1 false' for lane in range(4)]) + '>'
            result = function.emit(f'select <4 x i1> {condition}, <4 x i32> zeroinitializer, <4 x i32> {result}')
            _write(function, ins, args[0], function.emit(f'bitcast <4 x i32> {result} to i128'), 128)
        else:
            lane = INSERT_ELEM[op]
            count = 128 // lane
            kind = f'<{count} x i{lane}>'
            base = function.emit(f'bitcast i128 {read(args[1], 128)} to {kind}')
            value = _read(function, ins, args[2], lane)
            result = function.emit(f'insertelement {kind} {base}, i{lane} {value}, i32 {args[3].imm}')
            _write(function, ins, args[0], function.emit(f'bitcast {kind} {result} to i128'), 128)
    elif op in LEGACY_MOVES:
        lane = 64
        high = op.endswith('hps') or op.endswith('hpd')
        if len(args) >= 3:
            if high:
                base = function.emit(f'and i128 {read(args[1], 128)}, {(1 << lane) - 1}')
                value = function.emit(f'shl i128 {function.emit(f"zext i{lane} {read(args[2], lane)} to i128")}, {lane}')
            else:
                base = function.emit(f'and i128 {read(args[1], 128)}, {MASK128 ^ ((1 << lane) - 1)}')
                value = function.emit(f'zext i{lane} {read(args[2], lane)} to i128')
            _write(function, ins, args[0], function.emit(f'or i128 {base}, {value}'), 128)
        else:
            source = read(args[1], 128)
            if high:
                source = function.emit(f'lshr i128 {source}, {lane}')
            _write(function, ins, args[0], function.emit(f'trunc i128 {source} to i{lane}'), lane)
    elif op == 'vpbroadcastd':
        count = bits // 32
        scalar = read(args[1], 32)
        lane = function.emit(f'insertelement <{count} x i32> zeroinitializer, i32 {scalar}, i32 0')
        value = function.emit(f'shufflevector <{count} x i32> {lane}, <{count} x i32> zeroinitializer, <{count} x i32> zeroinitializer')
        _write(function, ins, args[0], function.emit(f'bitcast <{count} x i32> {value} to i{bits}'), bits)
    elif op == 'vpshufd':
        count = bits // 32
        source = function.emit(f'bitcast i{bits} {read(args[1])} to <{count} x i32>')
        mask = [(lane // 4) * 4 + ((args[2].imm >> ((lane % 4) * 2)) & 3) for lane in range(count)]
        indices = ', '.join(f'i32 {index}' for index in mask)
        value = function.emit(f'shufflevector <{count} x i32> {source}, <{count} x i32> zeroinitializer, <{count} x i32> <{indices}>')
        _write(function, ins, args[0], function.emit(f'bitcast <{count} x i32> {value} to i{bits}'), bits)
    elif op == 'vpsllvd':
        count = bits // 32
        left, shifts = (function.emit(f'bitcast i{bits} {read(operand)} to <{count} x i32>') for operand in args[1:3])
        threshold = '<' + ', '.join(['i32 32'] * count) + '>'
        mask = '<' + ', '.join(['i32 31'] * count) + '>'
        valid = function.emit(f'icmp ult <{count} x i32> {shifts}, {threshold}')
        safe = function.emit(f'and <{count} x i32> {shifts}, {mask}')
        shifted = function.emit(f'shl <{count} x i32> {left}, {safe}')
        value = function.emit(f'select <{count} x i1> {valid}, <{count} x i32> {shifted}, <{count} x i32> zeroinitializer')
        _write(function, ins, args[0], function.emit(f'bitcast <{count} x i32> {value} to i{bits}'), bits)
    return True


def _lower_perm(function, ins, bits):
    op, args = ins.mnemonic, ins.operands
    read = lambda operand, width=bits: _read(function, ins, operand, width)
    if op == 'vextractf128':
        source = read(args[1], 256)
        high = function.emit(f'lshr i256 {source}, {args[2].imm * 128}')
        high = function.emit(f'trunc i256 {high} to i128')
        _write(function, ins, args[0], high, 128)
    elif op == 'vinsertf128':
        base = read(args[1], 256)
        insert = function.emit(f'zext i128 {read(args[2], 128)} to i256')
        insert = function.emit(f'shl i256 {insert}, {args[3].imm * 128}')
        keep = function.emit(f'and i256 {base}, {((1 << 256) - 1) ^ (MASK128 << (args[3].imm * 128))}')
        _write(function, ins, args[0], function.emit(f'or i256 {keep}, {insert}'), 256)
    elif op in ('vperm2f128', 'vperm2i128'):
        control = args[3].imm
        left = read(args[1], 256)
        right = read(args[2], 256)
        parts = []
        for half in range(2):
            selector = (control >> (half * 4)) & 0xf
            if selector & 0x8:
                parts.append(None)
                continue
            source = left if ((selector >> 1) & 1) == 0 else right
            lane = selector & 1
            chunk = function.emit(f'lshr i256 {source}, {lane * 128}')
            chunk = function.emit(f'trunc i256 {chunk} to i128')
            parts.append(chunk)
        low, high = parts
        low_value = '0' if low is None else function.emit(f'zext i128 {low} to i256')
        if high is None:
            high_value = '0'
        else:
            high_value = function.emit(f'zext i128 {high} to i256')
            high_value = function.emit(f'shl i256 {high_value}, 128')
        _write(function, ins, args[0], function.emit(f'or i256 {low_value}, {high_value}'), 256)
    elif op in ('vpermq', 'vpermpd'):
        control = args[2].imm
        lanes = bits // 64
        source = function.emit(f'bitcast i{bits} {read(args[1])} to <{lanes} x i64>')
        if lanes == 2:
            indices = [control & 1, (control >> 1) & 1]
        else:
            indices = [(control >> (lane * 2)) & 3 for lane in range(4)]
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector <{lanes} x i64> {source}, <{lanes} x i64> zeroinitializer, <{lanes} x i32> <{mask}>')
        _write(function, ins, args[0], function.emit(f'bitcast <{lanes} x i64> {result} to i{bits}'), bits)
    elif op in ('vpermd', 'vpermps'):
        count = bits // 32
        source = function.emit(f'bitcast i{bits} {read(args[2])} to <{count} x i32>')
        indices = function.emit(f'bitcast i{bits} {read(args[1])} to <{count} x i32>')
        parts = []
        for lane in range(count):
            index = function.emit(f'extractelement <{count} x i32> {indices}, i32 {lane}')
            mask = function.emit(f'and i32 {index}, {count - 1}')
            selected = function.emit(f'extractelement <{count} x i32> {source}, i32 {mask}')
            parts.append(selected)
        result = 'zeroinitializer'
        for lane, value in enumerate(parts):
            result = function.emit(f'insertelement <{count} x i32> {result}, i32 {value}, i32 {lane}')
        _write(function, ins, args[0], function.emit(f'bitcast <{count} x i32> {result} to i{bits}'), bits)


import avx_ext  # noqa: E402  (delegates the extended lower families; imported last to avoid a cycle)

"""AVX/AVX2 instruction families whose lowering is split out of avx.py.

Covers the rounding/sqrt/reciprocal intrinsics, the cvt families with x86 rounding
and overflow semantics, scalar/vector float-to-int, the extract/insert-128 and
byte-shuffle instructions, and F16C. avx.py owns the tables and the analyze pass and
delegates lower() for these mnemonics.
"""
import avx


LOWERED = (set(avx.ROUNDS) | set(avx.SQRT) | set(avx.RECIP) | set(avx.CVT_ROUND)
           | set(avx.TO_INT) | avx.EXTRACT128 | avx.INSERT128 | set(avx.PSHUFB)
           | set(avx.PALIGNR) | avx.HALF | set(avx.SHUF_WORDS) | set(avx.MUL64)
           | set(avx.ADDSUB) | set(avx.MADD))
MASK128 = avx.MASK128
MASK256 = avx.MASK256


def _float_to_int(function, value, element_bits, count, result_bits):
    kind = f'<{count} x {"float" if element_bits == 32 else "double"}>'
    floating = 'float' if element_bits == 32 else 'double'
    low, high = (-2147483648.0, 2147483648.0) if result_bits == 32 else (-9223372036854775808.0, 9223372036854775808.0)
    low_vector = '<' + ', '.join([f'{floating} {low}'] * count) + '>'
    high_vector = '<' + ', '.join([f'{floating} {high}'] * count) + '>'
    above = function.emit(f'fcmp oge {kind} {value}, {low_vector}')
    below = function.emit(f'fcmp olt {kind} {value}, {high_vector}')
    in_range = function.emit(f'and <{count} x i1> {above}, {below}')
    zero = '<' + ', '.join([f'{floating} 0.000000e+00'] * count) + '>'
    clamped = function.emit(f'select <{count} x i1> {in_range}, {kind} {value}, {kind} {zero}')
    converted = function.emit(f'fptosi {kind} {clamped} to <{count} x i{result_bits}>')
    indefinite = '<' + ', '.join([f'i{result_bits} {-2 ** (result_bits - 1)}'] * count) + '>'
    return function.emit(f'select <{count} x i1> {in_range}, <{count} x i{result_bits}> {converted}, <{count} x i{result_bits}> {indefinite}')


def _scalar_float_to_int(function, value, element_bits, result_bits):
    kind = 'float' if element_bits == 32 else 'double'
    low, high = (-2147483648.0, 2147483648.0) if result_bits == 32 else (-9223372036854775808.0, 9223372036854775808.0)
    above = function.emit(f'fcmp oge {kind} {value}, {low}')
    below = function.emit(f'fcmp olt {kind} {value}, {high}')
    in_range = function.emit(f'and i1 {above}, {below}')
    clamped = function.emit(f'select i1 {in_range}, {kind} {value}, {kind} 0.000000e+00')
    converted = function.emit(f'fptosi {kind} {clamped} to i{result_bits}')
    return function.emit(f'select i1 {in_range}, i{result_bits} {converted}, i{result_bits} {-2 ** (result_bits - 1)}')


def _pack(function, value, vector_bits, target_bits):
    return value if vector_bits == target_bits else function.emit(f'zext i{vector_bits} {value} to i{target_bits}')


def lower(function, ins):
    op, args = ins.mnemonic, ins.operands
    bits = args[0].size * 8
    read = lambda operand, width=bits: avx._read(function, ins, operand, width)
    write = lambda operand, value, width: avx._write(function, ins, operand, value, width)

    if op in avx.SQRT:
        lane = avx.SQRT[op]
        if op.endswith(('ss', 'sd')):
            count = 128 // lane
            kind = 'float' if lane == 32 else 'double'
            suffix = 'f32' if lane == 32 else 'f64'
            src1 = args[1] if len(args) >= 3 else args[0]
            source = function.emit(f'bitcast i128 {read(src1, 128)} to <{count} x {kind}>')
            scalar = function.emit(f'bitcast i{lane} {read(args[-1], lane)} to {kind}')
            root = function.emit(f'call {kind} @llvm.sqrt.{suffix}({kind} {scalar})')
            merged = function.emit(f'insertelement <{count} x {kind}> {source}, {kind} {root}, i32 0')
            write(args[0], function.emit(f'bitcast <{count} x {kind}> {merged} to i128'), 128)
        else:
            count = bits // lane
            kind = f'<{count} x {"float" if lane == 32 else "double"}>'
            suffix = f'v{count}f32' if lane == 32 else f'v{count}f64'
            value = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
            root = function.emit(f'call {kind} @llvm.sqrt.{suffix}({kind} {value})')
            write(args[0], function.emit(f'bitcast {kind} {root} to i{bits}'), bits)
    elif op in avx.ROUNDS:
        lane = avx.ROUNDS[op]
        intrinsic = ('rint', 'floor', 'ceil', 'trunc')[args[-1].imm & 3]
        if op.endswith(('ss', 'sd')):
            count = 128 // lane
            kind = 'float' if lane == 32 else 'double'
            suffix = 'f32' if lane == 32 else 'f64'
            src1 = args[1] if len(args) >= 3 else args[0]
            source = function.emit(f'bitcast i128 {read(src1, 128)} to <{count} x {kind}>')
            scalar = function.emit(f'bitcast i{lane} {read(args[-2], lane)} to {kind}')
            rounded = function.emit(f'call {kind} @llvm.{intrinsic}.{suffix}({kind} {scalar})')
            merged = function.emit(f'insertelement <{count} x {kind}> {source}, {kind} {rounded}, i32 0')
            write(args[0], function.emit(f'bitcast <{count} x {kind}> {merged} to i128'), 128)
        else:
            count = bits // lane
            kind = f'<{count} x {"float" if lane == 32 else "double"}>'
            suffix = f'v{count}f32' if lane == 32 else f'v{count}f64'
            value = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
            rounded = function.emit(f'call {kind} @llvm.{intrinsic}.{suffix}({kind} {value})')
            write(args[0], function.emit(f'bitcast {kind} {rounded} to i{bits}'), bits)
    elif op in avx.RECIP:
        is_rsqrt = op.startswith('vrsqrt')
        if op.endswith('ss'):
            count = 4
            src1 = args[1] if len(args) >= 3 else args[0]
            source = function.emit(f'bitcast i128 {read(src1, 128)} to <{count} x float>')
            scalar = function.emit(f'bitcast i32 {read(args[-1], 32)} to float')
            if is_rsqrt:
                root = function.emit(f'call float @llvm.sqrt.f32(float {scalar})')
                result = function.emit(f'fdiv float 1.000000e+00, {root}')
            else:
                result = function.emit(f'fdiv float 1.000000e+00, {scalar}')
            merged = function.emit(f'insertelement <{count} x float> {source}, float {result}, i32 0')
            write(args[0], function.emit(f'bitcast <{count} x float> {merged} to i128'), 128)
        else:
            count = bits // 32
            kind = f'<{count} x float>'
            value = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
            ones = '<' + ', '.join(['float 1.000000e+00'] * count) + '>'
            if is_rsqrt:
                root = function.emit(f'call {kind} @llvm.sqrt.v{count}f32({kind} {value})')
                result = function.emit(f'fdiv {kind} {ones}, {root}')
            else:
                result = function.emit(f'fdiv {kind} {ones}, {value}')
            write(args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in avx.CVT_ROUND:
        source_bits = args[1].size * 8
        if op in ('vcvtps2dq', 'vcvttps2dq'):
            count = source_bits // 32
            kind = f'<{count} x float>'
            value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
            if op == 'vcvtps2dq':
                value = function.emit(f'call {kind} @llvm.rint.v{count}f32({kind} {value})')
            result = _float_to_int(function, value, 32, count, 32)
            write(args[0], function.emit(f'bitcast <{count} x i32> {result} to i{bits}'), bits)
        elif op in ('vcvtpd2dq', 'vcvttpd2dq'):
            count = source_bits // 64
            kind = f'<{count} x double>'
            value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
            if op == 'vcvtpd2dq':
                value = function.emit(f'call {kind} @llvm.rint.v{count}f64({kind} {value})')
            result = _float_to_int(function, value, 64, count, 32)
            packed = function.emit(f'bitcast <{count} x i32> {result} to i{count * 32}')
            write(args[0], _pack(function, packed, count * 32, bits), bits)
        elif op == 'vcvtdq2ps':
            count = source_bits // 32
            kind = f'<{count} x i32>'
            value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
            result = function.emit(f'sitofp {kind} {value} to <{count} x float>')
            write(args[0], function.emit(f'bitcast <{count} x float> {result} to i{bits}'), bits)
        elif op == 'vcvtpd2ps':
            count = source_bits // 64
            kind = f'<{count} x double>'
            value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
            result = function.emit(f'fptrunc {kind} {value} to <{count} x float>')
            packed = function.emit(f'bitcast <{count} x float> {result} to i{count * 32}')
            write(args[0], _pack(function, packed, count * 32, bits), bits)
        elif op == 'vcvtdq2pd':
            count = bits // 64
            source_bits = count * 32
            kind = f'<{count} x i32>'
            value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
            result = function.emit(f'sitofp {kind} {value} to <{count} x double>')
            write(args[0], function.emit(f'bitcast <{count} x double> {result} to i{bits}'), bits)
        elif op == 'vcvtps2pd':
            # The lane count comes from the destination: the 128-bit form widens two floats, the
            # 256-bit form four, and only that many floats are read from the source.
            count = bits // 64
            source_bits = count * 32
            kind = f'<{count} x float>'
            value = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to {kind}')
            result = function.emit(f'fpext {kind} {value} to <{count} x double>')
            write(args[0], function.emit(f'bitcast <{count} x double> {result} to i{bits}'), bits)
    elif op in avx.TO_INT:
        lane = avx.TO_INT[op]
        kind = 'float' if lane == 32 else 'double'
        dest_bits = args[0].size * 8
        scalar = function.emit(f'bitcast i{lane} {read(args[1], lane)} to {kind}')
        if op in ('vcvtss2si', 'vcvtsd2si'):
            scalar = function.emit(f'call {kind} @llvm.rint.{"f32" if lane == 32 else "f64"}({kind} {scalar})')
        write(args[0], _scalar_float_to_int(function, scalar, lane, dest_bits), dest_bits)
    elif op in avx.EXTRACT128:
        source = read(args[1], 256)
        high = function.emit(f'lshr i256 {source}, {args[2].imm * 128}')
        high = function.emit(f'trunc i256 {high} to i128')
        write(args[0], high, 128)
    elif op in avx.INSERT128:
        base = read(args[1], 256)
        insert = function.emit(f'zext i128 {read(args[2], 128)} to i256')
        insert = function.emit(f'shl i256 {insert}, {args[3].imm * 128}')
        keep = function.emit(f'and i256 {base}, {MASK256 ^ (MASK128 << (args[3].imm * 128))}')
        write(args[0], function.emit(f'or i256 {keep}, {insert}'), 256)
    elif op in avx.PSHUFB:
        count = bits // 8
        kind = f'<{count} x i8>'
        source = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        control = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
        result = 'zeroinitializer'
        for index in range(count):
            ctl = function.emit(f'extractelement {kind} {control}, i32 {index}')
            lane_base = (index // 16) * 16
            low = function.emit(f'and i8 {ctl}, 15')
            wide = function.emit(f'zext i8 {low} to i32')
            offset = function.emit(f'add i32 {wide}, {lane_base}')
            selected = function.emit(f'extractelement {kind} {source}, i32 {offset}')
            negative = function.emit(f'icmp slt i8 {ctl}, 0')
            value = function.emit(f'select i1 {negative}, i8 0, i8 {selected}')
            result = function.emit(f'insertelement {kind} {result}, i8 {value}, i32 {index}')
        write(args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in avx.PALIGNR:
        count = bits // 8
        amount = args[3].imm
        kind = f'<{count} x i8>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
        indices, valid = [], []
        for group in range(bits // 128):
            base = group * 16
            for lane in range(16):
                position = amount + lane
                if position < 16:
                    indices.append(base + position)
                    valid.append(True)
                elif position < 32:
                    indices.append(count + base + position - 16)
                    valid.append(True)
                else:
                    indices.append(0)
                    valid.append(False)
        mask = ', '.join(f'i32 {index}' for index in indices)
        shuffled = function.emit(f'shufflevector {kind} {right}, {kind} {left}, <{count} x i32> <{mask}>')
        condition = '<' + ', '.join('i1 true' if value else 'i1 false' for value in valid) + '>'
        result = function.emit(f'select <{count} x i1> {condition}, {kind} {shuffled}, {kind} zeroinitializer')
        write(args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in avx.HALF:
        if op == 'vcvtph2ps':
            dest_bits = args[0].size * 8
            count = dest_bits // 32
            source_bits = count * 16
            source = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to <{count} x half>')
            result = function.emit(f'fpext <{count} x half> {source} to <{count} x float>')
            packed = function.emit(f'bitcast <{count} x float> {result} to i{count * 32}')
            write(args[0], _pack(function, packed, count * 32, dest_bits), dest_bits)
        else:
            source_bits = args[1].size * 8
            count = source_bits // 32
            dest_bits = args[0].size * 8
            source = function.emit(f'bitcast i{source_bits} {read(args[1], source_bits)} to <{count} x float>')
            result = function.emit(f'fptrunc <{count} x float> {source} to <{count} x half>')
            packed = function.emit(f'bitcast <{count} x half> {result} to i{count * 16}')
            write(args[0], _pack(function, packed, count * 16, dest_bits), dest_bits)
    elif op in avx.SHUF_WORDS:
        count = bits // 16
        kind = f'<{count} x i16>'
        source = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        control = args[2].imm
        indices = []
        for group in range(bits // 128):
            base = group * 8
            for lane in range(8):
                if op == 'vpshuflw':
                    indices.append(base + ((control >> (lane * 2)) & 3) if lane < 4 else base + lane)
                else:
                    indices.append(base + lane if lane < 4 else base + 4 + ((control >> ((lane - 4) * 2)) & 3))
        mask = ', '.join(f'i32 {index}' for index in indices)
        result = function.emit(f'shufflevector {kind} {source}, {kind} zeroinitializer, <{count} x i32> <{mask}>')
        write(args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in avx.MUL64:
        signed = avx.MUL64[op]
        count = bits // 64
        kind32 = f'<{bits // 32} x i32>'
        kind64 = f'<{count} x i64>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind32}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {kind32}')
        even = ', '.join(f'i32 {index * 2}' for index in range(count))
        left_even = function.emit(f'shufflevector {kind32} {left}, {kind32} zeroinitializer, <{count} x i32> <{even}>')
        right_even = function.emit(f'shufflevector {kind32} {right}, {kind32} zeroinitializer, <{count} x i32> <{even}>')
        extension = 'sext' if signed else 'zext'
        even_kind = f'<{count} x i32>'
        left64 = function.emit(f'{extension} {even_kind} {left_even} to {kind64}')
        right64 = function.emit(f'{extension} {even_kind} {right_even} to {kind64}')
        product = function.emit(f'mul {kind64} {left64}, {right64}')
        write(args[0], function.emit(f'bitcast {kind64} {product} to i{bits}'), bits)
    elif op in avx.ADDSUB:
        lane = avx.ADDSUB[op]
        count = bits // lane
        kind = f'<{count} x {"float" if lane == 32 else "double"}>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {kind}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {kind}')
        added = function.emit(f'fadd {kind} {left}, {right}')
        subtracted = function.emit(f'fsub {kind} {left}, {right}')
        condition = '<' + ', '.join('i1 false' if index % 2 == 0 else 'i1 true' for index in range(count)) + '>'
        result = function.emit(f'select <{count} x i1> {condition}, {kind} {added}, {kind} {subtracted}')
        write(args[0], function.emit(f'bitcast {kind} {result} to i{bits}'), bits)
    elif op in avx.MADD:
        count = bits // 32
        wide = f'<{bits // 16} x i16>'
        left = function.emit(f'bitcast i{bits} {read(args[1])} to {wide}')
        right = function.emit(f'bitcast i{bits} {read(args[2])} to {wide}')
        left32 = function.emit(f'sext {wide} {left} to <{bits // 16} x i32>')
        right32 = function.emit(f'sext {wide} {right} to <{bits // 16} x i32>')
        product = function.emit(f'mul <{bits // 16} x i32> {left32}, {right32}')
        even = ', '.join(f'i32 {index * 2}' for index in range(count))
        odd = ', '.join(f'i32 {index * 2 + 1}' for index in range(count))
        even_values = function.emit(f'shufflevector <{bits // 16} x i32> {product}, <{bits // 16} x i32> zeroinitializer, <{count} x i32> <{even}>')
        odd_values = function.emit(f'shufflevector <{bits // 16} x i32> {product}, <{bits // 16} x i32> zeroinitializer, <{count} x i32> <{odd}>')
        result = function.emit(f'add <{count} x i32> {even_values}, {odd_values}')
        write(args[0], function.emit(f'bitcast <{count} x i32> {result} to i{bits}'), bits)
    else:
        return False
    return True

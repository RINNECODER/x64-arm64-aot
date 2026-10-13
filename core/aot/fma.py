"""FMA lowering (Phase 2 lifter slice 3): VFMADD/VFMSUB/VFNMADD/VFNMSUB/VFMADDSUB/VFMSUBADD.

Kept a fused operation (`llvm.fma`, never a separate multiply and add). Scalar and packed,
132/213/231 operand orders. Called from the compiler dispatcher before avx/vector, so the
lane that owns those modules is not touched.
"""
import re

import avx

PATTERN = re.compile(r'^vf(n?)(maddsub|msubadd|madd|msub)(132|213|231)(ss|sd|ps|pd)$')
SCALAR = {'ss': ('f32', 'float', 32), 'sd': ('f64', 'double', 64),
          'ps': ('f32', 'float', 32), 'pd': ('f64', 'double', 64)}


def _parts(op):
    match = PATTERN.match(op)
    return match.groups() if match else None


def _operands(order, args):
    destination, first, second = args[0], args[1], args[2]
    if order == '132':
        return destination, second, first
    if order == '213':
        return first, destination, second
    return first, second, destination


def _vector_type(bits, element):
    return f'<{bits // (32 if element == "float" else 64)} x {element}>'


def _scalar_fma(function, ins, bits, element, order, operation):
    a, b, c = _operands(order, ins.operands)
    width = 32 if element == 'float' else 64
    read = lambda operand: avx._read(function, ins, operand, width)
    left = function.emit(f'bitcast i{width} {read(a)} to {element}')
    right = function.emit(f'bitcast i{width} {read(b)} to {element}')
    addend = function.emit(f'bitcast i{width} {read(c)} to {element}')
    if operation == 'msub':
        addend = function.emit(f'fneg {element} {addend}')
    elif operation == 'nmadd':
        left = function.emit(f'fneg {element} {left}')
    elif operation == 'nmsub':
        left = function.emit(f'fneg {element} {left}')
        addend = function.emit(f'fneg {element} {addend}')
    width = 32 if element == 'float' else 64
    intrinsic = f'llvm.fma.f{width}'
    value = function.emit(f'call {element} @{intrinsic}({element} {left}, {element} {right}, {element} {addend})')
    low = function.emit(f'bitcast {element} {value} to i{width}')
    low = function.emit(f'zext i{width} {low} to i{bits}')
    preserve = avx._read(function, ins, ins.operands[0], bits)
    high = function.emit(f'and i{bits} {preserve}, {((1 << bits) - 1) ^ ((1 << width) - 1)}')
    avx._write(function, ins, ins.operands[0], function.emit(f'or i{bits} {low}, {high}'), bits)


def _packed_fma(function, ins, bits, element, order, operation):
    a, b, c = _operands(order, ins.operands)
    read = lambda operand: avx._read(function, ins, operand, bits)
    vector = _vector_type(bits, element)
    count = bits // (32 if element == 'float' else 64)
    intrinsic = f'llvm.fma.v{count}f{32 if element == "float" else 64}'
    left = function.emit(f'bitcast i{bits} {read(a)} to {vector}')
    right = function.emit(f'bitcast i{bits} {read(b)} to {vector}')
    addend = function.emit(f'bitcast i{bits} {read(c)} to {vector}')
    if operation == 'maddsub' or operation == 'msubadd':
        negated = function.emit(f'fneg {vector} {addend}')
        subtract = function.emit(f'call {vector} @{intrinsic}({vector} {left}, {vector} {right}, {vector} {negated})')
        added = function.emit(f'call {vector} @{intrinsic}({vector} {left}, {vector} {right}, {vector} {addend})')
        if operation == 'msubadd':
            subtract, added = added, subtract
        selector = '<' + ', '.join('i1 ' + ('true' if index % 2 == 0 else 'false') for index in range(count)) + '>'
        value = function.emit(f'select <{count} x i1> {selector}, {vector} {subtract}, {vector} {added}')
        avx._write(function, ins, ins.operands[0], function.emit(f'bitcast {vector} {value} to i{bits}'), bits)
        return
    if operation == 'msub':
        addend = function.emit(f'fneg {vector} {addend}')
    elif operation == 'nmadd':
        left = function.emit(f'fneg {vector} {left}')
    elif operation == 'nmsub':
        left = function.emit(f'fneg {vector} {left}')
        addend = function.emit(f'fneg {vector} {addend}')
    value = function.emit(f'call {vector} @{intrinsic}({vector} {left}, {vector} {right}, {vector} {addend})')
    avx._write(function, ins, ins.operands[0], function.emit(f'bitcast {vector} {value} to i{bits}'), bits)


def analyze(function, ins, state):
    parts = _parts(ins.mnemonic)
    if parts is None:
        return False
    if ins.bytes[0] not in (0xc4, 0xc5):
        function.fail(ins, 'only VEX encodings are implemented; EVEX masking requires separate lowering')
    suffix = parts[3]
    bits = ins.operands[0].size * 8
    # A scalar form reads only the low element of its sources; the destination's
    # preserved upper lanes are read at full width.
    source_bits = {'ss': 32, 'sd': 64}.get(suffix, bits)
    for index, operand in enumerate(ins.operands):
        avx._require(function, ins, state, operand, bits if index == 0 else source_bits)
    avx._define(function, ins, state, ins.operands[0], (1 << bits) - 1, bits)
    return True


def lower(function, ins):
    parts = _parts(ins.mnemonic)
    if parts is None:
        return False
    negate, operation, order, suffix = parts
    if negate:
        operation = {'madd': 'nmadd', 'msub': 'nmsub'}.get(operation, operation)
    kind, element, width = SCALAR[suffix]
    bits = ins.operands[0].size * 8
    if suffix in ('ss', 'sd'):
        _scalar_fma(function, ins, bits, element, order, operation)
    else:
        _packed_fma(function, ins, bits, element, order, operation)
    return True

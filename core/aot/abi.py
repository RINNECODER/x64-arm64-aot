import re


class ABIError(ValueError):
    pass


INTEGER_REGISTERS = ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9')
FLOAT_REGISTERS = tuple(f'xmm{index}' for index in range(8))
# Uniform guest-register ABI: every internal function takes a pointer to a guest register
# file and returns through it, so no per-function result/parameter types are required. The
# HLE import boundary keeps the typed SysV ABI above.
UNIFORM_GPRS = ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi') + tuple(f'r{i}' for i in range(8, 16))
UNIFORM_VECTORS = tuple(f'xmm{index}' for index in range(16))
UNIFORM_STACK_SLOTS = 32
UNIFORM_STACK_BASE = 8
UNIFORM_CONVENTION = 'x86_64-uniform'
INTEGER_TYPES = {'i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64', 'ptr'}
FLOAT_TYPES = {'f32', 'f64'}
TYPES = INTEGER_TYPES | FLOAT_TYPES | {'void'}
SOURCES = (
    'https://gitlab.com/x86-psABIs/x86-64-ABI',
    'https://raw.githubusercontent.com/llvm/llvm-project/main/llvm/lib/Target/X86/X86CallingConv.td',
    'https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms',
    'https://llvm.org/docs/LangRef.html#parameter-attributes',
)


def require(condition, message):
    if not condition:
        raise ABIError(message)


def bits(kind):
    require(isinstance(kind, str) and kind in TYPES - {'void'}, f'unsupported scalar ABI type: {kind}')
    return 64 if kind == 'ptr' else int(kind[1:])


def llvm_type(kind):
    require(isinstance(kind, str) and kind in TYPES, f'unsupported scalar ABI type: {kind}')
    if kind.startswith('u'):
        return 'i' + kind[1:]
    return {'f32': 'float', 'f64': 'double'}.get(kind, kind)


def extension(kind):
    if kind in ('i8', 'i16'):
        return 'signext'
    if kind in ('u8', 'u16'):
        return 'zeroext'
    return ''


def parameter_type(kind):
    require(kind != 'void', 'void is not a parameter type')
    return ' '.join(item for item in (llvm_type(kind), extension(kind)) if item)


def result_type(kind):
    return ' '.join(item for item in (extension(kind), llvm_type(kind)) if item)


def return_register(kind):
    llvm_type(kind)
    return None if kind == 'void' else ('xmm0' if kind in FLOAT_TYPES else 'rax')


def locations(parameters):
    require(isinstance(parameters, (list, tuple)), 'parameters must be a scalar type list')
    integer_index, float_index, offset = 0, 0, 8
    result = []
    for kind in parameters:
        width = bits(kind)
        descriptor = {'type': kind, 'bits': width}
        if kind in INTEGER_TYPES and integer_index < len(INTEGER_REGISTERS):
            descriptor.update(kind='register', name=INTEGER_REGISTERS[integer_index])
            integer_index += 1
        elif kind in FLOAT_TYPES and float_index < len(FLOAT_REGISTERS):
            descriptor.update(kind='register', name=FLOAT_REGISTERS[float_index])
            float_index += 1
        else:
            descriptor.update(kind='stack', offset=offset)
            offset += 8
        result.append(descriptor)
    return result


def uniform(contract):
    require(isinstance(contract, dict), 'function contract must be an object')
    return contract.get('guest_calling_convention') == UNIFORM_CONVENTION or bool(contract.get('uniform'))


def uniform_locations():
    """Every GPR (as a native pointer), every XMM, its YMM upper half, and a fixed incoming-stack window."""
    result = [{'kind': 'register', 'name': name, 'bits': 64, 'type': 'ptr'} for name in UNIFORM_GPRS]
    result += [{'kind': 'register', 'name': name, 'bits': 128, 'type': 'f64'} for name in UNIFORM_VECTORS]
    result += [{'kind': 'register', 'name': f'ymm_hi{index}', 'bits': 128, 'type': 'f64'}
               for index in range(len(UNIFORM_VECTORS))]
    result += [{'kind': 'stack', 'offset': UNIFORM_STACK_BASE + 8 * index, 'bits': 64, 'type': 'i64'}
               for index in range(UNIFORM_STACK_SLOTS)]
    return result


def uniform_stack_end():
    return UNIFORM_STACK_BASE + 8 * UNIFORM_STACK_SLOTS


def signature(contract):
    require(isinstance(contract, dict), 'function contract must be an object')
    if uniform(contract):
        require(contract.get('result', 'void') == 'void' and not contract.get('parameters'),
                'uniform ABI must declare a void result and no scalar parameters')
        require(isinstance(contract.get('name'), str)
                and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', contract['name']), 'invalid native symbol')
        return 'void', []
    require(not contract.get('variadic', False), 'variadic ABI requires argument and va_list reconstruction')
    require(not contract.get('sret') and not contract.get('byval'), 'aggregate ABI requires type layout reconstruction')
    result, parameters = contract.get('result'), contract.get('parameters')
    require(isinstance(result, str) and result in TYPES, 'unsupported result type')
    expected = locations(parameters)
    name = contract.get('name')
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name), 'invalid native symbol')
    convention = contract.get('guest_calling_convention', 'x86_64-sysv')
    require(convention in ('x86_64-sysv', 'x86_64-llvm-fastcc', UNIFORM_CONVENTION), 'unsupported guest calling convention')
    if convention != 'x86_64-sysv' or 'guest_locations' in contract:
        require(contract.get('guest_locations') == expected,
                'nonstandard guest ABI requires explicit verified SysV-compatible parameter locations')
        require(contract.get('guest_return_register') == return_register(result),
                'nonstandard guest ABI requires explicit verified return register')
    return result, parameters


def validate_import_annotations(contracts, annotations):
    """Reject a contracts image that disagrees with the ABI annotations it was generated from.

    A contracts file that predates an import's ABI verification keeps that import as a return-0
    stub; the guest then dereferences the null result (the title heap initialiser's mspace path
    did exactly that). Every import the ABI has verified must be typed in the contracts, and every
    import the contracts stub must be unverified in the ABI, so a stale pair fails loudly instead
    of lowering a verified import to a null return.
    """
    require(isinstance(contracts, dict) and isinstance(contracts.get('imports'), dict),
            'contracts must declare an imports map')
    records = annotations.get('imports') if isinstance(annotations, dict) else None
    require(isinstance(records, dict), 'ABI annotations must declare an imports map')
    for nid, contract in contracts['imports'].items():
        require(isinstance(contract, dict), f'import {nid} contract must be an object')
        record = records.get(nid) or {}
        if record.get('status') == 'verified':
            require(not contract.get('stub'),
                    f'import {nid} is verified as {record.get("hle_name") or nid} but the contracts stub it; '
                    'regenerate the contracts from the current ABI')
            require(contract.get('result') == record.get('result')
                    and list(contract.get('parameters') or []) == list(record.get('parameters') or []),
                    f'import {nid} ABI disagrees with the contracts; regenerate the contracts from the current ABI')
        else:
            require(contract.get('stub'),
                    f'import {nid} is not verified in the ABI but the contracts type it; '
                    'regenerate the contracts from the current ABI')

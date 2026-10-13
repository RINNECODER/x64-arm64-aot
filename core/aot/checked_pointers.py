from capstone.x86 import X86_OP_MEM, X86_OP_REG

import abi
import effects
import register_aliases


SYMBOL = 'NativeAotReadablePointer_nid_no_patch'


def parse(function):
    records = function.contract.get('checked_pointer_loads', [])
    if not isinstance(records, list):
        raise ValueError('checked pointer loads must be a list')
    if (records or function.contract.get('checked_pointer_arguments') or function.contract.get('checked_pointer_bases') or function.image.contracts.get('guard_diagnostics')) and (SYMBOL in {spec['name'] for spec in list(function.image.functions.values()) + list(function.image.imports.values())} or 'NativeAotReportGuardFailure_nid_no_patch' in {spec['name'] for spec in list(function.image.functions.values()) + list(function.image.imports.values())}):
        raise ValueError('checked pointer helper symbol is reserved')
    result = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {'address', 'bytes', 'nullable', 'evidence'}:
            raise ValueError('checked pointer load requires address, bytes, nullable and evidence')
        address = record['address']
        if type(address) is not int or address not in function.instructions or address in result:
            raise ValueError('checked pointer load must identify a unique decoded instruction')
        ins = function.instructions[address]
        if ins.mnemonic != 'mov' or len(ins.operands) != 2 or ins.operands[0].type != X86_OP_REG or ins.operands[0].size != 8 or ins.operands[1].type != X86_OP_MEM or ins.operands[1].size != 8:
            raise ValueError('checked pointer load requires a scalar eight-byte memory load')
        if type(record['bytes']) is not int or not 1 <= record['bytes'] <= 65536 or type(record['nullable']) is not bool:
            raise ValueError('checked pointer load has invalid extent or nullability')
        if not isinstance(record['evidence'], str) or not record['evidence'].strip():
            raise ValueError('checked pointer load requires source/layout evidence')
        result[address] = record
    return result


def emit(function, ins, operand, value):
    record = getattr(function, 'checked_pointer_loads', {}).get(ins.address)
    if record is None or operand is not ins.operands[1]:
        return value
    pointer = function.emit(f'inttoptr i64 {value} to ptr')
    nullable = 'true' if record['nullable'] else 'false'
    valid = function.emit(f'call zeroext i1 @{SYMBOL}(ptr {pointer}, i64 {record["bytes"]}, i1 zeroext {nullable})')
    good, bad = f'pointer_load_valid_{ins.address:x}', f'pointer_load_invalid_{ins.address:x}'
    function.lines.extend([f'  br i1 {valid}, label %{good}, label %{bad}', bad+':'] + function.trap(ins, 1) + [good+':'])
    return value


def parse_arguments(function):
    records = function.contract.get('checked_pointer_arguments', [])
    if not isinstance(records, list):
        raise ValueError('checked pointer arguments must be a list')
    result = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {'address', 'parameter', 'bytes', 'nullable', 'evidence'}:
            raise ValueError('checked pointer argument requires address, parameter, bytes, nullable and evidence')
        address, index = record['address'], record['parameter']
        ins = function.instructions.get(address) if type(address) is int else None
        if ins is None or ins.mnemonic != 'call':
            raise ValueError('checked pointer argument must identify a call')
        if ins.address in getattr(function, 'dispatch_calls', {}):
            continue
        contract, _ = function.image.call(ins, function.contract)
        if type(index) is not int or not 0 <= index < len(contract['parameters']) or contract['parameters'][index] != 'ptr':
            raise ValueError('checked argument is not a pointer in the declared native ABI')
        if (address, index) in result or type(record['bytes']) is not int or not 1 <= record['bytes'] <= 65536 or type(record['nullable']) is not bool:
            raise ValueError('checked pointer argument has invalid extent, nullability or duplicate site')
        if not isinstance(record['evidence'], str) or not record['evidence'].strip():
            raise ValueError('checked pointer argument requires source/ABI evidence')
        result[address, index] = record
    return result


def argument_allowed(function, ins, index):
    return (ins.address, index) in getattr(function, 'checked_pointer_arguments', {})


def emit_argument(function, ins, index, contract, pointer):
    record = getattr(function, 'checked_pointer_arguments', {}).get((ins.address, index))
    if record is None:
        return
    state = function.states[ins.address]
    location = abi.locations(contract['parameters'])[index]
    proven = (location['name'] in state['native_pointers']) if location['kind'] == 'register' else (state['rsp'] + location['offset'] - 8 in state['stack_pointers'])
    if record['nullable'] and (proven or effects.argument_value(ins, contract, index, state) == 0):
        return
    nullable = 'true' if record['nullable'] else 'false'
    valid = function.emit(f'call zeroext i1 @{SYMBOL}(ptr {pointer}, i64 {record["bytes"]}, i1 zeroext {nullable})')
    good, bad = f'pointer_argument_valid_{ins.address:x}_{index}', f'pointer_argument_invalid_{ins.address:x}_{index}'
    function.lines.extend([f'  br i1 {valid}, label %{good}, label %{bad}', bad+':'] + function.trap(ins, 2) + [good+':'])


def validated_registers(function, ins, state):
    if ins.address in getattr(function, 'dispatch_calls', {}):
        return set()
    contract, _ = function.image.call(ins, function.contract)
    result = set()
    for index, location in enumerate(abi.locations(contract['parameters'])):
        if location['kind'] != 'register' or not argument_allowed(function, ins, index):
            continue
        if effects.argument_value(ins, contract, index, state) == 0:
            continue
        result.update(register_aliases.equivalents(state, location['name']))
    return result


def parse_bases(function):
    records = function.contract.get('checked_pointer_bases', [])
    if not isinstance(records, list):
        raise ValueError('checked pointer bases must be a list')
    result = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {'address', 'operand', 'bytes', 'evidence'}:
            raise ValueError('checked pointer base requires address, operand, bytes and evidence')
        address, index = record['address'], record['operand']
        ins = function.instructions.get(address) if type(address) is int else None
        if ins is None or type(index) is not int or not 0 <= index < len(ins.operands) or (address,index) in result:
            raise ValueError('checked pointer base must identify a unique memory operand')
        operand = ins.operands[index]
        base = ins.reg_name(operand.mem.base) if operand.type == X86_OP_MEM else ''
        if ins.mnemonic in ('lea','nop') or operand.type != X86_OP_MEM or not base or base in ('rsp','rbp','rip') or ins.addr_size != 8 or operand.mem.segment:
            raise ValueError('checked pointer base requires a general-register 64-bit memory access')
        if type(record['bytes']) is not int or not 1 <= record['bytes'] <= 65536 or not isinstance(record['evidence'],str) or not record['evidence'].strip():
            raise ValueError('checked pointer base requires a bounded extent and evidence')
        result[address,index] = record
    return result


def base_record(function, ins, operand):
    for index, candidate in enumerate(ins.operands):
        if candidate is operand:
            return getattr(function, 'checked_pointer_bases', {}).get((ins.address,index))
    return None


def base_needs_guard(ins, operand, state):
    base, index = ins.reg_name(operand.mem.base), ins.reg_name(operand.mem.index)
    return base not in state['native_pointers'] and not (index in state['native_pointers'] and operand.mem.scale == 1)


def validated_bases(function, ins, state):
    result = set()
    for operand in ins.operands:
        if base_record(function, ins, operand) and base_needs_guard(ins, operand, state):
            result.update(register_aliases.equivalents(state, ins.reg_name(operand.mem.base)))
    return result


def emit_base(function, ins, operand):
    record = base_record(function, ins, operand)
    if record is None or not base_needs_guard(ins, operand, function.states[ins.address]):
        return
    value = function.load(ins.reg_name(operand.mem.base))
    pointer = function.emit(f'inttoptr i64 {value} to ptr')
    valid = function.emit(f'call zeroext i1 @{SYMBOL}(ptr {pointer}, i64 {record["bytes"]}, i1 zeroext false)')
    label = f'pointer_base_{ins.address:x}_{record["operand"]}'
    function.lines.extend([f'  br i1 {valid}, label %{label}_valid, label %{label}_invalid', label+'_invalid:'] + function.trap(ins,6) + [label+'_valid:'])

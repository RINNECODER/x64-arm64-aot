from capstone.x86 import X86_OP_REG

import abi
import effects


def validate(contract, internal=False):
    record = contract.get('pointer_outputs')
    if record is None:
        return
    if not isinstance(record, dict) or set(record) != {'success', 'fields', 'evidence'}:
        raise ValueError('pointer outputs require success, fields and evidence')
    if record['success'] not in ('zero', 'nonnegative') or contract['result'] not in ('i32', 'i64'):
        raise ValueError('pointer outputs require a signed status return and supported success predicate')
    if not isinstance(record['evidence'], str) or not record['evidence'].strip():
        raise ValueError('pointer outputs require source evidence')
    if not isinstance(record['fields'], list) or not record['fields']:
        raise ValueError('pointer outputs require nonempty fields')
    seen = set()
    for field in record['fields']:
        if not isinstance(field, dict) or set(field) not in ({'parameter', 'offset'}, {'parameter', 'offset', 'within_parameter'}):
            raise ValueError('pointer output field requires parameter and offset')
        index, offset = field['parameter'], field['offset']
        if type(index) is not int or not 0 <= index < len(contract['parameters']) or contract['parameters'][index] != 'ptr':
            raise ValueError('pointer output must identify a pointer parameter')
        if type(offset) is not int or not 0 <= offset <= 1024 * 1024 or offset % 8:
            raise ValueError('pointer output offset must be aligned and bounded')
        if (index, offset) in seen:
            raise ValueError('duplicate pointer output field')
        within = field.get('within_parameter')
        if within is not None and (type(within) is not int or not 0 <= within < len(contract['parameters']) or contract['parameters'][within] != 'ptr'):
            raise ValueError('pointer output bound must identify a pointer parameter')
        if internal and within is None:
            raise ValueError('internal pointer outputs require an enforced native region bound')
        seen.add((index, offset))


def capture(function, ins, original):
    if ins.address in getattr(function, 'dispatch_calls', {}):
        return frozenset()
    contract, slot = function.image.call(ins, function.contract)
    record = contract.get('pointer_outputs')
    inferred = function.image.pointer_output_summaries.get(effects.direct_target(function, ins), ())
    if record is None and inferred:
        record = {'success': 'always', 'fields': [{'parameter': index, 'offset': offset} for index, offset in inferred]}
    if record is None or (effects.direct_target(function, ins) is None and slot not in original['import_bindings']):
        return frozenset()
    cells = []
    for field in record['fields']:
        if 'within_parameter' in field:
            bounded_region(function, ins, contract, field, original)
        origin = effects.argument_pointer(function, ins, contract, field['parameter'], original)
        if origin is None or origin[0] not in ('frame', 'image'):
            continue
        kind, _, offset = origin
        offset += field['offset']
        if kind == 'frame':
            if offset < original['rsp'] or offset + 8 > 0:
                continue
        elif not any(spec['address'] <= offset and offset + 8 <= spec['address'] + spec['size'] for spec in function.image.data):
            continue
        cells.append((ins.address, record['success'], kind, offset))
    return frozenset(cells)


def refine(function, ins, state, target):
    records = frozenset(record for record in state.get('pending_outputs', frozenset()) if record[1] != 'always')
    if not records or ins.mnemonic not in ('je', 'jne', 'js', 'jns'):
        return state
    calls = {record[0] for record in records}
    if len(calls) != 1:
        return state
    call = function.instructions[next(iter(calls))]
    test = function.instructions.get(call.address + call.size)
    if test is None or test.mnemonic != 'test' or len(test.operands) != 2 or test.address + test.size != ins.address:
        return state
    contract, _ = function.image.call(call, function.contract)
    width = abi.bits(contract['result'])
    if any(op.type != X86_OP_REG or function.reg(test, op) != ('rax', width, 0) for op in test.operands):
        return state
    predecessors = lambda address: {source for source, targets in function.successors.items() if address in targets}
    if predecessors(test.address) != {call.address} or predecessors(ins.address) != {test.address}:
        return state
    result = dict(state)
    result['pending_outputs'] = frozenset()
    result['stack_pointers'] = state['stack_pointers'].copy()
    result['image_pointers'] = state['image_pointers']
    if ins.operands[0].imm == ins.address + ins.size:
        return state
    taken = target == ins.operands[0].imm
    for _, predicate, kind, offset in records:
        success = ((predicate == 'zero' and ((ins.mnemonic == 'je' and taken) or (ins.mnemonic == 'jne' and not taken))) or
                   (predicate == 'nonnegative' and ((ins.mnemonic == 'jns' and taken) or (ins.mnemonic == 'js' and not taken))))
        if success:
            if kind == 'frame':
                result['stack_pointers'].add(offset)
            else:
                result['image_pointers'] = result['image_pointers'] | {offset}
    return result


def bounded_region(function, ins, contract, field, state):
    source = effects.argument_pointer(function, ins, contract, field['within_parameter'], state)
    if source is not None:
        kind, _, offset = source
        if kind == 'image':
            for spec in function.image.data:
                if spec['address'] <= offset < spec['address'] + spec['size']:
                    return kind, spec['address'], spec['address'] + spec['size']
        if kind == 'frame':
            for spec in function.contract.get('stack_objects', []):
                if spec['offset'] <= offset < spec['offset'] + spec['size']:
                    return kind, spec['offset'], spec['offset'] + spec['size']
    function.fail(ins, 'pointer output source lacks a bounded native region')


def emit_checks(function, ins, contract, arguments, status):
    record = contract.get('pointer_outputs')
    fields = [] if record is None else [field for field in record['fields'] if 'within_parameter' in field]
    if not fields:
        return
    width = abi.bits(contract['result'])
    condition = function.emit(f'icmp {"eq" if record["success"] == "zero" else "sge"} i{width} {status}, 0')
    check, continuation, invalid = (f'pointer_output_{suffix}_{ins.address:x}' for suffix in ('check', 'continue', 'invalid'))
    function.lines.extend([f'  br i1 {condition}, label %{check}, label %{continuation}', check + ':'])
    valid = 'true'
    for field in fields:
        kind, begin, end = bounded_region(function, ins, contract, field, function.states[ins.address])
        low = function.image.pointer(begin) if kind == 'image' else function.frame_pointer(begin)
        high = function.emit(f'getelementptr i8, ptr {low}, i64 {end - begin}')
        pointer = function.emit(f'getelementptr i8, ptr {arguments[field["parameter"]]}, i64 {field["offset"]}')
        value = function.emit(f'load ptr, ptr {pointer}, align 1')
        lower = function.emit(f'icmp uge ptr {value}, {low}')
        upper = function.emit(f'icmp ult ptr {value}, {high}')
        inside = function.emit(f'and i1 {lower}, {upper}')
        valid = function.emit(f'and i1 {valid}, {inside}')
    function.lines.extend([f'  br i1 {valid}, label %{continuation}, label %{invalid}', invalid + ':'] + function.trap(ins, 4) + [continuation+':'])

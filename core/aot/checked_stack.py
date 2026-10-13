from capstone.x86 import X86_OP_MEM, X86_OP_REG


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse(function):
    records = function.contract.get('checked_stack_accesses', [])
    require(isinstance(records, list), 'checked_stack_accesses must be a list')
    objects = {obj['offset']: obj for obj in function.contract.get('stack_objects', [])}
    result = {}
    for record in records:
        require(isinstance(record, dict) and set(record) in ({'address', 'operand', 'object_offset', 'pointer'}, {'address', 'operand', 'object_offset', 'pointer', 'dynamic_base'}),
                'checked stack access requires address, operand, object_offset and pointer')
        require(type(record.get('dynamic_base', False)) is bool, 'checked dynamic frame flag must be boolean')
        address, index, offset = (record[key] for key in ('address', 'operand', 'object_offset'))
        require(type(address) is int and address in function.instructions and address not in result,
                'checked stack access must identify a unique decoded instruction')
        require(type(offset) is int and offset in objects, 'checked stack access has no declared object')
        ins = function.instructions[address]
        require(type(index) is int and 0 <= index < len(ins.operands), 'invalid checked operand index')
        operand = ins.operands[index]
        require(operand.type == X86_OP_MEM and sum(item.type == X86_OP_MEM for item in ins.operands) == 1,
                'checked stack access requires exactly one memory operand')
        require(ins.mnemonic not in ('lea', 'nop') and ins.addr_size == 8 and not operand.mem.segment,
                'checked stack access requires a 64-bit memory operation')
        require(type(record['pointer']) is bool, 'checked pointer flag must be boolean')
        obj = objects[offset]
        require(operand.size <= obj['size'], 'checked memory operation exceeds its object')
        if record['pointer']:
            require(ins.mnemonic == 'mov' and index == 1 and ins.operands[0].type == X86_OP_REG and operand.size == 8,
                    'checked pointer access requires an eight-byte scalar load')
            require(obj['size'] % 8 == 0 and obj['alignment'] >= 8, 'checked pointer table has an invalid layout')
        result[address] = dict(record, size=obj['size'])
    return result


def lookup(function, ins, operand):
    return function.checked_accesses.get(ins.address) if operand.type == X86_OP_MEM else None


def region(function, ins, state, operand):
    record = lookup(function, ins, operand)
    if record is None:
        return None
    base, index = ins.reg_name(operand.mem.base), ins.reg_name(operand.mem.index)
    frame = (base in ('rsp', 'rbp') and state[base] is not None) or state['pointers'].get(base, (None,))[0] == 'frame'
    if not record.get('dynamic_base', False) and (not frame or index in state['native_pointers']):
        function.fail(ins, 'checked memory operand is not a native frame address with a scalar index')
    begin = record['object_offset']
    return 'frame', begin, begin + record['size']


def pointer(function, ins, state, operand):
    record = lookup(function, ins, operand)
    if record is None or not record['pointer']:
        return False
    region(function, ins, state, operand)
    begin = record['object_offset']
    if not all(offset in state['stack_pointers'] for offset in range(begin, begin + record['size'], 8)):
        function.fail(ins, 'checked pointer table contains unproved pointer cells')
    return True


def guard(function, ins, operand, address):
    record = lookup(function, ins, operand)
    if record is None:
        return address
    base = function.frame_pointer(record['object_offset'])
    position = function.emit(f'ptrtoint ptr {address} to i64')
    start = function.emit(f'ptrtoint ptr {base} to i64')
    relative = function.emit(f'sub i64 {position}, {start}')
    valid = function.emit(f"icmp ule i64 {relative}, {record['size'] - operand.size}")
    if record['pointer']:
        residue = function.emit(f'and i64 {relative}, 7')
        aligned = function.emit(f'icmp eq i64 {residue}, 0')
        valid = function.emit(f'and i1 {valid}, {aligned}')
    label = valid[1:] + '_checked_stack'
    function.lines.extend([f'  br i1 {valid}, label %{label}_valid, label %{label}_invalid',
                           f'{label}_invalid:', '  call void @llvm.trap()', '  unreachable', f'{label}_valid:'])
    return address

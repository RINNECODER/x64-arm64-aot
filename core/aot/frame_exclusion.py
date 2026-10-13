from capstone.x86 import X86_OP_MEM


STORES = {'mov', 'movups', 'movaps', 'movupd', 'movapd', 'movdqu', 'movdqa', 'movd', 'movq',
          'movss', 'movsd', 'movlps', 'movlpd', 'vmovups', 'vmovaps', 'vmovdqu', 'vmovdqa', 'vmovd', 'vmovq'}


def parse(function):
    result = {}
    records = function.contract.get('checked_frame_exclusion', [])
    if not isinstance(records, list):
        raise ValueError('frame exclusion records must be a list')
    for record in records:
        if not isinstance(record, dict) or set(record) != {'address', 'evidence'}:
            raise ValueError('frame exclusion requires address and evidence')
        address = record['address']
        if type(address) is not int or address not in function.instructions or address in result:
            raise ValueError('frame exclusion requires a unique decoded instruction')
        if address in function.checked_accesses:
            raise ValueError('frame exclusion conflicts with a checked frame access')
        ins = function.instructions[address]
        if ins.mnemonic not in STORES or len(ins.operands) != 2 or ins.operands[0].type != X86_OP_MEM:
            raise ValueError('frame exclusion does not identify a supported memory store')
        if not isinstance(record['evidence'], str) or not record['evidence'].strip():
            raise ValueError('frame exclusion requires source evidence')
        result[address] = record['evidence']
    return result


def applies(function, ins, operand):
    return ins.address in getattr(function, 'frame_exclusions', {}) and operand is ins.operands[0]


def guard(function, ins, operand, pointer):
    if not applies(function, ins, operand):
        return pointer
    start = function.emit(f'ptrtoint ptr {pointer} to i64')
    end = function.emit(f'add i64 {start}, {operand.size}')
    low = function.emit('ptrtoint ptr %frame to i64')
    high = function.emit(f'add i64 {low}, {function.depth + function.stack_end}')
    nonwrapping = function.emit(f'icmp uge i64 {end}, {start}')
    before = function.emit(f'icmp ule i64 {end}, {low}')
    after = function.emit(f'icmp uge i64 {start}, {high}')
    outside = function.emit(f'or i1 {before}, {after}')
    valid = function.emit(f'and i1 {nonwrapping}, {outside}')
    continuation, invalid = f'frame_exclusion_continue_{ins.address:x}', f'frame_exclusion_invalid_{ins.address:x}'
    function.lines.extend([f'  br i1 {valid}, label %{continuation}, label %{invalid}', invalid+':'] + function.trap(ins, 3) + [continuation+':'])
    return pointer

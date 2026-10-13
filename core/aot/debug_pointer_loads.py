from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf.locationlists import BaseAddressEntry, LocationEntry
from elftools.dwarf.ranges import BaseAddressEntry as RangeBase, RangeEntry
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from recover import object_mappings


REGISTERS = {0: 'rax', 1: 'rdx', 2: 'rcx', 3: 'rbx', 4: 'rsi', 5: 'rdi', 6: 'rbp', 7: 'rsp',
             8: 'r8', 9: 'r9', 10: 'r10', 11: 'r11', 12: 'r12', 13: 'r13', 14: 'r14', 15: 'r15'}


def attribute(die, name):
    visited = set()
    while die is not None and die.offset not in visited:
        visited.add(die.offset)
        if name in die.attributes:
            return die, die.attributes[name]
        reference = 'DW_AT_abstract_origin' if 'DW_AT_abstract_origin' in die.attributes else 'DW_AT_specification'
        die = die.get_DIE_from_attribute(reference) if reference in die.attributes else None
    return None, None


def typename(die):
    owner, value = attribute(die, 'DW_AT_type')
    return owner.get_DIE_from_attribute('DW_AT_type') if value is not None else None


def unwrap(typ):
    seen = set()
    while typ is not None and typ.tag in ('DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type', 'DW_TAG_restrict_type'):
        if typ.offset in seen:
            return None
        seen.add(typ.offset)
        typ = typename(typ)
    return typ


def pointer_fields(typ, base=0, depth=0):
    typ = unwrap(typ)
    if typ is None or depth > 8:
        return []
    if typ.tag == 'DW_TAG_pointer_type':
        return [(base, 1)]
    if typ.tag == 'DW_TAG_structure_type':
        fields = []
        for member in typ.iter_children():
            location = member.attributes.get('DW_AT_data_member_location')
            if member.tag == 'DW_TAG_member' and location is not None and type(location.value) is int:
                fields.extend(pointer_fields(typename(member), base + location.value, depth + 1))
        return fields
    if typ.tag == 'DW_TAG_array_type':
        element = unwrap(typename(typ))
        if element is None:
            return []
        size = element.attributes.get('DW_AT_byte_size')
        count = 1
        for bound in typ.iter_children():
            if bound.tag != 'DW_TAG_subrange_type':
                continue
            value = bound.attributes.get('DW_AT_count')
            if value is None:
                value = bound.attributes.get('DW_AT_upper_bound')
                if value is None or type(value.value) is not int:
                    return []
                count *= value.value + 1
            elif type(value.value) is int:
                count *= value.value
            else:
                return []
        stride = 8 if element.tag == 'DW_TAG_pointer_type' else (size.value if size else None)
        if stride is None or not 0 <= count <= 1024:
            return []
        return [field for index in range(count) for field in pointer_fields(element, base + index * stride, depth + 1)]
    return []


def locations(die, dwarf, parser):
    location = die.attributes.get('DW_AT_location')
    if location is None:
        return []
    if isinstance(location.value, list):
        return [(0, 1 << 64, parser.parse_expr(location.value))]
    if type(location.value) is not int:
        return []
    result, base = [], 0
    for item in dwarf.location_lists().get_location_list_at_offset(location.value, die=die):
        if isinstance(item, BaseAddressEntry):
            base = item.base_address
        elif isinstance(item, LocationEntry):
            result.append((base + item.begin_offset, base + item.end_offset, parser.parse_expr(item.loc_expr)))
    return result


def scope_ranges(die, dwarf):
    scopes = [(0, 1 << 64)]
    parent = die.get_parent()
    while parent is not None:
        attrs = parent.attributes
        intervals = None
        if 'DW_AT_low_pc' in attrs and 'DW_AT_high_pc' in attrs:
            start = attrs['DW_AT_low_pc'].value
            end = attrs['DW_AT_high_pc']
            intervals = [(start, end.value if end.form == 'DW_FORM_addr' else start + end.value)]
        elif 'DW_AT_ranges' in attrs:
            base = parent.cu.get_top_DIE().attributes.get('DW_AT_low_pc')
            base = base.value if base else 0
            intervals = []
            for entry in dwarf.range_lists().get_range_list_at_offset(attrs['DW_AT_ranges'].value, cu=parent.cu):
                if isinstance(entry, RangeBase):
                    base = entry.base_address
                elif isinstance(entry, RangeEntry):
                    bias = 0 if entry.is_absolute else base
                    intervals.append((bias + entry.begin_offset, bias + entry.end_offset))
        if intervals is not None:
            scopes = [(max(a,c), min(b,d)) for a,b in scopes for c,d in intervals if max(a,c)<min(b,d)]
        parent = parent.get_parent()
    return scopes


def scoped_locations(die, dwarf, parser):
    return [(max(low, start), min(high, end), expression)
            for low, high, expression in locations(die, dwarf, parser)
            for start, end in scope_ranges(die, dwarf) if max(low, start) < min(high, end)]


def candidates(image, companion):
    obj, evidence, mappings = object_mappings(image.elf, companion)
    if len(mappings) != 1:
        raise ValueError('debug pointer candidates currently require one executable section')
    mapping = next(iter(mappings.values()))
    dwarf = obj.get_dwarf_info()
    parser = DWARFExprParser(dwarf.structs)
    variables = []
    for unit in dwarf.iter_CUs():
        for die in unit.iter_DIEs():
            if die.tag not in ('DW_TAG_variable', 'DW_TAG_formal_parameter'):
                continue
            _, name = attribute(die, 'DW_AT_name')
            typ = unwrap(typename(die))
            if name is None or typ is None:
                continue
            fields = dict(pointer_fields(typ))
            pointee = dict(pointer_fields(typename(typ))) if typ.tag == 'DW_TAG_pointer_type' else {}
            for low, high, expression in scoped_locations(die, dwarf, parser):
                if len(expression) != 1:
                    continue
                op = expression[0]
                storage = None
                if op.op_name == 'DW_OP_fbreg':
                    parent = die.get_parent()
                    while parent is not None and 'DW_AT_frame_base' not in parent.attributes:
                        parent = parent.get_parent()
                    if parent is None:
                        continue
                    frame = parser.parse_expr(parent.attributes['DW_AT_frame_base'].value)
                    if len(frame) == 1 and frame[0].op_name == 'DW_OP_reg6':
                        storage = ('frame', op.args[0])
                elif op.op_name.startswith('DW_OP_reg') and op.op_name[9:].isdigit():
                    register = REGISTERS.get(int(op.op_name[9:]))
                    if register:
                        storage = ('register', register)
                if storage:
                    variables.append((low, high, storage, fields, pointee, name.value.decode(errors='replace'), die.offset))
    result = []
    for function in image.functions.values():
        for ins in image.decoder.disasm(image.read(function['address'], function['size']), function['address']):
            if ins.mnemonic != 'mov' or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if dst.type != X86_OP_REG or dst.size != 8 or src.type != X86_OP_MEM or src.size != 8:
                continue
            relative = ins.address - mapping['address']
            names = []
            for low, high, storage, fields, pointee, name, offset in variables:
                base = ins.reg_name(src.mem.base)
                matched = low <= relative < high and storage[0] == 'frame' and base == 'rbp' and not src.mem.index and src.mem.disp - storage[1] in fields
                matched |= low <= relative < high and storage[0] == 'register' and base == storage[1] and not src.mem.index and src.mem.disp in pointee
                matched |= storage[0] == 'register' and ins.reg_name(dst.reg) == storage[1] and 0 in fields and low <= relative + ins.size < high
                if matched:
                    names.append(f'{name} (DIE 0x{offset:x})')
            if names:
                result.append({'function': function['name'], 'address': ins.address, 'bytes': 1, 'nullable': True,
                               'evidence': 'Matched companion '+evidence['sha256']+' DWARF pointer storage: '+', '.join(sorted(set(names)))})
    return result

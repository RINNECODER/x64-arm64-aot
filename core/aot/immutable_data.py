def require(condition, message):
    if not condition:
        raise ValueError(message)


def configure(image):
    records = image.contracts.get('immutable_data', [])
    require(isinstance(records, list), 'immutable_data must be a list')
    specs = {spec['address']: spec for spec in image.data}
    selected = {}
    for record in records:
        require(isinstance(record, dict) and set(record) == {'address', 'evidence'}, 'immutable data requires address and evidence')
        address = record['address']
        require(type(address) is int and address in specs and address not in selected, 'immutable data must identify unique complete data segments')
        require(isinstance(record['evidence'], str) and record['evidence'].strip(), 'immutable data requires source/profile evidence')
        selected[address] = record['evidence']
    image.immutable_regions = []
    image.immutable_initializers = {}
    image.immutable_cells = frozenset()
    image.immutable_bindings = frozenset()
    image.immutable_evidence = selected
    if not selected:
        return
    require(len(specs) == len(image.data), 'immutable data requires unique data segments')
    regions = [(address, address + specs[address]['size']) for address in selected]
    entries = [(slot, '@' + contract['name']) for slot, contract in image.import_slots.items()]
    entries.extend((slot, image.pointer(target)) for slot, target in image.relocations)
    initializers = {}
    for begin, end in regions:
        fields = sorted((slot, value) for slot, value in entries if begin <= slot < end)
        previous = begin
        for slot, _ in fields:
            require((slot - begin) % 8 == 0 and slot >= previous and slot + 8 <= end, 'immutable native pointer relocations overlap, cross the segment or lack alignment')
            previous = slot + 8
        initializers[begin] = fields
    names = {spec['name'] for spec in list(image.functions.values()) + list(image.imports.values())}
    require(not selected or not names.intersection({'__aps5_aot_readonly_ranges', 'NativeAotRequireReadOnly_nid_no_patch'}), 'immutable image symbol is reserved')
    image.immutable_regions = regions
    image.immutable_initializers = initializers
    image.immutable_cells = frozenset(slot for fields in initializers.values() for slot, _ in fields)
    image.immutable_bindings = frozenset(image.import_slots) & image.immutable_cells
    image.immutable_evidence = selected


def overlaps(image, begin, end):
    return any(begin < high and low < end for low, high in image.immutable_regions)


def declaration(image, spec):
    begin, end = spec['address'], spec['address'] + spec['size']
    types, values, cursor = [], [], begin

    def raw(low, high):
        if low == high:
            return
        data = image.read(low, high - low)
        typ = f'[{len(data)} x i8]'
        value = ''.join(f'\\{byte:02X}' for byte in data)
        types.append(typ)
        values.append(f'{typ} c"{value}"')

    for slot, value in image.immutable_initializers[begin]:
        raw(cursor, slot)
        types.append('ptr')
        values.append('ptr ' + value)
        cursor = slot + 8
    raw(cursor, end)
    typ, value = '<{ ' + ', '.join(types) + ' }>', '<{ ' + ', '.join(values) + ' }>'
    return f'@data_{begin:x} = constant {typ} {value}, section "{image.target_spec["readonly_section"]}", align 16'


def declarations(image):
    values = ', '.join(f'{{ ptr, i64 }} {{ ptr @data_{begin:x}, i64 {end - begin} }}' for begin, end in image.immutable_regions)
    return [f'@__aps5_aot_readonly_ranges = private constant [{len(image.immutable_regions)} x {{ ptr, i64 }}] [{values}], align 8',
            'declare void @NativeAotRequireReadOnly_nid_no_patch(ptr, i64)']

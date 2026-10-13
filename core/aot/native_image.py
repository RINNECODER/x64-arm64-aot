import struct

from calls import structural_signature


CALLBACKS = [
    ('void', []), ('void', []),
    ('ptr', ['u64']), ('void', ['ptr']), ('ptr', ['u64', 'u64']),
    ('ptr', ['ptr', 'u64']), ('ptr', ['u64', 'u64']),
    ('ptr', ['ptr', 'u64', 'u64']), ('i32', ['ptr', 'u64', 'u64']),
]
RESERVED = {'__aps5_aot_ranges', '__aps5_aot_functions', '__aps5_aot_image', 'NativeAotRegisterImage_nid_no_patch'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def describe(image):
    require(len(image.process_parameters) == 1, 'native image requires exactly one process-parameters descriptor')
    process, size = image.process_parameters[0]
    image.pointer(process, size)
    require(size >= 0x40, 'native process-parameters descriptor is truncated')
    relocations = dict(image.relocations)

    def read(address, count):
        image.pointer(address, count)
        return image.read(address, count)

    def u64(address):
        return struct.unpack('<Q', read(address, 8))[0]

    def data_pointer(slot):
        require(slot in relocations, 'native metadata pointer lacks a relative relocation')
        target = relocations[slot]
        require(target not in image.functions, 'native metadata pointer refers to code')
        image.pointer(target, 1)
        return target

    require(0x40 <= u64(process) <= size and struct.unpack('<I', read(process + 8, 4))[0] == 0x4942524f,
            'invalid native process parameters')
    libc = data_pointer(process + 0x38)
    libc_size = u64(libc)
    require(libc_size >= 0x38, 'invalid native libc parameters')
    read(libc, libc_size)
    replacement = data_pointer(libc + 0x30)
    read(replacement, 0x78)
    require(u64(replacement) == 0x78 and u64(replacement + 8) == 2, 'unsupported native allocator table')
    entries = []
    for index in range(12):
        slot = replacement + 0x10 + index * 8
        contract = image.import_slots.get(slot)
        if slot in relocations:
            require(contract is None and relocations[slot] in image.functions, 'allocator callback relocation does not identify native code')
            contract = image.functions[relocations[slot]]
        if contract is None:
            require(u64(slot) == 0, 'allocator callback lacks a native code relocation')
            entries.append(None)
            continue
        require(index < len(CALLBACKS), 'allocator extension callback ABI is not implemented')
        result, parameters = CALLBACKS[index]
        expected = {'name': 'callback', 'result': result, 'parameters': parameters}
        require(structural_signature(contract) == structural_signature(expected), 'allocator callback native ABI mismatch')
        entries.append(contract['name'])
    if any(entries[2:]):
        require(all(entries[2:9]), 'allocator API replacement is incomplete')
    names = list(dict.fromkeys(spec['name'] for spec in list(image.functions.values()) + list(image.imports.values())))
    require(not RESERVED.intersection(names), 'native image registration symbol is reserved')
    return {'version': 1, 'process_parameters': process, 'process_parameter_bytes': size,
            'allocator_callbacks': entries, 'native_functions': names}


def declarations(image, descriptor):
    ranges = ', '.join(f"{{ ptr, i64 }} {{ ptr {image.pointer(spec['address'])}, i64 {spec['size']} }}" for spec in image.data)
    functions = ', '.join(f'ptr @{name}' for name in descriptor['native_functions'])
    count = len(descriptor['native_functions'])
    process, size = descriptor['process_parameters'], descriptor['process_parameter_bytes']
    return [f'@__aps5_aot_ranges = private constant [{len(image.data)} x {{ ptr, i64 }}] [{ranges}], align 8',
            f'@__aps5_aot_functions = private constant [{count} x ptr] [{functions}], align 8',
            f'@__aps5_aot_image = private constant {{ i64, ptr, i64, ptr, i64, ptr, i64 }} {{ i64 1, ptr @__aps5_aot_ranges, i64 {len(image.data)}, ptr @__aps5_aot_functions, i64 {count}, ptr {image.pointer(process)}, i64 {size} }}, align 8',
            'declare void @NativeAotRegisterImage_nid_no_patch(ptr)']

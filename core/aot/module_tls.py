from elf_segments import runtime_segments
import re
import struct


RESOLVER = 'Aps5GuestTlsGetAddr_nid_no_patch'
REGISTER = 'Aps5GuestTlsRegister_nid_no_patch'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def layout(elf, raw, contracts):
    segments = [s for s in runtime_segments(elf) if s['p_type'] == 'PT_TLS' and s['p_memsz']]
    require(len(segments) <= 1, 'multiple nonempty TLS segments')
    if not segments:
        require('tls_model' not in contracts, 'TLS model declared without a TLS segment')
        return None
    require(contracts.get('module_image') and contracts.get('tls_model') == 'general-dynamic',
            'TLS requires a qualified general-dynamic module profile')
    segment = segments[0]
    size, initialized, alignment, offset = (segment[key] for key in ('p_memsz', 'p_filesz', 'p_align', 'p_offset'))
    require(0 < size <= 1048576 and 0 <= initialized <= size, 'invalid TLS template extent')
    require(0 < alignment <= 65536 and alignment & (alignment - 1) == 0 and segment['p_vaddr'] % alignment == 0,
            'unsupported TLS template alignment')
    require(offset <= len(raw) and initialized <= len(raw) - offset, 'TLS template exceeds input')
    return {'bytes': size, 'initialized': initialized, 'alignment': alignment,
            'block_bytes': (size + alignment - 1) & -alignment,
            'template': raw[offset:offset + initialized].hex(),
            'name': contracts.get('native_namespace', '') + 'tls_descriptor'}


def binding(image, symbol):
    if symbol['section']:
        require(image.tls_layout is not None and symbol['info'] >> 4 == 1, 'TLS definition requires a qualified local template')
        result = {'name': image.tls_layout['name'], 'offset': symbol['value'], 'size': symbol['size'],
                  'bytes': image.tls_layout['bytes']}
    else:
        require(symbol['name'] in image.contracts.get('tls_imports', {}), 'unresolved TLS module binding')
        result = image.contracts['tls_imports'][symbol['name']]
        require(isinstance(result, dict) and set(result) == {'name', 'offset', 'size', 'bytes', 'evidence'}
                and isinstance(result['evidence'], str) and result['evidence'].strip(), 'invalid TLS import qualification')
    require(symbol['info'] >> 4 == 1 and symbol['other'] in (0, 2, 3) and symbol['size'] in (0, result['size']),
            'TLS symbol binding or extent contradicts qualification')
    require(isinstance(result['name'], str) and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', result['name']), 'invalid native TLS name')
    require(all(type(result[key]) is int for key in ('offset', 'size', 'bytes')) and
            0 <= result['offset'] < result['bytes'] <= 1048576 and 0 < result['size'] <= result['bytes'] - result['offset'],
            'TLS symbol exceeds qualified template')
    return result


def relocations(image):
    rows = [r for r in image.dynamic['relocations'] if r['kind'] in (16, 17, 18)]
    image.tls_initializers, image.tls_indexes, image.tls_dependencies = [], set(), set()
    require(not any(r['kind'] == 18 for r in rows), 'initial-exec TLS requires separate lowering')
    offsets = {r['slot']: r for r in rows if r['kind'] == 17}
    used_offsets, used_imports = set(), set()
    for row in rows:
        if row['kind'] != 16:
            continue
        slot, index = row['slot'], row['symbol_index']
        image.pointer(slot, 16)
        require(slot % 8 == 0, 'unaligned TLS index')
        if index:
            symbol = image.dynamic['symbols'][index]
            module = binding(image, symbol)
            if not symbol['section']:
                used_imports.add(symbol['name'])
        else:
            require(image.tls_layout is not None, 'local TLS module relocation has no template')
            module = {'name': image.tls_layout['name'], 'bytes': image.tls_layout['bytes']}
        offset_row = offsets.get(slot + 8)
        if offset_row is not None:
            require(offset_row['symbol_index'] == index, 'TLS module/offset relocation identity mismatch')
            value = (binding(image, image.dynamic['symbols'][index])['offset'] if index else 0) + offset_row['addend']
            used_offsets.add(slot + 8)
        else:
            require(index == 0, 'global-dynamic TLS symbol lacks its offset relocation')
            value = struct.unpack('<Q', image.read(slot + 8, 8))[0]
        require(0 <= value < module['bytes'], 'TLS index offset outside template')
        image.tls_initializers += [(slot, 'ptr', '@' + module['name']), (slot + 8, 'i64', str(value))]
        image.tls_indexes.add(slot)
        image.tls_dependencies.add(module['name'])
    require(used_offsets == set(offsets), 'orphan TLS offset relocation')
    require(used_imports == set(image.contracts.get('tls_imports', {})), 'unused TLS import bindings')


def validate_indexes(image):
    require(all(any(begin <= slot and slot + 16 <= end for begin, end in image.immutable_regions)
                for slot in image.tls_indexes), 'TLS indexes must be in immutable native data')
    resolvers = [contract for contract in image.imports.values() if contract.get('tls_resolver')]
    if image.tls_indexes:
        require(len(resolvers) == 1 and resolvers[0]['name'] == RESOLVER and resolvers[0]['parameters'] == ['ptr']
                and resolvers[0]['result'] == 'ptr', 'TLS indexes require the qualified native resolver ABI')
    else:
        require(not resolvers, 'TLS resolver declared without qualified indexes')


def declarations(image):
    result = []
    descriptor_type = '{ i64, i64, i64, i64, i64, i64 }'
    if image.tls_layout:
        layout = image.tls_layout
        name = layout['name']
        template = bytes.fromhex(layout['template'])
        encoded = ''.join(f'\\{value:02X}' for value in template)
        result.append(f'@{name}_template = private constant [{len(template)} x i8] c"{encoded}", align {layout["alignment"]}')
        result.append(f'@{name} = global {descriptor_type} {{ i64 1, i64 ptrtoint (ptr @{name}_template to i64), '
                      f'i64 {len(template)}, i64 {layout["block_bytes"]}, i64 {layout["alignment"]}, i64 0 }}, align 8')
        result.append(f'declare void @{REGISTER}(ptr)')
    for name in sorted(image.tls_dependencies):
        if not image.tls_layout or name != image.tls_layout['name']:
            result.append(f'@{name} = external global {descriptor_type}')
    return result

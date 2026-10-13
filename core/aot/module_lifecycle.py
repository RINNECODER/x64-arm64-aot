import struct

from calls import structural_signature


def require(condition, message):
    if not condition:
        raise ValueError(message)


def describe(image):
    require(image.contracts.get('lifecycle') == {'owner': 'bundle'}, 'invalid bundle lifecycle contract')
    require(image.contracts.get('module_image') and type(image.contracts.get('bundle_main')) is bool,
            'bundle lifecycle requires a qualified module role')
    tags = image.dynamic['tags']
    relative = dict(image.relocations)
    expected = structural_signature({'name': 'initializer', 'parameters': [], 'result': 'void'})

    def function(address):
        require(address in image.functions and structural_signature(image.functions[address]) == expected,
                'lifecycle callback has no qualified void() ABI')
        require(not image.functions[address].get('noreturn'), 'lifecycle callback must return')
        return image.functions[address]['name']

    def array(tag, size_tag):
        address, size = tags.get(tag, 0), tags.get(size_tag, 0)
        require(type(size) is int and 0 <= size <= 32768 and size % 8 == 0, 'invalid lifecycle array extent')
        if not size:
            return []
        require(address, 'lifecycle array has no address')
        image.pointer(address, size)
        result = []
        for slot in range(address, address + size, 8):
            require(slot in relative, 'lifecycle array entry requires a relative native-code relocation')
            result.append(function(relative[slot]))
        return result

    preinit = array('DT_PREINIT_ARRAY', 'DT_PREINIT_ARRAYSZ')
    require(not preinit or image.contracts['bundle_main'], 'only the main module may have PREINIT_ARRAY')
    init = ([function(tags['DT_INIT'])] if tags.get('DT_INIT') else []) + array('DT_INIT_ARRAY', 'DT_INIT_ARRAYSZ')
    fini = list(reversed(array('DT_FINI_ARRAY', 'DT_FINI_ARRAYSZ'))) + ([function(tags['DT_FINI'])] if tags.get('DT_FINI') else [])
    return {'preinit': preinit, 'init': init, 'fini': fini}

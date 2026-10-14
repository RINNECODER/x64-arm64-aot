from collections import deque
from typing import NamedTuple

from capstone.x86 import X86_OP_IMM

import abi
import parameter_pointers


class MemoryEffects(NamedTuple):
    writes: tuple
    bindings: frozenset = frozenset()
    parameter_writes: tuple = ()


def validate_provider(contract):
    if 'memory_effects' not in contract:
        return
    effects = contract['memory_effects']
    if not isinstance(effects, dict) or set(effects) != {'writes', 'callbacks', 'evidence'}:
        raise ValueError('provider memory effects require writes, callbacks and evidence')
    if type(effects['callbacks']) is not bool or not isinstance(effects['evidence'], str) or not effects['evidence'].strip():
        raise ValueError('provider memory effects require a callback boolean and nonempty evidence')
    if not isinstance(effects['writes'], list):
        raise ValueError('provider memory writes must be a list')
    parameters = contract['parameters']
    for write in effects['writes']:
        if not isinstance(write, dict) or set(write) not in ({'parameter', 'size'}, {'parameter', 'size_parameter'}):
            raise ValueError('provider writes require a pointer parameter and one size source')
        index = write['parameter']
        if type(index) is not int or not 0 <= index < len(parameters) or parameters[index] != 'ptr':
            raise ValueError('provider write target must be a declared pointer parameter')
        if 'size' in write:
            if type(write['size']) is not int or not 0 <= write['size'] <= (1 << 64) - 1:
                raise ValueError('provider write size must be an unsigned 64-bit integer')
        else:
            index = write['size_parameter']
            if type(index) is not int or not 0 <= index < len(parameters) or parameters[index] not in abi.INTEGER_TYPES - {'ptr'}:
                raise ValueError('provider write size parameter must be an integer')


def argument_pointer(function, ins, contract, index, state):
    locations = abi.locations(contract['parameters'])
    if not 0 <= index < len(locations):
        # A uniform callee has no typed parameter list (the register file is the ABI).
        return None
    location = locations[index]
    if location['kind'] == 'stack':
        offset = state['rsp'] + location['offset'] - (8 if ins.mnemonic == 'call' else 0)
        return state['stack_origins'].get(offset) if offset in state['stack_pointers'] else None
    name = location['name']
    if name in ('rsp', 'rbp') and state[name] is not None:
        return 'frame', 0, state[name]
    return state['pointers'].get(name)


def argument_value(ins, contract, index, state):
    location = abi.locations(contract['parameters'])[index]
    if location['kind'] == 'register':
        value = state['constants'].get(location['name'])
    else:
        offset = state['rsp'] + location['offset'] - (8 if ins.mnemonic == 'call' else 0)
        size = location['bits'] // 8
        values = state['stack_values']
        if not all(offset + byte in values for byte in range(size)):
            return None
        value = sum(values[offset + byte] << (byte * 8) for byte in range(size))
    return None if value is None else value & ((1 << location['bits']) - 1)


def provider_writes(function, ins, contract, state):
    effects = contract.get('memory_effects')
    if effects is None or effects['callbacks']:
        return None
    writes = []
    for write in effects['writes']:
        size = write.get('size')
        if size is None:
            size = argument_value(ins, contract, write['size_parameter'], state)
            if size is None:
                return None
        if size == 0:
            continue
        pointer = argument_pointer(function, ins, contract, write['parameter'], state)
        if pointer is None or pointer[0] not in ('frame', 'image'):
            return None
        kind, _, begin = pointer
        end = begin + size
        if kind == 'frame':
            if not -function.depth <= begin <= end <= 0:
                return None
        elif not any(spec['address'] <= begin <= end <= spec['address'] + spec['size'] for spec in function.image.data):
            return None
        writes.append((kind, begin, end))
    return tuple(writes)


def direct_target(function, ins):
    if ins.mnemonic != 'call' and ins.address not in function.tail_calls:
        return None
    if ins.mnemonic not in ('call', 'jmp'):
        callee, _slot = function.tail_calls[ins.address]
        return callee['address']
    if not ins.operands:
        return None
    operand = ins.operands[0]
    if operand.type == X86_OP_IMM and operand.imm in function.image.functions:
        return operand.imm
    return None


def call_targets(function, ins):
    target = direct_target(function, ins)
    if target is not None:
        return {target}
    image = function.image
    site = image.annotated_calls(function.contract).get(ins.address)
    if site is None:
        return set()
    index = site.get('target_set')
    if index is None:
        return set(site['target_addresses']) & image.functions.keys()
    # The filtered target set depends only on the target set, which many owners share.
    cache = getattr(image, '_call_targets_cache', None)
    if cache is None:
        cache = image._call_targets_cache = {}
    cached = cache.get(index)
    if cached is None:
        cached = frozenset(set(site['target_addresses']) & image.functions.keys())
        cache[index] = cached
    return cached


def required_bindings(function, ins):
    image = function.image
    target = direct_target(function, ins)
    if target is not None:
        return image.provider_requirements.get(target, frozenset())
    site = image.annotated_calls(function.contract).get(ins.address)
    if site is None:
        return frozenset()
    # The union depends only on the target set, which many owners share; cache it per set.
    index = site.get('target_set')
    if index is None:
        return frozenset().union(*(image.provider_requirements.get(target, frozenset())
                                   for target in site['target_addresses']))
    cache = getattr(image, '_required_bindings_cache', None)
    if cache is None:
        cache = image._required_bindings_cache = {}
    cached = cache.get(index)
    if cached is None:
        cached = frozenset().union(*(image.provider_requirements.get(target, frozenset())
                                     for target in site['target_addresses']))
        cache[index] = cached
    return cached


def infer_requirements(functions):
    image = functions[0].image
    requirements = {function.contract['address']: set() for function in functions}
    callers = {address: set() for address in requirements}
    for function in functions:
        address = function.contract['address']
        for ins in function.instructions.values():
            if ins.mnemonic != 'call' and ins.address not in function.tail_calls:
                continue
            if ins.address in getattr(function, 'dispatch_calls', {}):
                continue
            target = direct_target(function, ins)
            if target is not None:
                # A fall-through tail call has no operand; its callee comes from the tail-call map.
                contract, slot = image.functions[target], None
            else:
                contract, slot = image.call(ins, function.contract)
            effects = contract.get('memory_effects')
            if type(slot) is int and effects is not None and not effects['callbacks']:
                requirements[address].add(slot)
            for target in call_targets(function, ins):
                # A whole-title image stubs rejected callees, which are not in this set.
                if target in callers:
                    callers[target].add(address)
    pending = deque(address for address, slots in requirements.items() if slots)
    while pending:
        target = pending.popleft()
        for caller in callers[target]:
            if not requirements[target] <= requirements[caller]:
                requirements[caller].update(requirements[target])
                pending.append(caller)
    image.provider_requirements = {address: frozenset(slots) for address, slots in requirements.items()}


def parameter_write(function, ins, state, operand):
    memory = operand.mem
    if ins.addr_size != 8 or memory.segment or memory.index:
        return None
    pointer = state['pointers'].get(ins.reg_name(memory.base))
    if pointer is None or pointer[0] != 'parameter':
        return None
    _, index, displacement = pointer
    begin = displacement + memory.disp
    end = begin + operand.size
    if not -(1 << 63) <= begin < end <= 1 << 63:
        return None
    return index, begin, end


def resolve_parameters(function, ins, contract, result, state):
    writes, parameters = list(result.writes), []
    for index, begin, end in result.parameter_writes:
        pointer = argument_pointer(function, ins, contract, index, state)
        if pointer is None:
            return None
        kind, parameter, offset = pointer
        begin, end = begin + offset, end + offset
        if not -(1 << 63) <= begin < end <= 1 << 63:
            return None
        if kind == 'parameter':
            parameters.append((parameter, begin, end))
            continue
        if kind == 'frame':
            if not -function.depth <= begin < end <= 0:
                return None
        elif kind == 'image':
            if not any(spec['address'] <= begin < end <= spec['address'] + spec['size'] for spec in function.image.data):
                return None
        else:
            return None
        writes.append((kind, begin, end))
    return MemoryEffects(tuple(writes), result.bindings, tuple(parameters))


def merge_ranges(ranges):
    merged = []
    for begin, end in sorted(ranges):
        if merged and begin <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((begin, end))
    return tuple(merged)


def call_writes(function, ins, state=None):
    if ins.address in getattr(function, 'dispatch_calls', {}):
        return None
    state = function.states[ins.address] if state is None else state
    target = direct_target(function, ins)
    if target is not None:
        # A uniform callee passes the whole register file, so the caller has no typed parameter
        # list to resolve against; its effects stay unknown.
        if abi.uniform(function.image.functions[target]):
            return None
        result = function.image.memory_effects.get(target)
        if result is None or not result.bindings <= state['import_bindings']:
            return None
        return resolve_parameters(function, ins, function.image.functions[target], result, state)
    contract, slot = function.image.call(ins, function.contract)
    if slot not in state['import_bindings']:
        return None
    writes = provider_writes(function, ins, contract, state)
    return None if writes is None else MemoryEffects(writes, frozenset({slot}))


def summarize(function):
    writes, bindings, parameters = set(), set(), set()
    for address, ins in function.instructions.items():
        if ins.mnemonic == 'call' or address in function.tail_calls:
            nested = call_writes(function, ins)
            if nested is None:
                return None
            writes.update((begin, end) for kind, begin, end in nested.writes if kind == 'image')
            bindings.update(nested.bindings)
            parameters.update(nested.parameter_writes)
        for operand in function.memory_writes.get(address, ()):
            origin = function.memory_write_region(ins, function.states[address], operand)
            if origin is None:
                parameter = parameter_write(function, ins, function.states[address], operand)
                if parameter is None:
                    return None
                parameters.add(parameter)
                continue
            kind, begin, end = origin
            if kind == 'outside_frame':
                return None
            if kind == 'image':
                writes.add((begin, end))
            elif end > 0:
                return None
    merged_parameters = tuple((index, begin, end) for index in sorted({index for index, _, _ in parameters})
                              for begin, end in merge_ranges((begin, end) for parameter, begin, end in parameters if parameter == index))
    return MemoryEffects(tuple(('image', begin, end) for begin, end in merge_ranges(writes)), frozenset(bindings), merged_parameters)


def analyze(functions, reject=None):
    """Compute per-function effects in callee order.

    `reject(function, error)` (whole-title builds) marks a function whose dataflow fails instead of
    aborting the image; the caller removes it afterwards and emits a trap stub.
    """
    if not functions:
        return
    image = functions[0].image
    image.memory_effects.clear()
    image.pointer_output_summaries.clear()
    infer_requirements(functions)
    by_address = {function.contract['address']: function for function in functions}
    dependencies, callers = {}, {address: set() for address in by_address}
    for address, function in by_address.items():
        dependencies[address] = {target for ins in function.instructions.values()
                                 if (target := direct_target(function, ins)) is not None and target in by_address}
        for target in dependencies[address]:
            callers[target].add(address)
    ready = deque(sorted(address for address, targets in dependencies.items() if not targets))
    analyzed = set()
    while ready:
        address = ready.popleft()
        function = by_address[address]
        try:
            function.analyze()
        except ValueError as error:
            if reject is None:
                raise
            reject(function, error)
            image.memory_effects[address] = None
            analyzed.add(address)
            for caller in sorted(callers[address]):
                dependencies[caller].discard(address)
                if not dependencies[caller] and caller not in analyzed:
                    ready.append(caller)
            continue
        image.memory_effects[address] = summarize(function)
        image.pointer_output_summaries[address] = parameter_pointers.summarize(function)
        analyzed.add(address)
        for caller in sorted(callers[address]):
            dependencies[caller].discard(address)
            if not dependencies[caller] and caller not in analyzed:
                ready.append(caller)
    for address in sorted(by_address.keys() - analyzed):
        try:
            by_address[address].analyze()
        except ValueError as error:
            if reject is None:
                raise
            reject(by_address[address], error)
        image.memory_effects[address] = None


def report(writes):
    if writes is None:
        return {'status': 'unknown'}
    result = {'status': 'inferred', 'image_writes': [{'address': begin, 'size': end - begin} for _, begin, end in writes.writes]}
    if writes.parameter_writes:
        result['parameter_writes'] = [{'parameter': index, 'offset': begin, 'size': end - begin} for index, begin, end in writes.parameter_writes]
    if writes.bindings:
        result['required_provider_bindings'] = sorted(writes.bindings)
    return result

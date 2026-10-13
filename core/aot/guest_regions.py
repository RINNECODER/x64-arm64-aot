PAGE_SIZE = 16384
LIMIT = 1 << 64


def immutable_ranges(loads, relro=(0, 0)):
    boundaries = set()
    mapped, writable = [], []
    for segment in loads:
        start, size = segment['vaddr'], segment['memsz']
        if not size or not segment['flags'] & 7:
            continue
        if start < 0 or size < 0 or start + size >= LIMIT:
            raise ValueError('invalid guest segment range')
        first, last = start // PAGE_SIZE * PAGE_SIZE, (start + size + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE
        mapped.append((first, last))
        if segment['flags'] & 2:
            writable.append((first, last))
        boundaries.update((first, last))
    start, size = relro
    if start < 0 or size < 0 or start + size >= LIMIT:
        raise ValueError('invalid guest RELRO range')
    first, last = (start + PAGE_SIZE - 1) // PAGE_SIZE * PAGE_SIZE, (start + size) // PAGE_SIZE * PAGE_SIZE
    if first < last:
        boundaries.update((first, last))
    result = []
    ordered = sorted(boundaries)
    for low, high in zip(ordered, ordered[1:]):
        if not any(a <= low and high <= b for a, b in mapped):
            continue
        if any(a <= low and high <= b for a, b in writable) and not (first <= low and high <= last):
            continue
        if result and result[-1][1] == low:
            result[-1] = (result[-1][0], high)
        else:
            result.append((low, high))
    return result


def available_bytes(ranges, address):
    for start, end in ranges:
        if start <= address < end:
            return end - address
    return 0


def sealed_tables(unit):
    from capstone.x86 import X86_OP_MEM
    ranges = immutable_ranges(unit.program.view.loads, unit.program.relro)
    result = set()
    for site, table in unit.tables.items():
        if table['status'] != 'qualified' or table.get('selector_load') is None:
            continue
        base, size = table['base'], table['count'] * 4
        if available_bytes(ranges, base) < size:
            continue
        if any(r['kind'] != 0 and r['slot'] < base + size and base < r['slot'] + 8
               for r in unit.program.dynamic['relocations']):
            continue
        ins = unit.instructions[table['selector_load']]
        operand = ins.operands[1]
        if ins.addr_size != 8 or operand.type != X86_OP_MEM or ins.reg_name(operand.mem.segment) not in ('', None, 'cs', 'ds', 'ss', 'es'):
            continue
        result.add(site)
    return result

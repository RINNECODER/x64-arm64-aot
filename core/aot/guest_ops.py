import re

from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

GPR = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
FLAGS = ['cf', 'pf', 'af', 'zf', 'sf', 'of']
STATE_XMM = 128
STATE_YMM_UPPER = 560
STATE_FS = 384
STATE_X87 = 400
STATE_X87_TOP = 528
STATE_X87_CONTROL = 536
STATE_X87_VALID = 544
ALIASES = {}
for full, dword, word, low in zip(GPR[:8], ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'],
                                  ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'],
                                  ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil']):
    for name, bits in ((full, 64), (dword, 32), (word, 16), (low, 8)):
        ALIASES[name] = (full, bits, 0)
for index, name in enumerate(['ah', 'ch', 'dh', 'bh']):
    ALIASES[name] = (GPR[index], 8, 8)
for full in GPR[8:]:
    for suffix, bits in (('', 64), ('d', 32), ('w', 16), ('b', 8)):
        ALIASES[full + suffix] = (full, bits, 0)
CONDITIONS = {'o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a', 's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g'}
CONDITION_ALIASES = {'c': 'b', 'nae': 'b', 'nb': 'ae', 'nc': 'ae', 'z': 'e', 'nz': 'ne', 'na': 'be', 'nbe': 'a',
                     'pe': 'p', 'po': 'np', 'nge': 'l', 'nl': 'ge', 'ng': 'le', 'nle': 'g'}
CONDITION_FLAGS = {'o': {'of'}, 'no': {'of'}, 'b': {'cf'}, 'ae': {'cf'}, 'e': {'zf'}, 'ne': {'zf'}, 'be': {'cf', 'zf'},
                   'a': {'cf', 'zf'}, 's': {'sf'}, 'ns': {'sf'}, 'p': {'pf'}, 'np': {'pf'}, 'l': {'sf', 'of'},
                   'ge': {'sf', 'of'}, 'le': {'zf', 'sf', 'of'}, 'g': {'zf', 'sf', 'of'}}
TRAP_UNKNOWN_ENTRY = 4
TRAP_FALLTHROUGH = 5
TRAP_DIVIDE = 3
TRAP_INVALID = 6
TRAP_HALT = 7
TRAP_UNSUPPORTED = 10
TRAP_ALIGNMENT = 11
TRAP_SPLIT_LOCK = 12
ATOMIC = {'add': 'add', 'sub': 'sub', 'and': 'and', 'or': 'or', 'xor': 'xor', 'inc': 'add', 'dec': 'sub', 'xadd': 'add'}


INTRINSIC = re.compile(r'call (<[^>]+>|\S+) (@llvm\.[\w.]+)\((.*)\)\s*$')


class Unsupported(ValueError):
    pass


def condition_name(suffix):
    suffix = CONDITION_ALIASES.get(suffix, suffix)
    if suffix not in CONDITIONS:
        raise Unsupported(f'unknown condition {suffix}')
    return suffix


def mask(bits):
    return (1 << bits) - 1


class Emitter:
    def __init__(self, unit, symbol):
        self.unit, self.symbol = unit, symbol
        self.lines = []
        self.counter = 0
        self.ins = None
        self.declarations = set()

    def tmp(self):
        self.counter += 1
        return f'%t{self.counter}'

    def label(self):
        self.counter += 1
        return f'k{self.counter}'

    def emit(self, text):
        if '@llvm.' in text:
            self.declare_intrinsic(text)
        self.lines.append('  ' + text)

    def declare_intrinsic(self, text):
        found = INTRINSIC.search(text)
        if found is None:
            return
        result, name, arguments = found.groups()
        types = []
        depth, current = 0, ''
        for character in arguments + ',':
            if character in '<(':
                depth += 1
            elif character in '>)':
                depth -= 1
            if character == ',' and depth == 0:
                piece = current.strip()
                if piece.startswith('<'):
                    end = piece.index('>') + 1
                    types.append(piece[:end])
                else:
                    types.append(piece.split(' ')[0])
                current = ''
            else:
                current += character
        self.declarations.add(f'declare {result} {name}({", ".join(types)})')

    def v(self, expression):
        name = self.tmp()
        self.emit(f'{name} = {expression}')
        return name

    def place(self, label):
        self.lines.append(f'{label}:')

    def const(self, value, bits):
        return str(value & mask(bits))

    def unsupported(self, message):
        raise Unsupported(f'0x{self.ins.address:x} {self.ins.mnemonic} {self.ins.op_str}: {message}')

    def gpr(self, name):
        return f'%R{GPR.index(name)}'

    def get_gpr(self, name):
        return self.v(f'load i64, ptr {self.gpr(name)}')

    def set_gpr(self, name, value):
        self.emit(f'store i64 {value}, ptr {self.gpr(name)}')

    def trunc(self, value, bits, source=64):
        if bits == source:
            return value
        return self.v(f'trunc i{source} {value} to i{bits}')

    def zext(self, value, bits, target=64):
        if bits == target:
            return value
        return self.v(f'zext i{bits} {value} to i{target}')

    def sext(self, value, bits, target=64):
        if bits == target:
            return value
        return self.v(f'sext i{bits} {value} to i{target}')

    def read_register(self, name):
        full, bits, shift = ALIASES[name]
        value = self.get_gpr(full)
        if shift:
            value = self.v(f'lshr i64 {value}, {shift}')
        return self.trunc(value, bits), bits

    def write_register(self, name, value):
        full, bits, shift = ALIASES[name]
        if bits == 64:
            self.set_gpr(full, value)
        elif bits == 32:
            self.set_gpr(full, self.zext(value, 32))
        else:
            old = self.get_gpr(full)
            cleared = self.v(f'and i64 {old}, {self.const(~(mask(bits) << shift), 64)}')
            wide = self.zext(value, bits)
            if shift:
                wide = self.v(f'shl i64 {wide}, {shift}')
            self.set_gpr(full, self.v(f'or i64 {cleared}, {wide}'))

    def flag(self, name):
        return self.v(f'load i1, ptr %F{name}')

    def set_flag(self, name, value):
        self.emit(f'store i1 {value}, ptr %F{name}')

    def address(self, operand):
        ins = self.ins
        memory = operand.mem
        base = ins.reg_name(memory.base) if memory.base else ''
        index = ins.reg_name(memory.index) if memory.index else ''
        segment = ins.reg_name(memory.segment) if memory.segment else ''
        if base == 'rip':
            value = self.v(f'add i64 %base, {ins.address + ins.size + memory.disp}')
        else:
            value = str(memory.disp & mask(64))
            if base:
                value = self.v(f'add i64 {self.register64(base)}, {value}')
            if index:
                scaled = self.register64(index)
                if memory.scale != 1:
                    scaled = self.v(f'mul i64 {scaled}, {memory.scale}')
                value = self.v(f'add i64 {value}, {scaled}')
        if ins.addr_size == 4:
            value = self.v(f'and i64 {value}, 4294967295')
        elif ins.addr_size != 8:
            self.unsupported('16-bit addressing')
        if segment == 'fs':
            fs = self.v(f'getelementptr i8, ptr %s, i64 {STATE_FS}')
            value = self.v(f'add i64 {value}, {self.v(f"load i64, ptr {fs}")}')
        elif segment not in ('', 'cs', 'ds', 'ss', 'es'):
            self.unsupported(f'segment {segment}')
        return value

    def register64(self, name):
        full, bits, shift = ALIASES[name]
        if bits != 64:
            self.unsupported('partial-width address register')
        return self.get_gpr(full)

    def pointer(self, address):
        return self.v(f'inttoptr i64 {address} to ptr')

    def load(self, address, bits):
        return self.v(f'load i{bits}, ptr {self.pointer(address)}, align 1')

    def store(self, address, value, bits):
        self.emit(f'store i{bits} {value}, ptr {self.pointer(address)}, align 1')

    def read(self, operand, bits=None):
        bits = bits or operand.size * 8
        if operand.type == X86_OP_REG:
            name = self.ins.reg_name(operand.reg)
            if name not in ALIASES:
                self.unsupported(f'register {name}')
            value, width = self.read_register(name)
            return value if width == bits else self.trunc(self.zext(value, width), bits)
        if operand.type == X86_OP_IMM:
            return self.const(operand.imm, bits)
        if operand.type == X86_OP_MEM:
            return self.load(self.address(operand), bits)
        self.unsupported('operand')

    def write(self, operand, value, bits=None):
        bits = bits or operand.size * 8
        if operand.type == X86_OP_REG:
            name = self.ins.reg_name(operand.reg)
            if name not in ALIASES:
                self.unsupported(f'register {name}')
            self.write_register(name, value)
        elif operand.type == X86_OP_MEM:
            self.store(self.address(operand), value, bits)
        else:
            self.unsupported('destination')

    def zf_sf_pf(self, result, bits):
        self.set_flag('zf', self.v(f'icmp eq i{bits} {result}, 0'))
        self.set_flag('sf', self.v(f'icmp slt i{bits} {result}, 0'))
        low = self.trunc(result, 8, bits) if bits > 8 else result
        count = self.v(f'call i8 @llvm.ctpop.i8(i8 {low})')
        bit = self.v(f'trunc i8 {count} to i1')
        self.set_flag('pf', self.v(f'xor i1 {bit}, true'))

    def auxiliary(self, left, right, result, bits):
        mixed = self.v(f'xor i{bits} {left}, {right}')
        mixed = self.v(f'xor i{bits} {mixed}, {result}')
        if bits > 4:
            mixed = self.v(f'lshr i{bits} {mixed}, 4')
        self.set_flag('af', self.v(f'trunc i{bits} {mixed} to i1'))

    def logic_flags(self, result, bits):
        self.set_flag('cf', 'false')
        self.set_flag('of', 'false')
        self.set_flag('af', 'false')
        self.zf_sf_pf(result, bits)

    def add_flags(self, left, right, result, bits, carry=None):
        wide = 2 * bits
        total = self.v(f'add i{wide} {self.zext(left, bits, wide)}, {self.zext(right, bits, wide)}')
        if carry is not None:
            total = self.v(f'add i{wide} {total}, {self.zext(carry, 1, wide)}')
        high = self.v(f'lshr i{wide} {total}, {bits}')
        self.set_flag('cf', self.v(f'icmp ne i{wide} {high}, 0'))
        a = self.v(f'xor i{bits} {left}, {result}')
        b = self.v(f'xor i{bits} {right}, {result}')
        self.set_flag('of', self.v(f'icmp slt i{bits} {self.v(f"and i{bits} {a}, {b}")}, 0'))
        self.auxiliary(left, right, result, bits)
        self.zf_sf_pf(result, bits)

    def sub_flags(self, left, right, result, bits, borrow=None):
        if borrow is None:
            self.set_flag('cf', self.v(f'icmp ult i{bits} {left}, {right}'))
        else:
            wide = 2 * bits
            subtrahend = self.v(f'add i{wide} {self.zext(right, bits, wide)}, {self.zext(borrow, 1, wide)}')
            self.set_flag('cf', self.v(f'icmp ult i{wide} {self.zext(left, bits, wide)}, {subtrahend}'))
        a = self.v(f'xor i{bits} {left}, {right}')
        b = self.v(f'xor i{bits} {left}, {result}')
        self.set_flag('of', self.v(f'icmp slt i{bits} {self.v(f"and i{bits} {a}, {b}")}, 0'))
        self.auxiliary(left, right, result, bits)
        self.zf_sf_pf(result, bits)

    def condition(self, suffix):
        code = condition_name(suffix)
        negate = code in ('no', 'ae', 'ne', 'a', 'ns', 'np', 'ge', 'g')
        base = {'no': 'o', 'ae': 'b', 'ne': 'e', 'a': 'be', 'ns': 's', 'np': 'p', 'ge': 'l', 'g': 'le'}.get(code, code)
        if base in ('o', 'b', 'e', 's', 'p'):
            value = self.flag({'o': 'of', 'b': 'cf', 'e': 'zf', 's': 'sf', 'p': 'pf'}[base])
        elif base == 'be':
            value = self.v(f'or i1 {self.flag("cf")}, {self.flag("zf")}')
        elif base == 'l':
            value = self.v(f'xor i1 {self.flag("sf")}, {self.flag("of")}')
        else:
            less = self.v(f'xor i1 {self.flag("sf")}, {self.flag("of")}')
            value = self.v(f'or i1 {self.flag("zf")}, {less}')
        return self.v(f'xor i1 {value}, true') if negate else value

    def trap(self, kind, detail='0'):
        self.emit(f'call void @NativeAotGuestTrap(i64 {kind}, i64 {self.v(f"add i64 %base, {self.ins.address}")}, i64 {detail})')
        self.emit('unreachable')

    def trap_if(self, condition, kind, detail='0'):
        bad, good = self.label(), self.label()
        self.emit(f'br i1 {condition}, label %{bad}, label %{good}')
        self.place(bad)
        self.trap(kind, detail)
        self.place(good)


class Integer(Emitter):
    def operands(self):
        return self.ins.operands

    def binary(self, operation):
        destination, source = self.operands()
        bits = destination.size * 8
        left = self.read(destination)
        right = self.read(source, bits) if source.type != X86_OP_IMM else self.const(source.imm, bits)
        if source.type == X86_OP_REG and source.size * 8 != bits:
            self.unsupported('mixed operand widths')
        return destination, bits, left, right

    def op_add(self):
        destination, bits, left, right = self.binary('add')
        result = self.v(f'add i{bits} {left}, {right}')
        self.add_flags(left, right, result, bits)
        self.write(destination, result)

    def op_adc(self):
        destination, bits, left, right = self.binary('adc')
        carry = self.flag('cf')
        result = self.v(f'add i{bits} {self.v(f"add i{bits} {left}, {right}")}, {self.zext(carry, 1, bits)}')
        self.add_flags(left, right, result, bits, carry)
        self.write(destination, result)

    def op_sub(self, store=True):
        destination, bits, left, right = self.binary('sub')
        result = self.v(f'sub i{bits} {left}, {right}')
        self.sub_flags(left, right, result, bits)
        if store:
            self.write(destination, result)

    def op_cmp(self):
        self.op_sub(False)

    def op_sbb(self):
        destination, bits, left, right = self.binary('sbb')
        borrow = self.flag('cf')
        result = self.v(f'sub i{bits} {self.v(f"sub i{bits} {left}, {right}")}, {self.zext(borrow, 1, bits)}')
        self.sub_flags(left, right, result, bits, borrow)
        self.write(destination, result)

    def logic(self, operation, store=True):
        destination, bits, left, right = self.binary(operation)
        result = self.v(f'{operation} i{bits} {left}, {right}')
        self.logic_flags(result, bits)
        if store:
            self.write(destination, result)

    def op_and(self):
        self.logic('and')

    def op_or(self):
        self.logic('or')

    def op_xor(self):
        destination, source = self.operands()
        if destination.type == source.type == X86_OP_REG and destination.reg == source.reg:
            bits = destination.size * 8
            self.write(destination, self.const(0, bits))
            self.logic_flags(self.const(0, bits), bits)
            return
        self.logic('xor')

    def op_test(self):
        self.logic('and', False)

    def op_inc(self, delta=1):
        destination, = self.operands()
        bits = destination.size * 8
        value = self.read(destination)
        one = self.const(1, bits)
        if delta > 0:
            result = self.v(f'add i{bits} {value}, {one}')
            self.set_flag('of', self.v(f'icmp eq i{bits} {result}, {self.const(1 << (bits - 1), bits)}'))
        else:
            result = self.v(f'sub i{bits} {value}, {one}')
            self.set_flag('of', self.v(f'icmp eq i{bits} {value}, {self.const(1 << (bits - 1), bits)}'))
        self.auxiliary(value, one, result, bits)
        self.zf_sf_pf(result, bits)
        self.write(destination, result)

    def op_dec(self):
        self.op_inc(-1)

    def op_neg(self):
        destination, = self.operands()
        bits = destination.size * 8
        value = self.read(destination)
        result = self.v(f'sub i{bits} 0, {value}')
        self.set_flag('cf', self.v(f'icmp ne i{bits} {value}, 0'))
        self.set_flag('of', self.v(f'icmp eq i{bits} {value}, {self.const(1 << (bits - 1), bits)}'))
        self.auxiliary('0', value, result, bits)
        self.zf_sf_pf(result, bits)
        self.write(destination, result)

    def op_not(self):
        destination, = self.operands()
        bits = destination.size * 8
        self.write(destination, self.v(f'xor i{bits} {self.read(destination)}, -1'))

    def op_mov(self):
        destination, source = self.operands()
        bits = destination.size * 8
        if source.type == X86_OP_REG and self.ins.reg_name(source.reg) not in ALIASES:
            self.unsupported('segment or special register move')
        self.write(destination, self.read(source, bits))

    op_movabs = op_mov

    def op_movzx(self):
        destination, source = self.operands()
        self.write(destination, self.zext(self.read(source), source.size * 8, destination.size * 8))

    def op_movsx(self):
        destination, source = self.operands()
        self.write(destination, self.sext(self.read(source), source.size * 8, destination.size * 8))

    op_movsxd = op_movsx

    def op_lea(self):
        destination, source = self.operands()
        if source.mem.segment:
            self.unsupported('segment-relative lea')
        self.write(destination, self.trunc(self.address(source), destination.size * 8))

    def extend_accumulator(self, source, target):
        value, _ = self.read_register(source)
        bits = ALIASES[source][1]
        self.write_register(target, self.sext(value, bits, ALIASES[target][1]))

    def op_cdqe(self):
        self.extend_accumulator('eax', 'rax')

    def op_cwde(self):
        self.extend_accumulator('ax', 'eax')

    def op_cbw(self):
        self.extend_accumulator('al', 'ax')

    def split_sign(self, source, target):
        value, bits = self.read_register(source)
        self.write_register(target, self.v(f'ashr i{bits} {value}, {bits - 1}'))

    def op_cdq(self):
        self.split_sign('eax', 'edx')

    def op_cqo(self):
        self.split_sign('rax', 'rdx')

    def op_cwd(self):
        self.split_sign('ax', 'dx')

    def op_nop(self):
        pass

    op_endbr64 = op_nop
    op_pause = op_nop

    def op_mfence(self):
        self.emit('fence seq_cst')

    op_lfence = op_mfence
    op_sfence = op_mfence
    op_prefetcht0 = op_nop
    op_prefetcht1 = op_nop
    op_prefetcht2 = op_nop
    op_prefetchnta = op_nop
    op_prefetchw = op_nop

    def op_push(self):
        source, = self.operands()
        bits = source.size * 8
        if bits != 64:
            self.unsupported('narrow push')
        value = self.read(source, 64) if source.type != X86_OP_IMM else self.const(source.imm, 64)
        rsp = self.v(f'sub i64 {self.get_gpr("rsp")}, 8')
        self.store(rsp, value, 64)
        self.set_gpr('rsp', rsp)

    def op_pop(self):
        destination, = self.operands()
        if destination.size != 8:
            self.unsupported('narrow pop')
        rsp = self.get_gpr('rsp')
        value = self.load(rsp, 64)
        self.set_gpr('rsp', self.v(f'add i64 {rsp}, 8'))
        self.write(destination, value)

    def op_leave(self):
        rbp = self.get_gpr('rbp')
        self.set_gpr('rbp', self.load(rbp, 64))
        self.set_gpr('rsp', self.v(f'add i64 {rbp}, 8'))

    def op_bswap(self):
        destination, = self.operands()
        bits = destination.size * 8
        self.write(destination, self.v(f'call i{bits} @llvm.bswap.i{bits}(i{bits} {self.read(destination)})'))

    def op_xchg(self):
        left, right = self.operands()
        bits = left.size * 8
        if left.type == X86_OP_MEM or right.type == X86_OP_MEM:
            memory, register = (left, right) if left.type == X86_OP_MEM else (right, left)
            pointer = self.aligned_atomic_pointer(memory, bits)
            old = self.v(f'atomicrmw xchg ptr {pointer}, i{bits} {self.read(register)} seq_cst, align {memory.size}')
            self.write(register, old)
            return
        a, b = self.read(left), self.read(right)
        self.write(left, b)
        self.write(right, a)

    def cmov(self, suffix):
        destination, source = self.operands()
        bits = destination.size * 8
        value = self.read(source)
        old = self.read(destination)
        self.write(destination, self.v(f'select i1 {self.condition(suffix)}, i{bits} {value}, i{bits} {old}'))

    def setcc(self, suffix):
        destination, = self.operands()
        self.write(destination, self.v(f'zext i1 {self.condition(suffix)} to i8'), 8)

    def shift_count(self, operand, bits, position=1):
        if len(self.operands()) <= position:
            count = '1'
        else:
            count = self.read(self.operands()[position], 8)
        return self.v(f'and i8 {count}, {63 if bits == 64 else 31}')

    def preserve_flags_if_zero(self, count, updates):
        zero = self.v(f'icmp eq i8 {count}, 0')
        for name, value in updates.items():
            old = self.flag(name)
            self.set_flag(name, self.v(f'select i1 {zero}, i1 {old}, i1 {value}'))

    def shift(self, kind):
        destination = self.operands()[0]
        bits = destination.size * 8
        value = self.read(destination)
        count = self.shift_count(destination, bits)
        wide = self.zext(value, bits, 128) if kind != 'sar' else self.sext(value, bits, 128)
        amount = self.zext(count, 8, 128)
        operation = {'shl': 'shl', 'shr': 'lshr', 'sar': 'ashr'}[kind]
        shifted = self.v(f'{operation} i128 {wide}, {amount}')
        result = self.trunc(shifted, bits, 128)
        if kind == 'shl':
            out = self.v(f'lshr i128 {shifted}, {bits}')
        else:
            back = self.v(f'sub i128 {amount}, 1')
            back = self.v(f'select i1 {self.v(f"icmp eq i128 {amount}, 0")}, i128 0, i128 {back}')
            out = self.v(f'{"ashr" if kind == "sar" else "lshr"} i128 {wide}, {back}')
        carry = self.v(f'trunc i128 {out} to i1')
        sign = self.v(f'icmp slt i{bits} {result}, 0')
        if kind == 'shl':
            overflow = self.v(f'xor i1 {sign}, {carry}')
        elif kind == 'shr':
            overflow = self.v(f'icmp slt i{bits} {value}, 0')
        else:
            overflow = 'false'
        zero = self.v(f'icmp eq i{bits} {result}, 0')
        low = self.trunc(result, 8, bits) if bits > 8 else result
        parity = self.v(f'xor i1 {self.v(f"trunc i8 {self.v(f"call i8 @llvm.ctpop.i8(i8 {low})")} to i1")}, true')
        self.preserve_flags_if_zero(count, {'cf': carry, 'of': overflow, 'zf': zero, 'sf': sign, 'pf': parity, 'af': 'false'})
        self.write(destination, result)

    def op_shl(self):
        self.shift('shl')

    op_sal = op_shl

    def op_shr(self):
        self.shift('shr')

    def op_sar(self):
        self.shift('sar')

    def rotate(self, left):
        destination = self.operands()[0]
        bits = destination.size * 8
        value = self.read(destination)
        count = self.shift_count(destination, bits)
        amount = self.v(f'urem i8 {count}, {bits}') if bits < 32 else count
        amount = self.zext(amount, 8, bits)
        name = 'fshl' if left else 'fshr'
        result = self.v(f'call i{bits} @llvm.{name}.i{bits}(i{bits} {value}, i{bits} {value}, i{bits} {amount})')
        high = self.v(f'icmp slt i{bits} {result}, 0')
        if left:
            carry = self.v(f'trunc i{bits} {result} to i1')
            overflow = self.v(f'xor i1 {high}, {carry}')
        else:
            carry = high
            second = self.v(f'trunc i{bits} {self.v(f"lshr i{bits} {result}, {bits - 2}")} to i1')
            overflow = self.v(f'xor i1 {high}, {second}')
        self.preserve_flags_if_zero(count, {'cf': carry, 'of': overflow})
        self.write(destination, result)

    def op_rol(self):
        self.rotate(True)

    def op_ror(self):
        self.rotate(False)

    def double_shift(self, left):
        destination, source = self.operands()[:2]
        bits = destination.size * 8
        value, fill = self.read(destination), self.read(source)
        count = self.shift_count(destination, bits, 2)
        if bits == 16:
            self.trap_if(self.v(f'icmp ugt i8 {count}, 16'), TRAP_UNSUPPORTED)
        amount = self.zext(count, 8, bits)
        name = 'fshl' if left else 'fshr'
        arguments = f'i{bits} {value}, i{bits} {fill}' if left else f'i{bits} {fill}, i{bits} {value}'
        result = self.v(f'call i{bits} @llvm.{name}.i{bits}({arguments}, i{bits} {amount})')
        if bits == 16:
            complete = self.v(f'icmp eq i8 {count}, 16')
            result = self.v(f'select i1 {complete}, i16 {fill}, i16 {result}')
        if left:
            out = self.v(f'lshr i{bits} {value}, {self.v(f"sub i{bits} {bits}, {amount}")}')
        else:
            out = self.v(f'lshr i{bits} {value}, {self.v(f"sub i{bits} {amount}, 1")}')
        carry = self.v(f'trunc i{bits} {out} to i1')
        sign = self.v(f'icmp slt i{bits} {result}, 0')
        overflow = self.v(f'xor i1 {sign}, {self.v(f"icmp slt i{bits} {value}, 0")}')
        zero = self.v(f'icmp eq i{bits} {result}, 0')
        low = self.trunc(result, 8, bits)
        parity = self.v(f'xor i1 {self.v(f"trunc i8 {self.v(f"call i8 @llvm.ctpop.i8(i8 {low})")} to i1")}, true')
        self.preserve_flags_if_zero(count, {'cf': carry, 'of': overflow, 'zf': zero, 'sf': sign, 'pf': parity, 'af': 'false'})
        self.write(destination, result)

    def op_shld(self):
        self.double_shift(True)

    def op_shrd(self):
        self.double_shift(False)

    def op_imul(self):
        operands = self.operands()
        if len(operands) == 1:
            self.wide_multiply(True)
            return
        destination = operands[0]
        bits = destination.size * 8
        left = self.read(operands[0] if len(operands) == 2 else operands[1])
        right = self.read(operands[1] if len(operands) == 2 else operands[2], bits)
        wide = self.v(f'mul i{2 * bits} {self.sext(left, bits, 2 * bits)}, {self.sext(right, bits, 2 * bits)}')
        result = self.trunc(wide, bits, 2 * bits)
        overflow = self.v(f'icmp ne i{2 * bits} {self.sext(result, bits, 2 * bits)}, {wide}')
        self.set_flag('cf', overflow)
        self.set_flag('of', overflow)
        self.zf_sf_pf(result, bits)
        self.set_flag('af', 'false')
        self.write(destination, result)

    def accumulator(self, bits):
        return {8: ('al', 'ah'), 16: ('ax', 'dx'), 32: ('eax', 'edx'), 64: ('rax', 'rdx')}[bits]

    def wide_multiply(self, signed):
        source, = self.operands()
        bits = source.size * 8
        low_name, high_name = self.accumulator(bits)
        left, _ = self.read_register(low_name)
        right = self.read(source)
        extend = self.sext if signed else self.zext
        wide = self.v(f'mul i{2 * bits} {extend(left, bits, 2 * bits)}, {extend(right, bits, 2 * bits)}')
        low = self.trunc(wide, bits, 2 * bits)
        high = self.trunc(self.v(f'lshr i{2 * bits} {wide}, {bits}'), bits, 2 * bits)
        if bits == 8:
            self.write_register('ax', self.trunc(wide, 16, 16))
        else:
            self.write_register(low_name, low)
            self.write_register(high_name, high)
        if signed:
            overflow = self.v(f'icmp ne i{2 * bits} {self.sext(low, bits, 2 * bits)}, {wide}')
        else:
            overflow = self.v(f'icmp ne i{bits} {high}, 0')
        self.set_flag('cf', overflow)
        self.set_flag('of', overflow)
        self.zf_sf_pf(low, bits)
        self.set_flag('af', 'false')

    def op_mul(self):
        self.wide_multiply(False)

    def divide(self, signed):
        source, = self.operands()
        bits = source.size * 8
        wide = 2 * bits
        divisor = self.read(source)
        if bits == 8:
            dividend = self.trunc(self.get_gpr('rax'), 16)
        else:
            low_name, high_name = self.accumulator(bits)
            low = self.read_register(low_name)[0]
            high = self.read_register(high_name)[0]
            dividend = self.v(f'or i{wide} {self.v(f"shl i{wide} {self.zext(high, bits, wide)}, {bits}")}, {self.zext(low, bits, wide)}')
        self.trap_if(self.v(f'icmp eq i{bits} {divisor}, 0'), TRAP_DIVIDE)
        extend = self.sext if signed else self.zext
        wide_divisor = extend(divisor, bits, wide)
        if signed:
            minus_one = self.v(f'icmp eq i{wide} {wide_divisor}, -1')
            safe = self.v(f'select i1 {minus_one}, i{wide} 1, i{wide} {wide_divisor}')
            quotient = self.v(f'sdiv i{wide} {dividend}, {safe}')
            quotient = self.v(f'select i1 {minus_one}, i{wide} {self.v(f"sub i{wide} 0, {dividend}")}, i{wide} {quotient}')
            remainder = self.v(f'select i1 {minus_one}, i{wide} 0, i{wide} {self.v(f"srem i{wide} {dividend}, {safe}")}')
            narrow = self.trunc(quotient, bits, wide)
            overflow = self.v(f'icmp ne i{wide} {self.sext(narrow, bits, wide)}, {quotient}')
            overflow = self.v(f'or i1 {overflow}, {self.v(f"and i1 {minus_one}, {self.v(f"icmp eq i{wide} {dividend}, {self.const(1 << (wide - 1), wide)}")}")}')
        else:
            quotient = self.v(f'udiv i{wide} {dividend}, {wide_divisor}')
            remainder = self.v(f'urem i{wide} {dividend}, {wide_divisor}')
            narrow = self.trunc(quotient, bits, wide)
            overflow = self.v(f'icmp ne i{wide} {self.zext(narrow, bits, wide)}, {quotient}')
        self.trap_if(overflow, TRAP_DIVIDE, '1')
        rest = self.trunc(remainder, bits, wide)
        if bits == 8:
            combined = self.v(f'or i16 {self.v(f"shl i16 {self.zext(rest, 8, 16)}, 8")}, {self.zext(narrow, 8, 16)}')
            self.write_register('ax', combined)
        else:
            low_name, high_name = self.accumulator(bits)
            self.write_register(low_name, narrow)
            self.write_register(high_name, rest)

    def op_div(self):
        self.divide(False)

    def op_idiv(self):
        self.divide(True)

    def bit_operand(self):
        destination, source = self.operands()
        bits = destination.size * 8
        if destination.type == X86_OP_MEM and source.type == X86_OP_REG:
            offset = self.sext(self.read(source), bits)
            address = self.address(destination)
            element = self.v(f'ashr i64 {offset}, {6 if bits == 64 else 5 if bits == 32 else 4}')
            address = self.v(f'add i64 {address}, {self.v(f"mul i64 {element}, {bits // 8}")}')
            index = self.v(f'and i64 {offset}, {bits - 1}')
            return ('memory', address), bits, self.load(address, bits), self.trunc(index, bits)
        value = self.read(destination)
        index = self.read(source, bits) if source.type != X86_OP_IMM else self.const(source.imm, bits)
        index = self.v(f'and i{bits} {index}, {bits - 1}')
        return ('operand', destination), bits, value, index

    def bit_test(self, kind):
        where, bits, value, index = self.bit_operand()
        selected = self.v(f'shl i{bits} 1, {index}')
        self.set_flag('cf', self.v(f'icmp ne i{bits} {self.v(f"and i{bits} {value}, {selected}")}, 0'))
        if kind == 'test':
            return
        if kind == 'set':
            result = self.v(f'or i{bits} {value}, {selected}')
        elif kind == 'reset':
            result = self.v(f'and i{bits} {value}, {self.v(f"xor i{bits} {selected}, -1")}')
        else:
            result = self.v(f'xor i{bits} {value}, {selected}')
        if where[0] == 'memory':
            self.store(where[1], result, bits)
        else:
            self.write(where[1], result)

    def op_bt(self):
        self.bit_test('test')

    def op_bts(self):
        self.bit_test('set')

    def op_btr(self):
        self.bit_test('reset')

    def op_btc(self):
        self.bit_test('complement')

    def bit_scan(self, reverse):
        destination, source = self.operands()
        bits = destination.size * 8
        value = self.read(source)
        zero = self.v(f'icmp eq i{bits} {value}, 0')
        if reverse:
            count = self.v(f'call i{bits} @llvm.ctlz.i{bits}(i{bits} {value}, i1 false)')
            position = self.v(f'sub i{bits} {bits - 1}, {count}')
        else:
            position = self.v(f'call i{bits} @llvm.cttz.i{bits}(i{bits} {value}, i1 false)')
        self.set_flag('zf', zero)
        if destination.type == X86_OP_REG and bits == 32:
            full = ALIASES[self.ins.reg_name(destination.reg)][0]
            old = self.get_gpr(full)
            self.set_gpr(full, self.v(f'select i1 {zero}, i64 {old}, i64 {self.zext(position, 32)}'))
            return
        old = self.read(destination)
        self.write(destination, self.v(f'select i1 {zero}, i{bits} {old}, i{bits} {position}'))

    def op_bsf(self):
        self.bit_scan(False)

    def op_bsr(self):
        self.bit_scan(True)

    def count_bits(self, intrinsic):
        destination, source = self.operands()
        bits = destination.size * 8
        value = self.read(source)
        result = self.v(f'call i{bits} @llvm.{intrinsic}.i{bits}(i{bits} {value}, i1 false)')
        self.set_flag('cf', self.v(f'icmp eq i{bits} {value}, 0'))
        self.set_flag('zf', self.v(f'icmp eq i{bits} {result}, 0'))
        self.write(destination, result)

    def op_tzcnt(self):
        self.count_bits('cttz')

    def op_lzcnt(self):
        self.count_bits('ctlz')

    def op_popcnt(self):
        destination, source = self.operands()
        bits = destination.size * 8
        value = self.read(source)
        result = self.v(f'call i{bits} @llvm.ctpop.i{bits}(i{bits} {value})')
        for name in ('cf', 'of', 'sf', 'af', 'pf'):
            self.set_flag(name, 'false')
        self.set_flag('zf', self.v(f'icmp eq i{bits} {value}, 0'))
        self.write(destination, result)

    def op_andn(self):
        destination, first, second = self.operands()
        bits = destination.size * 8
        inverted = self.v(f'xor i{bits} {self.read(first)}, -1')
        result = self.v(f'and i{bits} {inverted}, {self.read(second)}')
        self.logic_flags(result, bits)
        self.write(destination, result)

    def bmi_shift(self, operation):
        destination, source, count = self.operands()
        bits = destination.size * 8
        amount = self.v(f'and i{bits} {self.read(count)}, {bits - 1}')
        self.write(destination, self.v(f'{operation} i{bits} {self.read(source)}, {amount}'))

    def op_shlx(self):
        self.bmi_shift('shl')

    def op_shrx(self):
        self.bmi_shift('lshr')

    def op_sarx(self):
        self.bmi_shift('ashr')

    def op_rorx(self):
        destination, source, count = self.operands()
        bits = destination.size * 8
        amount = self.const(count.imm & (bits - 1), bits)
        value = self.read(source)
        self.write(destination, self.v(f'call i{bits} @llvm.fshr.i{bits}(i{bits} {value}, i{bits} {value}, i{bits} {amount})'))

    def op_bzhi(self):
        destination, source, index_operand = self.operands()
        bits = destination.size * 8
        value = self.read(source)
        index = self.zext(self.trunc(self.read(index_operand), 8, bits), 8, bits)
        large = self.v(f'icmp uge i{bits} {index}, {bits}')
        safe = self.v(f'select i1 {large}, i{bits} 0, i{bits} {index}')
        kept = self.v(f'sub i{bits} {self.v(f"shl i{bits} 1, {safe}")}, 1')
        result = self.v(f'select i1 {large}, i{bits} {value}, i{bits} {self.v(f"and i{bits} {value}, {kept}")}')
        self.set_flag('cf', large)
        self.set_flag('of', 'false')
        self.zf_sf_pf(result, bits)
        self.write(destination, result)

    def op_mulx(self):
        high_operand, low_operand, source = self.operands()
        bits = high_operand.size * 8
        accumulator = self.read_register('rdx' if bits == 64 else 'edx')[0]
        wide = self.v(f'mul i{2 * bits} {self.zext(accumulator, bits, 2 * bits)}, {self.zext(self.read(source), bits, 2 * bits)}')
        self.write(low_operand, self.trunc(wide, bits, 2 * bits))
        self.write(high_operand, self.trunc(self.v(f'lshr i{2 * bits} {wide}, {bits}'), bits, 2 * bits))

    def blsx(self, kind):
        destination, source = self.operands()
        bits = destination.size * 8
        value = self.read(source)
        if kind == 'blsr':
            result = self.v(f'and i{bits} {value}, {self.v(f"sub i{bits} {value}, 1")}')
        elif kind == 'blsi':
            result = self.v(f'and i{bits} {value}, {self.v(f"sub i{bits} 0, {value}")}')
        else:
            result = self.v(f'xor i{bits} {value}, {self.v(f"sub i{bits} {value}, 1")}')
        self.set_flag('cf', self.v(f'icmp {"ne" if kind == "blsi" else "eq"} i{bits} {value}, 0'))
        self.set_flag('of', 'false')
        self.zf_sf_pf(result, bits)
        self.write(destination, result)

    def op_blsr(self):
        self.blsx('blsr')

    def op_blsi(self):
        self.blsx('blsi')

    def op_blsmsk(self):
        self.blsx('blsmsk')

    def aligned_atomic_pointer(self, operand, bits):
        address = self.address(operand)
        if bits > 8:
            misaligned = self.v(f'icmp ne i64 {self.v(f"and i64 {address}, {bits // 8 - 1}")}, 0')
            self.trap_if(misaligned, TRAP_SPLIT_LOCK)
        return self.pointer(address)

    def locked(self):
        mnemonic = base_mnemonic(self.ins)
        operands = self.operands()
        destination = operands[0]
        if destination.type != X86_OP_MEM:
            self.unsupported('lock prefix without a memory destination')
        bits = destination.size * 8
        if bits not in (8, 16, 32, 64):
            self.unsupported('locked operand width')
        pointer = self.aligned_atomic_pointer(destination, bits)
        if mnemonic == 'xchg':
            self.write(operands[1], self.v(f'atomicrmw xchg ptr {pointer}, i{bits} {self.read(operands[1], bits)} seq_cst, align {bits // 8}'))
            return
        if mnemonic == 'cmpxchg':
            self.compare_exchange(pointer, bits, operands[1])
            return
        if mnemonic not in ATOMIC:
            self.unsupported('locked operation semantics are not implemented')
        if mnemonic in ('inc', 'dec'):
            source = self.const(1, bits)
        elif operands[1].type == X86_OP_IMM:
            source = self.const(operands[1].imm, bits)
        else:
            source = self.read(operands[1], bits)
        old = self.v(f'atomicrmw {ATOMIC[mnemonic]} ptr {pointer}, i{bits} {source} seq_cst, align {bits // 8}')
        self.rmw_flags(mnemonic, old, source, bits)
        if mnemonic == 'xadd':
            self.write(operands[1], old)

    def rmw_flags(self, mnemonic, old, source, bits):
        if mnemonic in ('add', 'xadd'):
            self.add_flags(old, source, self.v(f'add i{bits} {old}, {source}'), bits)
        elif mnemonic == 'sub':
            self.sub_flags(old, source, self.v(f'sub i{bits} {old}, {source}'), bits)
        elif mnemonic in ('and', 'or', 'xor'):
            self.logic_flags(self.v(f'{mnemonic} i{bits} {old}, {source}'), bits)
        else:
            carry = self.flag('cf')
            result = self.v(f'{"add" if mnemonic == "inc" else "sub"} i{bits} {old}, {source}')
            if mnemonic == 'inc':
                self.add_flags(old, source, result, bits)
            else:
                self.sub_flags(old, source, result, bits)
            self.set_flag('cf', carry)

    def compare_exchange(self, pointer, bits, source, atomic=True):
        accumulator = self.accumulator(bits)[0]
        expected, _ = self.read_register(accumulator)
        replacement = self.read(source, bits)
        if atomic:
            pair = self.v(f'cmpxchg ptr {pointer}, i{bits} {expected}, i{bits} {replacement} seq_cst seq_cst, align {bits // 8}')
            old = self.v(f'extractvalue {{ i{bits}, i1 }} {pair}, 0')
            success = self.v(f'extractvalue {{ i{bits}, i1 }} {pair}, 1')
        else:
            old = self.load(self.v(f'ptrtoint ptr {pointer} to i64'), bits) if getattr(self, 'concurrent', False) else self.v(f'load volatile i{bits}, ptr {pointer}, align 1')
            success = self.v(f'icmp eq i{bits} {expected}, {old}')
            stored = self.v(f'select i1 {success}, i{bits} {replacement}, i{bits} {old}')
            if getattr(self, 'concurrent', False):
                self.store(self.v(f'ptrtoint ptr {pointer} to i64'), stored, bits)
            else:
                self.emit(f'store volatile i{bits} {stored}, ptr {pointer}, align 1')
        self.sub_flags(expected, old, self.v(f'sub i{bits} {expected}, {old}'), bits)
        failed, done = self.label(), self.label()
        self.emit(f'br i1 {success}, label %{done}, label %{failed}')
        self.place(failed)
        self.write_register(accumulator, old)
        self.emit(f'br label %{done}')
        self.place(done)

    def op_cmpxchg(self):
        destination, source = self.operands()
        bits = destination.size * 8
        if destination.type == X86_OP_MEM:
            self.compare_exchange(self.pointer(self.address(destination)), bits, source, atomic=False)
            return
        accumulator = self.accumulator(bits)[0]
        expected, _ = self.read_register(accumulator)
        current = self.read(destination)
        replacement = self.read(source, bits)
        equal = self.v(f'icmp eq i{bits} {expected}, {current}')
        self.sub_flags(expected, current, self.v(f'sub i{bits} {expected}, {current}'), bits)
        stored, failed, done = self.label(), self.label(), self.label()
        self.emit(f'br i1 {equal}, label %{stored}, label %{failed}')
        self.place(stored)
        self.write(destination, replacement)
        self.emit(f'br label %{done}')
        self.place(failed)
        self.write_register(accumulator, current)
        self.emit(f'br label %{done}')
        self.place(done)

    def op_xadd(self):
        destination, source = self.operands()
        bits = destination.size * 8
        old = self.read(destination)
        addend = self.read(source, bits)
        total = self.v(f'add i{bits} {old}, {addend}')
        self.add_flags(old, addend, total, bits)
        self.write(source, old)
        self.write(destination, total)

    def x87_index(self, depth):
        top = self.v(f'load i64, ptr {self.v(f"getelementptr i8, ptr %s, i64 {STATE_X87_TOP}")}')
        return self.v(f'and i64 {self.v(f"add i64 {top}, {depth}")}, 7')

    def x87_slot(self, depth, reading=True):
        index = self.x87_index(depth)
        if reading:
            tags = self.v(f'load i64, ptr {self.v(f"getelementptr i8, ptr %s, i64 {STATE_X87_VALID}")}')
            bit = self.v(f'shl i64 1, {index}')
            self.trap_if(self.v(f'icmp eq i64 {self.v(f"and i64 {tags}, {bit}")}, 0'), TRAP_UNSUPPORTED)
        return self.v(f'getelementptr i8, ptr %s, i64 {self.v(f"add i64 {STATE_X87}, {self.v(f"mul i64 {index}, 16")}")}')

    def x87_tag(self, depth, valid, require_empty=False):
        pointer = self.v(f'getelementptr i8, ptr %s, i64 {STATE_X87_VALID}')
        tags = self.v(f'load i64, ptr {pointer}')
        bit = self.v(f'shl i64 1, {self.x87_index(depth)}')
        if require_empty:
            self.trap_if(self.v(f'icmp ne i64 {self.v(f"and i64 {tags}, {bit}")}, 0'), TRAP_UNSUPPORTED)
        value = self.v(f'or i64 {tags}, {bit}') if valid else self.v(f'and i64 {tags}, {self.v(f"xor i64 {bit}, -1")}')
        self.emit(f'store i64 {value}, ptr {pointer}')

    def x87_move_top(self, delta):
        pointer = self.v(f'getelementptr i8, ptr %s, i64 {STATE_X87_TOP}')
        top = self.v(f'load i64, ptr {pointer}')
        self.emit(f'store i64 {self.v(f"and i64 {self.v(f"add i64 {top}, {delta & 7}")}, 7")}, ptr {pointer}')

    def x87_push(self, value):
        self.x87_move_top(-1)
        self.x87_tag(0, True, require_empty=True)
        self.emit(f'store i80 {value}, ptr {self.x87_slot(0)}, align 1')

    def x87_register(self, operand):
        name = self.ins.reg_name(operand.reg)
        if not name.startswith('st'):
            self.unsupported(f'x87 register {name}')
        return 0 if name == 'st(0)' else int(name[3:-1])

    def op_fld(self):
        source, = self.operands()
        if source.type == X86_OP_MEM:
            if source.size == 10:
                value = self.load(self.address(source), 80)
            elif source.size in (4, 8):
                value = self.widen_x87(self.load(self.address(source), source.size * 8), source.size * 8)
            else:
                self.unsupported('x87 load format')
        else:
            value = self.v(f'load i80, ptr {self.x87_slot(self.x87_register(source))}, align 1')
        self.x87_push(value)

    def widen_x87(self, raw, bits):
        control = self.v(f'load i64, ptr {self.v(f"getelementptr i8, ptr %s, i64 {STATE_X87_CONTROL}")}')
        self.trap_if(self.v(f'icmp ne i64 {self.v(f"and i64 {control}, 63")}, 63'), TRAP_UNSUPPORTED)
        fraction_bits, bias, exponent_max = (52, 1023, 2047) if bits == 64 else (23, 127, 255)
        raw = self.zext(raw, bits, 64)
        fraction = self.v(f'and i64 {raw}, {(1 << fraction_bits) - 1}')
        exponent = self.v(f'and i64 {self.v(f"lshr i64 {raw}, {fraction_bits}")}, {exponent_max}')
        normal_sig = self.v(f'or i64 {self.v(f"shl i64 {fraction}, {63 - fraction_bits}")}, 9223372036854775808')
        zero_fraction = self.v(f'icmp eq i64 {fraction}, 0')
        leading = self.v(f'call i64 @llvm.ctlz.i64(i64 {fraction}, i1 false)')
        shift = self.v(f'select i1 {zero_fraction}, i64 0, i64 {leading}')
        sub_sig = self.v(f'shl i64 {fraction}, {shift}')
        sub_exp = self.v(f'sub i64 {16447 - bias - fraction_bits}, {leading}')
        sub_exp = self.v(f'select i1 {zero_fraction}, i64 0, i64 {sub_exp}')
        special_sig = self.v(f'or i64 {normal_sig}, {self.v(f"select i1 {zero_fraction}, i64 0, i64 4611686018427387904")}')
        special = self.v(f'icmp eq i64 {exponent}, {exponent_max}')
        zero_exp = self.v(f'icmp eq i64 {exponent}, 0')
        sig = self.v(f'select i1 {zero_exp}, i64 {sub_sig}, i64 {normal_sig}')
        sig = self.v(f'select i1 {special}, i64 {special_sig}, i64 {sig}')
        exp = self.v(f'select i1 {zero_exp}, i64 {sub_exp}, i64 {self.v(f"add i64 {exponent}, {16383 - bias}")}')
        exp = self.v(f'select i1 {special}, i64 32767, i64 {exp}')
        sign = self.v(f'lshr i64 {raw}, {bits - 1}')
        sign_exp = self.v(f'or i64 {exp}, {self.v(f"shl i64 {sign}, 15")}')
        high = self.v(f'shl i80 {self.v(f"zext i64 {sign_exp} to i80")}, 64')
        return self.v(f'or i80 {high}, {self.v(f"zext i64 {sig} to i80")}')

    def op_fnstcw(self):
        destination, = self.operands()
        value = self.v(f'load i64, ptr {self.v(f"getelementptr i8, ptr %s, i64 {STATE_X87_CONTROL}")}')
        self.write(destination, self.trunc(value, 16), 16)

    def op_fldz(self):
        self.x87_push('0')

    def op_fstp(self):
        destination, = self.operands()
        value = self.v(f'load i80, ptr {self.x87_slot(0)}, align 1')
        if destination.type == X86_OP_MEM:
            if destination.size != 10:
                self.unsupported('x87 store with format conversion')
            self.store(self.address(destination), value, 80)
        else:
            depth = self.x87_register(destination)
            self.x87_tag(depth, True)
            self.emit(f'store i80 {value}, ptr {self.x87_slot(depth)}, align 1')
        self.x87_tag(0, False)
        self.x87_move_top(1)

    def op_cpuid(self):
        self.flush()
        self.emit('call void @NativeAotGuestCpuid(ptr %s)')
        self.reload()

    def op_rdtsc(self):
        value = self.v('call i64 @NativeAotGuestReadTsc()')
        self.write_register('eax', self.trunc(value, 32))
        self.write_register('edx', self.trunc(self.v(f'lshr i64 {value}, 32'), 32))

    def op_pushfq(self):
        value = '514'
        for name, bit in (('cf', 0), ('pf', 2), ('af', 4), ('zf', 6), ('sf', 7), ('of', 11)):
            value = self.v(f'or i64 {value}, {self.v(f"shl i64 {self.zext(self.flag(name), 1)}, {bit}")}')
        rsp = self.v(f'sub i64 {self.get_gpr("rsp")}, 8')
        self.store(rsp, value, 64)
        self.set_gpr('rsp', rsp)

    def op_popfq(self):
        rsp = self.get_gpr('rsp')
        value = self.load(rsp, 64)
        self.set_gpr('rsp', self.v(f'add i64 {rsp}, 8'))
        control = self.v(f'and i64 {value}, {(1 << 8) | (1 << 10) | (1 << 18)}')
        self.trap_if(self.v(f'icmp ne i64 {control}, 0'), TRAP_UNSUPPORTED, control)
        for name, bit in (('cf', 0), ('pf', 2), ('af', 4), ('zf', 6), ('sf', 7), ('of', 11)):
            self.set_flag(name, self.v(f'trunc i64 {self.v(f"lshr i64 {value}, {bit}")} to i1'))

    def op_cmc(self):
        self.set_flag('cf', self.v(f'xor i1 {self.flag("cf")}, true'))

    def op_clc(self):
        self.set_flag('cf', 'false')

    def op_stc(self):
        self.set_flag('cf', 'true')

    def op_cld(self):
        pass

    def op_lahf(self):
        value = '2'
        for name, bit in (('cf', 0), ('pf', 2), ('af', 4), ('zf', 6), ('sf', 7)):
            value = self.v(f'or i8 {value}, {self.v(f"shl i8 {self.zext(self.flag(name), 1, 8)}, {bit}")}')
        self.write_register('ah', value)

    def op_sahf(self):
        value, _ = self.read_register('ah')
        for name, bit in (('cf', 0), ('pf', 2), ('af', 4), ('zf', 6), ('sf', 7)):
            self.set_flag(name, self.v(f'trunc i8 {self.v(f"lshr i8 {value}, {bit}")} to i1'))

    def string_operation(self, kind, bits):
        prefix = self.ins.prefix
        repeat = 0xf3 in prefix or 0xf2 in prefix
        step = bits // 8
        head, body, done = self.label(), self.label(), self.label()
        self.emit(f'br label %{head}')
        self.place(head)
        if repeat:
            count = self.get_gpr('rcx')
            self.emit(f'br i1 {self.v(f"icmp eq i64 {count}, 0")}, label %{done}, label %{body}')
        else:
            self.emit(f'br label %{body}')
        self.place(body)
        destination = self.get_gpr('rdi')
        if kind == 'movs':
            source = self.get_gpr('rsi')
            self.store(destination, self.load(source, bits), bits)
            self.set_gpr('rsi', self.v(f'add i64 {source}, {step}'))
        else:
            value, _ = self.read_register(self.accumulator(bits)[0])
            self.store(destination, value, bits)
        self.set_gpr('rdi', self.v(f'add i64 {destination}, {step}'))
        if repeat:
            self.set_gpr('rcx', self.v(f'sub i64 {self.get_gpr("rcx")}, 1'))
            self.emit(f'br label %{head}')
        else:
            self.emit(f'br label %{done}')
        self.place(done)

    def string(self):
        mnemonic = self.ins.mnemonic.split()[-1]
        widths = {'movsb': 8, 'movsw': 16, 'movsd': 32, 'movsq': 64, 'stosb': 8, 'stosw': 16, 'stosd': 32, 'stosq': 64}
        if mnemonic not in widths:
            self.unsupported('string operation')
        if 0xf2 in self.ins.prefix:
            self.unsupported('repne string move')
        self.string_operation(mnemonic[:4], widths[mnemonic])


LANES = {'b': (16, 8), 'w': (8, 16), 'd': (4, 32), 'q': (2, 64)}
FLOAT = {'ss': ('float', 32, 1), 'sd': ('double', 64, 1), 'ps': ('float', 32, 4), 'pd': ('double', 64, 2)}
INDEFINITE = {32: 0xffc00000, 64: 0xfff8000000000000}


class Vector(Integer):
    def vex_register(self, operand):
        if operand.type != X86_OP_REG:
            self.unsupported('VEX destination must be a vector register')
        name = self.ins.reg_name(operand.reg)
        if not name.startswith(('xmm', 'ymm')) or int(name[3:]) >= 16:
            self.unsupported(f'unsupported VEX register {name}')
        return int(name[3:]), 256 if name.startswith('ymm') else 128

    def vex_read(self, operand, bits, aligned=False):
        if operand.type == X86_OP_MEM:
            address = self.address(operand)
            if aligned:
                self.trap_if(self.v(f'icmp ne i64 {self.v(f"and i64 {address}, {bits // 8 - 1}")}, 0'), TRAP_ALIGNMENT)
            return self.load(address, bits)
        index, width = self.vex_register(operand)
        if width != bits:
            self.unsupported('VEX source width mismatch')
        low = self.get_xmm(index)
        if bits == 128:
            return low
        high = self.v(f'load i128, ptr %Y{index}')
        return self.v(f'or i256 {self.zext(low, 128, 256)}, {self.v(f"shl i256 {self.zext(high, 128, 256)}, 128")}')

    def vex_write(self, operand, value, bits, aligned=False):
        if operand.type == X86_OP_MEM:
            address = self.address(operand)
            if aligned:
                self.trap_if(self.v(f'icmp ne i64 {self.v(f"and i64 {address}, {bits // 8 - 1}")}, 0'), TRAP_ALIGNMENT)
            self.store(address, value, bits)
            return
        index, width = self.vex_register(operand)
        if width != bits:
            self.unsupported('VEX destination width mismatch')
        self.set_xmm(index, self.trunc(value, 128, bits))
        upper = '0' if bits == 128 else self.trunc(self.v(f'lshr i256 {value}, 128'), 128, 256)
        self.set_ymm_upper(index, upper)

    def vex_move(self, aligned):
        destination, source = self.operands()
        register = source if destination.type == X86_OP_MEM else destination
        _, bits = self.vex_register(register)
        self.vex_write(destination, self.vex_read(source, bits, aligned), bits, aligned)

    def op_vmovups(self):
        self.vex_move(False)

    op_vmovupd = op_vmovups
    op_vmovdqu = op_vmovups

    def op_vmovdqa(self):
        self.vex_move(True)

    op_vmovaps = op_vmovdqa
    op_vmovapd = op_vmovdqa

    def op_vmovd(self):
        destination, source = self.operands()
        bits = 32 if self.ins.mnemonic == 'vmovd' else 64
        if self.is_xmm(destination):
            value = self.low(source, bits) if self.is_xmm(source) else self.read(source, bits)
            self.vex_write(destination, self.zext(value, bits, 128), 128)
        else:
            self.write(destination, self.trunc(self.vex_read(source, 128), bits, 128), bits)

    op_vmovq = op_vmovd

    def vex_logic(self, operation):
        destination, left, right = self.operands()
        _, bits = self.vex_register(destination)
        a, b = self.vex_read(left, bits), self.vex_read(right, bits)
        self.vex_write(destination, self.v(f'{operation} i{bits} {a}, {b}'), bits)

    def op_vpand(self):
        self.vex_logic('and')

    def op_vpor(self):
        self.vex_logic('or')

    def op_vxorps(self):
        self.vex_logic('xor')

    op_vxorpd = op_vxorps
    op_vpxor = op_vxorps
    op_vandps = op_vpand
    op_vandpd = op_vpand
    op_vorps = op_vpor
    op_vorpd = op_vpor

    def op_vpbroadcastd(self):
        destination, source = self.operands()
        _, bits = self.vex_register(destination)
        value = self.low(source, 32)
        lanes = bits // 32
        vector = self.v(f'insertelement <{lanes} x i32> poison, i32 {value}, i32 0')
        result = self.v(f'shufflevector <{lanes} x i32> {vector}, <{lanes} x i32> poison, <{lanes} x i32> zeroinitializer')
        self.vex_write(destination, self.v(f'bitcast <{lanes} x i32> {result} to i{bits}'), bits)

    def op_vpsllvd(self):
        destination, source, counts = self.operands()
        _, bits = self.vex_register(destination)
        lanes = bits // 32
        kind = f'<{lanes} x i32>'
        data = self.v(f'bitcast i{bits} {self.vex_read(source, bits)} to {kind}')
        shift = self.v(f'bitcast i{bits} {self.vex_read(counts, bits)} to {kind}')
        maximum = '<' + ', '.join('i32 31' for _ in range(lanes)) + '>'
        safe = self.v(f'and {kind} {shift}, {maximum}')
        result = self.v(f'shl {kind} {data}, {safe}')
        valid = self.v(f'icmp ule {kind} {shift}, {maximum}')
        result = self.v(f'select <{lanes} x i1> {valid}, {kind} {result}, {kind} zeroinitializer')
        self.vex_write(destination, self.v(f'bitcast {kind} {result} to i{bits}'), bits)

    def op_vpshufd(self):
        destination, source, immediate = self.operands()
        if immediate.type != X86_OP_IMM:
            self.unsupported('VPSHUFD requires an immediate')
        _, bits = self.vex_register(destination)
        lanes = bits // 32
        vector = self.v(f'bitcast i{bits} {self.vex_read(source, bits)} to <{lanes} x i32>')
        mask_value = '<' + ', '.join(f'i32 {(index // 4) * 4 + ((immediate.imm >> (2 * (index % 4))) & 3)}' for index in range(lanes)) + '>'
        result = self.v(f'shufflevector <{lanes} x i32> {vector}, <{lanes} x i32> poison, <{lanes} x i32> {mask_value}')
        self.vex_write(destination, self.v(f'bitcast <{lanes} x i32> {result} to i{bits}'), bits)

    def op_vzeroupper(self):
        for index in range(16):
            self.set_ymm_upper(index, '0')

    def set_ymm_upper(self, index, value):
        self.emit(f'store i128 {value}, ptr %Y{index}')

    def xmm_index(self, operand):
        name = self.ins.reg_name(operand.reg)
        if not name.startswith('xmm'):
            self.unsupported(f'vector register {name}')
        return int(name[3:])

    def get_xmm(self, index):
        return self.v(f'load i128, ptr %X{index}')

    def set_xmm(self, index, value):
        self.emit(f'store i128 {value}, ptr %X{index}')

    def is_xmm(self, operand):
        return operand.type == X86_OP_REG and self.ins.reg_name(operand.reg).startswith('xmm')

    def read128(self, operand, aligned=False):
        if self.is_xmm(operand):
            return self.get_xmm(self.xmm_index(operand))
        if operand.type != X86_OP_MEM:
            self.unsupported('vector source')
        address = self.address(operand)
        if aligned:
            self.check_alignment(address)
        return self.load(address, 128)

    def check_alignment(self, address):
        self.trap_if(self.v(f'icmp ne i64 {self.v(f"and i64 {address}, 15")}, 0'), TRAP_ALIGNMENT)

    def write128(self, operand, value, aligned=False):
        if self.is_xmm(operand):
            self.set_xmm(self.xmm_index(operand), value)
            return
        address = self.address(operand)
        if aligned:
            self.check_alignment(address)
        self.store(address, value, 128)

    def low(self, operand, bits):
        if self.is_xmm(operand):
            return self.trunc(self.get_xmm(self.xmm_index(operand)), bits, 128)
        if operand.type == X86_OP_MEM:
            return self.load(self.address(operand), bits)
        return self.read(operand, bits)

    def lanes(self, value, kind):
        count, bits = LANES[kind]
        return self.v(f'bitcast i128 {value} to <{count} x i{bits}>'), f'<{count} x i{bits}>'

    def unlanes(self, value, kind):
        count, bits = LANES[kind]
        return self.v(f'bitcast <{count} x i{bits}> {value} to i128')

    def merge_low(self, destination_value, low_value, bits):
        upper = self.v(f'and i128 {destination_value}, {self.const(~mask(bits), 128)}')
        return self.v(f'or i128 {upper}, {self.zext(low_value, bits, 128)}')

    def destination_source(self):
        destination, source = self.operands()[:2]
        if not self.is_xmm(destination):
            self.unsupported('vector destination')
        return self.xmm_index(destination), destination, source

    def move128(self, aligned):
        destination, source = self.operands()
        self.write128(destination, self.read128(source, aligned), aligned)

    def op_movups(self):
        self.move128(False)

    op_movupd = op_movups
    op_movdqu = op_movups
    op_lddqu = op_movups

    def op_movaps(self):
        self.move128(True)

    op_movapd = op_movaps
    op_movdqa = op_movaps

    def move_scalar(self, bits):
        destination, source = self.operands()
        if self.is_xmm(destination) and self.is_xmm(source):
            index = self.xmm_index(destination)
            self.set_xmm(index, self.merge_low(self.get_xmm(index), self.low(source, bits), bits))
        elif self.is_xmm(destination):
            self.set_xmm(self.xmm_index(destination), self.zext(self.low(source, bits), bits, 128))
        else:
            self.store(self.address(destination), self.low(source, bits), bits)

    def op_movd(self):
        destination, source = self.operands()
        bits = 32 if self.ins.mnemonic == 'movd' else 64
        if self.is_xmm(destination):
            value = self.low(source, bits) if self.is_xmm(source) else self.read(source, bits)
            self.set_xmm(self.xmm_index(destination), self.zext(value, bits, 128))
        else:
            self.write(destination, self.low(source, bits), bits)

    op_movq = op_movd

    def op_movss(self):
        self.move_scalar(32)

    def op_movsd(self):
        if not any(self.is_xmm(operand) for operand in self.operands()):
            self.string()
            return
        self.move_scalar(64)

    def half_move(self, high):
        destination, source = self.operands()
        if self.is_xmm(destination):
            index = self.xmm_index(destination)
            old = self.get_xmm(index)
            value = self.zext(self.low(source, 64), 64, 128)
            if high:
                keep = self.v(f'and i128 {old}, {mask(64)}')
                self.set_xmm(index, self.v(f'or i128 {keep}, {self.v(f"shl i128 {value}, 64")}'))
            else:
                self.set_xmm(index, self.merge_low(old, self.trunc(value, 64, 128), 64))
        else:
            value = self.get_xmm(self.xmm_index(source))
            if high:
                value = self.v(f'lshr i128 {value}, 64')
            self.store(self.address(destination), self.trunc(value, 64, 128), 64)

    def op_movlps(self):
        self.half_move(False)

    op_movlpd = op_movlps

    def op_movhps(self):
        self.half_move(True)

    op_movhpd = op_movhps

    def op_movhlps(self):
        index, _, source = self.destination_source()
        high = self.trunc(self.v(f'lshr i128 {self.get_xmm(self.xmm_index(source))}, 64'), 64, 128)
        self.set_xmm(index, self.merge_low(self.get_xmm(index), high, 64))

    def op_movlhps(self):
        index, _, source = self.destination_source()
        low = self.zext(self.low(source, 64), 64, 128)
        keep = self.v(f'and i128 {self.get_xmm(index)}, {mask(64)}')
        self.set_xmm(index, self.v(f'or i128 {keep}, {self.v(f"shl i128 {low}, 64")}'))

    def bitwise(self, operation, invert=False):
        index, _, source = self.destination_source()
        left = self.get_xmm(index)
        if invert:
            left = self.v(f'xor i128 {left}, -1')
        self.set_xmm(index, self.v(f'{operation} i128 {left}, {self.read128(source, self.aligned_source())}'))

    def aligned_source(self):
        return not self.ins.mnemonic.startswith('v')

    def op_pxor(self):
        destination, source = self.operands()
        if self.is_xmm(source) and self.xmm_index(source) == self.xmm_index(destination):
            self.set_xmm(self.xmm_index(destination), '0')
            return
        self.bitwise('xor')

    op_xorps = op_pxor
    op_xorpd = op_pxor

    def op_pand(self):
        self.bitwise('and')

    op_andps = op_pand
    op_andpd = op_pand

    def op_pandn(self):
        self.bitwise('and', True)

    op_andnps = op_pandn
    op_andnpd = op_pandn

    def op_por(self):
        self.bitwise('or')

    op_orps = op_por
    op_orpd = op_por

    def lane_binary(self, kind, operation):
        index, _, source = self.destination_source()
        left, vector = self.lanes(self.get_xmm(index), kind)
        right, _ = self.lanes(self.read128(source, True), kind)
        self.set_xmm(index, self.unlanes(self.v(f'{operation} {vector} {left}, {right}'), kind))

    def lane_intrinsic(self, kind, intrinsic):
        index, _, source = self.destination_source()
        left, vector = self.lanes(self.get_xmm(index), kind)
        right, _ = self.lanes(self.read128(source, True), kind)
        count, bits = LANES[kind]
        name = f'@llvm.{intrinsic}.v{count}i{bits}'
        self.set_xmm(index, self.unlanes(self.v(f'call {vector} {name}({vector} {left}, {vector} {right})'), kind))

    def lane_compare(self, kind, predicate):
        index, _, source = self.destination_source()
        left, vector = self.lanes(self.get_xmm(index), kind)
        right, _ = self.lanes(self.read128(source, True), kind)
        count, bits = LANES[kind]
        compared = self.v(f'icmp {predicate} {vector} {left}, {right}')
        self.set_xmm(index, self.unlanes(self.v(f'sext <{count} x i1> {compared} to {vector}'), kind))

    def op_pmuludq(self):
        index, _, source = self.destination_source()
        left, _ = self.lanes(self.get_xmm(index), 'q')
        right, _ = self.lanes(self.read128(source, True), 'q')
        low = self.const(mask(32), 64)
        a = self.v(f'and <2 x i64> {left}, <i64 {low}, i64 {low}>')
        b = self.v(f'and <2 x i64> {right}, <i64 {low}, i64 {low}>')
        self.set_xmm(index, self.unlanes(self.v(f'mul <2 x i64> {a}, {b}'), 'q'))

    def op_pmovmskb(self):
        destination, source = self.operands()
        value, _ = self.lanes(self.get_xmm(self.xmm_index(source)), 'b')
        signs = self.v(f'icmp slt <16 x i8> {value}, zeroinitializer')
        bits = self.v(f'bitcast <16 x i1> {signs} to i16')
        self.write(destination, self.zext(bits, 16, destination.size * 8))

    def float_mask(self, kind):
        destination, source = self.operands()
        count, bits = (4, 32) if kind == 'ps' else (2, 64)
        value = self.v(f'bitcast i128 {self.get_xmm(self.xmm_index(source))} to <{count} x i{bits}>')
        signs = self.v(f'icmp slt <{count} x i{bits}> {value}, zeroinitializer')
        packed = self.v(f'bitcast <{count} x i1> {signs} to i{count}')
        self.write(destination, self.zext(packed, count, destination.size * 8))

    def op_movmskps(self):
        self.float_mask('ps')

    def op_movmskpd(self):
        self.float_mask('pd')

    def shuffle_words(self, kind):
        destination, source, immediate = self.operands()
        value = self.read128(source, True)
        selector = immediate.imm & 0xff
        if kind == 'd':
            vector, _ = self.lanes(value, 'd')
            order = [selector >> (2 * i) & 3 for i in range(4)]
            shuffled = self.v(f'shufflevector <4 x i32> {vector}, <4 x i32> poison, <4 x i32> <{", ".join(f"i32 {x}" for x in order)}>')
            self.set_xmm(self.xmm_index(destination), self.unlanes(shuffled, 'd'))
            return
        vector, _ = self.lanes(value, 'w')
        offset = 0 if kind == 'lw' else 4
        order = list(range(8))
        for i in range(4):
            order[offset + i] = offset + (selector >> (2 * i) & 3)
        shuffled = self.v(f'shufflevector <8 x i16> {vector}, <8 x i16> poison, <8 x i32> <{", ".join(f"i32 {x}" for x in order)}>')
        self.set_xmm(self.xmm_index(destination), self.unlanes(shuffled, 'w'))

    def op_pshufd(self):
        self.shuffle_words('d')

    def op_pshuflw(self):
        self.shuffle_words('lw')

    def op_pshufhw(self):
        self.shuffle_words('hw')

    def op_shufps(self):
        index, _, source = self.destination_source()
        selector = self.operands()[2].imm & 0xff
        left, _ = self.lanes(self.get_xmm(index), 'd')
        right, _ = self.lanes(self.read128(source, True), 'd')
        order = [selector & 3, selector >> 2 & 3, 4 + (selector >> 4 & 3), 4 + (selector >> 6 & 3)]
        shuffled = self.v(f'shufflevector <4 x i32> {left}, <4 x i32> {right}, <4 x i32> <{", ".join(f"i32 {x}" for x in order)}>')
        self.set_xmm(index, self.unlanes(shuffled, 'd'))

    def op_shufpd(self):
        index, _, source = self.destination_source()
        selector = self.operands()[2].imm & 0xff
        left, _ = self.lanes(self.get_xmm(index), 'q')
        right, _ = self.lanes(self.read128(source, True), 'q')
        order = [selector & 1, 2 + (selector >> 1 & 1)]
        shuffled = self.v(f'shufflevector <2 x i64> {left}, <2 x i64> {right}, <2 x i32> <i32 {order[0]}, i32 {order[1]}>')
        self.set_xmm(index, self.unlanes(shuffled, 'q'))

    def unpack(self, kind, high):
        index, _, source = self.destination_source()
        count, _ = LANES[kind]
        left, vector = self.lanes(self.get_xmm(index), kind)
        right, _ = self.lanes(self.read128(source, True), kind)
        start = count // 2 if high else 0
        order = []
        for i in range(count // 2):
            order += [start + i, count + start + i]
        shuffled = self.v(f'shufflevector {vector} {left}, {vector} {right}, <{count} x i32> <{", ".join(f"i32 {x}" for x in order)}>')
        self.set_xmm(index, self.unlanes(shuffled, kind))

    def pack(self, source_kind, target_bits, signed):
        index, _, source = self.destination_source()
        count, bits = LANES[source_kind]
        left, vector = self.lanes(self.get_xmm(index), source_kind)
        right, _ = self.lanes(self.read128(source, True), source_kind)
        joined = self.v(f'shufflevector {vector} {left}, {vector} {right}, <{2 * count} x i32> <{", ".join(f"i32 {x}" for x in range(2 * count))}>')
        wide = f'<{2 * count} x i{bits}>'
        if signed:
            low, high = -(1 << (target_bits - 1)), (1 << (target_bits - 1)) - 1
        else:
            low, high = 0, (1 << target_bits) - 1
        splat = lambda value: f'<{", ".join(f"i{bits} {value}" for _ in range(2 * count))}>'
        clamped = self.v(f'call {wide} @llvm.smax.v{2 * count}i{bits}({wide} {joined}, {wide} {splat(low)})')
        clamped = self.v(f'call {wide} @llvm.smin.v{2 * count}i{bits}({wide} {clamped}, {wide} {splat(high)})')
        narrow = self.v(f'trunc {wide} {clamped} to <{2 * count} x i{target_bits}>')
        self.set_xmm(index, self.v(f'bitcast <{2 * count} x i{target_bits}> {narrow} to i128'))

    def op_packuswb(self):
        self.pack('w', 8, False)

    def op_packsswb(self):
        self.pack('w', 8, True)

    def op_packssdw(self):
        self.pack('d', 16, True)

    def op_packusdw(self):
        self.pack('d', 16, False)

    def lane_shift(self, kind, operation):
        destination, source = self.operands()
        index = self.xmm_index(destination)
        count, bits = LANES[kind]
        vector, vtype = self.lanes(self.get_xmm(index), kind)
        amount = self.const(source.imm & 0xff, 64) if source.type == X86_OP_IMM else self.low(source, 64)
        large = self.v(f'icmp ugt i64 {amount}, {bits - 1}')
        effective = self.v(f'select i1 {large}, i64 {bits - 1 if operation == "ashr" else 0}, i64 {amount}')
        effective = self.trunc(effective, bits)
        splat = self.v(f'insertelement {vtype} poison, i{bits} {effective}, i32 0')
        splat = self.v(f'shufflevector {vtype} {splat}, {vtype} poison, <{count} x i32> zeroinitializer')
        shifted = self.v(f'{operation} {vtype} {vector}, {splat}')
        if operation != 'ashr':
            shifted = self.v(f'select i1 {large}, {vtype} zeroinitializer, {vtype} {shifted}')
        self.set_xmm(index, self.unlanes(shifted, kind))

    def byte_shift(self, left):
        destination, immediate = self.operands()
        index = self.xmm_index(destination)
        amount = immediate.imm & 0xff
        if amount > 15:
            self.set_xmm(index, '0')
            return
        self.set_xmm(index, self.v(f'{"shl" if left else "lshr"} i128 {self.get_xmm(index)}, {8 * amount}'))

    def op_pslldq(self):
        self.byte_shift(True)

    def op_psrldq(self):
        self.byte_shift(False)

    def op_pinsrw(self):
        destination, source, immediate = self.operands()
        index = self.xmm_index(destination)
        value = self.read(source, 16) if source.type == X86_OP_MEM else self.trunc(self.read(source, 32), 16, 32)
        vector, _ = self.lanes(self.get_xmm(index), 'w')
        inserted = self.v(f'insertelement <8 x i16> {vector}, i16 {value}, i32 {immediate.imm & 7}')
        self.set_xmm(index, self.unlanes(inserted, 'w'))

    def op_pextrw(self):
        destination, source, immediate = self.operands()
        vector, _ = self.lanes(self.get_xmm(self.xmm_index(source)), 'w')
        value = self.v(f'extractelement <8 x i16> {vector}, i32 {immediate.imm & 7}')
        self.write(destination, self.zext(value, 16, destination.size * 8))

    def float_vector(self, value, kind):
        name, bits, count = FLOAT[kind]
        if count == 1:
            return self.v(f'bitcast i{bits} {self.trunc(value, bits, 128)} to {name}'), name
        vtype = f'<{count} x {name}>'
        return self.v(f'bitcast i128 {value} to {vtype}'), vtype

    def float_source(self, source, kind):
        name, bits, count = FLOAT[kind]
        if count == 1:
            raw = self.low(source, bits)
            return self.v(f'bitcast i{bits} {raw} to {name}'), name
        return self.float_vector(self.read128(source, True), kind)

    def float_store(self, index, value, kind, vtype):
        name, bits, count = FLOAT[kind]
        if count == 1:
            raw = self.v(f'bitcast {name} {value} to i{bits}')
            self.set_xmm(index, self.merge_low(self.get_xmm(index), raw, bits))
        else:
            self.set_xmm(index, self.v(f'bitcast {vtype} {value} to i128'))

    def quiet(self, value, vtype, kind):
        name, bits, count = FLOAT[kind]
        itype = f'<{count} x i{bits}>' if count > 1 else f'i{bits}'
        raw = self.v(f'bitcast {vtype} {value} to {itype}')
        bit = 1 << (22 if bits == 32 else 51)
        constant = f'<{", ".join(f"i{bits} {bit}" for _ in range(count))}>' if count > 1 else str(bit)
        return self.v(f'bitcast {itype} {self.v(f"or {itype} {raw}, {constant}")} to {vtype}')

    def x86_nan(self, left, right, result, vtype, kind, unary=False):
        name, bits, count = FLOAT[kind]
        itype = f'<{count} x i{bits}>' if count > 1 else f'i{bits}'
        boolean = f'<{count} x i1>' if count > 1 else 'i1'
        indefinite_bits = f'<{", ".join(f"i{bits} {INDEFINITE[bits]}" for _ in range(count))}>' if count > 1 else str(INDEFINITE[bits])
        indefinite = self.v(f'bitcast {itype} {indefinite_bits} to {vtype}')
        output = self.v(f'select {boolean} {self.v(f"fcmp uno {vtype} {result}, {result}")}, {vtype} {indefinite}, {vtype} {result}')
        if not unary:
            right_nan = self.v(f'fcmp uno {vtype} {right}, {right}')
            output = self.v(f'select {boolean} {right_nan}, {vtype} {self.quiet(right, vtype, kind)}, {vtype} {output}')
        left_nan = self.v(f'fcmp uno {vtype} {left}, {left}')
        return self.v(f'select {boolean} {left_nan}, {vtype} {self.quiet(left, vtype, kind)}, {vtype} {output}')

    def float_binary(self, operation, kind):
        index, _, source = self.destination_source()
        left, vtype = self.float_vector(self.get_xmm(index), kind)
        right, _ = self.float_source(source, kind)
        result = self.v(f'{operation} {vtype} {left}, {right}')
        self.float_store(index, self.x86_nan(left, right, result, vtype, kind), kind, vtype)

    def float_extreme(self, kind, minimum):
        index, _, source = self.destination_source()
        name, bits, count = FLOAT[kind]
        left, vtype = self.float_vector(self.get_xmm(index), kind)
        right, _ = self.float_source(source, kind)
        boolean = f'<{count} x i1>' if count > 1 else 'i1'
        chosen = self.v(f'fcmp {"olt" if minimum else "ogt"} {vtype} {left}, {right}')
        self.float_store(index, self.v(f'select {boolean} {chosen}, {vtype} {left}, {vtype} {right}'), kind, vtype)

    def float_sqrt(self, kind):
        index, _, source = self.destination_source()
        name, bits, count = FLOAT[kind]
        value, vtype = self.float_source(source, kind)
        suffix = f'v{count}f{bits}' if count > 1 else f'f{bits}'
        result = self.v(f'call {vtype} @llvm.sqrt.{suffix}({vtype} {value})')
        self.float_store(index, self.x86_nan(value, value, result, vtype, kind, True), kind, vtype)

    def compare_flags(self, kind):
        destination, source = self.operands()
        name, bits, _ = FLOAT[kind]
        left = self.v(f'bitcast i{bits} {self.low(destination, bits)} to {name}')
        right, _ = self.float_source(source, kind)
        unordered = self.v(f'fcmp uno {name} {left}, {right}')
        less = self.v(f'fcmp ult {name} {left}, {right}')
        equal = self.v(f'fcmp ueq {name} {left}, {right}')
        self.set_flag('zf', equal)
        self.set_flag('pf', unordered)
        self.set_flag('cf', less)
        for flag in ('of', 'sf', 'af'):
            self.set_flag(flag, 'false')

    def op_ucomisd(self):
        self.compare_flags('sd')

    op_comisd = op_ucomisd

    def op_ucomiss(self):
        self.compare_flags('ss')

    op_comiss = op_ucomiss

    def compare_mask(self, kind, predicate_index):
        index, _, source = self.destination_source()
        name, bits, count = FLOAT[kind]
        left, vtype = self.float_vector(self.get_xmm(index), kind)
        right, _ = self.float_source(source, kind)
        predicate = ['oeq', 'olt', 'ole', 'uno', 'une', 'uge', 'ugt', 'ord'][predicate_index]
        result = self.v(f'fcmp {predicate} {vtype} {left}, {right}')
        itype = f'<{count} x i{bits}>' if count > 1 else f'i{bits}'
        widened = self.v(f'sext {"<%d x i1>" % count if count > 1 else "i1"} {result} to {itype}')
        if count == 1:
            self.set_xmm(index, self.merge_low(self.get_xmm(index), widened, bits))
        else:
            self.set_xmm(index, self.v(f'bitcast {itype} {widened} to i128'))

    def float_to_integer(self, kind, truncate):
        destination, source = self.operands()
        name, bits, _ = FLOAT[kind]
        target = destination.size * 8
        value, _ = self.float_source(source, kind)
        if not truncate:
            value = self.v(f'call {name} @llvm.rint.f{bits}({name} {value})')
        lowest = -(1 << (target - 1))
        if truncate and self.representable(lowest - 1, name):
            above = self.v(f'fcmp ogt {name} {value}, {self.float_literal(float(lowest - 1), name)}')
        else:
            above = self.v(f'fcmp oge {name} {value}, {self.float_literal(float(lowest), name)}')
        below = self.v(f'fcmp olt {name} {value}, {self.float_literal(float(1 << (target - 1)), name)}')
        valid = self.v(f'and i1 {above}, {below}')
        converted = self.v(f'fptosi {name} {value} to i{target}')
        self.write(destination, self.v(f'select i1 {valid}, i{target} {converted}, i{target} {self.const(1 << (target - 1), target)}'))

    def representable(self, value, name):
        import struct as packing
        if name == 'double':
            return int(float(value)) == value
        return int(packing.unpack('<f', packing.pack('<f', float(value)))[0]) == value

    def float_literal(self, value, name):
        import struct as packing
        if name == 'double':
            return '0x%016X' % packing.unpack('<Q', packing.pack('<d', value))[0]
        rounded = packing.unpack('<f', packing.pack('<f', value))[0]
        return '0x%016X' % packing.unpack('<Q', packing.pack('<d', rounded))[0]

    def integer_to_float(self, kind):
        index, _, source = self.destination_source()
        name, bits, _ = FLOAT[kind]
        width = source.size * 8
        value = self.read(source, width)
        converted = self.v(f'sitofp i{width} {value} to {name}')
        raw = self.v(f'bitcast {name} {converted} to i{bits}')
        self.set_xmm(index, self.merge_low(self.get_xmm(index), raw, bits))

    def op_cvtsi2sd(self):
        self.integer_to_float('sd')

    def op_cvtsi2ss(self):
        self.integer_to_float('ss')

    def op_cvttpd2dq(self):
        destination, source = self.operands()
        mode = self.v(f'load i64, ptr {self.v("getelementptr i8, ptr %s, i64 392")}')
        self.trap_if(self.v(f'icmp ne i64 {self.v(f"and i64 {mode}, 18446744073709551552")}, 8064'), TRAP_UNSUPPORTED)
        raw = self.read128(source, True)
        values = self.v(f'bitcast i128 {raw} to <2 x double>')
        result = '0'
        for lane in range(2):
            value = self.v(f'extractelement <2 x double> {values}, i32 {lane}')
            above = self.v(f'fcmp ogt double {value}, {self.float_literal(-2147483649.0, "double")}')
            below = self.v(f'fcmp olt double {value}, {self.float_literal(2147483648.0, "double")}')
            valid = self.v(f'and i1 {above}, {below}')
            converted = self.v(f'fptosi double {value} to i32')
            safe = self.v(f'select i1 {valid}, i32 {converted}, i32 2147483648')
            widened = self.v(f'zext i32 {safe} to i128')
            shifted = self.v(f'shl i128 {widened}, {lane * 32}')
            result = self.v(f'or i128 {result}, {shifted}')
        self.set_xmm(self.xmm_index(destination), result)

    def op_cvttsd2si(self):
        self.float_to_integer('sd', True)

    def op_cvttss2si(self):
        self.float_to_integer('ss', True)

    def op_cvtsd2si(self):
        self.float_to_integer('sd', False)

    def op_cvtss2si(self):
        self.float_to_integer('ss', False)

    def float_resize(self, source_kind, target_kind):
        index, _, source = self.destination_source()
        value, source_type = self.float_source(source, source_kind)
        target_name, target_bits, _ = FLOAT[target_kind]
        operation = 'fpext' if target_bits > FLOAT[source_kind][1] else 'fptrunc'
        result = self.v(f'{operation} {source_type} {value} to {target_name}')
        nan = self.v(f'fcmp uno {source_type} {value}, {value}')
        quieted = self.v(f'{operation} {source_type} {self.quiet(value, source_type, source_kind)} to {target_name}')
        result = self.v(f'select i1 {nan}, {target_name} {quieted}, {target_name} {result}')
        raw = self.v(f'bitcast {target_name} {result} to i{target_bits}')
        self.set_xmm(index, self.merge_low(self.get_xmm(index), raw, target_bits))

    def op_cvtss2sd(self):
        self.float_resize('ss', 'sd')

    def op_cvtsd2ss(self):
        self.float_resize('sd', 'ss')

    def op_cvtdq2pd(self):
        index, _, source = self.destination_source()
        low = self.low(source, 64)
        vector = self.v(f'bitcast i64 {low} to <2 x i32>')
        self.set_xmm(index, self.v(f'bitcast <2 x double> {self.v(f"sitofp <2 x i32> {vector} to <2 x double>")} to i128'))

    def op_cvtdq2ps(self):
        index, _, source = self.destination_source()
        vector, _ = self.lanes(self.read128(source, True), 'd')
        self.set_xmm(index, self.v(f'bitcast <4 x float> {self.v(f"sitofp <4 x i32> {vector} to <4 x float>")} to i128'))

    def op_paddb(self):
        self.lane_binary('b', 'add')

    def op_psubb(self):
        self.lane_binary('b', 'sub')

    def op_pcmpeqb(self):
        self.lane_compare('b', 'eq')

    def op_pcmpgtb(self):
        self.lane_compare('b', 'sgt')

    def op_paddw(self):
        self.lane_binary('w', 'add')

    def op_psubw(self):
        self.lane_binary('w', 'sub')

    def op_pcmpeqw(self):
        self.lane_compare('w', 'eq')

    def op_pcmpgtw(self):
        self.lane_compare('w', 'sgt')

    def op_paddd(self):
        self.lane_binary('d', 'add')

    def op_psubd(self):
        self.lane_binary('d', 'sub')

    def op_pcmpeqd(self):
        self.lane_compare('d', 'eq')

    def op_pcmpgtd(self):
        self.lane_compare('d', 'sgt')

    def op_paddq(self):
        self.lane_binary('q', 'add')

    def op_psubq(self):
        self.lane_binary('q', 'sub')

    def op_pcmpeqq(self):
        self.lane_compare('q', 'eq')

    def op_pcmpgtq(self):
        self.lane_compare('q', 'sgt')

    def op_punpcklbw(self):
        self.unpack('b', False)

    def op_punpckhbw(self):
        self.unpack('b', True)

    def op_punpcklwd(self):
        self.unpack('w', False)

    def op_punpckhwd(self):
        self.unpack('w', True)

    def op_punpckldq(self):
        self.unpack('d', False)

    def op_punpckhdq(self):
        self.unpack('d', True)

    def op_punpcklqdq(self):
        self.unpack('q', False)

    def op_punpckhqdq(self):
        self.unpack('q', True)

    def op_unpcklps(self):
        self.unpack('d', False)

    def op_unpckhps(self):
        self.unpack('d', True)

    def op_unpcklpd(self):
        self.unpack('q', False)

    def op_unpckhpd(self):
        self.unpack('q', True)

    def op_paddusb(self):
        self.lane_intrinsic('b', 'uadd.sat')

    def op_paddusw(self):
        self.lane_intrinsic('w', 'uadd.sat')

    def op_psubusb(self):
        self.lane_intrinsic('b', 'usub.sat')

    def op_psubusw(self):
        self.lane_intrinsic('w', 'usub.sat')

    def op_paddsb(self):
        self.lane_intrinsic('b', 'sadd.sat')

    def op_paddsw(self):
        self.lane_intrinsic('w', 'sadd.sat')

    def op_psubsb(self):
        self.lane_intrinsic('b', 'ssub.sat')

    def op_psubsw(self):
        self.lane_intrinsic('w', 'ssub.sat')

    def op_pmaxub(self):
        self.lane_intrinsic('b', 'umax')

    def op_pminub(self):
        self.lane_intrinsic('b', 'umin')

    def op_pmaxsw(self):
        self.lane_intrinsic('w', 'smax')

    def op_pminsw(self):
        self.lane_intrinsic('w', 'smin')

    def op_pmullw(self):
        self.lane_binary('w', 'mul')

    def op_psllw(self):
        self.lane_shift('w', 'shl')

    def op_pslld(self):
        self.lane_shift('d', 'shl')

    def op_psllq(self):
        self.lane_shift('q', 'shl')

    def op_psrlw(self):
        self.lane_shift('w', 'lshr')

    def op_psrld(self):
        self.lane_shift('d', 'lshr')

    def op_psrlq(self):
        self.lane_shift('q', 'lshr')

    def op_psraw(self):
        self.lane_shift('w', 'ashr')

    def op_psrad(self):
        self.lane_shift('d', 'ashr')

    def op_addsd(self):
        self.float_binary('fadd', 'sd')

    def op_subsd(self):
        self.float_binary('fsub', 'sd')

    def op_mulsd(self):
        self.float_binary('fmul', 'sd')

    def op_divsd(self):
        self.float_binary('fdiv', 'sd')

    def op_minsd(self):
        self.float_extreme('sd', True)

    def op_maxsd(self):
        self.float_extreme('sd', False)

    def op_sqrtsd(self):
        self.float_sqrt('sd')

    def op_cmpeqsd(self):
        self.compare_mask('sd', 0)

    def op_cmpltsd(self):
        self.compare_mask('sd', 1)

    def op_cmplesd(self):
        self.compare_mask('sd', 2)

    def op_cmpunordsd(self):
        self.compare_mask('sd', 3)

    def op_cmpneqsd(self):
        self.compare_mask('sd', 4)

    def op_cmpnltsd(self):
        self.compare_mask('sd', 5)

    def op_cmpnlesd(self):
        self.compare_mask('sd', 6)

    def op_cmpordsd(self):
        self.compare_mask('sd', 7)

    def op_addss(self):
        self.float_binary('fadd', 'ss')

    def op_subss(self):
        self.float_binary('fsub', 'ss')

    def op_mulss(self):
        self.float_binary('fmul', 'ss')

    def op_divss(self):
        self.float_binary('fdiv', 'ss')

    def op_minss(self):
        self.float_extreme('ss', True)

    def op_maxss(self):
        self.float_extreme('ss', False)

    def op_sqrtss(self):
        self.float_sqrt('ss')

    def op_cmpeqss(self):
        self.compare_mask('ss', 0)

    def op_cmpltss(self):
        self.compare_mask('ss', 1)

    def op_cmpless(self):
        self.compare_mask('ss', 2)

    def op_cmpunordss(self):
        self.compare_mask('ss', 3)

    def op_cmpneqss(self):
        self.compare_mask('ss', 4)

    def op_cmpnltss(self):
        self.compare_mask('ss', 5)

    def op_cmpnless(self):
        self.compare_mask('ss', 6)

    def op_cmpordss(self):
        self.compare_mask('ss', 7)

    def op_addpd(self):
        self.float_binary('fadd', 'pd')

    def op_subpd(self):
        self.float_binary('fsub', 'pd')

    def op_mulpd(self):
        self.float_binary('fmul', 'pd')

    def op_divpd(self):
        self.float_binary('fdiv', 'pd')

    def op_minpd(self):
        self.float_extreme('pd', True)

    def op_maxpd(self):
        self.float_extreme('pd', False)

    def op_sqrtpd(self):
        self.float_sqrt('pd')

    def op_cmpeqpd(self):
        self.compare_mask('pd', 0)

    def op_cmpltpd(self):
        self.compare_mask('pd', 1)

    def op_cmplepd(self):
        self.compare_mask('pd', 2)

    def op_cmpunordpd(self):
        self.compare_mask('pd', 3)

    def op_cmpneqpd(self):
        self.compare_mask('pd', 4)

    def op_cmpnltpd(self):
        self.compare_mask('pd', 5)

    def op_cmpnlepd(self):
        self.compare_mask('pd', 6)

    def op_cmpordpd(self):
        self.compare_mask('pd', 7)

    def op_addps(self):
        self.float_binary('fadd', 'ps')

    def op_subps(self):
        self.float_binary('fsub', 'ps')

    def op_mulps(self):
        self.float_binary('fmul', 'ps')

    def op_divps(self):
        self.float_binary('fdiv', 'ps')

    def op_minps(self):
        self.float_extreme('ps', True)

    def op_maxps(self):
        self.float_extreme('ps', False)

    def op_sqrtps(self):
        self.float_sqrt('ps')

    def op_cmpeqps(self):
        self.compare_mask('ps', 0)

    def op_cmpltps(self):
        self.compare_mask('ps', 1)

    def op_cmpleps(self):
        self.compare_mask('ps', 2)

    def op_cmpunordps(self):
        self.compare_mask('ps', 3)

    def op_cmpneqps(self):
        self.compare_mask('ps', 4)

    def op_cmpnltps(self):
        self.compare_mask('ps', 5)

    def op_cmpnleps(self):
        self.compare_mask('ps', 6)

    def op_cmpordps(self):
        self.compare_mask('ps', 7)


ALL_FLAGS = frozenset(FLAGS)
STATUS_WRITERS = {'add', 'sub', 'adc', 'sbb', 'cmp', 'neg', 'and', 'or', 'xor', 'test', 'imul', 'mul', 'popcnt', 'andn',
                  'bzhi', 'blsr', 'blsi', 'blsmsk', 'ucomisd', 'comisd', 'ucomiss', 'comiss', 'popfq', 'xadd', 'cmpxchg'}
COUNTED = {'shl', 'sal', 'shr', 'sar', 'shld', 'shrd', 'rol', 'ror'}


def base_mnemonic(ins):
    mnemonic = ins.mnemonic
    for prefix in ('lock ', 'rep ', 'repe ', 'repne ', 'repz ', 'repnz ', 'notrack ', 'bnd '):
        if mnemonic.startswith(prefix):
            mnemonic = mnemonic[len(prefix):]
    return mnemonic


def flag_effects(ins):
    mnemonic = base_mnemonic(ins)
    if mnemonic.startswith('j') and mnemonic != 'jmp':
        return frozenset(CONDITION_FLAGS[condition_name(mnemonic[1:])]), frozenset()
    if mnemonic.startswith('set') or mnemonic.startswith('cmov'):
        return frozenset(CONDITION_FLAGS[condition_name(mnemonic[3:] if mnemonic.startswith('set') else mnemonic[4:])]), frozenset()
    uses = frozenset()
    if mnemonic in ('adc', 'sbb', 'cmc'):
        uses = frozenset({'cf'})
    elif mnemonic == 'pushfq':
        uses = ALL_FLAGS
    elif mnemonic == 'lahf':
        uses = frozenset({'cf', 'pf', 'af', 'zf', 'sf'})
    if mnemonic in STATUS_WRITERS:
        return uses, ALL_FLAGS
    if mnemonic in ('inc', 'dec'):
        return uses, ALL_FLAGS - {'cf'}
    if mnemonic in COUNTED:
        operands = ins.operands
        count = operands[-1] if len(operands) > (2 if mnemonic in ('shld', 'shrd') else 1) else None
        if count is None or (count.type == X86_OP_IMM and count.imm & (63 if operands[0].size == 8 else 31)):
            return uses, frozenset({'cf', 'of'}) if mnemonic in ('rol', 'ror') else ALL_FLAGS
        return uses, frozenset()
    if mnemonic in ('bt', 'bts', 'btr', 'btc', 'clc', 'stc', 'cmc'):
        return uses, frozenset({'cf'})
    if mnemonic in ('bsf', 'bsr'):
        return uses, frozenset({'zf'})
    if mnemonic in ('tzcnt', 'lzcnt'):
        return uses, frozenset({'cf', 'zf'})
    if mnemonic == 'sahf':
        return uses, frozenset({'cf', 'pf', 'af', 'zf', 'sf'})
    return uses, frozenset()

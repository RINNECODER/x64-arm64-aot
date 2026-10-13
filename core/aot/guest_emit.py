import argparse
import json
import subprocess
import time
import re
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from capstone.x86 import X86_OP_IMM, X86_OP_MEM

import guest_lift
import guest_provider_calls
import guest_regions
from guest_ops import (FLAGS, GPR, STATE_XMM, STATE_YMM_UPPER, TRAP_FALLTHROUGH, TRAP_HALT, TRAP_INVALID, TRAP_UNKNOWN_ENTRY,
                       Unsupported, Vector)

TRAP_UNKNOWN_TARGET = 1
TRIPLE = 'arm64-apple-macosx14.0.0'
RUNTIME = ['declare void @NativeAotGuestFlushCacheLine(i64)', '@NativeAotGuestSharedMemory = external global i8', 'declare void @NativeAotGuestTrap(i64, i64, i64) noreturn', 'declare ptr @NativeAotGuestLookup(i64)', 'declare ptr @NativeAotGuestFind(i64)',
           'declare void @NativeAotGuestCpuid(ptr)', 'declare i64 @NativeAotGuestReadTsc()']


def symbol(address):
    return f'@__aps5_g_{address:x}'


class Lowering(Vector):
    def set_gpr(self, name, value):
        self.gpr_writes.add(GPR.index(name))
        super().set_gpr(name, value)

    def set_xmm(self, index, value):
        self.xmm_writes.add(index)
        super().set_xmm(index, value)

    def set_ymm_upper(self, index, value):
        self.ymm_writes.add(index)
        super().set_ymm_upper(index, value)

    def private_epoch(self):
        value = self.v('load atomic i8, ptr @NativeAotGuestSharedMemory acquire, align 1')
        return self.v(f'icmp eq i8 {value}, 0')

    def string_operation(self, kind, bits):
        if self.ins.addr_size != 8:
            self.unsupported('32-bit string addressing is not qualified')
        if (self.epoch_variant != 'private' and not (self.epoch_variant == 'native' and not self.concurrent)) or 0xf3 not in self.ins.prefix or (kind == 'stos' and bits != 8):
            return super().string_operation(kind, bits)
        count, destination = self.get_gpr('rcx'), self.get_gpr('rdi')
        step = bits // 8
        fits_count = self.v(f'icmp ule i64 {count}, {(1 << 64) // step - 1}')
        size = self.v(f'mul i64 {count}, {step}')
        destination_end = self.v(f'add i64 {destination}, {size}')
        fits_destination = self.v(f'icmp uge i64 {destination_end}, {destination}')
        valid = self.v(f'and i1 {fits_count}, {fits_destination}')
        if kind == 'movs':
            source = self.get_gpr('rsi')
            source_end = self.v(f'add i64 {source}, {size}')
            fits_source = self.v(f'icmp uge i64 {source_end}, {source}')
            before = self.v(f'icmp ule i64 {destination_end}, {source}')
            after = self.v(f'icmp ule i64 {source_end}, {destination}')
            disjoint = self.v(f'or i1 {before}, {after}')
            valid = self.v(f'and i1 {valid}, {self.v(f"and i1 {fits_source}, {disjoint}")}')
        fast, fallback, done = self.label(), self.label(), self.label()
        self.emit(f'br i1 {valid}, label %{fast}, label %{fallback}')
        self.place(fast)
        pointer = self.pointer(destination)
        if kind == 'movs':
            self.emit(f'call void @llvm.memcpy.p0.p0.i64(ptr align 1 {pointer}, ptr align 1 {self.pointer(source)}, i64 {size}, i1 false)')
            self.set_gpr('rsi', source_end)
        else:
            value, _ = self.read_register('al')
            self.emit(f'call void @llvm.memset.p0.i64(ptr align 1 {pointer}, i8 {value}, i64 {size}, i1 false)')
        self.set_gpr('rdi', destination_end)
        self.set_gpr('rcx', '0')
        self.emit(f'br label %{done}')
        self.place(fallback)
        super().string_operation(kind, bits)
        self.emit(f'br label %{done}')
        self.place(done)
    def op_clflush(self):
        operand, = self.operands()
        if operand.type != X86_OP_MEM:
            self.unsupported('CLFLUSH requires a memory operand')
        self.emit('fence seq_cst')
        self.emit(f'call void @NativeAotGuestFlushCacheLine(i64 {self.address(operand)})')
        self.emit('fence seq_cst')

    def op_cpuid(self):
        if self.concurrent:
            self.emit('fence seq_cst')
        super().op_cpuid()
        if self.concurrent:
            self.emit('fence seq_cst')

    def ordered_scalar_load(self, address, bits, fallback):
        pointer = self.pointer(address)
        ordering = 'seq_cst'
        instruction = f'load atomic volatile i{bits}, ptr {pointer} {ordering}, align {bits // 8}'
        if bits == 8:
            return self.zext(self.v(instruction), bits)
        aligned, unaligned, done = self.label(), self.label(), self.label()
        check = self.v(f'icmp eq i64 {self.v(f"and i64 {address}, {bits // 8 - 1}")}, 0')
        self.emit(f'br i1 {check}, label %{aligned}, label %{unaligned}')
        self.place(aligned)
        fast = self.zext(self.v(instruction), bits)
        self.emit(f'br label %{done}')
        self.place(unaligned)
        slow = self.v(fallback)
        self.emit(f'br label %{done}')
        self.place(done)
        return self.v(f'phi i64 [ {fast}, %{aligned} ], [ {slow}, %{unaligned} ]')

    def ordered_scalar_store(self, address, value, bits, fallback):
        pointer = self.pointer(address)
        ordering = 'seq_cst'
        instruction = f'store atomic volatile i{bits} {self.trunc(value, bits)}, ptr {pointer} {ordering}, align {bits // 8}'
        if bits == 8:
            self.emit(instruction)
            return
        aligned, unaligned, done = self.label(), self.label(), self.label()
        check = self.v(f'icmp eq i64 {self.v(f"and i64 {address}, {bits // 8 - 1}")}, 0')
        self.emit(f'br i1 {check}, label %{aligned}, label %{unaligned}')
        self.place(aligned)
        self.emit(instruction)
        self.emit(f'br label %{done}')
        self.place(unaligned)
        self.emit(fallback)
        self.emit(f'br label %{done}')
        self.place(done)

    def load(self, address, bits):
        if not self.concurrent or (bits == 32 and self.ins.address in self.readonly_table_loads):
            return super().load(address, bits)
        if bits > 64:
            low = self.load(address, 64)
            high = self.load(self.v(f'add i64 {address}, 8'), bits - 64)
            wide = self.v(f'zext i64 {low} to i{bits}')
            shifted = self.v(f'shl i{bits} {self.v(f"zext i{bits - 64} {high} to i{bits}")}, 64')
            return self.v(f'or i{bits} {wide}, {shifted}')
        opcode = {8: 'ldrb', 16: 'ldrh', 32: 'ldr', 64: 'ldr'}[bits]
        width = 'x' if bits == 64 else 'w'
        instruction = f'call i64 asm sideeffect "dmb ish\\0A{opcode} ${{0:{width}}}, [$1]\\0Admb ish", "=r,r,~{{memory}}"(i64 {address})'
        value = self.ordered_scalar_load(address, bits, instruction) if self.ordered_access == 'atomic' else self.v(instruction)
        return value if bits == 64 else self.v(f'trunc i64 {value} to i{bits}')

    def store(self, address, value, bits):
        if not self.concurrent:
            return super().store(address, value, bits)
        if bits > 64:
            self.store(address, self.v(f'trunc i{bits} {value} to i64'), 64)
            high = self.v(f'lshr i{bits} {value}, 64')
            self.store(self.v(f'add i64 {address}, 8'), self.v(f'trunc i{bits} {high} to i{bits - 64}'), bits - 64)
            return
        opcode = {8: 'strb', 16: 'strh', 32: 'str', 64: 'str'}[bits]
        width = 'x' if bits == 64 else 'w'
        extended = value if bits == 64 else self.v(f'zext i{bits} {value} to i64')
        instruction = f'call void asm sideeffect "dmb ish\\0A{opcode} ${{0:{width}}}, [$1]\\0Admb ish", "r,r,~{{memory}}"(i64 {extended}, i64 {address})'
        if self.ordered_access == 'atomic':
            self.ordered_scalar_store(address, extended, bits, instruction)
        else:
            self.emit(instruction)

    def flush(self):
        for index in range(16):
            if self.writeback is not None and index not in self.writeback[0]:
                continue
            pointer = self.v(f'getelementptr i8, ptr %s, i64 {8 * index}')
            self.emit(f'store i64 {self.v(f"load i64, ptr %R{index}")}, ptr {pointer}')
        for index in range(16):
            if self.writeback is not None and index not in self.writeback[1]:
                continue
            pointer = self.v(f'getelementptr i8, ptr %s, i64 {STATE_XMM + 16 * index}')
            self.emit(f'store i128 {self.v(f"load i128, ptr %X{index}")}, ptr {pointer}, align 16')

        for index in range(16):
            if self.writeback is not None and index not in self.writeback[2]:
                continue
            pointer = self.v(f'getelementptr i8, ptr %s, i64 {STATE_YMM_UPPER + 16 * index}')
            self.emit(f'store i128 {self.v(f"load i128, ptr %Y{index}")}, ptr {pointer}, align 16')

    def reload(self):
        for index in range(16):
            pointer = self.v(f'getelementptr i8, ptr %s, i64 {8 * index}')
            self.emit(f'store i64 {self.v(f"load i64, ptr {pointer}")}, ptr %R{index}')
        for index in range(16):
            pointer = self.v(f'getelementptr i8, ptr %s, i64 {STATE_XMM + 16 * index}')
            self.emit(f'store i128 {self.v(f"load i128, ptr {pointer}, align 16")}, ptr %X{index}')

        for index in range(16):
            pointer = self.v(f'getelementptr i8, ptr %s, i64 {STATE_YMM_UPPER + 16 * index}')
            self.emit(f'store i128 {self.v(f"load i128, ptr {pointer}, align 16")}, ptr %Y{index}')

    def prologue(self):
        extra = ', i64 %base' if self.epoch_variant in ('private', 'ordered') else ''
        self.lines.append(f'define hidden i64 {self.symbol}(ptr noalias %s, i64 %entry{extra}) uwtable {{')
        self.lines.append('prologue:')
        for index in range(16):
            self.emit(f'%R{index} = alloca i64')
        for index in range(16):
            self.emit(f'%X{index} = alloca i128, align 16')
            self.emit(f'%Y{index} = alloca i128, align 16')
        for flag in FLAGS:
            self.emit(f'%F{flag} = alloca i1')
            self.emit(f'store i1 false, ptr %F{flag}')
        self.emit('%Resume = alloca i64')
        if self.epoch_variant is not None:
            for site in self.unit.tables:
                self.emit(f'%Selector{site:x} = alloca i64')
                self.emit(f'store i64 0, ptr %Selector{site:x}')
        self.reload()
        if self.epoch_variant not in ('private', 'ordered'):
            self.emit('%base = load i64, ptr @__aps5_guest_base')
        expected = self.v(f'add i64 %base, {self.unit.start}')
        bad = self.label()
        first = f'L{self.unit.start:x}.trace' if self.trace else f'L{self.unit.start:x}'
        if self.epoch_variant == 'private':
            self.emit(f'br label %{first}')
        elif self.epoch_variant == 'ordered':
            offset = self.v('sub i64 %entry, %base')
            entries = [f'i64 {self.unit.start}, label %{first}']
            entries.extend(f'i64 {point}, label %L{point:x}' for point in self.resume_points() if point != self.unit.start)
            self.emit(f'switch i64 {offset}, label %{bad} [ {" ".join(entries)} ]')
        else:
            self.emit(f'br i1 {self.v(f"icmp eq i64 %entry, {expected}")}, label %{first}, label %{bad}')
        self.place(bad)
        self.emit(f'call void @NativeAotGuestTrap(i64 {TRAP_UNKNOWN_ENTRY}, i64 %entry, i64 {expected})')
        self.emit('unreachable')
        if self.trace:
            self.lines.append(f'L{self.unit.start:x}.trace:')

    def absolute(self, address):
        return self.v(f'add i64 %base, {address}')

    def target_value(self):
        operand = self.ins.operands[0]
        if operand.type == X86_OP_IMM:
            return self.absolute(operand.imm)
        return self.read(operand, 64)

    def import_slot(self, address):
        if self.epoch_variant is None or address not in self.units:
            return None
        unit = self.units[address]
        if len(unit.instructions) != 1:
            return None
        ins = unit.instructions[address]
        if ins.mnemonic != 'jmp' or ins.addr_size != 8 or len(ins.operands) != 1:
            return None
        operand = ins.operands[0]
        if (operand.type != X86_OP_MEM or ins.reg_name(operand.mem.base) != 'rip' or operand.mem.index
                or ins.reg_name(operand.mem.segment) not in ('', None, 'cs', 'ds', 'ss', 'es')):
            return None
        slot = ins.address + ins.size + operand.mem.disp
        return slot if unit.program.import_name(slot) is not None else None

    def invoke_import(self, slot):
        contract = guest_provider_calls.CALLS.get(self.unit.program.import_name(slot))
        if self.epoch_variant is None or contract is None:
            return self.invoke_import_general(slot)
        kind, name, count, returns = contract
        target = self.load(self.absolute(slot), 64)
        fast, fallback, done = self.label(), self.label(), self.label()
        matches = self.v(f'call i1 @NativeAotGlibcFastBinding(i64 {target}, i64 {kind})')
        if kind == 11:
            check = self.label()
            self.emit(f'br i1 {matches}, label %{check}, label %{fallback}')
            self.place(check)
            if self.concurrent:
                self.emit('fence seq_cst')
            matches = self.v(f'call i1 @NativeAotGlibcOnceReady(i64 {self.get_gpr("rdi")})')
        self.emit(f'br i1 {matches}, label %{fast}, label %{fallback}')
        self.place(fast)
        arguments = ', '.join(f'i64 {self.get_gpr(register)}' for register in ['rdi', 'rsi', 'rdx'][:count])
        if self.concurrent and kind != 11:
            self.emit('fence seq_cst')
        value = '0' if kind == 11 else self.v(f'call i64 @NativeAotGlibcFast{name}({arguments})')
        if self.concurrent:
            self.emit('fence seq_cst')
        if returns:
            self.set_gpr('rax', value)
        rsp = self.get_gpr('rsp')
        fast_target = self.load(rsp, 64)
        self.set_gpr('rsp', self.v(f'add i64 {rsp}, 8'))
        fast_end = self.label()
        self.emit(f'br label %{fast_end}')
        self.place(fast_end)
        self.emit(f'br label %{done}')
        self.place(fallback)
        slow_target = self.invoke_import_general(slot, target)
        slow_end = self.label()
        self.emit(f'br label %{slow_end}')
        self.place(slow_end)
        self.emit(f'br label %{done}')
        self.place(done)
        return self.v(f'phi i64 [ {fast_target}, %{fast_end} ], [ {slow_target}, %{slow_end} ]')

    def invoke_import_general(self, slot, target=None):
        self.flush()
        if target is None:
            target = self.load(self.absolute(slot), 64)
        function = self.v(f'call ptr @NativeAotGuestFind(i64 {target})')
        known, unknown, done = self.label(), self.label(), self.label()
        self.emit(f'br i1 {self.v(f"icmp eq ptr {function}, null")}, label %{unknown}, label %{known}')
        self.place(known)
        called = self.v(f'call i64 {function}(ptr %s, i64 {target})')
        self.emit(f'br label %{done}')
        self.place(unknown)
        self.emit(f'br label %{done}')
        self.place(done)
        result = self.v(f'phi i64 [ {called}, %{known} ], [ {target}, %{unknown} ]')
        result = self.finish_invoke(result)
        self.reload()
        return result

    def invoke(self, function, target):
        self.flush()
        extra = ', i64 %base' if function.startswith('@__aps5_g_') and function.endswith(('_private', '_ordered')) else ''
        result = self.v(f'call i64 {function}(ptr %s, i64 {target}{extra})')
        return self.finish_invoke(result)

    def finish_invoke(self, result):
        if self.epoch_variant == 'private':
            private, promoted, resume, outside = self.label(), self.label(), self.label(), self.label()
            self.emit(f'br i1 {self.private_epoch()}, label %{private}, label %{promoted}')
            self.place(promoted)
            offset = self.v(f'sub i64 {result}, %base')
            cases = ' '.join(f'i64 {point}, label %{resume}' for point in self.resume_points())
            self.emit(f'switch i64 {offset}, label %{outside} [ {cases} ]')
            self.place(resume)
            continued = self.v(f'tail call i64 {symbol(self.unit.start)}_ordered(ptr %s, i64 {result}, i64 %base)')
            self.leave_with(continued)
            self.place(outside)
            self.leave_with(result)
            self.place(private)
        return result

    def leave_with(self, value):
        if self.trace:
            self.emit(f'call void @NativeAotGuestTraceLeave(ptr %s, i64 {self.unit.start}, i64 {value})')
        self.emit(f'ret i64 {value}')

    def direct(self, address):
        if address not in self.units:
            return None
        suffix = '_' + self.epoch_variant if self.epoch_variant in ('private', 'ordered') else ''
        return symbol(address) + suffix

    def call_target(self, target_address, target):
        function = self.direct(target_address) if target_address is not None else None
        if function is None:
            function = self.v(f'call ptr @NativeAotGuestLookup(i64 {target})')
        return function

    def control(self, ins):
        unit, mnemonic = self.unit, ins.mnemonic
        following = ins.address + ins.size
        if mnemonic == 'call':
            operand = ins.operands[0]
            target = self.target_value()
            slot = self.import_slot(operand.imm) if operand.type == X86_OP_IMM else None
            function = self.call_target(operand.imm if operand.type == X86_OP_IMM else None, target) if slot is None else None
            back = self.absolute(following)
            rsp = self.v(f'sub i64 {self.get_gpr("rsp")}, 8')
            self.store(rsp, back, 64)
            self.set_gpr('rsp', rsp)
            if slot is None:
                result = self.invoke(function, target)
                self.reload()
            else:
                result = self.invoke_import(slot)
            propagate = self.label()
            continuation = f'L{following:x}' if following in unit.instructions else self.label()
            self.emit(f'br i1 {self.v(f"icmp eq i64 {result}, {back}")}, label %{continuation}, label %{propagate}')
            self.place(propagate)
            if slot is not None:
                self.flush()
            if self.resume_points():
                self.emit(f'store i64 {result}, ptr %Resume')
                self.emit('br label %resume')
                self.needs_resume = True
            else:
                self.leave_with(result)
            if following not in unit.instructions:
                self.place(continuation)
                self.trap(TRAP_FALLTHROUGH)
            return
        if mnemonic == 'ret':
            rsp = self.get_gpr('rsp')
            back = self.load(rsp, 64)
            extra = ins.operands[0].imm if ins.operands else 0
            self.set_gpr('rsp', self.v(f'add i64 {rsp}, {8 + extra}'))
            self.flush()
            self.leave_with(back)
            return
        if mnemonic in ('hlt', 'ud2', 'int3'):
            self.trap({'hlt': TRAP_HALT, 'ud2': TRAP_INVALID, 'int3': TRAP_INVALID}[mnemonic])
            return
        if mnemonic == 'jmp':
            if ins.address in unit.tables:
                self.table(ins)
                return
            operand = ins.operands[0]
            if operand.type == X86_OP_IMM and ins.address not in unit.tails:
                self.emit(f'br label %L{operand.imm:x}')
                return
            target = self.target_value()
            if operand.type == X86_OP_IMM:
                slot = self.import_slot(operand.imm)
                result = self.invoke(self.call_target(operand.imm, target), target) if slot is None else self.invoke_import(slot)
                if slot is not None:
                    self.flush()
                self.leave_with(result)
                return
            function = self.v(f'call ptr @NativeAotGuestFind(i64 {target})')
            local, remote = self.label(), self.label()
            self.emit(f'br i1 {self.v(f"icmp eq ptr {function}, null")}, label %{local}, label %{remote}')
            self.place(local)
            self.flush()
            self.leave_with(target)
            self.place(remote)
            self.leave_with(self.invoke(function, target))
            return
        suffix = mnemonic[1:]
        target = ins.operands[0].imm
        condition = self.condition(suffix)
        taken = f'L{target:x}'
        if ins.address in unit.tails:
            taken = self.label()
        self.emit(f'br i1 {condition}, label %{taken}, label %L{following:x}')
        if ins.address in unit.tails:
            self.place(taken)
            absolute = self.absolute(target)
            slot = self.import_slot(target)
            result = self.invoke(self.call_target(target, absolute), absolute) if slot is None else self.invoke_import(slot)
            if slot is not None:
                self.flush()
            self.leave_with(result)

    def resume_points(self):
        if not hasattr(self, '_resume'):
            unit = self.unit
            points = set(getattr(unit, 'landing_pads', []))
            for address, ins in unit.instructions.items():
                following = address + ins.size
                if ins.mnemonic == 'call' and following in unit.instructions:
                    points.add(following)
            self._resume = sorted(points)
        return self._resume

    def table(self, ins):
        description = self.unit.tables[ins.address]
        value = self.read(ins.operands[0], 64)
        offset = self.v(f'sub i64 {value}, %base')
        default = self.label()
        if self.epoch_variant is not None and description.get('selector_load') is not None:
            selector = self.v(f'load i64, ptr %Selector{ins.address:x}')
            fallback = self.label()
            if ins.address in self.sealed_tables:
                dense = ' '.join(f'i64 {index}, label %L{target:x}' for index, target in enumerate(description['targets']))
                self.emit(f'switch i64 {selector}, label %{fallback} [ {dense} ]')
                self.place(fallback)
                cases = ' '.join(f'i64 {target}, label %L{target:x}' for target in sorted(set(description['targets'])))
                self.emit(f'switch i64 {offset}, label %{default} [ {cases} ]')
                self.place(default)
                self.emit(f'call void @NativeAotGuestTrap(i64 {TRAP_UNKNOWN_TARGET}, i64 {value}, i64 {self.absolute(ins.address)})')
                self.emit('unreachable')
                return
            guards = {target: self.label() for target in sorted(set(description['targets']))}
            dense = ' '.join(f'i64 {index}, label %{guards[target]}' for index, target in enumerate(description['targets']))
            self.emit(f'switch i64 {selector}, label %{fallback} [ {dense} ]')
            for target, label in guards.items():
                self.place(label)
                matches = self.v(f'icmp eq i64 {offset}, {target}')
                self.emit(f'br i1 {matches}, label %L{target:x}, label %{fallback}')
            self.place(fallback)
        cases = ' '.join(f'i64 {target}, label %L{target:x}' for target in sorted(set(description['targets'])))
        self.emit(f'switch i64 {offset}, label %{default} [ {cases} ]')
        self.place(default)
        self.emit(f'call void @NativeAotGuestTrap(i64 {TRAP_UNKNOWN_TARGET}, i64 {value}, i64 {self.absolute(ins.address)})')
        self.emit('unreachable')

    def instruction(self, ins):
        self.ins = ins
        if self.epoch_variant is not None:
            for site, description in self.unit.tables.items():
                if description.get('selector_load') == ins.address:
                    self.emit(f'store i64 {self.get_gpr(description["index"])}, ptr %Selector{site:x}')
        if self.unit.program.abi != 'glibc' and any(operand.type == X86_OP_MEM and ins.reg_name(operand.mem.segment) in ('fs', 'gs') for operand in ins.operands):
            self.unsupported('SCE static TLS addressing requires a separate host ABI')
        mnemonic = ins.mnemonic
        if mnemonic in ('call', 'ret', 'jmp', 'hlt', 'ud2', 'int3') or (mnemonic.startswith('j') and mnemonic[1:]):
            self.control(ins)
            return
        if 0xf0 in ins.prefix:
            self.locked()
        elif mnemonic.startswith('rep') or mnemonic in ('movsb', 'movsw', 'movsq', 'stosb', 'stosw', 'stosd', 'stosq'):
            self.string()
        elif mnemonic.startswith('cmov'):
            self.cmov(mnemonic[4:])
        elif mnemonic.startswith('set'):
            self.setcc(mnemonic[3:])
        else:
            handler = getattr(self, 'op_' + mnemonic, None)
            if handler is None:
                self.unsupported('instruction semantics are not implemented')
            handler()
        following = ins.address + ins.size
        if following in self.unit.instructions:
            self.emit(f'br label %L{following:x}')
        else:
            self.trap(TRAP_FALLTHROUGH)


def lower_unit(unit, units, trace=False, concurrent=False, ordered_access="fenced", epoch_variant=None, writeback=None, seal_image=False):
    lowering = Lowering(unit, symbol(unit.start) + ('_' + epoch_variant if epoch_variant and epoch_variant != 'native' else ''))
    lowering.epoch_variant = epoch_variant
    lowering.sealed_tables = guest_regions.sealed_tables(unit) if seal_image else set()
    lowering.readonly_table_loads = {unit.tables[site]['selector_load'] for site in lowering.sealed_tables}
    lowering.writeback = writeback
    lowering.gpr_writes, lowering.xmm_writes, lowering.ymm_writes = set(), set(), set()
    lowering.units = units
    lowering.trace = trace
    lowering.concurrent = concurrent
    lowering.ordered_access = ordered_access
    lowering.prologue()
    if trace:
        lowering.emit(f'call void @NativeAotGuestTraceEnter(ptr %s, i64 {unit.start})')
        lowering.emit(f'br label %L{unit.start:x}')
    errors = []
    for address in sorted(unit.instructions):
        lowering.lines.append(f'L{address:x}:')
        mark = len(lowering.lines)
        try:
            lowering.instruction(unit.instructions[address])
        except Unsupported as error:
            errors.append(str(error))
            del lowering.lines[mark:]
            lowering.ins = unit.instructions[address]
            lowering.trap(10)
    if getattr(lowering, 'needs_resume', False):
        lowering.lines.append('resume:')
        result = lowering.v('load i64, ptr %Resume')
        outside = lowering.label()
        cases = ' '.join(f'i64 {address}, label %L{address:x}' for address in lowering.resume_points())
        lowering.emit(f'switch i64 {lowering.v(f"sub i64 {result}, %base")}, label %{outside} [ {cases} ]')
        lowering.place(outside)
        lowering.leave_with(result)
    lowering.lines.append('}')
    if epoch_variant is not None and writeback is None:
        return lower_unit(unit, units, trace, concurrent, ordered_access, epoch_variant, (lowering.gpr_writes, lowering.xmm_writes, lowering.ymm_writes), seal_image)
    return '\n'.join(lowering.lines), lowering.declarations, errors


def describe_image(program, units):
    view = program.view
    loads = view.loads
    blob, segments = bytearray(), []
    for segment in loads:
        segments.append((segment['vaddr'], segment['filesz'], segment['memsz'], len(blob), segment['flags']))
        blob += view.raw[segment['offset']:segment['offset'] + segment['filesz']]
    symbols, flags, index = [], [], {}
    relocations = []
    for relocation in program.dynamic['relocations']:
        number = 0
        if relocation['kind'] in (1, 6, 7):
            entry = program.dynamic['symbols'][relocation['symbol_index']]
            name = canonical_name(program, entry)
            if name not in index:
                index[name] = len(symbols)
                symbols.append(name)
                flags.append(1 if entry['info'] >> 4 == 2 else 0)
            number = index[name]
        relocations.append((relocation['slot'], relocation['kind'], number, relocation['addend']))
    span = max(s['vaddr'] + s['memsz'] for s in loads)
    relro_address, relro_size = program.relro
    exports = sorted((canonical_name(program, symbol, True), symbol['value']) for symbol in program.dynamic['symbols'][1:]
                     if symbol['name'] and symbol['section'] and symbol['section'] < 0xff00 and symbol['info'] & 15 in (1, 2))
    tls = program.tls
    tls_fields = (tls['vaddr'], tls['filesz'], tls['memsz'], max(tls['align'], 1)) if tls else (0, 0, 0, 1)
    return {'blob': bytes(blob), 'segments': segments, 'symbols': symbols, 'flags': flags, 'relocations': relocations,
            'span': span, 'relro': (relro_address, relro_size), 'entry': view.entry,
            'entries': sorted(units), 'tls': tls_fields, 'exports': exports, 'abi': program.abi}


def abi_code(name):
    return {'glibc': 0, 'sce-app': 1, 'sce-module': 2}[name]


def canonical_name(program, entry, exported=False):
    if program.abi == 'glibc' or '#' not in entry['name']:
        return entry['name']
    from bundle import identity
    return json.dumps(identity(program.dynamic, entry, exported, ''), separators=(',', ':'))


def namespace_ir(text, namespace):
    guest_lift.require(not namespace or re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*_', namespace), 'invalid guest image namespace')
    pattern = r'"(?:\\[0-9A-Fa-f]{2}|[^"\\])*"|@__aps5_[A-Za-z_0-9]+'
    return re.sub(pattern, lambda match: '@' + namespace + match.group()[1:] if match.group().startswith('@__aps5_') else match.group(), text)


def string_constant(name, text):
    data = text.encode() + b'\0'
    escaped = ''.join(chr(b) if 32 <= b < 127 and b not in (34, 92) else f'\\{b:02X}' for b in data)
    return f'{name} = private unnamed_addr constant [{len(data)} x i8] c"{escaped}"'


def descriptor_module(image, concurrent=False, memory_epochs=False, seal_image=False):
    lines = [f'target triple = "{TRIPLE}"', '@__aps5_guest_base = hidden global i64 0']
    for address in image['entries']:
        lines.append(f'declare i64 {symbol(address)}(ptr, i64)')
    blob = image['blob']
    escaped = ''.join(f'\\{b:02X}' for b in blob)
    lines.append(f'@__aps5_guest_bytes = private constant [{len(blob)} x i8] c"{escaped}", align 16')
    lines.append(f'@__aps5_guest_segments = private constant [{len(image["segments"])} x [5 x i64]] [' +
                 ', '.join('[5 x i64] [' + ', '.join(f'i64 {v}' for v in s) + ']' for s in image['segments']) + ']')
    relocations = image['relocations'] or [(0, 0, 0, 0)]
    lines.append(f'@__aps5_guest_relocations = private constant [{len(relocations)} x [4 x i64]] [' +
                 ', '.join('[4 x i64] [' + ', '.join(f'i64 {v}' for v in r) + ']' for r in relocations) + ']')
    names = []
    for number, name in enumerate(image['symbols']):
        lines.append(string_constant(f'@__aps5_guest_symbol_{number}', name))
        names.append(f'ptr @__aps5_guest_symbol_{number}')
    symbol_count = len(image['symbols'])
    lines.append(f'@__aps5_guest_symbols = private constant [{max(symbol_count, 1)} x ptr] [{", ".join(names) or "ptr null"}]')
    lines.append(f'@__aps5_guest_symbol_flags = private constant [{max(symbol_count, 1)} x i64] [{", ".join(f"i64 {f}" for f in image["flags"]) or "i64 0"}]')
    lines.append(f'@__aps5_guest_entries = private constant [{len(image["entries"])} x {{ i64, ptr }}] [' +
                 ', '.join(f'{{ i64, ptr }} {{ i64 {a}, ptr {symbol(a)} }}' for a in image['entries']) + ']')
    exports = image['exports']
    for number, (name, _) in enumerate(exports):
        lines.append(string_constant(f'@__aps5_guest_export_{number}', name))
    lines.append(f'@__aps5_guest_exports = private constant [{max(len(exports), 1)} x {{ ptr, i64 }}] [' +
                 (', '.join(f'{{ ptr, i64 }} {{ ptr @__aps5_guest_export_{number}, i64 {address} }}' for number, (_, address) in enumerate(exports)) or '{ ptr, i64 } zeroinitializer') + ']')
    fields = ['i64 9', 'ptr @__aps5_guest_bytes', f'i64 {len(blob)}', 'ptr @__aps5_guest_segments', f'i64 {len(image["segments"])}',
              'ptr @__aps5_guest_relocations', f'i64 {len(image["relocations"])}', 'ptr @__aps5_guest_symbols',
              'ptr @__aps5_guest_symbol_flags', f'i64 {symbol_count}', 'ptr @__aps5_guest_entries', f'i64 {len(image["entries"])}',
              f'i64 {image["entry"]}', f'i64 {image["span"]}', f'i64 {image["relro"][0]}', f'i64 {image["relro"][1]}',
              'ptr @__aps5_guest_base', *[f'i64 {value}' for value in image['tls']], 'ptr @__aps5_guest_exports', f'i64 {len(exports)}', f'i64 {3 if seal_image else 2 if memory_epochs else int(concurrent)}', f'i64 {abi_code(image.get("abi", "glibc"))}']
    types = ', '.join(field.split(' ')[0] for field in fields)
    lines.append(f'@__aps5_guest_image = constant {{ {types} }} {{ {", ".join(fields)} }}')
    return '\n'.join(lines) + '\n'


def shard_module(texts, declarations, defined, called):
    lines = [f'target triple = "{TRIPLE}"', '@__aps5_guest_base = external hidden global i64', *RUNTIME, *guest_provider_calls.declarations(), *sorted(declarations)]
    for address in sorted(called - defined):
        lines.append(f'declare hidden i64 {symbol(address)}(ptr, i64)')
    lines.extend(texts)
    return '\n\n'.join(lines) + '\n'


def callees(unit, units):
    return {target for target in [*unit.calls.values(), *unit.tails.values()] if target in units}


def epoch_dispatch(start):
    name = symbol(start)
    return f"""define hidden i64 {name}(ptr %s, i64 %entry) {{
dispatch:
  %base = load i64, ptr @__aps5_guest_base
  %expected = add i64 %base, {start}
  %valid = icmp eq i64 %expected, %entry
  br i1 %valid, label %choose, label %bad
bad:
  call void @NativeAotGuestTrap(i64 4, i64 %entry, i64 %expected)
  unreachable
choose:
  %epoch = load atomic i8, ptr @NativeAotGuestSharedMemory acquire, align 1
  %private = icmp eq i8 %epoch, 0
  br i1 %private, label %fast, label %ordered
fast:
  %a = tail call i64 {name}_private(ptr %s, i64 %entry, i64 %base)
  ret i64 %a
ordered:
  %b = tail call i64 {name}_ordered(ptr %s, i64 %entry, i64 %base)
  ret i64 %b
}}"""


def lower_shard(arguments):
    raw, starts, output, extra, trace, concurrent, abi, ordered_access, memory_epochs, seal_image, optimize_calls, namespace = arguments
    program = guest_lift.Program(raw, abi=abi)
    units, _, _ = guest_lift.discover(program, extra)
    texts, declarations, errors, called = [], set(), [], set()
    for start in starts:
        if memory_epochs:
            text, declared, failures = lower_unit(units[start], units, trace, True, ordered_access, 'ordered', seal_image=seal_image)
            texts.append(text)
            declarations |= declared
            errors.extend(failures)
            text, declared, failures = lower_unit(units[start], units, trace, False, ordered_access, 'private', seal_image=seal_image)
            texts.append(text)
            declarations |= declared
            errors.extend(failures)
            texts.append(epoch_dispatch(start))
        else:
            text, declared, failures = lower_unit(units[start], units, trace, concurrent, ordered_access,
                                                  'native' if optimize_calls else None)
            texts.append(text)
            declarations |= declared
            errors.extend(failures)
        called |= callees(units[start], units)
    if memory_epochs:
        declarations |= {f'declare hidden i64 {symbol(address)}_{mode}(ptr, i64, i64)' for address in called - set(starts) for mode in ('private', 'ordered')}
    if trace:
        declarations |= {'declare void @NativeAotGuestTraceEnter(ptr, i64)', 'declare void @NativeAotGuestTraceLeave(ptr, i64, i64)'}
    Path(output).write_text(namespace_ir(shard_module(texts, declarations, set(starts), called), namespace))
    return errors


def build(input_path, output_dir, shards=16, jobs=8, extra=(), strict=True, trace=False, concurrent=False, abi="glibc", ordered_access=None, memory_epochs=False, seal_image=False, optimize_calls=False, namespace=""):
    if ordered_access is None:
        ordered_access = 'atomic' if concurrent else 'fenced'
    guest_lift.require(ordered_access in ('fenced', 'atomic'), 'unknown ordered access implementation')
    guest_lift.require(concurrent or ordered_access == 'fenced', 'atomic access requires --concurrent')
    guest_lift.require(not seal_image or memory_epochs, 'sealed image requires memory epochs')
    guest_lift.require(not memory_epochs or (concurrent and abi == 'glibc'), 'memory epochs require the concurrent glibc profile')
    guest_lift.require(not memory_epochs or not trace, 'memory epoch tracing is not qualified')
    guest_lift.require(not optimize_calls or (abi == 'glibc' and not trace), 'optimized calls require an untraced glibc profile')
    namespace_ir('', namespace)
    started = time.monotonic()
    raw = Path(input_path).read_bytes()
    program = guest_lift.Program(raw, abi=abi)
    units, failures, obligations = guest_lift.discover(program, extra)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    image = describe_image(program, units)
    (output / 'image.ll').write_text(namespace_ir(descriptor_module(image, concurrent, memory_epochs, seal_image), namespace))
    ordered = sorted(units, key=lambda start: -len(units[start].instructions))
    buckets = [[] for _ in range(shards)]
    sizes = [0] * shards
    for start in ordered:
        smallest = sizes.index(min(sizes))
        buckets[smallest].append(start)
        sizes[smallest] += len(units[start].instructions)
    work = [(raw, sorted(bucket), str(output / f'shard{number:02}.ll'), tuple(extra), trace, concurrent, abi, ordered_access, memory_epochs, seal_image, optimize_calls, namespace) for number, bucket in enumerate(buckets) if bucket]
    if jobs == 1:
        errors = [error for item in work for error in lower_shard(item)]
    else:
        with ProcessPoolExecutor(jobs) as pool:
            errors = [error for result in pool.map(lower_shard, work) for error in result]
    report = {'schema': 'anyps5.aot.guest-lowering.v1', 'input_sha256': program.sha256, 'units': len(units),
              'startup_abi': abi, 'native_namespace': namespace, 'ordered_access': ordered_access, 'memory_epochs': memory_epochs, 'sealed_image': seal_image, 'optimized_calls': optimize_calls or memory_epochs,
              'sealed_dispatch_tables': sum(len(guest_regions.sealed_tables(u)) for u in units.values()) if seal_image else 0,
              'memory_profile': 'ordered-normal-memory' if concurrent else 'single-thread',
              'instructions': sum(len(unit.instructions) for unit in units.values()),
              'jump_tables': {status: sum(1 for unit in units.values() for table in unit.tables.values() if table['status'] == status)
                              for status in ('qualified', 'candidate')},
              'unsupported': sorted(set(errors)), 'failed_soft_roots': failures, 'obligations': obligations,
              'imports': image['symbols'], 'seconds': round(time.monotonic() - started, 3)}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if strict and errors:
        raise guest_lift.LiftError(f'{len(set(errors))} unsupported instruction sites, first: {sorted(set(errors))[0]}')
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--shards', type=int, default=16)
    parser.add_argument('--inventory', action='store_true')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--namespace', default='')
    parser.add_argument('--concurrent', action='store_true')
    parser.add_argument('--memory-epochs', action='store_true')
    parser.add_argument('--seal-image', action='store_true')
    parser.add_argument('--optimize-calls', action='store_true')
    parser.add_argument('--ordered-access', choices=('fenced', 'atomic'))
    parser.add_argument('--abi', choices=('glibc', 'sce-app', 'sce-module'), default='glibc')
    args = parser.parse_args()
    report = build(args.input, args.output, args.shards, strict=not args.inventory, trace=args.trace, concurrent=args.concurrent, abi=args.abi, ordered_access=args.ordered_access, memory_epochs=args.memory_epochs, seal_image=args.seal_image, optimize_calls=args.optimize_calls, namespace=args.namespace)
    print(json.dumps({key: report[key] for key in ('units', 'instructions', 'jump_tables', 'seconds')}))
    print(f'{len(report["unsupported"])} unsupported instruction sites')


if __name__ == '__main__':
    main()

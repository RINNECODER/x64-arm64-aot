import os
import random
import struct
import subprocess
import tempfile
from pathlib import Path

from elftools.elf.elffile import ELFFile

import guest_emit
import guest_lift

ROOT = Path(__file__).resolve().parents[3]
NATIVE = ROOT / 'core/libs/native'
CODE = 0x1000
DYNAMIC = 0x40000
BUFFER_MARK = 0xFEED000000000000
SCRATCH_MARK = 0xFEEE000000000000
BUFFER_SIZE = 512
EDGES = [0, 1, 2, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff,
         0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff, 0x100000000, 0xfffffffe, 63, 64, 31, 32]
GPR = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
ALL_FLAGS = 0x8d5

HARNESS = r'''
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef LIFTED
#include "native/NativeAotGuest.hpp"
extern "C" const NativeAotGuestImage __aps5_guest_image;
#else
struct NativeAotGuestState {
    std::uint64_t Gpr[16];
    std::uint8_t Xmm[16][16];
    std::uint64_t Rest[20];
};
extern "C" void lab_enter(std::uint64_t body, NativeAotGuestState* state);
extern "C" char lab_bodies[];
#endif

int main(int argc, char** argv) {
    FILE* input = std::fopen(argv[1], "rb");
    FILE* output = std::fopen(argv[2], "wb");
    std::uint64_t count;
    std::fread(&count, 8, 1, input);
#ifdef LIFTED
    const auto base = NativeAotGuest::Load(__aps5_guest_image);
    const auto stack = NativeAotGuest::AllocateStack(1 << 20);
#endif
    alignas(64) static std::uint8_t buffer[%(buffer)d + 64];
    alignas(16) static std::uint64_t scratch[4];
    for (std::uint64_t index = 0; index < count; ++index) {
        std::uint64_t offset;
        std::fread(&offset, 8, 1, input);
        static NativeAotGuestState state;
        std::memset(&state, 0, sizeof(state));
        std::fread(state.Gpr, 8, 16, input);
        std::fread(state.Xmm, 16, 16, input);
        std::fread(&scratch[1], 8, 1, input);
        std::fread(buffer, 1, %(buffer)d, input);
        for (auto& value : state.Gpr) {
            if ((value >> 48) == 0xfeed) value = reinterpret_cast<std::uint64_t>(buffer) + (value & 0xffffffff);
            else if ((value >> 48) == 0xfeee) value = reinterpret_cast<std::uint64_t>(scratch);
        }
#ifdef LIFTED
        state.Gpr[4] = stack;
        state.Mxcsr = 0x1f80;
        state.X87Control = 0x37f;
        NativeAotGuest::Invoke(state, base + %(code)d + offset);
#else
        lab_enter(reinterpret_cast<std::uint64_t>(lab_bodies) + offset, &state);
#endif
        const auto begin = reinterpret_cast<std::uint64_t>(buffer);
        for (auto& value : state.Gpr) {
            if (value >= begin && value < begin + %(buffer)d + 64) value = 0xfeed000000000000ull | (value - begin);
            else if (value == reinterpret_cast<std::uint64_t>(scratch)) value = 0xfeee000000000000ull;
        }
        state.Gpr[4] = 0;
        std::fwrite(state.Gpr, 8, 16, output);
        std::fwrite(state.Xmm, 16, 16, output);
        std::fwrite(&scratch[0], 8, 1, output);
        std::fwrite(buffer, 1, %(buffer)d, output);
    }
    std::fclose(output);
    return 0;
}
'''

TRAMPOLINE = r'''
.intel_syntax noprefix
.data
lab_state: .quad 0
lab_target: .quad 0
.text
.globl _lab_enter
_lab_enter:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov [rip + lab_state], rsi
    mov [rip + lab_target], rdi
%(load_xmm)s
    mov rax, [rsi]
    mov rcx, [rsi + 8]
    mov rdx, [rsi + 16]
    mov rbx, [rsi + 24]
    mov rbp, [rsi + 40]
    mov rdi, [rsi + 56]
    mov r8, [rsi + 64]
    mov r9, [rsi + 72]
    mov r10, [rsi + 80]
    mov r11, [rsi + 88]
    mov r12, [rsi + 96]
    mov r13, [rsi + 104]
    mov r14, [rsi + 112]
    mov r15, [rsi + 120]
    mov rsi, [rsi + 48]
    call qword ptr [rip + lab_target]
    push rax
    mov rax, [rip + lab_state]
    mov [rax + 8], rcx
    mov [rax + 16], rdx
    mov [rax + 24], rbx
    mov [rax + 40], rbp
    mov [rax + 48], rsi
    mov [rax + 56], rdi
    mov [rax + 64], r8
    mov [rax + 72], r9
    mov [rax + 80], r10
    mov [rax + 88], r11
    mov [rax + 96], r12
    mov [rax + 104], r13
    mov [rax + 112], r14
    mov [rax + 120], r15
%(store_xmm)s
    pop rcx
    mov [rax], rcx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
'''


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, **kwargs)
    if result.returncode != 0:
        raise AssertionError(f'{command[0]} failed with {result.returncode}: {result.stderr.decode(errors="replace")[-2000:]}')
    return result


def body_source(cases, symbol_prefix):
    lines = ['.intel_syntax noprefix', '.text', f'.globl {symbol_prefix}lab_bodies', f'{symbol_prefix}lab_bodies:']
    for index, case in enumerate(cases):
        lines += ['.p2align 4', f'body_{index}:', '    push qword ptr [r15 + 8]', '    popfq']
        lines += [f'    {line}' for line in case['asm']]
        lines += ['    pushfq', '    pop qword ptr [r15]', '    ret']
    return '\n'.join(lines) + '\n'


def assemble_elf_bodies(cases, directory):
    source = directory / 'bodies.s'
    source.write_text(body_source(cases, ''))
    obj = directory / 'bodies.o'
    run(['xcrun', 'clang', '--target=x86_64-unknown-linux-gnu', '-c', str(source), '-o', str(obj)])
    with obj.open('rb') as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name('.text').data()
        offsets = {}
        for symbol in elf.get_section_by_name('.symtab').iter_symbols():
            if symbol.name.startswith('body_'):
                offsets[int(symbol.name[5:])] = symbol['st_value']
    return text, [offsets[index] for index in range(len(cases))]


def fixture_image(code):
    size = 0x40000 + 0x1000
    image = bytearray(size)
    phnum = 3
    struct.pack_into('<16sHHIQQQIHHHHHH', image, 0, b'\x7fELF\x02\x01\x01' + bytes(9), 3, 62, 1, 0, 64, 0, 0, 64, 56, phnum, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, CODE, CODE, CODE, len(code), len(code), 0x1000)
    image[CODE:CODE + len(code)] = code
    strings = DYNAMIC + 0x100
    symbols = DYNAMIC + 0x140
    table = DYNAMIC + 0x180
    struct.pack_into('<III', image, table, 1, 1, 0)
    tags = [(5, strings), (10, 1), (6, symbols), (11, 24), (4, table), (0, 0)]
    for index, tag in enumerate(tags):
        struct.pack_into('<qQ', image, DYNAMIC + index * 16, *tag)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, 6, DYNAMIC, DYNAMIC, DYNAMIC, 0x1000, 0x1000, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 176, 2, 6, DYNAMIC, DYNAMIC, DYNAMIC, len(tags) * 16, len(tags) * 16, 8)
    return bytes(image)


class Lab:
    def __init__(self, directory, memory_epochs=False):
        self.directory = Path(directory)
        self.memory_epochs = memory_epochs

    def lifted_binary(self, cases, memory_epochs=None):
        if memory_epochs is None:
            memory_epochs = self.memory_epochs
        code, offsets = assemble_elf_bodies(cases, self.directory)
        raw = fixture_image(code)
        image = self.directory / 'fixture.elf'
        image.write_bytes(raw)
        roots = [CODE + offset for offset in offsets]
        output = self.directory / 'lifted'
        guest_emit.build(image, output, shards=1, jobs=1, extra=roots, concurrent=memory_epochs, memory_epochs=memory_epochs)
        harness = self.directory / 'lifted_harness.cpp'
        harness.write_text('#define LIFTED 1\n' + HARNESS % {'buffer': BUFFER_SIZE, 'code': CODE})
        objects = []
        for module in sorted(output.glob('*.ll')):
            obj = module.with_suffix('.o')
            run(['xcrun', 'clang', '-c', '-O2', '-arch', 'arm64', '-Wno-override-module', str(module), '-o', str(obj)])
            objects.append(str(obj))
        binary = self.directory / 'lifted_run'
        run(['xcrun', 'clang++', '-std=c++20', '-O1', '-arch', 'arm64', f'-I{ROOT / "core/libs"}', str(harness),
             str(NATIVE / 'NativeAotGuest.cpp'), str(ROOT / 'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp'), *objects, '-o', str(binary)])
        return binary, roots

    def oracle_binary(self, cases):
        source = self.directory / 'oracle_bodies.s'
        source.write_text(body_source(cases, '_'))
        trampoline = self.directory / 'trampoline.s'
        load = '\n'.join(f'    movdqu xmm{i}, [rsi + {128 + 16 * i}]' for i in range(16))
        store = '\n'.join(f'    movdqu [rax + {128 + 16 * i}], xmm{i}' for i in range(16))
        trampoline.write_text(TRAMPOLINE % {'load_xmm': load, 'store_xmm': store})
        harness = self.directory / 'oracle_harness.cpp'
        harness.write_text(HARNESS % {'buffer': BUFFER_SIZE, 'code': CODE})
        binary = self.directory / 'oracle_run'
        run(['xcrun', 'clang++', '-std=c++20', '-O1', '-arch', 'x86_64', str(harness), str(source), str(trampoline), '-o', str(binary)])
        return binary

    def inputs(self, cases, roots, samples, seed):
        generator = random.Random(seed)
        records = []
        for index, case in enumerate(cases):
            for _ in range(samples):
                gpr = []
                for name in GPR:
                    if name == 'r15':
                        gpr.append(SCRATCH_MARK)
                    elif name in case.get('pointers', {}):
                        gpr.append(BUFFER_MARK | case['pointers'][name])
                    elif name in case.get('fixed', {}):
                        choice = case['fixed'][name]
                        gpr.append(generator.choice(choice) if isinstance(choice, list) else choice)
                    else:
                        value = generator.choice(EDGES) if generator.random() < 0.3 else generator.getrandbits(64)
                        while value >> 48 in (0xfeed, 0xfeee):
                            value = generator.getrandbits(64)
                        gpr.append(value)
                xmm = b''.join(self.vector(generator, case) for _ in range(16))
                flags = 2 | sum(1 << bit for bit in (0, 2, 4, 6, 7, 11) if generator.random() < 0.5)
                memory = bytes(generator.getrandbits(8) for _ in range(BUFFER_SIZE))
                records.append((roots[index] - CODE, gpr, xmm, flags, memory))
        return records

    def vector(self, generator, case):
        kind = case.get('vectors', 'bits')
        if kind == 'double':
            values = [generator.choice([0.0, -0.0, 1.0, -1.5, 2.5, 3.5, 1e300, -1e300, 1e-310, float('inf'), float('-inf'),
                                        float('nan'), 2.0 ** 63, -2.0 ** 63, 2.0 ** 31, -2.0 ** 31 - 1, 4294967296.5])
                      if generator.random() < 0.4 else generator.uniform(-1e6, 1e6) for _ in range(2)]
            raw = struct.pack('<2d', *values)
            if generator.random() < 0.1:
                raw = struct.pack('<Q', 0x7ff0000000000001 | generator.getrandbits(50)) + raw[8:]
            return raw
        if kind == 'float':
            values = [generator.choice([0.0, -0.0, 1.0, -1.5, float('inf'), float('nan'), 3.4e38, 1e-40, 2.0 ** 31])
                      if generator.random() < 0.4 else generator.uniform(-1e6, 1e6) for _ in range(4)]
            return struct.pack('<4f', *values)
        if generator.random() < 0.2:
            return bytes(generator.choice([0, 0xff, 0x80, 0x7f, 1]) for _ in range(16))
        return bytes(generator.getrandbits(8) for _ in range(16))

    def write_inputs(self, records, path):
        with open(path, 'wb') as stream:
            stream.write(struct.pack('<Q', len(records)))
            for offset, gpr, xmm, flags, memory in records:
                stream.write(struct.pack('<Q', offset))
                stream.write(struct.pack('<16Q', *gpr))
                stream.write(xmm)
                stream.write(struct.pack('<Q', flags))
                stream.write(memory)

    def read_outputs(self, path, count):
        data = Path(path).read_bytes()
        record = 128 + 256 + 8 + BUFFER_SIZE
        if len(data) != count * record:
            raise AssertionError(f'harness wrote {len(data)} bytes for {count} records')
        results = []
        for index in range(count):
            chunk = data[index * record:(index + 1) * record]
            results.append((struct.unpack('<16Q', chunk[:128]), chunk[128:384], struct.unpack('<Q', chunk[384:392])[0], chunk[392:]))
        return results

    def compare(self, cases, samples=64, seed=1):
        lifted, roots = self.lifted_binary(cases)
        oracle = self.oracle_binary(cases)
        records = self.inputs(cases, roots, samples, seed)
        source = self.directory / 'inputs.bin'
        self.write_inputs(records, source)
        run([str(lifted), str(source), str(self.directory / 'lifted.bin')])
        run(['arch', '-x86_64', str(oracle), str(source), str(self.directory / 'oracle.bin')])
        lifted_results = self.read_outputs(self.directory / 'lifted.bin', len(records))
        oracle_results = self.read_outputs(self.directory / 'oracle.bin', len(records))
        failures = []
        for number, (record, mine, theirs) in enumerate(zip(records, lifted_results, oracle_results)):
            case = cases[number // samples]
            flags_mask = case.get('flags', ALL_FLAGS)
            ignored = set(case.get('ignore', ()))
            problems = []
            for index, name in enumerate(GPR):
                if name not in ignored and mine[0][index] != theirs[0][index]:
                    problems.append(f'{name}: {mine[0][index]:#x} != {theirs[0][index]:#x}')
            if mine[1] != theirs[1]:
                for index in range(16):
                    if mine[1][16 * index:16 * index + 16] != theirs[1][16 * index:16 * index + 16]:
                        problems.append(f'xmm{index}: {mine[1][16 * index:16 * index + 16].hex()} != {theirs[1][16 * index:16 * index + 16].hex()}')
            if (mine[2] ^ theirs[2]) & flags_mask:
                problems.append(f'flags: {mine[2]:#x} != {theirs[2]:#x} (mask {flags_mask:#x})')
            if mine[3] != theirs[3]:
                problems.append('memory differs')
            if problems:
                failures.append({'asm': case['asm'], 'input': [hex(v) for v in record[1]], 'flags_in': hex(record[3]),
                                 'problems': problems})
        return failures


def lab_directory():
    return tempfile.TemporaryDirectory(prefix='anyps5-guest-lab-')


def assemble_program(source, directory):
    path = Path(directory) / 'program.s'
    path.write_text('.intel_syntax noprefix\n.text\n' + source)
    obj = Path(directory) / 'program.o'
    run(['xcrun', 'clang', '--target=x86_64-unknown-linux-gnu', '-c', str(path), '-o', str(obj)])
    with obj.open('rb') as stream:
        elf = ELFFile(stream)
        text = elf.get_section_by_name('.text')
        for section in elf.iter_sections():
            if section.name.startswith('.rela'):
                if any(True for _ in section.iter_relocations()):
                    raise AssertionError('fixture program must not need object relocations')
        labels = {symbol.name: symbol['st_value'] for symbol in elf.get_section_by_name('.symtab').iter_symbols() if symbol.name}
        return text.data(), labels


def unwind_tables(ranges, header, frame):
    from test_load_facts import cie, padded, uleb
    stream = bytearray(cie())
    fdes = []
    for begin, size in ranges:
        address = frame + len(stream)
        field = address + 4
        body = padded(struct.pack('<Iii', field - frame, begin - (field + 4), size) + uleb(0))
        stream += struct.pack('<I', len(body)) + body
        fdes.append(address)
    stream += bytes(4)
    entries = sorted(zip((begin for begin, _ in ranges), fdes))
    index = struct.pack('<BBBBiI', 1, 0x1b, 0x03, 0x3b, frame - (header + 4), len(entries))
    index += b''.join(struct.pack('<ii', location - header, fde - header) for location, fde in entries)
    return bytes(index), bytes(stream)


def program_image(code, labels, imports=(), data_imports=(), entry='_start', relative=(), unwind=(), tls=None):
    image = bytearray(0x40000 + 0x2000)
    struct.pack_into('<16sHHIQQQIHHHHHH', image, 0, b'\x7fELF\x02\x01\x01' + bytes(9), 3, 62, 1, CODE + labels[entry], 64, 0, 0, 64, 56, 3, 64, 0, 0)
    struct.pack_into('<IIQQQQQQ', image, 64, 1, 5, CODE, CODE, CODE, len(code), len(code), 0x1000)
    image[CODE:CODE + len(code)] = code
    names = [name for name, _ in imports] + [name for name, _ in data_imports]
    strings = bytearray(b'\0')
    symbols = bytearray(24)
    for index, name in enumerate(names):
        info = 0x12 if index < len(imports) else 0x11
        symbols += struct.pack('<IBBHQQ', len(strings), info, 0, 0, 0, 0)
        strings += name.encode() + b'\0'
    plt = bytearray()
    for index, (_, slot) in enumerate(imports):
        plt += struct.pack('<QQq', CODE + labels[slot], ((index + 1) << 32) | 7, 0)
    rela = bytearray()
    for index, (_, slot) in enumerate(data_imports):
        rela += struct.pack('<QQq', CODE + labels[slot], ((len(imports) + index + 1) << 32) | 6, 0)
    for slot, target in relative:
        rela += struct.pack('<QQq', CODE + labels[slot], 8, CODE + labels[target])
    places = {'strings': DYNAMIC + 0x400, 'symbols': DYNAMIC + 0x800, 'hash': DYNAMIC + 0xc00, 'plt': DYNAMIC + 0x1000, 'rela': DYNAMIC + 0x1400}
    image[places['strings']:places['strings'] + len(strings)] = strings
    image[places['symbols']:places['symbols'] + len(symbols)] = symbols
    count = len(names) + 1
    struct.pack_into(f'<II{count}I', image, places['hash'], 1, count, 0, *([0] * (count - 1)))
    image[places['plt']:places['plt'] + len(plt)] = plt
    image[places['rela']:places['rela'] + len(rela)] = rela
    tags = [(5, places['strings']), (10, len(strings)), (6, places['symbols']), (11, 24), (4, places['hash'])]
    if plt:
        tags += [(23, places['plt']), (2, len(plt)), (20, 7)]
    if rela:
        tags += [(7, places['rela']), (8, len(rela)), (9, 24)]
    tags.append((0, 0))
    for index, tag in enumerate(tags):
        struct.pack_into('<qQ', image, DYNAMIC + index * 16, *tag)
    struct.pack_into('<IIQQQQQQ', image, 120, 1, 6, DYNAMIC, DYNAMIC, DYNAMIC, 0x2000, 0x2000, 0x1000)
    struct.pack_into('<IIQQQQQQ', image, 176, 2, 6, DYNAMIC, DYNAMIC, DYNAMIC, len(tags) * 16, len(tags) * 16, 8)
    if tls is not None:
        template, memsz, align = tls
        address = DYNAMIC + 0x1c00
        image[address:address + len(template)] = template
        count = struct.unpack_from('<H', image, 0x38)[0]
        struct.pack_into('<IIQQQQQQ', image, 64 + count * 56, 7, 4, address, address, address, len(template), memsz, align)
        struct.pack_into('<H', image, 0x38, count + 1)
    if unwind:
        header, frame = DYNAMIC + 0x1800, DYNAMIC + 0x1900
        index, stream = unwind_tables([(CODE + labels[start], labels[end] - labels[start]) for start, end in unwind], header, frame)
        image[header:header + len(index)] = index
        image[frame:frame + len(stream)] = stream
        count = struct.unpack_from('<H', image, 0x38)[0]
        struct.pack_into('<H', image, 0x38, count + 1)
        struct.pack_into('<IIQQQQQQ', image, 64 + count * 56, 0x6474e550, 4, header, header, header, len(index), len(index), 4)
    return bytes(image)


def build_program(raw, directory, roots=(), strict=True, concurrent=False, abi="glibc", launcher=None, ordered_access=None, memory_epochs=False, seal_image=False, optimize_calls=False):
    directory = Path(directory)
    image = directory / 'program.elf'
    image.write_bytes(raw)
    output = directory / 'converted'
    report = guest_emit.build(image, output, shards=1, jobs=1, extra=roots, strict=strict, concurrent=concurrent, abi=abi, ordered_access=ordered_access, memory_epochs=memory_epochs, seal_image=seal_image, optimize_calls=optimize_calls)
    objects = []
    for module in sorted(output.glob('*.ll')):
        obj = module.with_suffix('.o')
        run(['xcrun', 'clang', '-c', '-O2', '-arch', 'arm64', '-Wno-override-module', str(module), '-o', str(obj)])
        objects.append(str(obj))
    binary = directory / 'program'
    sources = [str(path) for path in sorted(NATIVE.glob('NativeAotGuest*.cpp')) + sorted(NATIVE.glob('NativeAotGlibc*.cpp'))]
    sources.append(str(ROOT / 'core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp'))
    if launcher is not None:
        sources.remove(str(NATIVE / 'NativeAotGuestMain.cpp'))
        main = directory / 'launcher.cpp'
        main.write_text(launcher)
        sources.append(str(main))
    run(['xcrun', 'clang++', '-std=c++20', '-O1', '-arch', 'arm64', f'-I{ROOT / "core/libs"}', *sources, *objects, '-o', str(binary)])
    return binary, report

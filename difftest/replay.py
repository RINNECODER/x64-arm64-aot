#!/usr/bin/env python3
"""Differential replay: the same inputs through the AOT ARM64 function and through
the original x86 bytes executed in a Rosetta-relinked layout.

The x86 side maps the synthetic image's PT_LOAD segments at the engine's relinked
base (0x140000000) instead of their low original addresses, so macOS' __PAGEZERO
does not block the mapping and RIP-relative references stay intact. Inputs are the
general-purpose registers and a zeroed data image; outputs compared are RAX (and
RDX) plus a memory window.
"""
import ctypes
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

AOT = Path(__file__).resolve().parent.parent / "core" / "aot"
sys.path.insert(0, str(AOT))

from toolchain import build_native_object  # noqa: E402

REGISTERS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
BASE = 0x140000000

X86_RUNNER = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#define BASE 0x140000000ULL
struct regs { uint64_t r[16]; };
uint64_t invoke_frame;  /* the trampoline's own frame base, which the guest may clobber */
extern uint64_t invoke(void* entry, struct regs* in, struct regs* out, uint64_t* stack, uint64_t stack_words);
__asm__(
".text\n"
".globl _invoke\n"
"_invoke:\n"
"  pushq %rbp\n  movq %rsp, %rbp\n"
"  pushq %rbx\n  pushq %r12\n  pushq %r13\n  pushq %r14\n  pushq %r15\n"
"  subq $32, %rsp\n"
"  movq %rdx, -48(%rbp)\n"   /* out */
"  movq %rdi, -56(%rbp)\n"   /* entry */
"  movq %rsi, -64(%rbp)\n"   /* in */
"  leaq -8(%rcx,%r8,8), %rsp\n"
"  movq -64(%rbp), %r10\n"
"  movq 0(%r10), %rax\n  movq 8(%r10), %rbx\n  movq 16(%r10), %rcx\n  movq 24(%r10), %rdx\n"
"  movq 32(%r10), %rsi\n  movq 40(%r10), %rdi\n"
"  movq 64(%r10), %r8\n  movq 72(%r10), %r9\n"
"  movq 88(%r10), %r11\n  movq 96(%r10), %r12\n  movq 104(%r10), %r13\n  movq 112(%r10), %r14\n  movq 120(%r10), %r15\n"
"  movq 80(%r10), %r10\n"
"  movq %rbp, _invoke_frame(%rip)\n"
"  movq -56(%rbp), %r11\n"
"  callq *%r11\n"
"  movq _invoke_frame(%rip), %rbp\n"
"  movq -48(%rbp), %r9\n"
"  movq %rax, 0(%r9)\n  movq %rbx, 8(%r9)\n  movq %rcx, 16(%r9)\n  movq %rdx, 24(%r9)\n"
"  movq %rsi, 32(%r9)\n  movq %rdi, 40(%r9)\n  movq %r8, 64(%r9)\n"
"  movq %r12, 96(%r9)\n  movq %r13, 104(%r9)\n  movq %r14, 112(%r9)\n  movq %r15, 120(%r9)\n"
"  leaq -40(%rbp), %rsp\n"
"  popq %r15\n  popq %r14\n  popq %r13\n  popq %r12\n  popq %rbx\n  popq %rbp\n  ret\n");
int main(int argc, char** argv) {
    uint64_t address = strtoull(argv[2], 0, 16);
    FILE* segments = fopen(argv[1], "rb");
    uint32_t count = 0;
    if (fread(&count, 4, 1, segments) != 1) return 2;
    for (uint32_t index = 0; index < count; ++index) {
        uint64_t vaddr, filesz, memsz;
        if (fread(&vaddr, 8, 1, segments) != 1 || fread(&filesz, 8, 1, segments) != 1 || fread(&memsz, 8, 1, segments) != 1) return 2;
        void* page = mmap((void*)(BASE + (vaddr & ~0xfffull)), memsz + (vaddr & 0xfff), PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (page == MAP_FAILED) { perror("mmap"); return 3; }
        if (filesz && fread((char*)page + (vaddr & 0xfff), 1, filesz, segments) != (size_t)filesz) return 4;
    }
    uint64_t page = BASE + (address & ~0xfffull);
    if (mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC) != 0) { perror("mprotect"); return 5; }
    struct regs in, out;
    void* guest_stack = mmap((void*)(BASE + 0x70000000), 0x100000, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (guest_stack == MAP_FAILED) { perror("stack mmap"); return 7; }
    void* scratch = mmap((void*)(BASE + 0x60000000), 0x100000, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (scratch == MAP_FAILED) { perror("scratch mmap"); return 8; }
    if (argc > 5) {
        FILE* pages = fopen(argv[5], "rb");
        if (pages != NULL) {
            uint32_t page_count = 0;
            if (fread(&page_count, 4, 1, pages) == 1) {
                for (uint32_t index = 0; index < page_count; ++index) {
                    uint64_t vaddr = 0, bytes = 0;
                    if (fread(&vaddr, 8, 1, pages) != 1 || fread(&bytes, 8, 1, pages) != 1) break;
                    void* mapped = mmap((void*)vaddr, bytes, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                    if (mapped == MAP_FAILED) break;
                    if (fread(mapped, 1, bytes, pages) != bytes) break;
                }
            }
            fclose(pages);
        }
    }
    FILE* input = fopen(argv[3], "rb");
    if (fread(&in, 1, sizeof(in), input) != sizeof(in)) return 6;
    memset(&out, 0, sizeof(out));
    invoke((void*)(BASE + address), &in, &out, (uint64_t*)(BASE + 0x70080000), 0x10000);
    FILE* output = fopen(argv[4], "wb");
    fwrite(&out, 1, sizeof(out), output);
    fclose(output); fclose(input); fclose(segments);
    return 0;
}
"""


def elf_segments(image):
    """PT_LOAD (vaddr, filesz, memsz, bytes) for the runner's segment file."""
    from elftools.elf.elffile import ELFFile
    import io
    elf = ELFFile(io.BytesIO(image))
    result = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        data = image[segment["p_offset"]:segment["p_offset"] + segment["p_filesz"]]
        result.append((segment["p_vaddr"], segment["p_filesz"], segment["p_memsz"], data))
    return result


def build_arm64(ir, directory):
    object_file = directory / "native.o"
    build_native_object(ir, object_file)
    dylib = directory / "native.dylib"
    extra = []
    if "NativeAotDispatch_nid_no_patch" in ir:
        dispatch_source = Path(__file__).resolve().parent.parent / "core" / "libs" / "native" / "NativeAotDispatch.cpp"
        dispatch_object = directory / "dispatch.o"
        subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-O2", "-c", str(dispatch_source), "-o", str(dispatch_object)],
                       check=True, capture_output=True)
        extra = [str(dispatch_object)]
    subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-dynamiclib", str(object_file), *extra, "-o", str(dylib)],
                   check=True, capture_output=True)
    return dylib


def call_arm64(dylib, name, address, arguments):
    library = ctypes.CDLL(str(dylib))
    function = getattr(library, name)
    runtime = ctypes.cast(function, ctypes.c_void_p).value
    base = runtime - address
    function.restype = ctypes.c_uint64
    function.argtypes = [ctypes.c_uint64] * len(arguments)
    return function(*arguments), base, library


def normalize_pointer(library, value, data_ranges):
    """Map an AOT data pointer back to the guest vaddr it represents."""
    for vaddr, size in data_ranges:
        try:
            runtime = ctypes.cast(getattr(library, f"data_{vaddr:x}"), ctypes.c_void_p).value
        except AttributeError:
            continue
        if runtime is not None and runtime <= value < runtime + size:
            return vaddr + (value - runtime)
    return None


def build_x86_runner(directory):
    source = directory / "runner.c"
    source.write_text(X86_RUNNER)
    binary = directory / "runner"
    subprocess.run(["xcrun", "clang", "-arch", "x86_64", "-O1", str(source), "-o", str(binary)], check=True, capture_output=True)
    return binary


def run_x86(directory, runner, image, address, registers, memory, pages=None):
    segments = directory / "segments.bin"
    with segments.open("wb") as stream:
        entries = elf_segments(image)
        stream.write(struct.pack("<I", len(entries)))
        for vaddr, filesz, memsz, data in entries:
            stream.write(struct.pack("<QQQ", vaddr, filesz, memsz))
            stream.write(data)
    input_file = directory / "case.bin"
    input_file.write_bytes(b"".join(int(registers.get(name, 0)).to_bytes(8, "little") for name in REGISTERS) + memory)
    output_file = directory / "out.bin"
    pages_file = directory / "pages.bin"
    with pages_file.open("wb") as stream:
        stream.write(struct.pack("<I", len(pages) if pages else 0))
        for vaddr, data in pages or []:
            stream.write(struct.pack("<QQ", vaddr, len(data)))
            stream.write(data)
    result = subprocess.run([str(runner), str(segments), hex(address), str(input_file), str(output_file), str(pages_file)], capture_output=True)
    if result.returncode != 0:
        return None, result.returncode
    raw = output_file.read_bytes()
    return {name: int.from_bytes(raw[index * 8:index * 8 + 8], "little") for index, name in enumerate(REGISTERS)}, 0


def uniform_call(dylib, name, registers):
    """Call a uniform-ABI function (void @f(ptr %rf)); returns RAX and the library."""
    library = ctypes.CDLL(str(dylib))
    function = getattr(library, name)
    function.restype = None
    function.argtypes = [ctypes.c_void_p]
    libc = ctypes.CDLL(None)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap(ctypes.c_void_p(BASE + 0x70000000), 0x100000, 1 | 2, 0x02 | 0x1000 | 0x10, -1, 0)
    libc.mmap(ctypes.c_void_p(BASE + 0x60000000), 0x100000, 1 | 2, 0x02 | 0x1000 | 0x10, -1, 0)
    regfile = (ctypes.c_uint64 * 123)()
    for index, register in enumerate(UNIFORM_GPRS):
        regfile[index] = registers.get(register, 0)
    regfile[4] = BASE + 0x700FFFF8  # rsp, matching the x86 runner
    function(ctypes.byref(regfile))
    return regfile[0], library


UNIFORM_GPRS = ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi") + tuple(f"r{i}" for i in range(8, 16))


def replay_case(directory, ir, name, image, address, registers, memory, uniform=False):
    dylib = build_arm64(ir, directory)
    if uniform:
        arm, library = uniform_call(dylib, name, registers)
    else:
        arguments = [int(registers.get(register, 0)) for register in ("rdi", "rsi", "rdx", "rcx", "r8", "r9")]
        arm, dylib_base, library = call_arm64(dylib, name, address, arguments)
    runner = build_x86_runner(directory)
    x86, code = run_x86(directory, runner, image, address, registers, memory)
    if x86 is None:
        return {"arm64_rax": arm, "status": "x86-fault", "x86_exit": code}
    x86_rax = x86["rax"]
    mask = 0xffffffffffffffff
    x86_vaddr = (x86_rax - BASE) & mask
    data_ranges = [(vaddr, memsz) for vaddr, _filesz, memsz, _data in elf_segments(image) if memsz]
    normalized = normalize_pointer(library, arm, data_ranges)
    matches = arm == x86_rax or (normalized is not None and normalized == x86_vaddr)
    return {"arm64_rax": arm, "arm64_vaddr": normalized, "x86_rax": x86_rax, "x86_vaddr": x86_vaddr,
            "match": matches, "x86_registers": x86}


if __name__ == "__main__":
    raise SystemExit("import difftest.replay; the orchestrator lives in difftest.py")

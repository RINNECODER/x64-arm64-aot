#!/usr/bin/env python3
"""Full-state differential harness: uniform-compile a function, run it on ARM64 and on the
native x86 bytes (Rosetta-relinked) with randomized registers and memory, and compare the whole
architectural state — GPRs, RFLAGS, xmm/ymm 0-15 and every scratch byte written.

usage: difftest_full.py <address> <seeds...>      (one function, prints JSON)
       difftest_full.py --campaign <count> <seeds>
"""
import atexit
import ctypes
import importlib.util
import multiprocessing
import json
import os
import random
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

def work_directory():
    """The title work directory (never a personal path): the eboot ELF and the FDE starts live
    under it. Set ANYPS5_NATIVE_WORK, or pass the two paths in ANYPS5_ELF / ANYPS5_FDE_STARTS."""
    value = os.environ.get("ANYPS5_NATIVE_WORK")
    if not value and not (os.environ.get("ANYPS5_ELF") and os.environ.get("ANYPS5_FDE_STARTS")):
        raise SystemExit("set ANYPS5_NATIVE_WORK to the title work directory, or set both "
                         "ANYPS5_ELF and ANYPS5_FDE_STARTS")
    return Path(value) if value else Path(os.environ["ANYPS5_ELF"]).parent.parent


REPO = Path(__file__).resolve().parent.parent
W = work_directory()
ELF = Path(os.environ.get("ANYPS5_ELF", W / "out/elf/eboot.elf"))
STARTS = Path(os.environ.get("ANYPS5_FDE_STARTS", W / "cfg/eboot.fde-starts.txt"))
sys.path.insert(0, str(REPO / "core" / "aot"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import difftest as harness  # noqa: E402
import real_image  # noqa: E402
import replay  # noqa: E402
import call_record  # noqa: E402

BASE = replay.BASE
SCRATCH = BASE + 0x60000000
SCRATCH_SIZE = 0x10000
SCRATCH_MAP = 0x100000
STACK = BASE + 0x700FFFF8
# The x86 reference runner sets its stack to the top of a fixed buffer and then `callq`s the guest,
# so the guest's first instruction sees the return address pushed below that top. The ARM side must
# start on the same value, or a stack-adjustment flag result (and anything derived from the guest
# stack pointer) is computed from a different address.
RUNNER_STACK = BASE + 0x70080000
RUNNER_STACK_WORDS = 0x10000
RUNNER_ENTRY_RSP = RUNNER_STACK + RUNNER_STACK_WORDS * 8 - 16
REGFILE = 123 * 8
CLOSURE_LIMIT = 600
STATE = 16 * 8 + 8 + 256 + 256 + 512 + 16 * 16  # gprs, rflags, xmm, ymm upper, fxsave, scratch ptrs

RUNNER = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#define BASE 0x140000000ULL
struct regs { uint64_t r[16]; };
extern uint64_t invoke(void* entry, struct regs* in, struct regs* out, uint64_t* stack, uint64_t stack_words);
uint64_t g_frame, g_out, g_entry, g_r9, g_r10, g_r11, g_zero;
__asm__(
".text\n.globl _invoke\n_invoke:\n"
"  pushq %rbp\n  movq %rsp, %rbp\n"
"  movq %rbp, _g_frame(%rip)\n  movq %rdx, _g_out(%rip)\n  movq %rdi, _g_entry(%rip)\n"
"  pushq %rbx\n  pushq %r12\n  pushq %r13\n  pushq %r14\n  pushq %r15\n  subq $32, %rsp\n"
"  movq %rsi, %r10\n  leaq -8(%rcx,%r8,8), %rsp\n"
"  movq 0(%r10), %rax\n  movq 8(%r10), %rbx\n  movq 16(%r10), %rcx\n  movq 24(%r10), %rdx\n"
"  movq 32(%r10), %rsi\n  movq 40(%r10), %rdi\n  movq 48(%r10), %rbp\n  movq 64(%r10), %r8\n  movq 72(%r10), %r9\n"
"  movq 88(%r10), %r11\n  movq 96(%r10), %r12\n  movq 104(%r10), %r13\n  movq 112(%r10), %r14\n  movq 120(%r10), %r15\n"
"  movq 80(%r10), %r10\n  pushq _g_zero(%rip)\n  popfq\n  callq *_g_entry(%rip)\n"
"  movq %r9, _g_r9(%rip)\n  movq %r10, _g_r10(%rip)\n  movq %r11, _g_r11(%rip)\n  movq _g_out(%rip), %r9\n"
"  movq %rax, 0(%r9)\n  movq %rbx, 8(%r9)\n  movq %rcx, 16(%r9)\n  movq %rdx, 24(%r9)\n"
"  movq %rsi, 32(%r9)\n  movq %rdi, 40(%r9)\n  movq %rbp, 48(%r9)\n  movq %r8, 64(%r9)\n"
"  movq _g_r9(%rip), %r10\n  movq %r10, 72(%r9)\n  movq _g_r10(%rip), %r10\n  movq %r10, 80(%r9)\n"
"  movq _g_r11(%rip), %r10\n  movq %r10, 88(%r9)\n"
"  movq %r12, 96(%r9)\n  movq %r13, 104(%r9)\n  movq %r14, 112(%r9)\n  movq %r15, 120(%r9)\n"
"  movq _g_frame(%rip), %rbp\n  leaq -40(%rbp), %rsp\n  popq %r15\n  popq %r14\n  popq %r13\n  popq %r12\n  popq %rbx\n  popq %rbp\n  ret\n");
static void fault_handler(int sig, siginfo_t* info, void* context) {
    ucontext_t* uc = (ucontext_t*)context;
    fprintf(stderr, "[runner] fault sig=%d addr=%p rip=%llx\n", sig, info ? info->si_addr : 0,
            uc ? (unsigned long long)uc->uc_mcontext->__ss.__rip : 0);
    _exit(9);
}
int main(int argc, char** argv) {
    struct sigaction action; memset(&action, 0, sizeof(action));
    action.sa_sigaction = fault_handler; action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &action, 0); sigaction(SIGBUS, &action, 0); sigaction(SIGILL, &action, 0);
    uint64_t address = strtoull(argv[2], 0, 16);
    FILE* segments = fopen(argv[1], "rb");
    uint32_t count = 0;
    if (fread(&count, 4, 1, segments) != 1) return 2;
    struct { uint64_t vaddr, filesz, memsz; unsigned char* data; } seg[4096];
    if (count > 4096) return 2;
    for (uint32_t index = 0; index < count; ++index) {
        if (fread(&seg[index].vaddr,8,1,segments)!=1||fread(&seg[index].filesz,8,1,segments)!=1||fread(&seg[index].memsz,8,1,segments)!=1) return 2;
        seg[index].data = malloc(seg[index].filesz ? seg[index].filesz : 1);
        if (seg[index].filesz && fread(seg[index].data, 1, seg[index].filesz, segments) != (size_t)seg[index].filesz) return 4;
    }
    /* A 4 KiB page can host several segments; map every page once, otherwise MAP_FIXED
       discards the bytes of a segment that was copied into a page an earlier segment mapped. */
    uint64_t low = ~0ull, high = 0;
    for (uint32_t index = 0; index < count; ++index) {
        uint64_t page = seg[index].vaddr & ~0xfffull;
        uint64_t end = page + (seg[index].vaddr & 0xfff) + seg[index].memsz;
        if (page < low) low = page;
        if (end > high) high = end;
    }
    if (high > low) {
        void* region = mmap((void*)(BASE + low), high - low, 3, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (region == MAP_FAILED) return 3;
    }
    for (uint32_t index = 0; index < count; ++index)
        if (seg[index].filesz) memcpy((void*)(BASE + seg[index].vaddr), seg[index].data, seg[index].filesz);
    /* The guest may call or jump anywhere in its own image, not just into the entry page: a page
       that is mapped read/write but not executable faults on the first instruction fetched from
       it, which reads as the guest and the reference "agreeing" on a fault. */
    if (high > low) mprotect((void*)(BASE + low), high - low, 7);
    if (mprotect((void*)(BASE + (address & ~0xfffull)), 0x1000, 7) != 0) return 5;
    struct regs in, out;
    mmap((void*)(BASE+0x70000000), 0x100000, 3, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    void* scratch = mmap((void*)0x140000000ULL + 0x60000000, 0x100000, 3, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
    if (scratch == MAP_FAILED) return 8;
    FILE* pages = fopen(argv[5], "rb");
    if (pages) { if (fread((void*)(BASE + 0x60000000), 1, 0x10000, pages) != 0x10000) return 9; fclose(pages); }
    FILE* input = fopen(argv[3], "rb");
    if (fread(&in, 1, sizeof(in), input) != sizeof(in)) return 6;
    memset(&out, 0, sizeof(out));
    __asm__ volatile("vzeroall" ::: "memory");
    __asm__ volatile("fninit" ::: "memory");  /* the AOT register file starts with zeroed vectors */
    invoke((void*)(BASE + address), &in, &out, (uint64_t*)(BASE + 0x70080000), 0x10000);
    unsigned char fx[512] __attribute__((aligned(16)));
    __asm__ volatile("fxsave %0" : "=m"(fx));
    unsigned char ymm[16][16] __attribute__((aligned(16)));
    #define Y(i) __asm__ volatile("vextractf128 $1, %%ymm" #i ", %0" : "=m"(ymm[i]));
    Y(0) Y(1) Y(2) Y(3) Y(4) Y(5) Y(6) Y(7) Y(8) Y(9) Y(10) Y(11) Y(12) Y(13) Y(14) Y(15)
    uint64_t flags; __asm__ volatile("pushfq\n popq %0" : "=r"(flags));
    FILE* output = fopen(argv[4], "wb");
    fwrite(&out, 1, sizeof(out), output);
    fwrite(&flags, 1, 8, output);
    fwrite(fx, 1, 512, output);
    fwrite(ymm, 1, 256, output);
    fwrite((void*)(BASE + 0x60000000), 1, 0x10000, output);
    fclose(output); fclose(input); fclose(segments);
    return 0;
}
"""

TLS_STUB = 'extern "C" void* NativeAotTlsBase_nid_no_patch(void) { return 0; }\n'

# The real-image path maps the segments itself (with the profile's relocations applied), so the
# generated native_image_init's NativeAotMapImage call is a no-op here.
REAL_STUB = ('extern "C" void* NativeAotTlsBase_nid_no_patch(void) { return 0; }\n'
            'extern "C" void NativeAotMapImage_nid_no_patch(void*, unsigned long) {}\n'
            'extern "C" void NativeAotApplyRelocations_nid_no_patch(void* const*, unsigned long) {}\n'
            'extern "C" void Aps5GuestTlsRegister_nid_no_patch(void*) {}\n')


_RUNNER = None
_SCRATCH_DIRS = []


def _scratch(prefix):
    """A per-process scratch directory, removed when the process exits.

    These directories hold a built object or binary, so they are reused for the process's lifetime
    rather than removed per call; the exit hook keeps a long batch from filling TMPDIR.
    """
    directory = Path(tempfile.mkdtemp(prefix=prefix))
    _SCRATCH_DIRS.append(directory)
    return directory


def _cleanup():
    while _SCRATCH_DIRS:
        shutil.rmtree(_SCRATCH_DIRS.pop(), ignore_errors=True)


atexit.register(_cleanup)


def build_runner(directory):
    """The x86 reference runner, built once per process and reused for every case."""
    global _RUNNER
    if _RUNNER is not None and Path(_RUNNER).exists():
        return _RUNNER
    source = directory / "runner.c"
    source.write_text(RUNNER)
    binary = _scratch("runner-") / "runner"
    subprocess.run(["xcrun", "clang", "-arch", "x86_64", "-O1", str(source), "-o", str(binary)],
                   check=True, capture_output=True)
    _RUNNER = binary
    return binary


def build_arm64(ir, directory, stub_source=None):
    if stub_source is not None:
        # The function calls others: link the generated recorded-call replay stubs, plus the TLS
        # stub because the caller may still reference the runtime TLS base.
        from toolchain import build_native_object
        build_native_object(ir, directory / "native.o")
        (directory / "replay_stubs.c").write_text(stub_source)
        subprocess.run(["xcrun", "clang", "-arch", "arm64", "-O2", "-c", str(directory / "replay_stubs.c"),
                        "-o", str(directory / "replay_stubs.o")], check=True, capture_output=True)
        stub = directory / "tls_stub.cc"
        stub.write_text(TLS_STUB)
        stub_object = directory / "tls_stub.o"
        subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-c", str(stub), "-o", str(stub_object)],
                       check=True, capture_output=True)
        extra = [str(directory / "replay_stubs.o"), str(stub_object)]
        if "NativeAotDispatch_nid_no_patch" in ir:
            dispatch = REPO / "core" / "libs" / "native" / "NativeAotDispatch.cpp"
            subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-O2", "-c", str(dispatch),
                            "-o", str(directory / "d.o")], check=True, capture_output=True)
            extra.append(str(directory / "d.o"))
        subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-dynamiclib", str(directory / "native.o"), *extra,
                        "-o", str(directory / "native.dylib")], check=True, capture_output=True)
        return directory / "native.dylib"
    try:
        return replay.build_arm64(ir, directory)
    except subprocess.CalledProcessError:
        # A TLS-using function references the runtime TLS base; link a stub so it still runs.
        from toolchain import build_native_object
        build_native_object(ir, directory / "native.o")
        stub = directory / "tls_stub.cc"
        stub.write_text(TLS_STUB)
        stub_object = directory / "tls_stub.o"
        subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-c", str(stub), "-o", str(stub_object)],
                       check=True, capture_output=True)
        extra = [str(stub_object)]
        if "NativeAotDispatch_nid_no_patch" in ir:
            dispatch = REPO / "core" / "libs" / "native" / "NativeAotDispatch.cpp"
            subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-O2", "-c", str(dispatch), "-o", str(directory / "d.o")],
                           check=True, capture_output=True)
            extra.append(str(directory / "d.o"))
        subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-dynamiclib", str(directory / "native.o"), *extra,
                        "-o", str(directory / "native.dylib")], check=True, capture_output=True)
        return directory / "native.dylib"


def arm_state(dylib, name, registers, memory, timeout=30, image=None):
    """Run the ARM64 function in a forked child (so an infinite loop can be killed) and return
    the register file bytes plus the scratch bytes, or None on a timeout/fault.

    `image` is the real module image's segment list: mapping it at BASE + vaddr is what makes a
    guest_data reference (and the native dispatch table's keys) resolve."""
    out_path = _scratch("arm-") / "state.bin"
    try:
        return _arm_state_run(out_path, dylib, name, registers, memory, timeout, image)
    finally:
        # One directory per call would otherwise accumulate for the life of a batch.
        shutil.rmtree(out_path.parent, ignore_errors=True)
        if out_path.parent in _SCRATCH_DIRS:
            _SCRATCH_DIRS.remove(out_path.parent)


def _arm_state_run(out_path, dylib, name, registers, memory, timeout, image):
    pid = os.fork()
    if pid == 0:
        try:
            libc = ctypes.CDLL(None)
            libc.mmap.restype = ctypes.c_void_p
            libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
            libc.mmap(ctypes.c_void_p(SCRATCH), SCRATCH_MAP, 3, 0x02 | 0x1000 | 0x10, -1, 0)
            ctypes.memmove(SCRATCH, memory, len(memory))
            libc.mmap(ctypes.c_void_p(BASE + 0x70000000), 0x100000, 3, 0x02 | 0x1000 | 0x10, -1, 0)
            if image is not None:
                real_image.map_segments(image)
            library = ctypes.CDLL(str(dylib))
            function = getattr(library, name)
            function.restype = None
            function.argtypes = [ctypes.c_void_p]
            regfile = (ctypes.c_uint64 * 123)()
            for index, register in enumerate(replay.UNIFORM_GPRS):
                regfile[index] = registers.get(register, 0)
            function(ctypes.byref(regfile))
            out_path.write_bytes(bytes(regfile) + ctypes.string_at(SCRATCH, SCRATCH_SIZE))
            os._exit(0)
        except BaseException:
            import traceback
            out_path.write_bytes(b"ERROR" + traceback.format_exc().encode())
            os._exit(1)
    deadline = time.time() + timeout
    status = None
    while time.time() < deadline:
        done, _ = os.waitpid(pid, os.WNOHANG)
        if done == pid:
            status = _
            break
        time.sleep(0.05)
    if status is None:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        return "timeout"
    if os.WIFSIGNALED(status):
        return "fault"  # the guest dereferenced something bad; the handler never ran
    if not out_path.exists():
        return "timeout"
    data = out_path.read_bytes()
    if data[:5] == b"ERROR":
        raise RuntimeError(data[5:].decode("utf-8", "replace")[-400:])
    if os.WEXITSTATUS(status) != 0:
        return "fault"
    return data


def _regfile_geps(ir):
    """Names of the pointers the uniform epilogue stores through (they come from a %regfile gep)."""
    geps, pending = set(), None
    for line in ir.splitlines():
        text = line.strip()
        if text.startswith('%') and 'getelementptr inbounds %regfile' in text:
            pending = text.split(' ', 1)[0]
            geps.add(pending)
        elif text.startswith('store ') and pending and pending in text:
            continue
    return geps


def plant_ir(ir, plant, address):
    """Plant a defect in the emitted IR, so the harness has to catch a known miscompile. Each plant
    targets a feature the harness compares; the proof is that the mismatch names that feature."""
    if plant is None:
        return ir
    lines = ir.splitlines()
    bank = {'gpr1': (0, 0, 'add i64', '1'), 'gpr1-caller': (0, 0, 'add i64', '1'), 'xmm1': (1, 0, 'xor i128', '1'),
            'float-ulp': (1, 0, 'xor i128', '1'), 'flags-of': (3, 0, 'xor i64', '2048'),
            'flags-of-shr1': (3, 0, 'xor i64', '2048')}[plant] if plant != 'store-drop' else None
    if bank is not None:
        group, index, operation, value = bank
        marker = f'getelementptr inbounds %regfile, ptr %rf, i64 0, i32 {group}, i64 {index}'
        for position, line in enumerate(lines):
            if marker in line:
                pointer = line.strip().split(' ', 1)[0]
                for following in range(position + 1, len(lines)):
                    if lines[following].strip().startswith('store ') and (pointer + ',') in lines[following]:
                        original = lines[following].strip().split(' ', 2)[2].split(',')[0]
                        lines.insert(following, f'  %plant = {operation} {original}, {value}')
                        lines[following + 1] = lines[following + 1].replace(original, '%plant', 1)
                        return '\n'.join(lines) + '\n'
        raise ValueError(f'plant {plant}: no regfile store for the function at 0x{address:x}')
    if plant == 'store-drop':
        geps = _regfile_geps(ir)
        for position in range(len(lines) - 1, -1, -1):
            text = lines[position].strip()
            if text.startswith('store ') and not any(gep in text for gep in geps):
                lines[position] = '  ; dropped store'
                return '\n'.join(lines) + '\n'
        raise ValueError(f'plant store-drop: no guest store for the function at 0x{address:x}')
    raise ValueError(f'unknown plant {plant}')


def run_case(address, seed, directory, plant=None, profile=None, record=True):
    sizes = profile.sizes if profile is not None else harness.fde_sizes(STARTS)
    title = harness.Title(ELF)
    # Contracts with the real image's segment map and guest_data (the way tools/native/title_image.py
    # builds them) were tried here: they do compile the low-address references, but in the synthetic
    # image the compiler treats the function's own code page as data, and the runtime does not map
    # every such page, so previously-passing functions hang or fault. Off until the harness builds
    # contracts from the real image (see REPORT20).
    sites = [site for site in call_record.find_sites(title, sizes, address)
             if site['target'] in sizes and sizes[site['target']] and site['target'] != address]
    callees = sorted({site['target'] for site in sites})
    result = harness.compile_one(title, sizes, address, CLOSURE_LIMIT, directory, uniform=True,
                                 external=set(callees) if record else (), profile=profile)
    if result["status"] != "compiled":
        return {"status": "rejected", "reason": result.get("reason", "")[:120], "call_sites": len(sites)}
    ir, image = result["ir"], (directory / f"{address:x}.elf").read_bytes()
    ir = plant_ir(ir, plant, address)
    os.environ["ANYPS5_AOT_EBOOT"] = str(directory / f"{address:x}.elf")
    rng = random.Random(seed)
    memory = rng.randbytes(SCRATCH_SIZE)
    registers = {item: SCRATCH + (rng.randrange(0, SCRATCH_SIZE // 4) & ~7)
                 for item in replay.UNIFORM_GPRS if item != "rsp"}
    # The x86 runner reaches the guest through a `call`, so its guest sees rsp = STACK - 8. This is
    # inert on the ARM side: the AOT lowering overwrites the guest rsp with `&frame + 136` (a host
    # stack address) at entry, so the harness cannot choose it. See REPORT22 defect (b): that is a
    # compiler-side rsp emulation gap, and an `add rsp,imm` flag result follows the host address.
    registers["rsp"] = STACK - 8
    # A function that calls others is verified by recording those calls on the x86 side and
    # replaying them as native stubs, so its own code is tested without its callees having to
    # compile. The recorder must run before the ARM dylib is built: it produces the stubs.
    x86 = None
    stub_source = None
    if record and sites:
        try:
            records, x86 = call_record.record_calls(title, sizes, address, sites, registers, memory, directory)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            return {"status": "x86-fault", "reason": str(error)[-120:], "call_sites": len(sites)}
        stub_source = call_record.replay_stub_source(records, callees)
    dylib = build_arm64(ir, directory, stub_source)
    library = ctypes.CDLL(str(dylib))
    data_ranges = [(vaddr, memsz) for vaddr, _filesz, memsz, _data in replay.elf_segments(image) if memsz]
    arm = arm_state(dylib, f"sub_{address:x}", registers, memory)
    if x86 is None:
        runner = build_runner(directory)
        (directory / "segments.bin").write_bytes(_segments(image))
        (directory / "case.bin").write_bytes(
            b"".join(int(registers.get(name, 0)).to_bytes(8, "little") for name in replay.REGISTERS))
        (directory / "pages.bin").write_bytes(memory)
        try:
            completed = subprocess.run([str(runner), str(directory / "segments.bin"), hex(address),
                                        str(directory / "case.bin"), str(directory / "out.bin"), str(directory / "pages.bin")],
                                       capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            return {"status": "x86-timeout", "call_sites": len(sites)}
        if arm == "fault" and completed.returncode != 0:
            # Both runners died on the same wild access: the randomized entry state drove the guest
            # into undefined behavior, and they agree that it is undefined.
            return {"status": "both-fault", "call_sites": len(sites)}
        if completed.returncode != 0:
            return {"status": "x86-fault", "code": completed.returncode, "call_sites": len(sites)}
        x86 = (directory / "out.bin").read_bytes()
    if arm in ("timeout", "fault"):
        return {"status": arm, "call_sites": len(sites)}
    return {"status": "ok", "arm": arm, "x86": x86, "library": library, "data_ranges": data_ranges,
            "call_sites": len(sites)}


_REAL_OBJECTS = None


def build_arm64_real(ir, directory):
    """Link the real-image native object with the runtime dispatch table the compiler's
    NativeAotDispatch lowering needs. The two runtime objects are built once per process."""
    global _REAL_OBJECTS
    from toolchain import build_native_object
    build_native_object(ir, directory / "native.o")
    if _REAL_OBJECTS is None or not all(Path(item).exists() for item in _REAL_OBJECTS):
        folder = _scratch("realobj-")
        dispatch = REPO / "core" / "libs" / "native" / "NativeAotDispatch.cpp"
        subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-O2", "-c", str(dispatch),
                        "-o", str(folder / "dispatch.o")], check=True, capture_output=True)
        (folder / "real_stub.cc").write_text(REAL_STUB)
        subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-c", str(folder / "real_stub.cc"),
                        "-o", str(folder / "real_stub.o")], check=True, capture_output=True)
        _REAL_OBJECTS = (str(folder / "dispatch.o"), str(folder / "real_stub.o"))
    subprocess.run(["xcrun", "clang++", "-arch", "arm64", "-dynamiclib", str(directory / "native.o"),
                    *_REAL_OBJECTS, "-o", str(directory / "native.dylib")], check=True, capture_output=True)
    return directory / "native.dylib"


def saturated_memory(rng, size=SCRATCH_SIZE):
    """Scratch bytes in which every 8-byte slot names a valid object.

    A real heap does not look like random bytes: a field that holds a pointer holds the address of
    a mapped object, so a load-then-dereference chain stays inside mapped memory. With random bytes
    the guest loads a garbage address and both runners die on the same wild access, which is
    agreement on undefined behavior rather than a comparison (REPORT22: 73.85 % `both-fault`).
    Seeding every slot with a pointer into this window keeps any such chain valid.
    """
    slots = size // 8
    data = bytearray(size)
    for index in range(slots):
        struct.pack_into("<Q", data, index * 8, SCRATCH + 8 * rng.randrange(slots))
    return bytes(data)


def realistic_state(rng, segments=(), recorded=None):
    """An entry state whose pointer registers and scratch slots all name mapped objects.

    Registers point into the scratch window (mapped by both runners), with a share pointing at the
    real image's writable data so a function can read a real object as well. `recorded` replaces
    them with the GPRs a real run had at this function's entry (the rsp stays the runner's: the
    recorded one names the real run's stack, which this harness does not map).
    """
    memory = saturated_memory(rng)
    if recorded is not None:
        registers = {name: recorded.get(name, 0) for name in replay.UNIFORM_GPRS}
        registers["rsp"] = RUNNER_ENTRY_RSP
        return registers, memory
    slots = SCRATCH_SIZE // 8
    writable = [(vaddr, memsz) for vaddr, _filesz, memsz, _data, flags in segments
                if flags & 2 and memsz >= 16]
    registers = {}
    for index, name in enumerate(replay.UNIFORM_GPRS):
        if name == "rsp":
            continue
        if writable and index % 4 == 3:
            vaddr, memsz = writable[rng.randrange(len(writable))]
            registers[name] = BASE + vaddr + 8 * rng.randrange(memsz // 8)
        else:
            registers[name] = SCRATCH + 8 * rng.randrange(slots)
    registers["rsp"] = RUNNER_ENTRY_RSP
    return registers, memory


def runner_fault(completed):
    """The `addr=... rip=...` a faulting runner printed, for a fault census."""
    for line in completed.stderr.decode(errors="replace").splitlines():
        if "[runner] fault" in line:
            return line.split("[runner] fault", 1)[1].strip()
    return ""


def run_case_real(address, seed, directory, profile, plant=None, saturate_segments=False,
                   recorded=None):
    """Verify against the real module image: the compiler reads the real eboot and the real module
    profile (guest_data + dispatch), both runners map the real segments at BASE + vaddr with the
    profile's pointer relocations applied, and an indirect call or a tail call into a function
    outside the closure no longer rejects the function."""
    rng = random.Random(seed)
    segments = real_image.segments(ELF)
    segments = real_image.patch(segments, profile.relocations)
    if saturate_segments:
        segments = real_image.saturate(segments, random.Random(seed ^ 0x5EED),
                                       extra=[(SCRATCH, SCRATCH_SIZE)])
    title = harness.Title(ELF)
    _closure, contracts = harness.real_contracts(title, profile, address, CLOSURE_LIMIT,
                                                 real_image.sha256(ELF), BASE, title.elf["e_entry"])
    result = harness.compile_real(str(ELF), contracts)
    if result["status"] != "compiled":
        return {"status": "rejected", "reason": result.get("reason", "")[:160], "call_sites": 0}
    ir = plant_ir(result["ir"], plant, address)
    os.environ["ANYPS5_AOT_EBOOT"] = str(ELF)
    dylib = build_arm64_real(ir, directory)
    library = ctypes.CDLL(str(dylib))
    data_ranges = [(vaddr, memsz) for vaddr, _filesz, memsz, _data, _flags in segments]
    registers, memory = realistic_state(rng, segments, recorded)
    arm = arm_state(dylib, f"sub_{address:x}", registers, memory, image=segments)
    runner = build_runner(directory)
    (directory / "segments.bin").write_bytes(real_image.blob(segments))
    (directory / "case.bin").write_bytes(
        b"".join(int(registers.get(name, 0)).to_bytes(8, "little") for name in replay.REGISTERS))
    (directory / "pages.bin").write_bytes(memory)
    try:
        completed = subprocess.run([str(runner), str(directory / "segments.bin"), hex(address),
                                    str(directory / "case.bin"), str(directory / "out.bin"),
                                    str(directory / "pages.bin")], capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"status": "x86-timeout", "call_sites": 0}
    if arm == "fault" and completed.returncode != 0:
        return {"status": "both-fault", "call_sites": 0, "fault": runner_fault(completed)}
    if completed.returncode != 0:
        return {"status": "x86-fault", "code": completed.returncode, "call_sites": 0,
                "fault": runner_fault(completed)}
    if arm in ("timeout", "fault"):
        return {"status": arm, "call_sites": 0}
    x86 = (directory / "out.bin").read_bytes()
    return {"status": "ok", "arm": arm, "x86": x86, "library": library, "data_ranges": data_ranges,
            "call_sites": 0}


def _segments(image):
    stream = __import__("io").BytesIO()
    entries = replay.elf_segments(image)
    stream.write(struct.pack("<I", len(entries)))
    for vaddr, filesz, memsz, data in entries:
        stream.write(struct.pack("<QQQ", vaddr, filesz, memsz))
        stream.write(data)
    return stream.getvalue()


def normalize_nan(blob):
    """Canonicalize every 4-byte lane that is a NaN: the FP profile leaves the payload and
    sign of a NaN unobserved, so the two runners may legitimately differ there."""
    value = bytearray(blob)
    for offset in range(0, len(value) - 3, 4):
        bits = int.from_bytes(value[offset:offset + 4], "little")
        if bits & 0x7f800000 == 0x7f800000 and bits & 0x007fffff:
            value[offset:offset + 4] = (0x7fc00000).to_bytes(4, "little")
    return bytes(value)


def nan_slot(blob, offset, width):
    if offset + width > len(blob):
        return False
    bits = int.from_bytes(blob[offset:offset + width], "little")
    if width == 4:
        return bits & 0x7f800000 == 0x7f800000 and bits & 0x007fffff != 0
    return bits & 0x7ff0000000000000 == 0x7ff0000000000000 and bits & 0x000fffffffffffff != 0


def memory_explained_by_nan(arm, x86, offset):
    for width in (4, 8):
        base = offset & ~(width - 1)
        if nan_slot(arm, base, width) and nan_slot(x86, base, width):
            return True
    return False


def extended_to_double(raw):
    """The double nearest an x87 80-bit extended value (the AOT stack is f64)."""
    bits = int.from_bytes(raw, "little")
    sign, exponent, significand = (bits >> 79) & 1, (bits >> 64) & 0x7fff, bits & ((1 << 64) - 1)
    if exponent == 0:
        value = 0.0
    elif exponent == 0x7fff:
        value = float("inf") if significand == (1 << 63) else float("nan")
    else:
        import math
        value = math.ldexp(significand / float(1 << 63), exponent - 16383)
    return -value if sign else value


def compare(arm, x86, library, data_ranges):
    """Compare GPRs (pointer-normalized), RFLAGS, xmm/ymm and the scratch bytes."""
    gprs = struct.unpack_from("<16Q", x86, 0)
    flags = struct.unpack_from("<Q", x86, 128)[0]
    xmm = x86[136 + 160:136 + 160 + 256]
    ymm_upper = x86[136 + 512:136 + 512 + 256]
    scratch = x86[136 + 512 + 256:136 + 512 + 256 + SCRATCH_SIZE]
    arm_gprs = struct.unpack_from("<16Q", arm, 0)
    arm_xmm = arm[128:128 + 256]
    arm_ymm = arm[128 + 256:128 + 512]
    arm_scratch = arm[REGFILE:REGFILE + SCRATCH_SIZE]
    arm_flags = struct.unpack_from("<Q", arm, 640)[0]
    arm_mask = struct.unpack_from("<Q", arm, 648)[0]
    arm_x87 = struct.unpack_from("<8d", arm, 656)
    differences = []
    mask = (1 << 0) | (1 << 2) | (1 << 6) | (1 << 7) | (1 << 11)
    # Only the flags the contract defines are compared (the ABI publishes a definedness mask).
    if (arm_flags ^ flags) & (arm_mask & mask):
        differences.append(f"flags: arm={arm_flags & arm_mask & mask:#x} x86={flags & arm_mask & mask:#x}")
    if any(arm_x87):
        # The AOT x87 stack is f64; compare only when the function actually used it.
        for index in range(8):
            reference = extended_to_double(x86[136 + 32 + index * 16:136 + 32 + index * 16 + 10])
            value = arm_x87[index]
            if value != reference and not (value != value and reference != reference):
                differences.append(f"x87 st({index}): arm={value!r} x86={reference!r}")
    for index, name in enumerate(replay.UNIFORM_GPRS):
        if name == "rsp":
            continue
        arm_value = arm_gprs[index]
        x86_value = gprs[replay.REGISTERS.index(name)]
        if arm_value == x86_value:
            continue
        normalized = replay.normalize_pointer(library, arm_value, data_ranges)
        if normalized is not None and normalized == (x86_value - BASE) & 0xffffffffffffffff:
            continue
        # guest_data: the AOT pointer is the guest vaddr already (or the guest vaddr slid by BASE).
        if arm_value in ((x86_value - BASE) & 0xffffffffffffffff, x86_value):
            continue
        differences.append(f"{name}: arm={arm_value:#x} x86={x86_value:#x}")
    if normalize_nan(arm_xmm) != normalize_nan(xmm):
        differences.append("xmm")
    if normalize_nan(arm_ymm) != normalize_nan(ymm_upper):
        differences.append("ymm-upper")
    unexplained = [i for i in range(SCRATCH_SIZE) if arm_scratch[i] != scratch[i]
                   and not memory_explained_by_nan(arm_scratch, scratch, i)]
    if unexplained:
        first = unexplained[0]
        base = first & ~7
        arm_slot = int.from_bytes(arm_scratch[base:base + 8], "little")
        x86_slot = int.from_bytes(scratch[base:base + 8], "little")
        normalized = replay.normalize_pointer(library, arm_slot, data_ranges)
        if normalized is None or normalized != (x86_slot - BASE) & 0xffffffffffffffff:
            differences.append(f"memory@{first:#x}: arm={arm_scratch[first]:#x} x86={scratch[first]:#x}")
    return flags, differences


def worker(arguments):
    address, seed_count = arguments[:2]
    plant = arguments[2] if len(arguments) > 2 else None
    directory = Path(tempfile.mkdtemp(prefix=f"full-{address:x}-"))
    try:
        return _worker_cases(address, seed_count, plant, directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _worker_cases(address, seed_count, plant, directory):
    outcomes = []
    for seed in range(seed_count):
        try:
            outcome = run_case(address, seed, directory, plant)
        except Exception as error:
            outcomes.append({"address": address, "seed": seed, "status": "error", "reason": str(error)[-100:]})
            continue
        if outcome["status"] != "ok":
            outcomes.append({"address": address, "seed": seed, "status": outcome["status"]})
            continue
        flags, differences = compare(outcome["arm"], outcome["x86"], outcome["library"], outcome["data_ranges"])
        if differences:
            outcomes.append({"address": address, "seed": seed, "status": "mismatch",
                             "differences": differences[:6], "flags": flags})
    return outcomes


def main():
    if sys.argv[1] == "--campaign":
        count, seed_count = int(sys.argv[2]), int(sys.argv[3])
        starts = sorted({int(line, 16) for line in STARTS.read_text().split()})
        sample = starts[::max(1, len(starts) // count)][:count]
        jobs = [(address, seed_count) for address in sample]
        results = []
        context = multiprocessing.get_context("fork")
        with context.Pool(2) as pool:
            for index, part in enumerate(pool.imap_unordered(worker, jobs, chunksize=2)):
                results.extend(part)
                if (index + 1) % 100 == 0:
                    print(f"progress {index + 1}/{len(jobs)} mismatches={sum(1 for r in results if r['status'] == 'mismatch')}", flush=True)
        mismatches = [r for r in results if r["status"] == "mismatch"]
        counts = {}
        for entry in results:
            counts[entry["status"]] = counts.get(entry["status"], 0) + 1
        compared = len(sample) * seed_count - counts.get("rejected", 0) * seed_count
        print(json.dumps({"sample": len(sample), "seeds": seed_count, "cases": len(sample) * seed_count,
                          "mismatches": len(mismatches), "status": counts,
                          "other": [r for r in results if r["status"] not in ("mismatch",)][:20],
                          "details": mismatches[:40]}, indent=1))
        return
    address = int(sys.argv[1], 16)
    directory = Path(tempfile.mkdtemp(prefix=f"full-{address:x}-"))
    plant = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].isdigit() else None
    seeds = [int(value) for value in sys.argv[2 + (1 if plant else 0):]]
    try:
        for seed in seeds:
            outcome = run_case(address, seed, directory, plant)
            print(json.dumps({"address": address, "seed": seed, "plant": plant, "status": outcome["status"],
                              "differences": compare(outcome["arm"], outcome["x86"], outcome["library"], outcome["data_ranges"])[1][:6] if outcome["status"] == "ok" else None}))
    finally:
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    main()

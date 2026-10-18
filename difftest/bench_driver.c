/* Microbenchmark driver for the generated ARM64 code against the x86-64 guest code.
 *
 * Both builds call the function under test `iterations` times through the same memory
 * register file (the uniform ABI the differential harness already uses), so the only
 * difference is the machine code that runs: the AOT-compiled ARM64 body or the original
 * x86-64 body executed by Rosetta.
 *
 *   arm:  bench_driver <dylib> <symbol> <iterations> <rf.bin> <scratch.bin> <out.bin> [segments.bin]
 *   x86:  bench_driver <segments.bin> <address-hex> <stubs.txt> <iterations> <rf.bin> <scratch.bin> <out.bin>
 *
 * out.bin: 16 GPRs + flags + the scratch window. `stubs.txt` lists the guest addresses whose
 * entry byte is replaced by `ret`: on the ARM side those functions are external stubs that
 * return immediately, so both sides execute only the function under test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>

#define BASE 0x140000000ULL
#define SCRATCH (BASE + 0x60000000ULL)
#define SCRATCH_SIZE 0x10000ULL
#define SCRATCH_MAP 0x100000ULL
#define STACK (BASE + 0x70000000ULL)
#define STACK_SIZE 0x100000ULL
#define STACK_WORDS 0x10000ULL
#define STACK_ENTRY_RSP (STACK + STACK_WORDS * 8 - 8)
#define REGFILE 123

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

static void fail(const char* what) {
    fprintf(stderr, "[bench] %s\n", what);
    _exit(1);
}

static void map_at(uint64_t address, uint64_t size, int protect) {
    void* page = mmap((void*)address, size, 3, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        fprintf(stderr, "[bench] map_at %#llx size %#llx\n", (unsigned long long)address, (unsigned long long)size);
        _exit(3);
    }
    if (protect && mprotect((void*)address, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect");
        _exit(3);
    }
}

static unsigned char* read_file(const char* path, uint64_t* size) {
    FILE* file = fopen(path, "rb");
    if (file == NULL) fail("open input");
    if (fseek(file, 0, SEEK_END) != 0) fail("seek");
    long length = ftell(file);
    if (length < 0) fail("tell");
    unsigned char* data = malloc((size_t)length ? (size_t)length : 1);
    if (data == NULL) fail("alloc");
    rewind(file);
    if (fread(data, 1, (size_t)length, file) != (size_t)length) fail("read");
    fclose(file);
    if (size != NULL) *size = (uint64_t)length;
    return data;
}

/* Segments stream: count, then (vaddr, filesz, memsz) and filesz bytes per entry, mapped at
 * BASE + vaddr. The regions are page-aligned and non-overlapping (the caller merges them), so
 * each one gets its own mapping. The x86 side executes the guest bytes there; the ARM side only
 * needs it when the compiler referenced title data at its guest address. */
static void map_segments(const char* path) {
    uint64_t length = 0;
    unsigned char* blob = read_file(path, &length);
    uint32_t count = 0;
    if (length < 4) fail("segments");
    memcpy(&count, blob, 4);
    uint64_t offset = 4;
    for (uint32_t index = 0; index < count; ++index) {
        uint64_t vaddr, filesz, memsz;
        if (offset + 24 > length) fail("segments entry");
        memcpy(&vaddr, blob + offset, 8);
        memcpy(&filesz, blob + offset + 8, 8);
        memcpy(&memsz, blob + offset + 16, 8);
        offset += 24;
        if (offset + filesz > length) fail("segments data");
        map_at(BASE + vaddr, memsz, 0);
        if (filesz) memcpy((void*)(BASE + vaddr), blob + offset, filesz);
        offset += filesz;
    }
    free(blob);
}

static void map_runtime(const char* scratch_path, uint64_t* scratch_bytes) {
    map_at(SCRATCH, SCRATCH_MAP, 0);
    map_at(STACK, STACK_SIZE, 0);
    uint64_t length = 0;
    unsigned char* bytes = read_file(scratch_path, &length);
    if (length > SCRATCH_SIZE) fail("scratch too large");
    memcpy((void*)SCRATCH, bytes, length);
    free(bytes);
    *scratch_bytes = length;
}

/* iterations == 0: size the timed loop so one round takes about 50 ms. */
static uint64_t tune_iterations(uint64_t requested, uint64_t probe_ns, uint64_t probe_count) {
    if (requested != 0) return requested;
    double per_call = (double)probe_ns / (double)probe_count;
    uint64_t tuned = (uint64_t)(50000000.0 / (per_call > 0.0 ? per_call : 1.0));
    if (tuned < 200) tuned = 200;
    if (tuned > 20000000) tuned = 20000000;
    return tuned;
}

static void write_out(const char* path, const uint64_t* gprs, uint64_t flags, uint64_t mask) {
    FILE* file = fopen(path, "wb");
    if (file == NULL) fail("open out");
    fwrite(gprs, 8, 16, file);
    fwrite(&flags, 8, 1, file);
    fwrite(&mask, 8, 1, file);
    fwrite((void*)SCRATCH, 1, SCRATCH_SIZE, file);
    fclose(file);
}

#define DEFINED_FLAGS ((1ull << 0) | (1ull << 2) | (1ull << 6) | (1ull << 7) | (1ull << 11))

#ifdef BENCH_X86
struct regs { uint64_t r[16]; };
/* `invoke` runs the guest and returns the flags the guest's `ret` left, captured before anything
 * else can write them. Reading pushfq out in the caller would report this loop's flags instead,
 * because the loop's own increment and compare write ZF and PF after the guest is done. */
uint64_t g_frame, g_out, g_entry, g_r9, g_r10, g_r11, g_zero;
extern uint64_t invoke(void* entry, struct regs* in, struct regs* out, uint64_t* stack, uint64_t stack_words);
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
"  pushfq\n  popq %rax\n"
"  movq _g_frame(%rip), %rbp\n  leaq -40(%rbp), %rsp\n  popq %r15\n  popq %r14\n  popq %r13\n  popq %r12\n  popq %rbx\n  popq %rbp\n  ret\n");

static void fault_handler(int signal_number, siginfo_t* info, void* context) {
    ucontext_t* uc = (ucontext_t*)context;
    fprintf(stderr, "[bench] fault sig=%d addr=%p rip=%llx\n", signal_number, info ? info->si_addr : NULL,
            uc ? (unsigned long long)uc->uc_mcontext->__ss.__rip : 0);
    _exit(9);
}

int main(int argc, char** argv) {
    if (argc < 8) fail("usage: bench_driver <segments> <address> <stubs> <iterations> <rf> <scratch> <out> [size]");
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = fault_handler;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &action, 0);
    sigaction(SIGBUS, &action, 0);
    sigaction(SIGILL, &action, 0);
    uint64_t address = strtoull(argv[2], NULL, 16);
    uint64_t iterations = strtoull(argv[4], NULL, 10);
    map_segments(argv[1]);
    uint64_t scratch_bytes = 0;
    map_runtime(argv[6], &scratch_bytes);    (void)scratch_bytes;
    /* Stub every declared callee: any call or jump into it returns immediately, so both sides
     * run only the function under test. */
    map_at(BASE + 0x40000000ULL, 0x1000, 1);
    *(unsigned char*)(BASE + 0x40000000ULL) = 0xC3;
    FILE* stubs = fopen(argv[3], "r");
    if (stubs != NULL) {
        unsigned long long target;
        uint64_t last_page = 0;
        while (fscanf(stubs, "%llx", &target) == 1) {
            uint64_t page = BASE + (target & ~0xfffull);
            if (page != last_page) {
                if (mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) fail("mprotect stub");
                last_page = page;
            }
            *(unsigned char*)(BASE + target) = 0xC3;
        }
        fclose(stubs);
    }
    uint64_t size = argc > 8 ? strtoull(argv[8], NULL, 16) : 0x1000;
    mprotect((void*)(BASE + (address & ~0xfffull)),
             (size + (address & 0xfff) + 0xfff) & ~0xfffull, PROT_READ | PROT_EXEC);
    struct regs registers;
    uint64_t length = 0;
    unsigned char* rf = read_file(argv[5], &length);
    if (length != sizeof(registers)) fail("regfile size");
    memcpy(&registers, rf, sizeof(registers));
    free(rf);
    /* Warm up (Rosetta translates on first execution), then take the best of three runs. */
    for (uint64_t index = 0; index < 200; ++index)
        invoke((void*)(BASE + address), &registers, &registers, (uint64_t*)STACK, STACK_WORDS);
    {
        uint64_t probe_start = now_ns();
        for (uint64_t index = 0; index < 200; ++index)
            invoke((void*)(BASE + address), &registers, &registers, (uint64_t*)STACK, STACK_WORDS);
        iterations = tune_iterations(iterations, now_ns() - probe_start, 200);
    }
    double best = 1e18;
    for (int round = 0; round < 3; ++round) {
        uint64_t start = now_ns();
        for (uint64_t index = 0; index < iterations; ++index)
            invoke((void*)(BASE + address), &registers, &registers, (uint64_t*)STACK, STACK_WORDS);
        uint64_t elapsed = now_ns() - start;
        double per_call = (double)elapsed / (double)iterations;
        if (per_call < best) best = per_call;
    }
    uint64_t flags = invoke((void*)(BASE + address), &registers, &registers, (uint64_t*)STACK, STACK_WORDS);
    printf("ns_per_call %.2f\niterations %llu\n", best, (unsigned long long)iterations);
    write_out(argv[7], registers.r, flags, DEFINED_FLAGS);
    return 0;
}
#else
#define _XOPEN_SOURCE 700
#include <dlfcn.h>
#include <ucontext.h>

static void arm_fault_handler(int signal_number, siginfo_t* info, void* context) {
    ucontext_t* uc = (ucontext_t*)context;
    fprintf(stderr, "[bench] fault sig=%d addr=%p pc=%llx\n", signal_number, info ? info->si_addr : NULL,
            uc ? (unsigned long long)uc->uc_mcontext->__ss.__pc : 0);
    _exit(9);
}

int main(int argc, char** argv) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = arm_fault_handler;
    action.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &action, 0);
    sigaction(SIGBUS, &action, 0);
    sigaction(SIGILL, &action, 0);
    if (argc < 7) fail("usage: bench_driver <dylib> <symbol> <iterations> <rf> <scratch> <out> [segments]");
    void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (library == NULL) {
        fprintf(stderr, "[bench] dlopen: %s\n", dlerror());
        return 2;
    }
    void (*function)(uint64_t*) = (void (*)(uint64_t*))dlsym(library, argv[2]);
    if (function == NULL) fail("dlsym");
    uint64_t iterations = strtoull(argv[3], NULL, 10);
    if (argc > 7) map_segments(argv[7]);
    uint64_t scratch_bytes = 0;
    map_runtime(argv[5], &scratch_bytes);
    uint64_t* regfile = (uint64_t*)calloc(REGFILE, 8);
    uint64_t length = 0;
    unsigned char* rf = read_file(argv[4], &length);
    if (length > 16 * 8) fail("regfile size");
    memcpy(regfile, rf, length);
    free(rf);
    for (uint64_t index = 0; index < 200; ++index) function(regfile);
    {
        uint64_t probe_start = now_ns();
        for (uint64_t index = 0; index < 200; ++index) function(regfile);
        iterations = tune_iterations(iterations, now_ns() - probe_start, 200);
    }
    double best = 1e18;
    for (int round = 0; round < 3; ++round) {
        uint64_t start = now_ns();
        for (uint64_t index = 0; index < iterations; ++index) function(regfile);
        uint64_t elapsed = now_ns() - start;
        double per_call = (double)elapsed / (double)iterations;
        if (per_call < best) best = per_call;
    }
    printf("ns_per_call %.2f\niterations %llu\n", best, (unsigned long long)iterations);
    write_out(argv[6], regfile, regfile[80], regfile[81]);
    return 0;
}
#endif

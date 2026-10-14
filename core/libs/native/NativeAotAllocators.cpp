// Fork-only: bind a title's allocator replacement table to its natively compiled allocator
// functions. The title's heap API entries are uniform-ABI functions (a pointer to the guest
// register file); the runtime calls them through the dispatch table. The generated
// native_image_init replaces each non-null slot with the matching typed wrapper below.
#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" void* NativeAotDispatch_nid_no_patch(std::uint64_t value);

namespace {

struct RegFile {
    std::uint64_t gpr[16];
    unsigned __int128 xmm[16];
    unsigned __int128 ymm_hi[16];
    std::uint64_t flags;
    std::uint64_t flags_mask;
    double x87[8];
    std::uint64_t x87_top;
    std::uint64_t stack[32];
};

// Slots 0..9 are the heap API; 10/11 are the table's initialize/finalize callbacks.
constexpr std::uint64_t kSlots = 12;
std::uint64_t allocatorTargets[kSlots] = {};

using UniformEntry = void (*)(void*);

// SysV argument 0..5 -> the uniform register file's GPR order (UNIFORM_GPRS).
constexpr int argumentSlot[6] = {7, 6, 2, 1, 8, 9};

std::uint64_t Call(std::uint64_t guest, const std::uint64_t* arguments, int count) {
    if (guest == 0) return 0;
    const auto native = reinterpret_cast<UniformEntry>(NativeAotDispatch_nid_no_patch(guest));
    if (native == nullptr) {
        std::fprintf(stderr, "[aot] allocator callback %#llx is not in the dispatch table\n",
                     static_cast<unsigned long long>(guest));
        std::abort();
    }
    RegFile registers{};
    for (int index = 0; index < count && index < 6; ++index)
        registers.gpr[argumentSlot[index]] = arguments[index];
    native(&registers);
    return registers.gpr[0];
}

}

extern "C" void* NativeAotAllocatorAllocate(std::uint64_t bytes) {
    const std::uint64_t arguments[1] = {bytes};
    return reinterpret_cast<void*>(Call(allocatorTargets[0], arguments, 1));
}

extern "C" void NativeAotAllocatorFree(void* pointer) {
    const std::uint64_t arguments[1] = {reinterpret_cast<std::uint64_t>(pointer)};
    static_cast<void>(Call(allocatorTargets[1], arguments, 1));
}

extern "C" void* NativeAotAllocatorCalloc(std::uint64_t count, std::uint64_t bytes) {
    const std::uint64_t arguments[2] = {count, bytes};
    return reinterpret_cast<void*>(Call(allocatorTargets[2], arguments, 2));
}

extern "C" void* NativeAotAllocatorReallocate(void* pointer, std::uint64_t bytes) {
    const std::uint64_t arguments[2] = {reinterpret_cast<std::uint64_t>(pointer), bytes};
    return reinterpret_cast<void*>(Call(allocatorTargets[3], arguments, 2));
}

extern "C" void* NativeAotAllocatorAlign(std::uint64_t alignment, std::uint64_t bytes) {
    const std::uint64_t arguments[2] = {alignment, bytes};
    return reinterpret_cast<void*>(Call(allocatorTargets[4], arguments, 2));
}

extern "C" void* NativeAotAllocatorRealign(void* pointer, std::uint64_t bytes, std::uint64_t alignment) {
    const std::uint64_t arguments[3] = {reinterpret_cast<std::uint64_t>(pointer), bytes, alignment};
    return reinterpret_cast<void*>(Call(allocatorTargets[5], arguments, 3));
}

extern "C" int NativeAotAllocatorPosixAlign(void** out, std::uint64_t alignment, std::uint64_t bytes) {
    const std::uint64_t arguments[3] = {reinterpret_cast<std::uint64_t>(out), alignment, bytes};
    return static_cast<int>(Call(allocatorTargets[6], arguments, 3));
}

extern "C" void NativeAotAllocatorInitialize(const void* api) {
    const std::uint64_t arguments[1] = {reinterpret_cast<std::uint64_t>(api)};
    static_cast<void>(Call(allocatorTargets[10], arguments, 1));
}

extern "C" void NativeAotAllocatorFinalize(const void* api) {
    const std::uint64_t arguments[1] = {reinterpret_cast<std::uint64_t>(api)};
    static_cast<void>(Call(allocatorTargets[11], arguments, 1));
}

extern "C" void* const nativeAotAllocatorWrappers[kSlots] = {
    reinterpret_cast<void*>(NativeAotAllocatorAllocate), reinterpret_cast<void*>(NativeAotAllocatorFree),
    reinterpret_cast<void*>(NativeAotAllocatorCalloc), reinterpret_cast<void*>(NativeAotAllocatorReallocate),
    reinterpret_cast<void*>(NativeAotAllocatorAlign), reinterpret_cast<void*>(NativeAotAllocatorRealign),
    reinterpret_cast<void*>(NativeAotAllocatorPosixAlign), nullptr, nullptr, nullptr,
    reinterpret_cast<void*>(NativeAotAllocatorInitialize), reinterpret_cast<void*>(NativeAotAllocatorFinalize)};

extern "C" void NativeAotBindAllocator_nid_no_patch(void** slot, std::uint64_t guest, std::uint64_t index) {
    if (slot == nullptr || index >= kSlots || nativeAotAllocatorWrappers[index] == nullptr) return;
    allocatorTargets[index] = guest;
    *slot = const_cast<void*>(nativeAotAllocatorWrappers[index]);
}

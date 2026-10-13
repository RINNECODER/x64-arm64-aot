#include "prx/libc/include/NativeAotImage.hpp"
#include "prx/libSceAgcDriver/Execution/include/VulkanDevice.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <sys/sysctl.h>

extern "C" {
void _init_env_nid_postfix();
std::uint64_t sceKernelGetDirectMemorySize();
int sceKernelAllocateDirectMemory(std::int64_t, std::int64_t, std::uint64_t, std::uint64_t, int, std::int64_t*);
int sceKernelMapDirectMemory(void**, std::uint64_t, int, int, std::int64_t, std::uint64_t);
int sceKernelReleaseDirectMemory(std::int64_t, std::uint64_t);
int sceVideoOutOpen(int, int, int, const void*);
int sceVideoOutClose(int);
}

int main(int argc, char**) {
    int translated = 0;
    std::size_t translatedSize = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &translatedSize, nullptr, 0) == 0 && translated)
        throw std::runtime_error("native runtime executed under translation");
    std::array<std::uint64_t, 8> parameters{};
    std::array<std::uint64_t, 7> libc{};
    std::array<std::uint64_t, 15> replacement{};
    parameters[0] = sizeof(parameters);
    parameters[1] = 0x4942524f;
    parameters[7] = reinterpret_cast<std::uint64_t>(libc.data());
    libc[0] = sizeof(libc);
    libc[6] = reinterpret_cast<std::uint64_t>(replacement.data());
    replacement[0] = sizeof(replacement);
    replacement[1] = 2;
    const NativeAotDataRange ranges[]{{parameters.data(), sizeof(parameters)},
        {libc.data(), sizeof(libc)}, {replacement.data(), sizeof(replacement)}};
    const NativeAotImage image{1, ranges, 3, nullptr, 0, parameters.data(), sizeof(parameters)};
    NativeAotRegisterImage_nid_no_patch(&image);
    _init_env_nid_postfix();
    auto* heap = static_cast<unsigned char*>(ApplicationHeapAllocate_nid_no_patch(1024));
    std::memset(heap, 0xa5, 1024);
    heap = static_cast<unsigned char*>(ApplicationHeapReallocate_nid_no_patch(heap, 2048));
    for (unsigned index = 0; index < 1024; ++index)
        if (heap[index] != 0xa5) throw std::runtime_error("native heap reallocation corrupted data");
    ApplicationHeapFree_nid_no_patch(heap);
    constexpr std::uint64_t bytes = 65536;
    std::int64_t physical = 0;
    if (sceKernelAllocateDirectMemory(0, sceKernelGetDirectMemorySize(), bytes, bytes, 3, &physical) != 0)
        throw std::runtime_error("direct memory allocation failed");
    void* mapped = nullptr;
    if (sceKernelMapDirectMemory(&mapped, bytes, 3, 0, physical, bytes) != 0)
        throw std::runtime_error("direct memory mapping failed");
    std::memset(mapped, 0x5a, bytes);
    for (std::uint64_t offset = 0; offset < bytes; ++offset)
        if (static_cast<unsigned char*>(mapped)[offset] != 0x5a)
            throw std::runtime_error("direct memory readback failed");
    if (sceKernelReleaseDirectMemory(physical, bytes) != 0)
        throw std::runtime_error("direct memory release failed");
    if (argc > 1) {
        AgcDriver::VulkanDevice device;
        std::printf("native GPU: %s\n", device.DeviceName().c_str());
        device.WaitIdle();
        const int handle = sceVideoOutOpen(255, 0, 0, nullptr);
        if (handle < 0 || sceVideoOutClose(handle) != 0)
            throw std::runtime_error("video output open/close failed");
    }
    std::puts("native ARM64 runtime: heap and direct memory passed");
}

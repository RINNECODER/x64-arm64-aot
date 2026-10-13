#include "prx/libc/include/ApplicationHeap.hpp"
#include "prx/libc/include/GuestAllocations.hpp"
#include "prx/libc/include/NativeAotImage.hpp"
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>

extern "C" void _init_env_nid_postfix();
extern "C" int sceKernelUsleep_nid_postfix(unsigned int);
extern "C" int sceKernelSendNotificationRequest(int, const void*, std::size_t, int);

namespace {

const std::array<unsigned char, 64> readonlyData{1, 2, 3};
std::array<unsigned char, 64> writableData{};

void Require(bool value, const char* reason) {
    if (!value) {
        std::fprintf(stderr, "native runtime: %s\n", reason);
        std::abort();
    }
}

}

int main() {
    std::array<std::uint64_t, 8> process{};
    std::array<std::uint64_t, 7> libc{};
    std::array<std::uint64_t, 15> replacement{};
    process[0] = sizeof(process);
    process[1] = 0x4942524f;
    process[7] = reinterpret_cast<std::uint64_t>(libc.data());
    libc[0] = sizeof(libc);
    libc[6] = reinterpret_cast<std::uint64_t>(replacement.data());
    replacement[0] = sizeof(replacement);
    replacement[1] = 2;
    const NativeAotDataRange ranges[]{{process.data(), sizeof(process)}, {libc.data(), sizeof(libc)},
        {replacement.data(), sizeof(replacement)}};
    const NativeAotImage image{1, ranges, 3, nullptr, 0, process.data(), sizeof(process)};
    NativeAotRegisterImage_nid_no_patch(&image);
    _init_env_nid_postfix();
    _init_env_nid_postfix();
    {
        GuestAllocations::Mutation mutation;
        mutation.RegisterMainImage();
        mutation.RegisterMainImage();
    }
    {
        const auto mappings = GuestAllocations::GuestAllocationsAcquireAll_nid_postfix();
        const auto find = [&](const void* pointer) {
            const auto address = reinterpret_cast<std::uintptr_t>(pointer);
            for (const auto& range : mappings)
                if (address >= range->address && address - range->address < range->bytes) return *range;
            throw std::runtime_error("main image address is not registered");
        };
        const auto ro = find(readonlyData.data());
        const auto rw = find(writableData.data());
        Require(ro.readable && !ro.writable && !ro.releasable, "readonly main-image protection");
        Require(rw.readable && rw.writable && !rw.releasable, "writable main-image protection");
    }
    auto* memory = static_cast<unsigned char*>(ApplicationHeapCalloc_nid_no_patch(64, 32));
    for (std::size_t index = 0; index < 2048; ++index) Require(memory[index] == 0, "calloc did not zero memory");
    std::memset(memory, 0x5a, 2048);
    memory = static_cast<unsigned char*>(ApplicationHeapReallocate_nid_no_patch(memory, 4096));
    for (std::size_t index = 0; index < 2048; ++index) Require(memory[index] == 0x5a, "realloc lost contents");
    ApplicationHeapFree_nid_no_patch(memory);
    auto* aligned = ApplicationHeapAlign_nid_no_patch(256, 1024);
    Require(reinterpret_cast<std::uintptr_t>(aligned) % 256 == 0, "aligned allocation");
    ApplicationHeapFree_nid_no_patch(aligned);
    bool overflowRejected = false;
    try { ApplicationHeapCalloc_nid_no_patch(std::numeric_limits<std::size_t>::max(), 2); }
    catch (const std::length_error&) { overflowRejected = true; }
    Require(overflowRejected, "calloc overflow accepted");
    std::array<unsigned char, 3120> request{};
    std::memcpy(request.data() + 45, "native runtime provider test", 29);
    Require(sceKernelSendNotificationRequest(0, request.data(), request.size(), 0) == 0, "notification failed");
    Require(sceKernelSendNotificationRequest(0, request.data(), 12, 0) == static_cast<int>(0x80020016u), "invalid notification size accepted");
    Require(sceKernelSendNotificationRequest(0, nullptr, request.size(), 0) == static_cast<int>(0x8002000eu), "null notification accepted");
    Require(sceKernelSendNotificationRequest(0, request.data(), request.size(), 1) == static_cast<int>(0x8002002du), "unsupported notification flags accepted");
    const auto started = std::chrono::steady_clock::now();
    Require(sceKernelUsleep_nid_postfix(10000) == 0, "native sleep failed");
    Require(std::chrono::steady_clock::now() - started >= std::chrono::milliseconds(9), "native sleep returned early");
}

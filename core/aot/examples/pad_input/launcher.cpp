#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <sys/sysctl.h>
#include <vector>
#ifdef PAD_INPUT_REFERENCE
#include "prx/libc/include/NativeAotImage.hpp"
#include <array>
#endif

extern "C" {
void guest_start(void*, void (*)());
int guest_source_main();
[[noreturn]] void exit_nid_postfix(int);
int atexit_nid_postfix(void (*)());
void _init_env_nid_postfix();
int sceKernelSendNotificationRequest(int, const void*, std::size_t, int);
[[noreturn]] void Aps5StartGuest_nid_no_patch(void (*)(void*, void*), void*);
void aot_bridge_init_env(void*) { _init_env_nid_postfix(); }
int aot_bridge_sceKernelSendNotificationRequest(int device, const void* request, std::int32_t bytes, int flags) {
    return sceKernelSendNotificationRequest(device, request, static_cast<std::uint32_t>(bytes), flags);
}
}

#ifdef PAD_INPUT_TEST
void ConfigurePadInputTest(int, char**);
#endif

static void Teardown() { std::fprintf(stderr, "native pad guest teardown completed\n"); }
static void Entry(void* parameters, void*) {
#ifdef PAD_INPUT_REFERENCE
    exit_nid_postfix(guest_source_main());
#else
    guest_start(parameters, Teardown);
#endif
}

int main(int argc, char** argv) {
    int translated = 0;
    std::size_t bytes = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &bytes, nullptr, 0) != 0 && errno != ENOENT) return 90;
    if (translated != 0) return 91;
    std::fprintf(stderr, "architecture=arm64 translated=%d\n", translated);
#ifdef PAD_INPUT_TEST
    ConfigurePadInputTest(argc, argv);
#endif
#ifdef PAD_INPUT_REFERENCE
    std::array<std::uint64_t, 8> metadata{};
    std::array<std::uint64_t, 7> libc{};
    std::array<std::uint64_t, 15> replacement{};
    metadata[0] = sizeof(metadata);
    metadata[1] = 0x4942524f;
    metadata[7] = reinterpret_cast<std::uint64_t>(libc.data());
    libc[0] = sizeof(libc);
    libc[6] = reinterpret_cast<std::uint64_t>(replacement.data());
    replacement[0] = sizeof(replacement);
    replacement[1] = 2;
    const NativeAotDataRange ranges[]{{metadata.data(), sizeof(metadata)},
        {libc.data(), sizeof(libc)}, {replacement.data(), sizeof(replacement)}};
    const NativeAotImage image{1, ranges, 3, nullptr, 0, metadata.data(), sizeof(metadata)};
    NativeAotRegisterImage_nid_no_patch(&image);
    _init_env_nid_postfix();
    if (atexit_nid_postfix(Teardown) != 0) return 92;
#endif
    std::vector<std::uintptr_t> parameters(static_cast<std::size_t>(argc) + 2);
    parameters[0] = static_cast<std::uintptr_t>(argc);
    for (int index = 0; index < argc; ++index) parameters[index + 1] = reinterpret_cast<std::uintptr_t>(argv[index]);
    Aps5StartGuest_nid_no_patch(Entry, parameters.data());
}

#include "prx/libc/include/NativeAotImage.hpp"
#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cerrno>
#include <sys/sysctl.h>
extern "C" int guest_source_main();
extern "C" [[noreturn]] void exit_nid_postfix(int);
extern "C" void _init_env_nid_postfix();
extern "C" [[noreturn]] void Aps5StartGuest_nid_no_patch(void (*)(void*,void*),void*);
extern "C" int atexit_nid_postfix(void (*)());
static void Teardown() { std::fprintf(stderr, "native GPU guest teardown completed\n"); }
static void Entry(void*,void*) { exit_nid_postfix(guest_source_main()); }
int main() {
    int translated = 0;
    std::size_t bytes = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &bytes, nullptr, 0) != 0 && errno != ENOENT) return 90;
    if (translated != 0) return 91;
    std::fprintf(stderr, "architecture=arm64 translated=%d\n", translated);
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
    std::fprintf(stderr,"source-native baseline arm64; AOT not used\n");
    if (atexit_nid_postfix(Teardown) != 0) return 92;
    Aps5StartGuest_nid_no_patch(Entry,nullptr);
}

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <sys/sysctl.h>
#include <vector>

extern "C" {
void guest_start(void*, void (*)());
void _init_env_nid_postfix();
int sceKernelSendNotificationRequest(int, const void*, std::size_t, int);
[[noreturn]] void Aps5StartGuest_nid_no_patch(void (*)(void*, void*), void*);
void aot_bridge_init_env(void*) { _init_env_nid_postfix(); }
int aot_bridge_sceKernelSendNotificationRequest(int device, const void* request, std::int32_t bytes, int flags) {
    return sceKernelSendNotificationRequest(device, request, static_cast<std::uint32_t>(bytes), flags);
}
}

static void Teardown() { std::fprintf(stderr, "native GPU guest teardown completed\n"); }
static void Entry(void* parameters, void*) { guest_start(parameters, Teardown); }

int main(int argc, char** argv) {
    int translated = 0;
    std::size_t bytes = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &bytes, nullptr, 0) != 0 && errno != ENOENT) return 90;
    if (translated != 0) return 91;
    std::fprintf(stderr, "architecture=arm64 translated=%d\n", translated);
    std::vector<std::uintptr_t> parameters(static_cast<std::size_t>(argc) + 2);
    parameters[0] = static_cast<std::uintptr_t>(argc);
    for (int index = 0; index < argc; ++index) parameters[index + 1] = reinterpret_cast<std::uintptr_t>(argv[index]);
    Aps5StartGuest_nid_no_patch(Entry, parameters.data());
}

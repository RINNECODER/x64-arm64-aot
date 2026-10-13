#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#ifdef __APPLE__
#include <sys/sysctl.h>
#else
#include <array>
#include <fstream>
#include <sys/utsname.h>
#endif
#include <vector>

extern "C" void guest_start(void*, void (*)());


namespace {

void Teardown() {
    std::fputs("native teardown completed\n", stderr);
}

}

int main(int argc, char** argv) {
#ifdef __APPLE__
    int translated = 0;
    std::size_t bytes = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &bytes, nullptr, 0) != 0 && errno != ENOENT)
        return 90;
    if (translated != 0) return 91;
    std::fprintf(stderr, "architecture=arm64 translated=%d\n", translated);
#else
    static_assert(sizeof(void*) == 8);
    utsname host{};
    if (uname(&host) != 0 || std::string(host.machine) != "aarch64") return 90;
    std::array<unsigned char, 20> header{};
    std::ifstream executable("/proc/self/exe", std::ios::binary);
    executable.read(reinterpret_cast<char*>(header.data()), header.size());
    if (!executable || header[0] != 0x7f || header[1] != 'E' || header[2] != 'L' || header[3] != 'F' ||
        header[4] != 2 || header[5] != 1 || header[18] != 183 || header[19] != 0) return 91;
    std::fputs("architecture=arm64 host=aarch64 format=ELF\n", stderr);
#endif
    std::vector<std::uintptr_t> parameters(static_cast<std::size_t>(argc) + 2);
    parameters[0] = static_cast<std::uintptr_t>(argc);
    for (int index = 0; index < argc; ++index)
        parameters[index + 1] = reinterpret_cast<std::uintptr_t>(argv[index]);
    guest_start(parameters.data(), Teardown);
    return 92;
}

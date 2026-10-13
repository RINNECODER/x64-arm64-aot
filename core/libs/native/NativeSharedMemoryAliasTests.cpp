#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <source_location>

extern "C" {
int sceKernelJitCreateSharedMemory(const char*, std::size_t, int, int*);
int sceKernelJitCreateAliasOfSharedMemory(int, int, int*);
int sceKernelJitMapSharedMemory(int, int, void**);
int sceKernelMunmap(void*, std::size_t);
int close_nid_postfix(int);
}

void Require(bool value, std::source_location location = std::source_location::current()) {
    if (value) return;
    std::fprintf(stderr, "shared memory failure at %u\n", location.line());
    std::abort();
}

int main() {
    constexpr std::size_t bytes = 0x10000;
    for (int iteration = 0; iteration < 32; ++iteration) {
        int fd = -1, alias = -1;
        Require(sceKernelJitCreateSharedMemory(nullptr, bytes, 3, &fd) == 0);
        Require((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
        Require(sceKernelJitCreateAliasOfSharedMemory(fd, 1, &alias) == 0);
        void* writable = nullptr;
        void* readable = nullptr;
        Require(sceKernelJitMapSharedMemory(fd, 3, &writable) == 0);
        Require(sceKernelJitMapSharedMemory(alias, 1, &readable) == 0);
        static_cast<unsigned char*>(writable)[0] = static_cast<unsigned char>(iteration);
        static_cast<unsigned char*>(writable)[bytes - 1] = 91;
        Require(static_cast<const unsigned char*>(readable)[0] == iteration);
        Require(static_cast<const unsigned char*>(readable)[bytes - 1] == 91);
        Require(close_nid_postfix(fd) == 0);
        Require(static_cast<const unsigned char*>(readable)[bytes - 1] == 91);
        Require(sceKernelMunmap(writable, bytes) == 0);
        Require(sceKernelMunmap(readable, bytes) == 0);
        Require(close_nid_postfix(alias) == 0);
    }
}

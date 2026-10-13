#include "prx/libc/include/NativeAotImage.hpp"
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <sys/mman.h>
#include <unistd.h>

namespace {

void Require(bool value, const char* reason) {
    if (!value) {
        std::fprintf(stderr, "native readonly: %s\n", reason);
        std::abort();
    }
}

template<class Action>
void Reject(Action action) {
    bool rejected = false;
    try { action(); }
    catch (const std::exception&) { rejected = true; }
    Require(rejected, "invalid readonly range accepted");
}

}

int main() {
    const auto page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    Require(page > 0 && page < 1024 * 1024, "invalid page size");
    auto* memory = static_cast<unsigned char*>(mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    Require(memory != MAP_FAILED, "allocation failed");
    memory[0] = 17;
    memory[page] = 23;
    NativeAotRequireReadOnly_nid_no_patch(nullptr, 0);
    Reject([] { NativeAotRequireReadOnly_nid_no_patch(nullptr, 1); });
    NativeAotDataRange first{memory, page};
    Reject([&] { NativeAotRequireReadOnly_nid_no_patch(&first, 1); });
    Require(mprotect(memory, page, PROT_READ) == 0, "readonly protection failed");
    NativeAotRequireReadOnly_nid_no_patch(&first, 1);
    NativeAotDataRange both{memory, 2 * page};
    Reject([&] { NativeAotRequireReadOnly_nid_no_patch(&both, 1); });
    NativeAotDataRange overflow{memory, std::numeric_limits<std::size_t>::max()};
    Reject([&] { NativeAotRequireReadOnly_nid_no_patch(&overflow, 1); });
    Require(mprotect(memory + page, page, PROT_READ) == 0, "second readonly protection failed");
    NativeAotRequireReadOnly_nid_no_patch(&both, 1);
    Require(mprotect(memory + page, page, PROT_NONE) == 0, "inaccessible protection failed");
    Reject([&] { NativeAotRequireReadOnly_nid_no_patch(&both, 1); });
    Require(munmap(memory + page, page) == 0, "unmap failed");
    Reject([&] { NativeAotRequireReadOnly_nid_no_patch(&both, 1); });
    Require(memory[0] == 17, "readonly bytes changed");
    Require(munmap(memory, page) == 0, "cleanup failed");
}

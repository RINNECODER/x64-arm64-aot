// Fork-only: guest TLS base for the uniform ABI. The generated code calls
// NativeAotTlsBase for every %fs: access; it returns a per-thread zero-initialized block.
// The guest's FreeBSD variant-II layout puts the image block below the thread pointer, so
// the returned base is the top of the allocation and negative displacements stay in range.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace {

constexpr std::size_t kTlsBlockBytes = 256 * 1024;
constexpr std::size_t kTcbBytes = 64 * 1024;
thread_local std::uint8_t* tlsBase = nullptr;

}

extern "C" void* NativeAotTlsBase_nid_no_patch() {
    if (tlsBase == nullptr) {
        auto* raw = static_cast<std::uint8_t*>(::calloc(1, kTlsBlockBytes + kTcbBytes));
        if (raw == nullptr)
            std::abort();
        tlsBase = raw + kTlsBlockBytes;
    }
    return tlsBase;
}

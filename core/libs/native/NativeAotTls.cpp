// Fork-only: guest TLS base for the uniform ABI. The generated code calls
// NativeAotTlsBase for every %fs: access; it returns a per-thread block with the image's
// TLS initial data copied in. The guest's FreeBSD variant-II layout puts the image block
// below the thread pointer, so the returned base is the top of the allocation and negative
// displacements stay in range. NativeAotRegisterTls is called from the generated
// native_image_init with the image's PT_TLS contents and sizes.
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <pthread.h>

namespace {

constexpr std::size_t kMaxTlsBytes = 512 * 1024;
constexpr std::size_t kTcbBytes = 64 * 1024;
thread_local std::uint8_t* tlsBase = nullptr;
std::atomic<std::size_t> liveBlocks{0};
pthread_key_t tlsKey;
pthread_once_t tlsKeyOnce = PTHREAD_ONCE_INIT;

// Runs at thread exit with the calloc'd block; the %fs base is the block's top, never the pointer.
void ReleaseTls(void* raw) {
    tlsBase = nullptr;
    liveBlocks.fetch_sub(1);
    ::free(raw);
}

void MakeTlsKey() {
    if (pthread_key_create(&tlsKey, ReleaseTls) != 0)
        std::abort();
}

const std::uint8_t* tlsInit = nullptr;
std::size_t tlsFileSize = 0;
std::size_t tlsBlockSize = 0;

}

extern "C" void NativeAotRegisterTls_nid_no_patch(const void* init, std::uint64_t fileSize, std::uint64_t blockSize) {
    if (blockSize > kMaxTlsBytes || fileSize > blockSize)
        std::abort();
    tlsInit = static_cast<const std::uint8_t*>(init);
    tlsFileSize = static_cast<std::size_t>(fileSize);
    tlsBlockSize = static_cast<std::size_t>(blockSize);
}

extern "C" void* NativeAotTlsBase_nid_no_patch() {
    if (tlsBase == nullptr) {
        auto* raw = static_cast<std::uint8_t*>(::calloc(1, kMaxTlsBytes + kTcbBytes));
        if (raw == nullptr)
            std::abort();
        pthread_once(&tlsKeyOnce, MakeTlsKey);
        if (pthread_setspecific(tlsKey, raw) != 0)
            std::abort();
        liveBlocks.fetch_add(1);
        tlsBase = raw + kMaxTlsBytes;
        if (tlsInit != nullptr && tlsFileSize != 0)
            std::memcpy(tlsBase - tlsBlockSize, tlsInit, tlsFileSize);
    }
    return tlsBase;
}

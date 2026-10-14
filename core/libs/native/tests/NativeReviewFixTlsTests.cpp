// Every thread's TLS block must be released when the thread exits.
#include "../NativeAotTls.cpp"
#include <cstdio>
#include <pthread.h>

int main() {
    static const std::uint8_t init[4] = {1, 2, 3, 4};
    NativeAotRegisterTls_nid_no_patch(init, 4, 16);
    for (int round = 0; round < 64; ++round) {
        pthread_t thread;
        ::pthread_create(&thread, nullptr, [](void*) -> void* {
            auto* base = static_cast<std::uint8_t*>(NativeAotTlsBase_nid_no_patch());
            if (base[-16] != 1 || base[-13] != 4 || NativeAotTlsBase_nid_no_patch() != base) std::abort();
            return nullptr;
        }, nullptr);
        ::pthread_join(thread, nullptr);
    }
    if (liveBlocks.load() != 0) {
        std::fprintf(stderr, "tls blocks leaked: %zu\n", static_cast<std::size_t>(liveBlocks.load()));
        return 1;
    }
    std::puts("ok");
    return 0;
}

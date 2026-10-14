// A guest segment whose range overlaps a live host mapping must be refused, not replace it.
#include "../NativeAotImage.cpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>

static void Check(bool value, int line) {
    if (value) return;
    std::fprintf(stderr, "image test failure at line %d\n", line);
    std::abort();
}
#define CHECK(x) Check((x), __LINE__)

int main() {
    char path[] = "/tmp/anyps5-image-test-XXXXXX";
    const int file = ::mkstemp(path);
    CHECK(file >= 0);
    unsigned char payload[0x1000];
    std::memset(payload, 0xA5, sizeof(payload));
    CHECK(::write(file, payload, sizeof(payload)) == static_cast<ssize_t>(sizeof(payload)));
    ::close(file);
    ::setenv("ANYPS5_AOT_EBOOT", path, 1);

    const std::size_t pageBytes = 0x4000;
    auto* host = static_cast<unsigned char*>(::mmap(nullptr, pageBytes * 3, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
    CHECK(host != MAP_FAILED);
    std::memset(host, 0x5A, pageBytes * 3);
    // Segment 0 overlaps the middle host page (and must be refused); segment 1 lands on a free range.
    void* freeRange = ::mmap(nullptr, 0x4000, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    CHECK(freeRange != MAP_FAILED);
    ::munmap(freeRange, 0x4000);
    NativeAotSegment segments[2] = {
        {reinterpret_cast<std::uint64_t>(host) + pageBytes, 0, 0x1000, 0x1000, 0},
        {reinterpret_cast<std::uint64_t>(freeRange), 0, 0x1000, 0x1000, 0},
    };
    NativeAotMapImage_nid_no_patch(segments, 2);
    for (std::size_t index = 0; index < pageBytes * 3; ++index) CHECK(host[index] == 0x5A);
    CHECK(static_cast<unsigned char*>(freeRange)[0] == 0xA5);
    ::unlink(path);
    std::puts("ok");
    return 0;
}

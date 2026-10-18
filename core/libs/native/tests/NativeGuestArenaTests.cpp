// The native arm64 guest arena must sit at the slide the compiler used (GuestLayout::NativeSlide),
// above the range macOS refuses to map, and hand out addresses inside it. The slide is read from
// the environment before the arena is first used, which is how the native launcher applies it.
#include "prx/libc/include/GuestArena.hpp"
#include "prx/libc/include/GuestLayout.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>

static void Check(bool value, int line) {
    if (value) return;
    std::fprintf(stderr, "guest arena test failure at line %d\n", line);
    std::abort();
}
#define CHECK(x) Check((x), __LINE__)

int main() {
    ::setenv(GuestLayout::SlideEnvironment, "0x8000000000", 1);
    std::uintptr_t base = 0;
    std::size_t bytes = 0;
    GuestArena::GuestArenaRange_nid_postfix(&base, &bytes);
    const auto expectedBase = static_cast<std::uintptr_t>(GuestLayout::ApplicationAreaStart) + GuestLayout::NativeSlide;
    const auto expectedEnd = static_cast<std::uintptr_t>(GuestLayout::ApplicationAreaEnd) + GuestLayout::NativeSlide;
    CHECK(GuestArena::GuestArenaAvailable_nid_postfix());
    CHECK(base == expectedBase);
    CHECK(base + bytes == expectedEnd);
    // The whole application area, and so every fixed guest mapping in it, clears the macOS hole.
    CHECK(base >= GuestLayout::MacOsRefusedEnd);
    CHECK(GuestArena::GuestArenaContains_nid_postfix(reinterpret_cast<void*>(base + 0x1000), 0x1000));
    // A raw guest address from below the hole is not a valid host address here.
    CHECK(!GuestArena::GuestArenaContains_nid_postfix(reinterpret_cast<void*>(GuestLayout::ApplicationAreaStart + 0x1000), 0x1000));
    void* block = GuestArena::GuestArenaAllocate_nid_postfix(0x4000, 0x4000);
    CHECK(block != nullptr);
    CHECK(reinterpret_cast<std::uintptr_t>(block) >= GuestLayout::MacOsRefusedEnd);
    CHECK(GuestArena::GuestArenaContains_nid_postfix(block, 0x4000));
    GuestArena::GuestArenaRelease_nid_postfix(block, 0x4000);
    std::puts("ok");
    return 0;
}

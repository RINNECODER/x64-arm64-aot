#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_GUESTLAYOUT_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_GUESTLAYOUT_HPP

#include <cstdint>

// The guest address space, shared by the native AOT compiler (core/aot/guest_layout.py mirrors
// these values), the native runtime and the HLE libs. A native arm64 process cannot map the PS5
// guest at its raw addresses (macOS refuses fixed mappings in the 64-512 GiB hole), so the whole
// space is slid by one offset; the compiler's guest_base, the runtime's image mapping and the
// guest arena all use it. test_guest_layout parses this header and fails if the Python mirror
// drifts.
namespace GuestLayout {

// Raw PS5 addresses, as the title's own libc and libkernel see them.
inline constexpr std::uint64_t ApplicationAreaStart = 0x0000000200000000ull; // 8 GiB
inline constexpr std::uint64_t SystemReservedStart = 0x00000007FFFFC000ull;
inline constexpr std::uint64_t SystemReservedEnd = 0x0000001000000000ull; // 64 GiB
inline constexpr std::uint64_t ApplicationAreaEnd = 0x000000FC00000000ull; // 1008 GiB

// macOS refuses fixed mappings here, natively and under Rosetta (DirectMemory.cpp relocates them
// per request on the Rosetta path, where the guest arena is not used).
inline constexpr std::uint64_t MacOsRefusedStart = 0x0000001000000000ull; // 64 GiB
inline constexpr std::uint64_t MacOsRefusedEnd = 0x0000008000000000ull; // 512 GiB

// The slide the native arm64 build places the whole guest address space at. Sliding by 512 GiB
// puts the application area at [520 GiB, 1520 GiB], entirely above the hole.
inline constexpr std::uint64_t NativeSlide = 0x0000008000000000ull; // 512 GiB

// The environment variable the native launcher exports so the HLE arena agrees with the compiler.
inline constexpr const char* SlideEnvironment = "ANYPS5_GUEST_BASE";

}

#endif

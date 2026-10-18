"""The guest address space the native arm64 compiler and the HLE libs agree on.

The values mirror ``core/libs/prx/libc/include/GuestLayout.hpp``; ``test_guest_layout`` parses that
header and fails if they drift. The native compiler places the title image at ``guest_base + vaddr``
and the HLE arena at ``guest_base + ApplicationAreaStart``, so both must use the same slide.
"""

APPLICATION_AREA_START = 0x0000000200000000  # 8 GiB
SYSTEM_RESERVED_START = 0x00000007FFFFC000
SYSTEM_RESERVED_END = 0x0000001000000000  # 64 GiB
APPLICATION_AREA_END = 0x000000FC00000000  # 1008 GiB

MACOS_REFUSED_START = 0x0000001000000000  # 64 GiB
MACOS_REFUSED_END = 0x0000008000000000  # 512 GiB

# The slide the native arm64 build places the whole guest address space at.
NATIVE_GUEST_BASE = 0x0000008000000000  # 512 GiB


def arena_range(slide=NATIVE_GUEST_BASE):
    """The host range the guest arena occupies for a given slide, as (start, end)."""
    return APPLICATION_AREA_START + slide, APPLICATION_AREA_END + slide

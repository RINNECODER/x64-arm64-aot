#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_NATIVEAOTIMAGE_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_NATIVEAOTIMAGE_HPP

#include <cstddef>
#include <cstdint>

struct NativeAotDataRange {
    const void* address;
    std::size_t bytes;
};

struct NativeAotImage {
    std::uint64_t version;
    const NativeAotDataRange* ranges;
    std::size_t rangeCount;
    const void* const* functions;
    std::size_t functionCount;
    const void* processParameters;
    std::size_t processParameterBytes;
};

extern "C" void NativeAotRegisterImage_nid_no_patch(const NativeAotImage* image);
extern "C" void NativeAotRequireReadOnly_nid_no_patch(const NativeAotDataRange* ranges, std::size_t count);

#endif

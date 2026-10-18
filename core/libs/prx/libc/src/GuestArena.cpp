#include "prx/libc/include/GuestArena.hpp"
#include "prx/libc/include/GuestLayout.hpp"
#include "prx/libc/include/GuestWriteWatch.hpp"
#include "prx/libc/include/WindowsMappings.hpp"
#include <algorithm>
#include <atomic>
#include <cstdint>
#ifndef _WIN32
#include <cerrno>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/mman.h>
#endif
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <map>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

namespace GuestArena {
namespace {

#ifdef _WIN32
std::atomic<std::uint64_t> commitGeneration{1};
std::atomic<void (*)(std::uintptr_t, std::size_t, std::uint64_t)> privateMappingObserver{nullptr};
#endif

#ifdef ANYPS5_ENABLE_ASAN
constexpr std::uintptr_t DefaultSlide = 0x0000100000000000ull;
#else
constexpr std::uintptr_t DefaultSlide = 0;
#endif

// One slide moves the whole guest address space (application area and system reservation) so the
// native arm64 process can map it above the range macOS refuses. The compiler's guest_base and the
// image's segment table carry the same value. The native launcher sets it with
// GuestArenaSetOffset, or exports ANYPS5_GUEST_BASE, which the arena reads before it is
// constructed. The read is lazy so a launcher's setenv in main is seen.
std::atomic<std::uintptr_t> arenaSlide{DefaultSlide};
std::atomic<bool> arenaSlideExplicit{false};

std::uintptr_t ReadSlide() {
    if (arenaSlideExplicit.load(std::memory_order_acquire)) return arenaSlide.load(std::memory_order_acquire);
    if (const char* value = std::getenv(GuestLayout::SlideEnvironment)) {
        char* end = nullptr;
        const auto parsed = std::strtoull(value, &end, 0);
        if (end != value && *end == '\0') return static_cast<std::uintptr_t>(parsed);
    }
    return arenaSlide.load(std::memory_order_acquire);
}

struct Layout {
    std::uintptr_t arenaStart;
    std::uintptr_t systemReservedStart;
    std::uintptr_t systemReservedEnd;
    std::uintptr_t applicationAreaEnd;
};

Layout ComputeLayout() {
    const std::uintptr_t slide = ReadSlide();
    return {static_cast<std::uintptr_t>(GuestLayout::ApplicationAreaStart) + slide,
            static_cast<std::uintptr_t>(GuestLayout::SystemReservedStart) + slide,
            static_cast<std::uintptr_t>(GuestLayout::SystemReservedEnd) + slide,
            static_cast<std::uintptr_t>(GuestLayout::ApplicationAreaEnd) + slide};
}

std::uintptr_t alignUp(std::uintptr_t value, std::size_t alignment) {
    return (value + alignment - 1) & ~(static_cast<std::uintptr_t>(alignment) - 1);
}

class Arena {
public:
    static Arena& Get() {
        static Arena arena;
        return arena;
    }

    bool Available() const {
        return _base != 0;
    }

    bool Contains(const void* pointer, std::size_t bytes) const {
        const auto address = reinterpret_cast<std::uintptr_t>(pointer);
        return _base != 0 && address >= _base && bytes <= _end - _base && address - _base <= (_end - _base) - bytes;
    }

    void* Allocate(std::size_t bytes, std::size_t alignment) {
        return AllocateAtOrAbove(0, bytes, alignment);
    }

    void* AllocateAtOrAbove(std::uintptr_t hint, std::size_t bytes, std::size_t alignment) {
        if (_base == 0) throw std::runtime_error("guest address space arena is unavailable");
        if (alignment == 0 || (alignment & (alignment - 1)) != 0) throw std::invalid_argument("invalid guest arena alignment");
        std::lock_guard lock(_lock);
        if (hint >= _end) throw std::runtime_error("mapping address hint is above the guest address space arena");
        std::uintptr_t candidate = alignUp(std::max(_base, hint), alignment);
        auto it = _used.upper_bound(candidate);
        if (it != _used.begin() && std::prev(it)->second > candidate) --it;
        for (; it != _used.end(); ++it) {
            const auto& [start, end] = *it;
            if (candidate <= _end && bytes <= _end - candidate && candidate + bytes <= start) break;
            candidate = std::max(candidate, alignUp(end, alignment));
        }
        if (candidate > _end || bytes > _end - candidate) throw std::runtime_error("guest address space arena exhausted");
        _used.emplace(candidate, candidate + bytes);
        return reinterpret_cast<void*>(candidate);
    }

    std::uintptr_t HighestFree(std::size_t bytes, std::size_t alignment) {
        if (_base == 0) throw std::runtime_error("guest address space arena is unavailable");
        if (bytes == 0 || alignment == 0 || (alignment & (alignment - 1)) != 0) throw std::invalid_argument("invalid guest arena window");
        std::lock_guard lock(_lock);
        auto limit = _end;
        while (limit >= _base && bytes <= limit - _base) {
            const auto candidate = (limit - bytes) & ~(alignment - 1);
            if (candidate < _base) break;
            const auto next = _used.lower_bound(candidate + bytes);
            if (next == _used.begin() || std::prev(next)->second <= candidate) return candidate;
            limit = std::prev(next)->first;
        }
        return 0;
    }

    bool MarkUsedForCommit(const void* pointer, std::size_t bytes) {
        std::lock_guard lock(_lock);
        const auto start = reinterpret_cast<std::uintptr_t>(pointer);
        const auto end = start + bytes;
        const auto exact = _used.find(start);
        if (exact != _used.end() && exact->second >= end) return false;
        const auto next = _used.lower_bound(start);
        if ((next != _used.end() && next->first < end) || (next != _used.begin() && std::prev(next)->second > start)) {
            char message[160];
            std::snprintf(message, sizeof(message), "guest arena commit 0x%llx+0x%zx overlaps a used range", static_cast<unsigned long long>(start), bytes);
            throw std::runtime_error(message);
        }
        _used.emplace(start, end);
        return true;
    }

    void MarkUsed(const void* pointer, std::size_t bytes) {
        std::lock_guard lock(_lock);
        const auto start = reinterpret_cast<std::uintptr_t>(pointer);
        const auto next = _used.lower_bound(start);
        if ((next != _used.end() && next->first < start + bytes) || (next != _used.begin() && std::prev(next)->second > start)) {
            char message[160];
            std::snprintf(message, sizeof(message), "fixed guest mapping 0x%llx+0x%zx overlaps %s", static_cast<unsigned long long>(start), bytes, OverlapsHostRegion(start, bytes) ? "a host region in the guest arena" : "a guest arena range");
            throw std::runtime_error(message);
        }
        _used.emplace(start, start + bytes);
    }

    void Release(const void* pointer, std::size_t bytes) {
        std::lock_guard lock(_lock);
        const auto start = reinterpret_cast<std::uintptr_t>(pointer);
        const auto end = start + bytes;
        auto it = _used.upper_bound(start);
        if (it != _used.begin()) --it;
        while (it != _used.end() && it->first < end) {
            const auto rangeStart = it->first;
            const auto rangeEnd = it->second;
            if (rangeEnd <= start) {
                ++it;
                continue;
            }
            it = _used.erase(it);
            if (rangeStart < start) _used.emplace(rangeStart, start);
            if (rangeEnd > end) _used.emplace(end, rangeEnd);
        }
        for (const auto& [holeStart, holeEnd] : _holes) {
            if (holeStart < end && start < holeEnd) _used.emplace(holeStart, holeEnd);
        }
    }

private:
    Arena() {
        const Layout layout = ComputeLayout();
#if defined(__linux__)
        SeedLinuxUsedRanges(layout);
        _base = layout.arenaStart;
        _end = layout.applicationAreaEnd;
#elif defined(_WIN32)
        _writeWatched = std::getenv("APS5_NO_WRITE_WATCH") == nullptr;
        SYSTEM_INFO system{};
        GetSystemInfo(&system);
        const std::uintptr_t granularity = system.dwAllocationGranularity;
        const std::uintptr_t end = layout.applicationAreaEnd;
        std::uint32_t retries = 0;
        for (std::uintptr_t cursor = layout.arenaStart; cursor < end;) {
            MEMORY_BASIC_INFORMATION info{};
            if (VirtualQuery(reinterpret_cast<const void*>(cursor), &info, sizeof(info)) == 0) throw std::system_error(static_cast<int>(GetLastError()), std::system_category(), "query the guest arena range");
            const auto regionEnd = std::min(end, reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize);
            const auto first = info.State == MEM_FREE ? std::min(regionEnd, alignUp(cursor, granularity)) : regionEnd;
            const auto last = std::max(first, regionEnd & ~(granularity - 1));
            if (first < last && WindowsMappings::Get().Reserve(reinterpret_cast<void*>(first), last - first) == nullptr) {
                const auto error = GetLastError();
                if (error == ERROR_INVALID_ADDRESS && ++retries < 64u) continue;
                throw std::system_error(static_cast<int>(error), std::system_category(), "reserve the guest arena range");
            }
            retries = 0;
            if (cursor < first) _holes.emplace_back(cursor, first);
            if (last < regionEnd) _holes.emplace_back(last, regionEnd);
            cursor = regionEnd;
        }
        _hostRegions = _holes;
        _holes.emplace_back(layout.systemReservedStart, layout.systemReservedEnd);
        for (const auto& [holeStart, holeEnd] : _holes) _used.emplace(holeStart, holeEnd);
        _base = layout.arenaStart;
        _end = end;
#elif defined(__APPLE__)
        // macOS has no /proc/self/maps and refuses fixed mappings in [64 GiB, 512 GiB). The arena
        // is only usable once the slide has moved it above that hole; otherwise it stays
        // unavailable and DirectMemory places mappings itself (the Rosetta path).
        if (layout.arenaStart >= GuestLayout::MacOsRefusedEnd) {
            SeedDarwinUsedRanges(layout);
            _base = layout.arenaStart;
            _end = layout.applicationAreaEnd;
        }
#endif
    }

#if defined(__linux__)
    void SeedLinuxUsedRanges(const Layout& layout) {
        std::ifstream maps("/proc/self/maps");
        if (!maps.is_open()) throw std::runtime_error("guest arena: cannot open /proc/self/maps");
        std::string line;
        while (std::getline(maps, line)) {
            std::istringstream fields(line);
            std::uintptr_t begin = 0, end = 0;
            char dash = 0;
            if (!(fields >> std::hex >> begin >> dash >> end) || dash != '-' || end <= begin) throw std::runtime_error("guest arena: malformed /proc/self/maps line: " + line);
            if (end <= layout.arenaStart || begin >= layout.applicationAreaEnd) continue;
            const auto first = std::max(begin, layout.arenaStart);
            const auto last = std::min(end, layout.applicationAreaEnd);
            _used.emplace(first, last);
            _hostRegions.emplace_back(first, last);
        }
        _used.emplace(layout.systemReservedStart, layout.systemReservedEnd);
        _hostRegions.emplace_back(layout.systemReservedStart, layout.systemReservedEnd);
        ReserveFreeRanges(layout);
    }

    static void TryReserve(std::vector<std::pair<std::uintptr_t, std::uintptr_t>>& occupied, std::uintptr_t from, std::uintptr_t to) {
        constexpr std::uintptr_t kChunk = 1ULL << 30;
        for (std::uintptr_t cursor = from; cursor < to; cursor += kChunk) {
            const auto end = std::min(cursor + kChunk, to);
            void* const wanted = reinterpret_cast<void*>(cursor);
            void* const placed = mmap(wanted, end - cursor, PROT_NONE,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
            if (placed == wanted) continue;
            const int failed = placed == MAP_FAILED ? errno : EINVAL;
            if (placed != MAP_FAILED) munmap(placed, end - cursor);
            if (failed != EEXIST) {
                char message[128];
                std::snprintf(message, sizeof(message), "guest arena: cannot reserve 0x%llx+0x%llx",
                    static_cast<unsigned long long>(cursor), static_cast<unsigned long long>(end - cursor));
                throw std::system_error(failed, std::system_category(), message);
            }
            occupied.emplace_back(cursor, end);
        }
    }

    void ReserveFreeRanges(const Layout& layout) {
        std::vector<std::pair<std::uintptr_t, std::uintptr_t>> occupied;
        std::uintptr_t cursor = layout.arenaStart;
        for (const auto& [usedStart, usedEnd] : _used) {
            if (usedStart > layout.applicationAreaEnd) break;
            if (usedStart > cursor) TryReserve(occupied, cursor, std::min(usedStart, layout.applicationAreaEnd));
            if (usedEnd > cursor) cursor = usedEnd;
            if (cursor >= layout.applicationAreaEnd) break;
        }
        if (cursor < layout.applicationAreaEnd) TryReserve(occupied, cursor, layout.applicationAreaEnd);
        for (const auto& [from, to] : occupied) {
            _used.emplace(from, to);
            _hostRegions.emplace_back(from, to);
        }
    }
#endif

#if defined(__APPLE__)
    // No /proc/self/maps on macOS: walk the process's mappings with mach_vm_region and mark every
    // host range inside the arena used, then reserve the PS5 system area. Nothing is reserved
    // eagerly; the arena is far above the process's own mappings and commits lazily with MAP_FIXED.
    void SeedDarwinUsedRanges(const Layout& layout) {
        mach_vm_address_t region = layout.arenaStart;
        while (region < layout.applicationAreaEnd) {
            mach_vm_size_t size = 0;
            vm_region_basic_info_data_64_t info{};
            mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object = MACH_PORT_NULL;
            if (mach_vm_region(mach_task_self(), &region, &size, VM_REGION_BASIC_INFO_64,
                               reinterpret_cast<vm_region_info_t>(&info), &count, &object) != KERN_SUCCESS)
                break;
            const auto begin = static_cast<std::uintptr_t>(region);
            const auto end = begin + static_cast<std::uintptr_t>(size);
            const auto first = std::max(begin, layout.arenaStart);
            const auto last = std::min(end, layout.applicationAreaEnd);
            if (first < last) {
                _used.emplace(first, last);
                _hostRegions.emplace_back(first, last);
            }
            region = end;
        }
        _used.emplace(layout.systemReservedStart, layout.systemReservedEnd);
        _hostRegions.emplace_back(layout.systemReservedStart, layout.systemReservedEnd);
    }
#endif

    std::mutex _lock;
    std::map<std::uintptr_t, std::uintptr_t> _used;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> _holes;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> _hostRegions;
    std::uintptr_t _base = 0;
    std::uintptr_t _end = 0;
    bool _writeWatched = false;

public:
    std::uintptr_t Base() const { return _base; }
    std::size_t Size() const { return _end - _base; }
    bool WriteWatched() const { return _writeWatched; }
    bool OverlapsHostRegion(std::uintptr_t start, std::size_t bytes) const {
        for (const auto& [regionStart, regionEnd] : _hostRegions) {
            if (regionStart < start + bytes && start < regionEnd) return true;
        }
        return false;
    }
};

// On Linux and Windows the arena reserves its address space at load time. On Darwin the slide is
// set by the native launcher in main, before the guest heap first asks for the arena, so the
// construction is left lazy there.
#if !defined(__APPLE__)
const bool g_reserved = (Arena::Get(), true);
#endif

}

void GuestArenaSetOffset_nid_postfix(std::uint64_t offset) {
    if ((offset & 0xFFF) != 0) throw std::invalid_argument("guest arena offset must be page aligned");
    arenaSlide.store(static_cast<std::uintptr_t>(offset), std::memory_order_release);
    arenaSlideExplicit.store(true, std::memory_order_release);
}

bool GuestArenaAvailable_nid_postfix() {
    return Arena::Get().Available();
}

bool GuestArenaContains_nid_postfix(const void* pointer, std::size_t bytes) {
    return Arena::Get().Contains(pointer, bytes);
}

void* GuestArenaAllocate_nid_postfix(std::size_t bytes, std::size_t alignment) {
    return Arena::Get().Allocate(bytes, alignment);
}

void* GuestArenaAllocateAtOrAbove_nid_postfix(std::uintptr_t hint, std::size_t bytes, std::size_t alignment) {
    return Arena::Get().AllocateAtOrAbove(hint, bytes, alignment);
}

std::uintptr_t GuestArenaHighestFree_nid_no_patch(std::size_t bytes, std::size_t alignment) {
    return Arena::Get().HighestFree(bytes, alignment);
}

void GuestArenaMarkUsed_nid_postfix(const void* pointer, std::size_t bytes) {
    Arena::Get().MarkUsed(pointer, bytes);
}

void GuestArenaRelease_nid_postfix(const void* pointer, std::size_t bytes) {
    Arena::Get().Release(pointer, bytes);
}

void GuestArenaRange_nid_postfix(std::uintptr_t* base, std::size_t* bytes) {
    *base = Arena::Get().Base();
    *bytes = Arena::Get().Size();
}

namespace {

std::invalid_argument OutsideArena(const char* operation, const void* pointer, std::size_t bytes) {
    char message[128];
    std::snprintf(message, sizeof(message), "%s 0x%llx+0x%zx outside the guest arena", operation, static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(pointer)), bytes);
    return std::invalid_argument(message);
}

}

#ifdef _WIN32
void GuestArenaSetProtection_nid_postfix(std::uintptr_t address, std::size_t bytes, std::uint32_t protection) {
    WindowsMappings::Get().SetProtection(address, bytes, protection);
}

bool GuestArenaHandleWrite_nid_postfix(std::uintptr_t address) {
    return WindowsMappings::Get().HandleWrite(address);
}

void GuestArenaPinWritable_nid_postfix(const void* pointer, std::size_t bytes) {
    if (!Arena::Get().Contains(pointer, bytes)) return;
    WindowsMappings::Get().Pin(reinterpret_cast<std::uintptr_t>(pointer), bytes);
}

void GuestArenaUnpinWritable_nid_postfix(const void* pointer, std::size_t bytes) {
    if (!Arena::Get().Contains(pointer, bytes)) return;
    WindowsMappings::Get().Unpin(reinterpret_cast<std::uintptr_t>(pointer), bytes);
}

bool GuestArenaProtection_nid_postfix(std::uintptr_t address, std::uint32_t* protection) {
    return WindowsMappings::Get().Protection(address, protection);
}

bool GuestArenaCollectWrites_nid_postfix(std::uintptr_t address, std::size_t bytes, void** pages, std::size_t* count, bool clear) {
    return WindowsMappings::Get().Collect(address, bytes, pages, count, clear);
}

bool GuestArenaHostRegionOverlaps_nid_postfix(std::uintptr_t address, std::size_t bytes) {
    return Arena::Get().OverlapsHostRegion(address, bytes);
}

std::uint64_t GuestArenaCommitGeneration_nid_postfix() {
    return commitGeneration.load(std::memory_order_acquire);
}

void GuestArenaSetPrivateMappingObserver_nid_postfix(void (*callback)(std::uintptr_t, std::size_t, std::uint64_t)) {
    privateMappingObserver.store(callback, std::memory_order_release);
}

void GuestArenaCommit_nid_postfix(void* pointer, std::size_t bytes, std::uint32_t protection, std::size_t granule) {
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("commit", pointer, bytes);
    const auto generation = commitGeneration.fetch_add(1, std::memory_order_acq_rel) + 1;
    const auto created = WindowsMappings::Get().Commit(pointer, bytes, protection, granule, Arena::Get().WriteWatched());
    if (const auto callback = privateMappingObserver.load(std::memory_order_acquire)) {
        for (const auto& [address, size] : created) callback(address, size, generation);
    }
}

void GuestArenaReset_nid_postfix(void* pointer, std::size_t bytes) {
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("reset", pointer, bytes);
    WindowsMappings::Get().Reset(pointer, bytes);
}

void GuestArenaMap_nid_postfix(void* pointer, std::size_t bytes, void* section, std::uint64_t offset, std::uint32_t protection) {
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("shared mapping", pointer, bytes);
    WindowsMappings::Get().Map(pointer, bytes, section, offset, protection);
}

void* GuestArenaMapAlias_nid_postfix(std::uintptr_t address, std::size_t bytes) {
    return WindowsMappings::Get().MapAlias(address, bytes);
}

void GuestArenaUnmapAlias_nid_postfix(void* alias) {
    WindowsMappings::Get().UnmapAlias(alias);
}
#endif

#if defined(__linux__) || defined(__APPLE__)
namespace {
int PosixProtection(std::uint32_t windowsProtection) {
    switch (windowsProtection) {
    case 0x01: return PROT_NONE;
    case 0x02: return PROT_READ;
    case 0x04: return PROT_READ | PROT_WRITE;
    case 0x08: return PROT_READ | PROT_WRITE;
    case 0x10: return PROT_EXEC;
    case 0x20: return PROT_READ | PROT_EXEC;
    case 0x40: return PROT_READ | PROT_WRITE | PROT_EXEC;
    default: throw std::runtime_error("guest arena: unmapped protection value");
    }
}

void* PlaceAt(void* pointer, std::size_t bytes, std::uint32_t protection) {
    return mmap(pointer, bytes, PosixProtection(protection), MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
}
}
#endif

#if defined(__linux__) || defined(__APPLE__)
void GuestArenaSetProtection_nid_postfix(std::uintptr_t address, std::size_t bytes, std::uint32_t protection) {
    if (!Arena::Get().Contains(reinterpret_cast<void*>(address), bytes)) throw OutsideArena("set protection", reinterpret_cast<void*>(address), bytes);
    if (mprotect(reinterpret_cast<void*>(address), bytes, PosixProtection(protection)) != 0)
        throw std::system_error(errno, std::generic_category(), "guest arena protection failed");
}

void GuestArenaCommit_nid_postfix(void* pointer, std::size_t bytes, std::uint32_t protection, std::size_t granule) {
    (void)granule;
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("commit", pointer, bytes);
    const bool marked = Arena::Get().MarkUsedForCommit(pointer, bytes);
    try {
        if (PlaceAt(pointer, bytes, protection) == MAP_FAILED) throw std::system_error(errno, std::generic_category(), "guest arena commit failed");
    } catch (...) {
        if (marked) Arena::Get().Release(pointer, bytes);
        throw;
    }
}

void GuestArenaReset_nid_postfix(void* pointer, std::size_t bytes) {
    if (!Arena::Get().Contains(pointer, bytes)) throw OutsideArena("reset", pointer, bytes);
    if (PlaceAt(pointer, bytes, 0x01) == MAP_FAILED) throw std::system_error(errno, std::generic_category(), "guest arena reset failed");
}
#endif

bool GuestArenaWriteWatched_nid_postfix() {
    return Arena::Get().WriteWatched();
}

bool GuestArenaBeginHostWrite_nid_postfix(void* pointer, std::size_t bytes) {
#ifdef _WIN32
    return WindowsMappings::Get().BeginHostWrite(reinterpret_cast<std::uintptr_t>(pointer), bytes);
#else
    GuestWriteWatch::GuestWriteWatchBeginHostWrite_nid_postfix(pointer, bytes);
    return true;
#endif
}

void GuestArenaEndHostWrite_nid_postfix(void* pointer, std::size_t bytes) {
#ifdef _WIN32
    WindowsMappings::Get().EndHostWrite(reinterpret_cast<std::uintptr_t>(pointer), bytes);
#else
    GuestWriteWatch::GuestWriteWatchEndHostWrite_nid_postfix(pointer, bytes);
#endif
}

#ifndef _WIN32
namespace {

std::atomic<SharedBackingResolver> sharedBackingResolver{nullptr};
std::atomic<SharedBackingWriter> sharedBackingWriter{nullptr};

}

void GuestArenaSetSharedBacking_nid_postfix(SharedBackingResolver resolver) {
    sharedBackingResolver.store(resolver, std::memory_order_release);
}

void GuestArenaSetSharedBackingWriter_nid_no_patch(SharedBackingWriter writer) {
    sharedBackingWriter.store(writer, std::memory_order_release);
}

bool GuestArenaWriteSharedBacking_nid_no_patch(std::uintptr_t address, const void* source, std::size_t bytes) {
    const auto writer = sharedBackingWriter.load(std::memory_order_acquire);
    return writer != nullptr && writer(address, source, bytes);
}

bool GuestArenaSharedBacking_nid_postfix(std::uintptr_t address, std::size_t bytes, int* file, std::uint64_t* offset) {
    const auto resolver = sharedBackingResolver.load(std::memory_order_acquire);
    return resolver != nullptr && resolver(address, bytes, file, offset);
}
#endif

}

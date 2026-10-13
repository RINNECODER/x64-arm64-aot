// Fork-only: runtime dispatch table for the uniform ABI. An indirect branch whose target the
// compiler could not prove is lowered to NativeAotDispatch(value); the generated per-image
// table maps a guest code address to its native function. Unknown targets return null and the
// compiled site reports and traps. Registered once by the generated native_image_init.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

namespace {

struct NativeAotDispatchEntry {
    std::uint64_t guest;
    const void* native;
};

const NativeAotDispatchEntry* dispatchEntries = nullptr;
std::size_t dispatchCount = 0;

void Require(bool condition, const char* reason) {
    if (!condition) throw std::invalid_argument(reason);
}

}

extern "C" void NativeAotRegisterDispatch_nid_no_patch(const NativeAotDispatchEntry* entries, std::size_t count) {
    Require(count == 0 || entries != nullptr, "native AOT dispatch table is null");
    dispatchEntries = entries;
    dispatchCount = count;
}

extern "C" void* NativeAotDispatch_nid_no_patch(std::uint64_t value) {
    const NativeAotDispatchEntry* entries = dispatchEntries;
    const std::size_t count = dispatchCount;
    std::size_t low = 0, high = count;
    while (low < high) {
        const std::size_t middle = low + (high - low) / 2;
        if (entries[middle].guest < value)
            low = middle + 1;
        else
            high = middle;
    }
    if (low < count && entries[low].guest == value)
        return const_cast<void*>(entries[low].native);
    return nullptr;
}

extern "C" void NativeAotReportDispatchFailure_nid_no_patch(std::uint64_t site, std::uint64_t value) {
    std::fprintf(stderr, "[aot] dispatch miss at 0x%llx: target 0x%llx\n",
                 static_cast<unsigned long long>(site), static_cast<unsigned long long>(value));
}

// Entry counters: the generated image keeps one relaxed atomic counter per function and a
// parallel table of guest addresses. Enabled by the launcher (ANYPS5_AOT_COUNT).
namespace {
const std::uint64_t* entryCounts = nullptr;
std::size_t entryCountNumber = 0;
const std::uint64_t* entryCountAddresses = nullptr;
}

static void ReportEntryCounts() {
    const auto* counts = entryCounts;
    const auto number = entryCountNumber;
    const auto* addresses = entryCountAddresses;
    if (counts == nullptr || addresses == nullptr) return;
    std::size_t executed = 0, total = 0;
    for (std::size_t index = 0; index < number; ++index) {
        if (counts[index] == 0) continue;
        ++executed;
        total += static_cast<std::size_t>(counts[index]);
        std::fprintf(stderr, "[aot] count 0x%llx %llu\n",
                     static_cast<unsigned long long>(addresses[index]),
                     static_cast<unsigned long long>(counts[index]));
    }
    std::fprintf(stderr, "[aot] entry counts: %zu functions executed, %zu entries\n", executed, total);
    std::fflush(stderr);
}

// The launcher calls this from a fatal-signal handler too, so a trap still reports the counts.
extern "C" void NativeAotReportEntryCounts_nid_no_patch() { ReportEntryCounts(); }

// Registered by the generated native_image_init; reports at exit when ANYPS5_AOT_COUNT is set.
extern "C" void NativeAotRegisterEntryCounts_nid_no_patch(const std::uint64_t* counts, std::size_t number,
                                                          const std::uint64_t* addresses) {
    entryCounts = counts;
    entryCountNumber = number;
    entryCountAddresses = addresses;
    if (std::getenv("ANYPS5_AOT_COUNT") != nullptr) std::atexit(ReportEntryCounts);
}

// A declared function the lifter rejected: the generated stub reports its guest address and traps.
extern "C" void NativeAotReportUnimplemented_nid_no_patch(std::uint64_t address) {
    std::fprintf(stderr, "[aot] unimplemented function at 0x%llx\n",
                 static_cast<unsigned long long>(address));
    std::fflush(stderr);
}

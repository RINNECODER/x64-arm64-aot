#include "prx/libc/include/NativeAotImage.hpp"
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" void NativeAotRequireReadOnly_nid_no_patch(const NativeAotDataRange* ranges, std::size_t count) {
    if (ranges == nullptr && count != 0) throw std::invalid_argument("native AOT readonly ranges are missing");
    if (count == 0) return;
    struct Mapping {
        std::uintptr_t begin;
        std::uintptr_t end;
        bool readonly;
    };
    std::ifstream input("/proc/self/maps");
    if (!input) throw std::runtime_error("cannot read native AOT process mappings");
    std::vector<Mapping> mappings;
    for (std::string line; std::getline(input, line);) {
        std::istringstream fields(line);
        std::uintptr_t begin = 0, end = 0;
        char separator = 0;
        std::string permissions;
        if (!(fields >> std::hex >> begin >> separator >> end >> permissions) || separator != '-' ||
            end <= begin || permissions.size() < 2)
            throw std::runtime_error("invalid native AOT process mapping");
        mappings.push_back({begin, end, permissions[0] == 'r' && permissions[1] != 'w'});
    }
    if (!input.eof()) throw std::runtime_error("incomplete native AOT process mappings");
    for (std::size_t index = 0; index < count; ++index) {
        const auto& range = ranges[index];
        auto cursor = reinterpret_cast<std::uintptr_t>(range.address);
        if (cursor == 0 || range.bytes == 0 || range.bytes > std::numeric_limits<std::uintptr_t>::max() - cursor)
            throw std::invalid_argument("invalid native AOT readonly range");
        const auto end = cursor + range.bytes;
        for (const auto& mapping : mappings) {
            if (mapping.end <= cursor) continue;
            if (mapping.begin > cursor || !mapping.readonly) break;
            cursor = mapping.end;
            if (cursor >= end) break;
        }
        if (cursor < end) throw std::runtime_error("native AOT immutable data is not mapped read-only");
    }
}

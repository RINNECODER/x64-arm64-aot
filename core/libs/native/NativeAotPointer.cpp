#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

extern "C" bool NativeAotReadablePointer_nid_no_patch(const void* pointer, std::size_t bytes, bool nullable) {
    if (pointer == nullptr) return nullable;
    auto cursor = reinterpret_cast<std::uintptr_t>(pointer);
    if (bytes == 0 || bytes > std::numeric_limits<std::uintptr_t>::max() - cursor) return false;
    const auto end = cursor + bytes;
#ifdef __APPLE__
    while (cursor < end) {
        mach_vm_address_t address = cursor;
        mach_vm_size_t length = 0;
        vm_region_basic_info_data_64_t info{};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        const auto status = mach_vm_region(mach_task_self(), &address, &length, VM_REGION_BASIC_INFO_64,
            reinterpret_cast<vm_region_info_t>(&info), &count, &object);
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (status != KERN_SUCCESS || address > cursor || length == 0 ||
            length > std::numeric_limits<mach_vm_address_t>::max() - address || address + length <= cursor ||
            (info.protection & VM_PROT_READ) == 0) return false;
        cursor = address + length;
    }
    return true;
#else
    auto* maps = std::fopen("/proc/self/maps", "r");
    if (maps == nullptr) return false;
    char line[1024];
    while (cursor < end && std::fgets(line, sizeof(line), maps) != nullptr) {
        unsigned long begin = 0, finish = 0;
        char protection[5]{};
        if (std::sscanf(line, "%lx-%lx %4s", &begin, &finish, protection) != 3) continue;
        if (finish <= cursor) continue;
        if (begin > cursor || protection[0] != 'r') break;
        cursor = finish;
    }
    const bool valid = cursor >= end && !std::ferror(maps);
    std::fclose(maps);
    return valid;
#endif
}

extern "C" void NativeAotReportGuardFailure_nid_no_patch(std::uint64_t address, std::uint32_t kind) {
    const char* label = kind == 1 ? "pointer load" : kind == 2 ? "pointer argument" : kind == 3 ? "frame exclusion" : kind == 6 ? "pointer base" : "pointer output";
    std::fprintf(stderr, "native AOT guard failed: %s at guest 0x%llx\n", label, static_cast<unsigned long long>(address));
    std::fflush(stderr);
}

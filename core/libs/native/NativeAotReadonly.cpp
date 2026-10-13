#include "prx/libc/include/NativeAotImage.hpp"
#include <limits>
#include <stdexcept>
#include <mach/mach.h>
#include <mach/mach_vm.h>

extern "C" void NativeAotRequireReadOnly_nid_no_patch(const NativeAotDataRange* ranges, std::size_t count) {
    if (ranges == nullptr && count != 0) throw std::invalid_argument("native AOT readonly ranges are missing");
    for (std::size_t index = 0; index < count; ++index) {
        const auto& range = ranges[index];
        auto cursor = reinterpret_cast<mach_vm_address_t>(range.address);
        if (cursor == 0 || range.bytes == 0 || range.bytes > std::numeric_limits<mach_vm_address_t>::max() - cursor)
            throw std::invalid_argument("invalid native AOT readonly range");
        const auto end = cursor + range.bytes;
        while (cursor < end) {
            mach_vm_address_t address = cursor;
            mach_vm_size_t bytes = 0;
            vm_region_basic_info_data_64_t info{};
            mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object = MACH_PORT_NULL;
            const auto result = mach_vm_region(mach_task_self(), &address, &bytes, VM_REGION_BASIC_INFO_64,
                reinterpret_cast<vm_region_info_t>(&info), &infoCount, &object);
            if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
            if (result != KERN_SUCCESS || address > cursor || bytes == 0 ||
                bytes > std::numeric_limits<mach_vm_address_t>::max() - address || address + bytes <= cursor ||
                !(info.protection & VM_PROT_READ) || (info.protection & VM_PROT_WRITE))
                throw std::runtime_error("native AOT immutable data is not mapped read-only");
            cursor = address + bytes;
        }
    }
}

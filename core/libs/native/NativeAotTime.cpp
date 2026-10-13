#include "prx/libkernel/Time/include/TimedWait.hpp"
#include <cstdint>

extern "C" int sceKernelUsleep_nid_postfix(unsigned int microseconds) {
    TimedWait::SleepNanos(static_cast<std::uint64_t>(microseconds) * 1000ULL);
    return 0;
}

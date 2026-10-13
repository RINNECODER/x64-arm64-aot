#include "SceTypes.hpp"
#include "prx/libScePad/include/Pad.hpp"
#include "prx/libScePad/include/PadState.hpp"
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>

extern "C" {
int PadInputProviderGetUser(int*);
int PadInputProviderInit();
int PadInputProviderOpen(int, int, int, const void*);
int PadInputProviderRead(int, PadData*);
int PadInputProviderClose(int);
int scePadGetHandle(int, int, int);
}

static_assert(offsetof(PadData, buttons) == 0);
static_assert(sizeof(PadData) <= 1024);
static_assert(sizeof(PadData::buttons) == 4);

namespace {
std::string scenario;
int reads = 0;
int sleeps = 0;
int closes = 0;
int userId = 0;

void Require(bool condition) {
    if (!condition) throw std::runtime_error("pad input test contract failed");
}

void Receipt() {
    std::fprintf(stderr, "input-test reads=%d sleeps=%d closes=%d\n", reads, sleeps, closes);
}
}

void ConfigurePadInputTest(int argc, char** argv) {
    Require(argc == 2);
    scenario = argv[1];
    Require(scenario == "edges" || scenario == "read-error" || scenario == "user-error" ||
            scenario == "init-error" || scenario == "open-error" || scenario == "timeout");
    std::atexit(Receipt);
}

extern "C" int sceUserServiceGetInitialUser(int* user) {
    if (scenario == "user-error") return -1;
    const int result = PadInputProviderGetUser(user);
    Require(result == 0 && user != nullptr);
    userId = *user;
    return result;
}

extern "C" int scePadInit_nid_postfix() {
    if (scenario == "init-error") return -1;
    return PadInputProviderInit();
}

extern "C" int scePadOpen_nid_postfix(int user, int type, int index, const void* parameter) {
    if (scenario == "open-error") return PadInputProviderOpen(user, type, 1, parameter);
    Require(user == userId && type == 0 && index == 0 && parameter == nullptr);
    return PadInputProviderOpen(user, type, index, parameter);
}

extern "C" int scePadReadState(int handle, PadData* data) {
    const auto* bytes = reinterpret_cast<const unsigned char*>(data);
    for (std::size_t index = 0; index < 1024; ++index) Require(bytes[index] == 0);
    const int position = reads++;
    if (scenario == "read-error" && position == 0) return PadInputProviderRead(-1, data);
    constexpr std::uint32_t buttons[] = {0, 0x4000, 0x4000, 0, 0x80004000, 0, 0x4000, 8};
    PadInputState input;
    const int step = position - (scenario == "read-error" ? 1 : 0);
    input.buttons = scenario == "timeout" ? 0 : buttons[step < 8 ? step : 7];
    PadPublishInput_nid_postfix(input);
    return PadInputProviderRead(handle, data);
}

extern "C" int scePadClose_nid_postfix(int handle) {
    ++closes;
    const int result = PadInputProviderClose(handle);
    Require(result == 0 && scePadGetHandle(userId, 0, 0) < 0);
    return result;
}

extern "C" int sceKernelUsleep_nid_postfix(unsigned int microseconds) {
    Require(microseconds == 16000);
    ++sleeps;
    return 0;
}

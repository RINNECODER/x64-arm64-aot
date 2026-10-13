#include "native/NativeAotGlibcSupport.hpp"
#include <cstring>

namespace {

using namespace NativeAotGlibcSupport;

struct GuestPhdrInfo {
    std::uint64_t address;
    const char* name;
    std::uint64_t headers;
    std::uint16_t count;
    std::uint64_t additions;
    std::uint64_t subtractions;
    std::uint64_t tlsModule;
    std::uint64_t tlsData;
};

static_assert(sizeof(GuestPhdrInfo) == 64);

template<class Value>
Value Read(std::uint64_t address) {
    Value value;
    std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
    return value;
}

void DlIteratePhdr(State& state) {
    const auto callback = NativeAotGuest::Argument(state, 0);
    const auto data = NativeAotGuest::Argument(state, 1);
    const auto base = NativeAotGuest::ImageBase();
    if (Read<std::uint32_t>(base) != 0x464c457f) Unsupported("guest image header is not mapped at its base");
    GuestPhdrInfo info{};
    info.address = base;
    info.name = "";
    info.headers = base + Read<std::uint64_t>(base + 0x20);
    info.count = Read<std::uint16_t>(base + 0x38);
    info.additions = 1;
    info.tlsModule = 0;
    state.Gpr[7] = reinterpret_cast<std::uint64_t>(&info);
    state.Gpr[6] = sizeof(info);
    state.Gpr[2] = data;
    NativeAotGuest::Return(state, NativeAotGuest::Invoke(state, callback) & 0xffffffff);
}

void Dladdr(State& state) {
    const auto address = NativeAotGuest::Argument(state, 0);
    auto* output = Pointer<std::uint64_t>(state, 1);
    const auto base = NativeAotGuest::ImageBase();
    if (address < base || address - base >= NativeAotGuest::ImageSpan()) {
        ReturnInteger(state, 0);
        return;
    }
    output[0] = reinterpret_cast<std::uint64_t>("");
    output[1] = base;
    output[2] = 0;
    output[3] = 0;
    ReturnInteger(state, 1);
}

void Dlsym(State& state) {
    const auto* name = Text(state, 1);
    const auto address = NativeAotGuest::ExportAddress(name);
    if (address == 0) {
        ReturnPointer(state, nullptr);
        return;
    }
    ReturnInteger(state, static_cast<std::int64_t>(address));
}

const NativeAotGuest::ProviderBinding Bindings[] = {
    {"dl_iterate_phdr", DlIteratePhdr, nullptr, true, true},
    {"dladdr", Dladdr, nullptr, true, true},
    {"dlsym", Dlsym, nullptr, true, true},
};

}

namespace NativeAotGlibcSupport {

void RegisterDynamic() {
    Register(Bindings, sizeof(Bindings) / sizeof(Bindings[0]));
}

}

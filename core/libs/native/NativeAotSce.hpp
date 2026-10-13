#ifndef NATIVE_AOT_SCE_HPP
#define NATIVE_AOT_SCE_HPP

#include "native/NativeAotGuest.hpp"
#include <span>

namespace NativeAotSce {

struct Binding {
    const char* Identity;
    const char* NativeName;
    const void* Address;
    bool Data;
};

using BoundaryObserver = void (*)(const char*, const NativeAotGuestState&);
void Register(std::span<const Binding> bindings);
void SetBoundaryObserver(BoundaryObserver observer);
std::uint64_t InvokeCallback(std::uint64_t target, std::uint64_t argument = 0);

}

#endif

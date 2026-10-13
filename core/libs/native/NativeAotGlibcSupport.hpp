#ifndef NATIVE_AOT_GLIBC_SUPPORT_HPP
#define NATIVE_AOT_GLIBC_SUPPORT_HPP

#include "native/NativeAotGuest.hpp"
#include <cerrno>
#include <cstdint>
#include <string>

namespace NativeAotGlibcSupport {

using State = NativeAotGuestState;

[[noreturn]] void Unsupported(const std::string& message);
int GuestErrno(int host);
int HostErrno(int guest);
void SetGuestErrno(int value);
int CurrentGuestErrno();
void Register(const NativeAotGuest::ProviderBinding* bindings, std::size_t count);

struct ErrnoScope {
    int before;
    ErrnoScope() : before(errno) { errno = 0; }
    ~ErrnoScope() {
        if (errno != 0) SetGuestErrno(GuestErrno(errno));
        errno = before;
    }
};

template<class Value>
Value* Pointer(const State& state, std::size_t index) {
    return reinterpret_cast<Value*>(NativeAotGuest::Argument(state, index));
}

inline const char* Text(const State& state, std::size_t index) {
    return Pointer<const char>(state, index);
}

inline std::int64_t Signed(const State& state, std::size_t index) {
    return static_cast<std::int64_t>(NativeAotGuest::Argument(state, index));
}

inline int Integer(const State& state, std::size_t index) {
    return static_cast<int>(static_cast<std::uint32_t>(NativeAotGuest::Argument(state, index)));
}

inline void ReturnPointer(State& state, const void* value) {
    NativeAotGuest::Return(state, reinterpret_cast<std::uint64_t>(value));
}

inline void ReturnInteger(State& state, std::int64_t value) {
    NativeAotGuest::Return(state, static_cast<std::uint64_t>(value));
}

void RegisterLocale();
void RegisterThreads();
void RegisterDynamic();
void RegisterMath();
void RegisterPosix();

}

#endif

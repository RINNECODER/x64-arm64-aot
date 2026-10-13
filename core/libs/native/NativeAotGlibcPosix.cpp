#include "native/NativeAotGlibcSupport.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <crt_externs.h>
#include <libgen.h>
#include <sys/time.h>
#include <sys/random.h>
#include <unistd.h>

namespace {

using namespace NativeAotGlibcSupport;
using NativeAotGuest::Argument;

struct GuestTm {
    std::int32_t Second, Minute, Hour, Day, Month, Year, Weekday, Yearday, Daylight;
    std::int32_t Padding;
    std::int64_t Offset;
    std::uint64_t Zone;
};
static_assert(sizeof(GuestTm) == 56);
static_assert(offsetof(GuestTm, Offset) == 40);

std::tm ReadTm(const State& state, std::size_t index) {
    GuestTm value;
    std::memcpy(&value, Pointer<void>(state, index), sizeof(value));
    std::tm result{};
    result.tm_sec = value.Second; result.tm_min = value.Minute; result.tm_hour = value.Hour;
    result.tm_mday = value.Day; result.tm_mon = value.Month; result.tm_year = value.Year;
    result.tm_wday = value.Weekday; result.tm_yday = value.Yearday; result.tm_isdst = value.Daylight;
    result.tm_gmtoff = value.Offset;
    result.tm_zone = reinterpret_cast<char*>(value.Zone);
    return result;
}

void WriteTm(const State& state, std::size_t index, const std::tm& value) {
    GuestTm result{value.tm_sec, value.tm_min, value.tm_hour, value.tm_mday, value.tm_mon, value.tm_year,
                   value.tm_wday, value.tm_yday, value.tm_isdst, 0, value.tm_gmtoff, reinterpret_cast<std::uint64_t>(value.tm_zone)};
    std::memcpy(Pointer<void>(state, index), &result, sizeof(result));
}

template<std::tm* (*Function)(const time_t*, std::tm*)>
void BrokenTime(State& state) {
    ErrnoScope scope;
    std::int64_t seconds;
    std::memcpy(&seconds, Pointer<void>(state, 0), sizeof(seconds));
    const auto time = static_cast<time_t>(seconds);
    std::tm value{};
    const auto result = Function(&time, &value);
    if (result != nullptr) WriteTm(state, 1, value);
    ReturnPointer(state, result ? Pointer<void>(state, 1) : nullptr);
}

template<time_t (*Function)(std::tm*)>
void MakeTime(State& state) {
    ErrnoScope scope;
    auto value = ReadTm(state, 0);
    const auto result = Function(&value);
    WriteTm(state, 0, value);
    ReturnInteger(state, result);
}

void Strptime(State& state) {
    auto value = ReadTm(state, 2);
    const auto result = ::strptime(Text(state, 0), Text(state, 1), &value);
    WriteTm(state, 2, value);
    ReturnPointer(state, result);
}

void Strftime(State& state) {
    const auto value = ReadTm(state, 3);
    ReturnInteger(state, std::strftime(Pointer<char>(state, 0), Argument(state, 1), Text(state, 2), &value));
}

void Gettimeofday(State& state) {
    if (Argument(state, 1) != 0) Unsupported("gettimeofday timezone argument is not qualified");
    ErrnoScope scope;
    timeval value{};
    const auto result = ::gettimeofday(&value, nullptr);
    if (result == 0 && Argument(state, 0) != 0) {
        const std::int64_t fields[2] = {value.tv_sec, value.tv_usec};
        std::memcpy(Pointer<void>(state, 0), fields, sizeof(fields));
    }
    ReturnInteger(state, result);
}

void Time(State& state) {
    ErrnoScope scope;
    const std::int64_t value = std::time(nullptr);
    if (Argument(state, 0)) std::memcpy(Pointer<void>(state, 0), &value, sizeof(value));
    ReturnInteger(state, value);
}

void Putchar(State& state) { ErrnoScope scope; ReturnInteger(state, std::putchar(Integer(state, 0))); }
void Getentropy(State& state) { ErrnoScope scope; ReturnInteger(state, ::getentropy(Pointer<void>(state, 0), Argument(state, 1))); }
void Getpid(State& state) { ReturnInteger(state, ::getpid()); }
void Strspn(State& state) { ReturnInteger(state, std::strspn(Text(state, 0), Text(state, 1))); }
void Clearerr(State& state) { std::clearerr(Pointer<FILE>(state, 0)); }
void Dirname(State& state) { ReturnPointer(state, ::dirname(Pointer<char>(state, 0))); }
void Stpcpy(State& state) { ReturnPointer(state, ::stpcpy(Pointer<char>(state, 0), Text(state, 1))); }
void Realpath(State& state) { ErrnoScope scope; ReturnPointer(state, ::realpath(Text(state, 0), Pointer<char>(state, 1))); }
void Memmem(State& state) {
    ReturnPointer(state, Argument(state, 3) == 0 ? Pointer<void>(state, 0)
        : ::memmem(Pointer<void>(state, 0), Argument(state, 1), Pointer<void>(state, 2), Argument(state, 3)));
}

void Pathconf(State& state) {
    constexpr int names[] = {_PC_LINK_MAX, _PC_MAX_CANON, _PC_MAX_INPUT, _PC_NAME_MAX, _PC_PATH_MAX, _PC_PIPE_BUF,
                            _PC_CHOWN_RESTRICTED, _PC_NO_TRUNC, _PC_VDISABLE};
    const auto number = Integer(state, 1);
    if (number >= 9 && number <= 20) Unsupported("pathconf name requires a qualified glibc mapping");
    if (number < 0 || static_cast<std::size_t>(number) >= std::size(names)) {
        SetGuestErrno(22); ReturnInteger(state, -1); return;
    }
    ErrnoScope scope;
    ReturnInteger(state, ::pathconf(Text(state, 0), names[number]));
}

const NativeAotGuest::ProviderBinding Bindings[] = {
    {"gmtime_r", BrokenTime<::gmtime_r>, nullptr, true, true},
    {"localtime_r", BrokenTime<::localtime_r>, nullptr, true, true},
    {"timegm", MakeTime<::timegm>, nullptr, true, true},
    {"mktime", MakeTime<::mktime>, nullptr, true, true},
    {"strptime", Strptime, nullptr, true, true}, {"strftime", Strftime, nullptr, true, true},
    {"gettimeofday", Gettimeofday, nullptr, true, true}, {"time", Time, nullptr, true, true},
    {"putchar", Putchar, nullptr, true, true}, {"getentropy", Getentropy, nullptr, true, true},
    {"getpid", Getpid, nullptr, true, true}, {"strspn", Strspn, nullptr, true, true},
    {"clearerr", Clearerr, nullptr, true, true}, {"dirname", Dirname, nullptr, true, true},
    {"stpcpy", Stpcpy, nullptr, true, true}, {"pathconf", Pathconf, nullptr, true, true},
    {"realpath", Realpath, nullptr, true, true}, {"memmem", Memmem, nullptr, true, true},
};

}

namespace NativeAotGlibcSupport {
void RegisterPosix() {
    const NativeAotGuest::ProviderBinding environment{"environ", nullptr, _NSGetEnviron(), true, true};
    Register(&environment, 1);
    Register(Bindings, sizeof(Bindings) / sizeof(Bindings[0]));
}
}

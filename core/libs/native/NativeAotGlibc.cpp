#include "native/NativeAotGlibc.hpp"
#include "native/NativeAotGlibcSupport.hpp"
#include "native/NativeAotGuest.hpp"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <atomic>
#include <condition_variable>
#include <cwchar>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#include <vector>
#include <type_traits>

extern "C" bool NativeAotGlibcThreadFastBinding(std::uint64_t, std::uint64_t);

extern "C" {
std::uint64_t NativeAotGlibcFastMalloc(std::uint64_t a) {
    NativeAotGlibcSupport::ErrnoScope scope;
    return reinterpret_cast<std::uint64_t>(std::malloc(a));
}

std::uint64_t NativeAotGlibcFastCalloc(std::uint64_t a, std::uint64_t b) {
    NativeAotGlibcSupport::ErrnoScope scope;
    return reinterpret_cast<std::uint64_t>(std::calloc(a, b));
}

std::uint64_t NativeAotGlibcFastRealloc(std::uint64_t a, std::uint64_t b) {
    NativeAotGlibcSupport::ErrnoScope scope;
    return reinterpret_cast<std::uint64_t>(std::realloc(reinterpret_cast<void*>(a), b));
}

std::uint64_t NativeAotGlibcFastFree(std::uint64_t a) {
    std::free(reinterpret_cast<void*>(a));
    return 0;
}

std::uint64_t NativeAotGlibcFastMemcpy(std::uint64_t a, std::uint64_t b, std::uint64_t c) {
    return reinterpret_cast<std::uint64_t>(std::memcpy(reinterpret_cast<void*>(a), reinterpret_cast<const void*>(b), c));
}

std::uint64_t NativeAotGlibcFastMemmove(std::uint64_t a, std::uint64_t b, std::uint64_t c) {
    return reinterpret_cast<std::uint64_t>(std::memmove(reinterpret_cast<void*>(a), reinterpret_cast<const void*>(b), c));
}

std::uint64_t NativeAotGlibcFastMemset(std::uint64_t a, std::uint64_t b, std::uint64_t c) {
    return reinterpret_cast<std::uint64_t>(std::memset(reinterpret_cast<void*>(a), static_cast<int>(static_cast<std::uint32_t>(b)), c));
}

std::uint64_t NativeAotGlibcFastMemcmp(std::uint64_t a, std::uint64_t b, std::uint64_t c) {
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(std::memcmp(reinterpret_cast<const void*>(a), reinterpret_cast<const void*>(b), c)));
}

std::uint64_t NativeAotGlibcFastStrlen(std::uint64_t a) {
    return std::strlen(reinterpret_cast<const char*>(a));
}

}

namespace NativeAotGlibcSupport {

thread_local int guestErrno = 0;

[[noreturn]] void Unsupported(const std::string& message) {
    std::fprintf(stderr, "native AOT glibc provider: %s\n", message.c_str());
    std::fflush(stderr);
    std::_Exit(127);
}

const std::pair<int, int> ErrnoPairs[] = {
    {EPERM, 1}, {ENOENT, 2}, {ESRCH, 3}, {EINTR, 4}, {EIO, 5}, {ENXIO, 6}, {E2BIG, 7}, {ENOEXEC, 8}, {EBADF, 9},
    {ECHILD, 10}, {EAGAIN, 11}, {ENOMEM, 12}, {EACCES, 13}, {EFAULT, 14}, {ENOTBLK, 15}, {EBUSY, 16}, {EEXIST, 17},
    {EXDEV, 18}, {ENODEV, 19}, {ENOTDIR, 20}, {EISDIR, 21}, {EINVAL, 22}, {ENFILE, 23}, {EMFILE, 24}, {ENOTTY, 25},
    {ETXTBSY, 26}, {EFBIG, 27}, {ENOSPC, 28}, {ESPIPE, 29}, {EROFS, 30}, {EMLINK, 31}, {EPIPE, 32}, {EDOM, 33},
    {ERANGE, 34}, {EDEADLK, 35}, {ENAMETOOLONG, 36}, {ENOLCK, 37}, {ENOSYS, 38}, {ENOTEMPTY, 39}, {ELOOP, 40},
    {ENOMSG, 42}, {EIDRM, 43}, {ENOSTR, 60}, {ENODATA, 61}, {ETIME, 62}, {ENOSR, 63}, {ENOLINK, 67}, {EPROTO, 71},
    {EMULTIHOP, 72}, {EBADMSG, 74}, {EOVERFLOW, 75}, {EILSEQ, 84}, {EUSERS, 87}, {ENOTSOCK, 88}, {EDESTADDRREQ, 89},
    {EMSGSIZE, 90}, {EPROTOTYPE, 91}, {ENOPROTOOPT, 92}, {EPROTONOSUPPORT, 93}, {ESOCKTNOSUPPORT, 94},
    {ENOTSUP, 95}, {EPFNOSUPPORT, 96}, {EAFNOSUPPORT, 97}, {EADDRINUSE, 98}, {EADDRNOTAVAIL, 99}, {ENETDOWN, 100},
    {ENETUNREACH, 101}, {ENETRESET, 102}, {ECONNABORTED, 103}, {ECONNRESET, 104}, {ENOBUFS, 105}, {EISCONN, 106},
    {ENOTCONN, 107}, {ESHUTDOWN, 108}, {ETOOMANYREFS, 109}, {ETIMEDOUT, 110}, {ECONNREFUSED, 111}, {EHOSTDOWN, 112},
    {EHOSTUNREACH, 113}, {EALREADY, 114}, {EINPROGRESS, 115}, {ESTALE, 116}, {EDQUOT, 122}, {ECANCELED, 125},
    {EOWNERDEAD, 130}, {ENOTRECOVERABLE, 131}};

int GuestErrno(int host) {
    if (host == 0) return 0;
    for (const auto& [native, guest] : ErrnoPairs)
        if (native == host) return guest;
    Unsupported("host errno " + std::to_string(host) + " has no glibc x86-64 equivalent");
}

int HostErrno(int guest) {
    if (guest == 0) return 0;
    for (const auto& [native, value] : ErrnoPairs)
        if (value == guest) return native;
    return -1;
}

void SetGuestErrno(int value) {
    guestErrno = value;
}

int CurrentGuestErrno() {
    return guestErrno;
}

void Register(const NativeAotGuest::ProviderBinding* bindings, std::size_t count) {
    NativeAotGuest::RegisterProviders(bindings, count);
}


}

namespace {

using namespace NativeAotGlibcSupport;
using NativeAotGuest::Argument;
using NativeAotGuest::Return;

FILE* guestStdin = stdin;
FILE* guestStdout = stdout;
FILE* guestStderr = stderr;
std::mutex exitLock;
std::vector<std::pair<std::uint64_t, std::uint64_t>> exitHandlers;
std::map<DIR*, std::vector<std::uint8_t>> directoryEntries;
std::uint64_t signalHandlers[65] = {};
std::uint64_t signalStack = 0;

int HostSignal(int guest) {
    switch (guest) {
        case 1: return SIGHUP;
        case 2: return SIGINT;
        case 3: return SIGQUIT;
        case 4: return SIGILL;
        case 5: return SIGTRAP;
        case 6: return SIGABRT;
        case 7: return SIGBUS;
        case 8: return SIGFPE;
        case 9: return SIGKILL;
        case 10: return SIGUSR1;
        case 11: return SIGSEGV;
        case 12: return SIGUSR2;
        case 13: return SIGPIPE;
        case 14: return SIGALRM;
        case 15: return SIGTERM;
        case 17: return SIGCHLD;
        case 18: return SIGCONT;
        case 19: return SIGSTOP;
        case 20: return SIGTSTP;
        case 21: return SIGTTIN;
        case 22: return SIGTTOU;
        case 23: return SIGURG;
        case 24: return SIGXCPU;
        case 25: return SIGXFSZ;
        case 26: return SIGVTALRM;
        case 27: return SIGPROF;
        case 28: return SIGWINCH;
        case 29: return SIGIO;
        case 31: return SIGSYS;
        default: Unsupported("glibc signal " + std::to_string(guest) + " has no host equivalent");
    }
}

int GuestSignal(int host) {
    for (int guest = 1; guest < 32; ++guest) {
        if (guest == 16 || guest == 30) continue;
        if (HostSignal(guest) == host) return guest;
    }
    return 0;
}

void RunExitHandlers() {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> handlers;
    {
        std::lock_guard<std::mutex> lock(exitLock);
        handlers.swap(exitHandlers);
    }
    auto& state = NativeAotGuest::CurrentState();
    for (auto it = handlers.rbegin(); it != handlers.rend(); ++it) {
        state.Gpr[7] = it->second;
        NativeAotGuest::Invoke(state, it->first);
    }
}

void CopyStat(const struct stat& host, std::uint8_t* guest) {
    std::memset(guest, 0, 144);
    const std::uint64_t dev = host.st_dev, ino = host.st_ino, nlink = host.st_nlink, rdev = host.st_rdev;
    const std::uint32_t mode = host.st_mode, uid = host.st_uid, gid = host.st_gid;
    const std::int64_t size = host.st_size, blksize = host.st_blksize, blocks = host.st_blocks;
    const std::int64_t times[6] = {host.st_atimespec.tv_sec, host.st_atimespec.tv_nsec, host.st_mtimespec.tv_sec,
                                   host.st_mtimespec.tv_nsec, host.st_ctimespec.tv_sec, host.st_ctimespec.tv_nsec};
    std::memcpy(guest + 0, &dev, 8);
    std::memcpy(guest + 8, &ino, 8);
    std::memcpy(guest + 16, &nlink, 8);
    std::memcpy(guest + 24, &mode, 4);
    std::memcpy(guest + 28, &uid, 4);
    std::memcpy(guest + 32, &gid, 4);
    std::memcpy(guest + 40, &rdev, 8);
    std::memcpy(guest + 48, &size, 8);
    std::memcpy(guest + 56, &blksize, 8);
    std::memcpy(guest + 64, &blocks, 8);
    std::memcpy(guest + 72, times, sizeof(times));
}

void StatResult(State& state, int result, const struct stat& host, std::size_t output) {
    if (result == 0) CopyStat(host, Pointer<std::uint8_t>(state, output));
    ReturnInteger(state, result);
}

void RequireStatVersion(const State& state) {
    if (Integer(state, 0) != 1) Unsupported("unsupported glibc stat version");
}

int HostOpenFlags(std::int64_t guest) {
    const std::pair<std::int64_t, int> table[] = {{0100, O_CREAT}, {0200, O_EXCL}, {0400, O_NOCTTY}, {01000, O_TRUNC},
                                                  {02000, O_APPEND}, {04000, O_NONBLOCK}, {010000, O_DSYNC},
                                                  {0200000, O_DIRECTORY}, {0400000, O_NOFOLLOW}, {02000000, O_CLOEXEC},
                                                  {04000000, O_SYNC}, {0100000, 0}};
    int host = static_cast<int>(guest & 3);
    auto remaining = guest & ~std::int64_t{3};
    for (const auto& [bit, value] : table) {
        if ((remaining & bit) == bit) {
            host |= value;
            remaining &= ~bit;
        }
    }
    if (remaining != 0) Unsupported("unsupported glibc open flags");
    return host;
}

int HostDirectory(std::int64_t guest) {
    return guest == -100 ? AT_FDCWD : static_cast<int>(guest);
}

struct VarArgs {
    const State* state = nullptr;
    std::size_t integer = 0;
    std::size_t floating = 0;
    std::uint64_t stack = 0;
    std::uint64_t list = 0;
    std::uint32_t integerOffset = 0;
    std::uint32_t floatingOffset = 0;
    std::uint64_t saveArea = 0;

    VarArgs(const State& value, std::size_t fixedIntegers)
        : state(&value), integer(fixedIntegers), stack(value.Gpr[4] + 8) {}

    explicit VarArgs(std::uint64_t vaList) : list(vaList) {
        std::memcpy(&integerOffset, reinterpret_cast<const void*>(vaList), 4);
        std::memcpy(&floatingOffset, reinterpret_cast<const void*>(vaList + 4), 4);
        std::memcpy(&stack, reinterpret_cast<const void*>(vaList + 8), 8);
        std::memcpy(&saveArea, reinterpret_cast<const void*>(vaList + 16), 8);
    }

    std::uint64_t Overflow() {
        std::uint64_t value;
        std::memcpy(&value, reinterpret_cast<const void*>(stack), 8);
        stack += 8;
        return value;
    }

    std::uint64_t Next() {
        if (list != 0) {
            if (integerOffset < 48) {
                std::uint64_t value;
                std::memcpy(&value, reinterpret_cast<const void*>(saveArea + integerOffset), 8);
                integerOffset += 8;
                return value;
            }
            return Overflow();
        }
        if (integer < 6) return Argument(*state, integer++);
        return Overflow();
    }

    double NextDouble() {
        double value;
        if (list != 0) {
            if (floatingOffset < 176) {
                std::memcpy(&value, reinterpret_cast<const void*>(saveArea + floatingOffset), 8);
                floatingOffset += 16;
                return value;
            }
        } else if (floating < 8) {
            std::memcpy(&value, state->Xmm[floating++], 8);
            return value;
        }
        const auto raw = Overflow();
        std::memcpy(&value, &raw, 8);
        return value;
    }
};

std::string Format(const char* format, VarArgs& arguments) {
    std::string output;
    char buffer[512];
    for (const char* cursor = format; *cursor != '\0';) {
        if (*cursor != '%') {
            output += *cursor++;
            continue;
        }
        const char* start = cursor++;
        if (*cursor == '%') {
            output += '%';
            ++cursor;
            continue;
        }
        std::string spec = "%";
        while (std::strchr("-+ #0'", *cursor) != nullptr && *cursor != '\0') spec += *cursor++;
        int stars[2] = {0, 0};
        int starCount = 0;
        if (*cursor == '*') {
            stars[starCount++] = static_cast<int>(arguments.Next());
            spec += '*';
            ++cursor;
        } else {
            while (*cursor >= '0' && *cursor <= '9') spec += *cursor++;
        }
        if (*cursor == '.') {
            spec += *cursor++;
            if (*cursor == '*') {
                stars[starCount++] = static_cast<int>(arguments.Next());
                spec += '*';
                ++cursor;
            } else {
                while (*cursor >= '0' && *cursor <= '9') spec += *cursor++;
            }
        }
        std::string length;
        while (std::strchr("hlLqjzt", *cursor) != nullptr && *cursor != '\0') length += *cursor++;
        const char conversion = *cursor++;
        if (conversion == '\0') Unsupported("truncated format string");
        auto print = [&](auto value) {
            const auto finalSpec = spec + conversion;
            int written;
            if (starCount == 2) written = std::snprintf(buffer, sizeof(buffer), finalSpec.c_str(), stars[0], stars[1], value);
            else if (starCount == 1) written = std::snprintf(buffer, sizeof(buffer), finalSpec.c_str(), stars[0], value);
            else written = std::snprintf(buffer, sizeof(buffer), finalSpec.c_str(), value);
            if (written < 0) Unsupported("host formatting failed");
            if (static_cast<std::size_t>(written) < sizeof(buffer)) {
                output.append(buffer, static_cast<std::size_t>(written));
                return;
            }
            std::vector<char> large(static_cast<std::size_t>(written) + 1);
            if (starCount == 2) std::snprintf(large.data(), large.size(), finalSpec.c_str(), stars[0], stars[1], value);
            else if (starCount == 1) std::snprintf(large.data(), large.size(), finalSpec.c_str(), stars[0], value);
            else std::snprintf(large.data(), large.size(), finalSpec.c_str(), value);
            output.append(large.data(), static_cast<std::size_t>(written));
        };
        switch (conversion) {
            case 'd':
            case 'i': {
                const auto raw = arguments.Next();
                long long value;
                if (length == "hh") value = static_cast<signed char>(raw);
                else if (length == "h") value = static_cast<short>(raw);
                else if (length.empty()) value = static_cast<int>(raw);
                else value = static_cast<long long>(raw);
                spec += "ll";
                print(value);
                break;
            }
            case 'u':
            case 'x':
            case 'X':
            case 'o': {
                const auto raw = arguments.Next();
                unsigned long long value;
                if (length == "hh") value = static_cast<unsigned char>(raw);
                else if (length == "h") value = static_cast<unsigned short>(raw);
                else if (length.empty()) value = static_cast<unsigned int>(raw);
                else value = raw;
                spec += "ll";
                print(value);
                break;
            }
            case 'c':
                if (!length.empty()) Unsupported("wide character formatting");
                print(static_cast<int>(static_cast<unsigned char>(arguments.Next())));
                break;
            case 's': {
                if (!length.empty()) Unsupported("wide string formatting");
                const auto* value = reinterpret_cast<const char*>(arguments.Next());
                print(value == nullptr ? "(null)" : value);
                break;
            }
            case 'p': {
                const auto value = arguments.Next();
                if (value == 0) {
                    spec += 's';
                    std::snprintf(buffer, sizeof(buffer), spec.c_str(), "(nil)");
                    output += buffer;
                } else {
                    print(reinterpret_cast<void*>(value));
                }
                break;
            }
            case 'f':
            case 'F':
            case 'e':
            case 'E':
            case 'g':
            case 'G':
            case 'a':
            case 'A':
                if (length == "L") Unsupported("long double formatting requires x87 conversion");
                print(arguments.NextDouble());
                break;
            case 'm':
                output += std::strerror(HostErrno(CurrentGuestErrno()));
                break;
            case 'n':
                Unsupported("%n formatting");
            default:
                Unsupported(std::string("unsupported format conversion in ") + start);
        }
    }
    return output;
}

void WriteStream(State& state, FILE* stream, const std::string& text) {
    ErrnoScope scope;
    const auto written = std::fwrite(text.data(), 1, text.size(), stream);
    ReturnInteger(state, written == text.size() ? static_cast<std::int64_t>(text.size()) : -1);
}

void WriteBuffer(State& state, char* buffer, std::uint64_t capacity, const std::string& text) {
    if (capacity != 0) {
        const auto count = std::min<std::uint64_t>(capacity - 1, text.size());
        std::memcpy(buffer, text.data(), count);
        buffer[count] = '\0';
    }
    ReturnInteger(state, static_cast<std::int64_t>(text.size()));
}

void WriteFormatted(State& state, FILE* stream, const char* format, std::size_t fixed) {
    VarArgs arguments(state, fixed);
    const auto text = Format(format, arguments);
    ErrnoScope scope;
    const auto written = std::fwrite(text.data(), 1, text.size(), stream);
    ReturnInteger(state, written == text.size() ? static_cast<std::int64_t>(text.size()) : -1);
}

int Scan(const char* input, const char* format, VarArgs& arguments) {
    const char* cursor = input;
    int assigned = 0;
    bool converted = false;
    for (const char* spec = format; *spec != '\0';) {
        if (std::isspace(static_cast<unsigned char>(*spec))) {
            while (std::isspace(static_cast<unsigned char>(*spec))) ++spec;
            while (std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
            continue;
        }
        if (*spec != '%' || spec[1] == '%') {
            const char expected = *spec == '%' ? '%' : *spec;
            spec += *spec == '%' ? 2 : 1;
            if (expected == '%')
                while (std::isspace(static_cast<unsigned char>(*cursor))) ++cursor;
            if (*cursor != expected) return (*cursor == '\0' && !converted) ? -1 : assigned;
            ++cursor;
            continue;
        }
        ++spec;
        const bool suppressed = *spec == '*';
        if (suppressed) ++spec;
        std::string width;
        while (std::isdigit(static_cast<unsigned char>(*spec))) width += *spec++;
        std::string length;
        while (*spec != '\0' && std::strchr("hlLqjzt", *spec) != nullptr) length += *spec++;
        const char conversion = *spec++;
        std::string set;
        if (conversion == '[') {
            set = "[";
            if (*spec == '^') set += *spec++;
            if (*spec == ']') set += *spec++;
            while (*spec != '\0' && *spec != ']') set += *spec++;
            if (*spec != ']') Unsupported("unterminated scanf set");
            set += *spec++;
        }
        if (conversion == 'n') {
            if (!suppressed) {
                const auto target = arguments.Next();
                const auto count = static_cast<std::int64_t>(cursor - input);
                const auto size = length == "hh" ? 1 : length == "h" ? 2 : length.empty() ? 4 : 8;
                std::memcpy(reinterpret_cast<void*>(target), &count, static_cast<std::size_t>(size));
            }
            continue;
        }
        if (length == "L" || (!length.empty() && length != "hh" && length != "h" && length != "l" && length != "ll" &&
                              length != "j" && length != "z" && length != "t" && length != "q"))
            Unsupported("unsupported scanf length modifier");
        int consumed = -1;
        std::string host = std::string("%") + (suppressed ? "*" : "") + width;
        int result;
        if (std::strchr("diuxXo", conversion) != nullptr) {
            long long value = 0;
            host += "ll";
            host += conversion;
            host += "%n";
            result = suppressed ? std::sscanf(cursor, host.c_str(), &consumed) : std::sscanf(cursor, host.c_str(), &value, &consumed);
            if (consumed < 0) return (result == EOF && !converted) ? -1 : assigned;
            if (!suppressed) {
                const auto size = length == "hh" ? 1 : length == "h" ? 2 : length.empty() ? 4 : 8;
                std::memcpy(reinterpret_cast<void*>(arguments.Next()), &value, static_cast<std::size_t>(size));
            }
        } else if (std::strchr("fFeEgGaA", conversion) != nullptr) {
            double value = 0;
            host += "l";
            host += conversion;
            host += "%n";
            result = suppressed ? std::sscanf(cursor, host.c_str(), &consumed) : std::sscanf(cursor, host.c_str(), &value, &consumed);
            if (consumed < 0) return (result == EOF && !converted) ? -1 : assigned;
            if (!suppressed) {
                const auto target = reinterpret_cast<void*>(arguments.Next());
                if (length.empty()) {
                    const float narrow = static_cast<float>(value);
                    std::memcpy(target, &narrow, sizeof(narrow));
                } else {
                    std::memcpy(target, &value, sizeof(value));
                }
            }
        } else if (conversion == 'p') {
            void* value = nullptr;
            host += "p%n";
            result = suppressed ? std::sscanf(cursor, host.c_str(), &consumed) : std::sscanf(cursor, host.c_str(), &value, &consumed);
            if (consumed < 0) return (result == EOF && !converted) ? -1 : assigned;
            if (!suppressed) std::memcpy(reinterpret_cast<void*>(arguments.Next()), &value, sizeof(value));
        } else if (conversion == 's' || conversion == 'c' || conversion == '[') {
            if (length == "l") Unsupported("wide scanf conversion");
            host += conversion == '[' ? set : std::string(1, conversion);
            host += "%n";
            if (suppressed) result = std::sscanf(cursor, host.c_str(), &consumed);
            else result = std::sscanf(cursor, host.c_str(), reinterpret_cast<char*>(arguments.Next()), &consumed);
            if (consumed < 0) return (result == EOF && !converted) ? -1 : assigned;
        } else {
            Unsupported(std::string("unsupported scanf conversion ") + conversion);
        }
        cursor += consumed;
        converted = true;
        if (!suppressed) ++assigned;
    }
    return assigned;
}

void ErrnoLocation(State& state) {
    ReturnPointer(state, &NativeAotGlibcSupport::guestErrno);
}

void FxStat(State& state) {
    RequireStatVersion(state);
    ErrnoScope scope;
    struct stat host {};
    const auto result = fstat(Integer(state, 1), &host);
    StatResult(state, result, host, 2);
}

void XStat(State& state) {
    RequireStatVersion(state);
    ErrnoScope scope;
    struct stat host {};
    const auto result = stat(Text(state, 1), &host);
    StatResult(state, result, host, 2);
}

void LxStat(State& state) {
    RequireStatVersion(state);
    ErrnoScope scope;
    struct stat host {};
    const auto result = lstat(Text(state, 1), &host);
    StatResult(state, result, host, 2);
}

[[noreturn]] void Exit(int code) {
    RunExitHandlers();
    std::exit(code);
}

void LibcStartMain(State& state) {
    const auto main = Argument(state, 0);
    const auto argc = Argument(state, 1);
    const auto argv = Argument(state, 2);
    const auto init = Argument(state, 3);
    const auto fini = Argument(state, 4);
    const auto environment = argv + 8 * (argc + 1);
    if (fini != 0) {
        std::lock_guard<std::mutex> lock(exitLock);
        exitHandlers.emplace_back(fini, 0);
    }
    if (init != 0) {
        state.Gpr[7] = argc;
        state.Gpr[6] = argv;
        state.Gpr[2] = environment;
        NativeAotGuest::Invoke(state, init);
    }
    state.Gpr[7] = argc;
    state.Gpr[6] = argv;
    state.Gpr[2] = environment;
    const auto result = NativeAotGuest::Invoke(state, main);
    Exit(static_cast<int>(static_cast<std::uint32_t>(result)));
}

void SignalTrampoline(int host) {
    const auto guest = GuestSignal(host);
    if (guest == 0 || signalHandlers[guest] == 0) return;
    static NativeAotGuestState state;
    std::memset(&state, 0, sizeof(state));
    state.Mxcsr = 0x1f80;
    state.Gpr[4] = signalStack;
    state.Gpr[7] = static_cast<std::uint64_t>(guest);
    NativeAotGuest::Invoke(state, signalHandlers[guest]);
}

void SysvSignal(State& state) {
    NativeAotGuest::PromoteSharedMemory();
    const auto guest = Integer(state, 0);
    const auto handler = Argument(state, 1);
    if (guest <= 0 || guest >= 65) {
        SetGuestErrno(22);
        ReturnInteger(state, -1);
        return;
    }
    const auto host = HostSignal(guest);
    const auto previous = signalHandlers[guest];
    void (*action)(int);
    if (handler == 0) action = SIG_DFL;
    else if (handler == 1) action = SIG_IGN;
    else {
        if (signalStack == 0) signalStack = NativeAotGuest::AllocateStack(1024 * 1024) - 64;
        action = SignalTrampoline;
    }
    ErrnoScope scope;
    auto old = std::signal(host, action);
    if (old == SIG_ERR) {
        ReturnInteger(state, -1);
        return;
    }
    signalHandlers[guest] = handler > 1 ? handler : 0;
    if (old == SIG_IGN) Return(state, 1);
    else if (old == SignalTrampoline) Return(state, previous);
    else Return(state, 0);
}

void Abort(State&) {
    std::abort();
}

void Backtrace(State&) {
    Unsupported("backtrace requires guest CFA unwinding");
}

void BacktraceSymbols(State&) {
    Unsupported("backtrace_symbols requires guest CFA unwinding");
}

template<auto Function, bool HasResult = true>
void ScalarProvider(State& state) {
    std::uint64_t value;
    if constexpr (std::is_invocable_r_v<std::uint64_t, decltype(Function), std::uint64_t>)
        value = Function(Argument(state, 0));
    else if constexpr (std::is_invocable_r_v<std::uint64_t, decltype(Function), std::uint64_t, std::uint64_t>)
        value = Function(Argument(state, 0), Argument(state, 1));
    else
        value = Function(Argument(state, 0), Argument(state, 1), Argument(state, 2));
    if constexpr (HasResult) Return(state, value);
}









void Chmod(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, chmod(Text(state, 0), static_cast<mode_t>(Argument(state, 1))));
}

void Chown(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, chown(Text(state, 0), static_cast<uid_t>(Argument(state, 1)), static_cast<gid_t>(Argument(state, 2))));
}

void Fchmod(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, fchmod(Integer(state, 0), static_cast<mode_t>(Argument(state, 1))));
}

void Fchown(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, fchown(Integer(state, 0), static_cast<uid_t>(Argument(state, 1)), static_cast<gid_t>(Argument(state, 2))));
}

void Clock(State& state) {
    ReturnInteger(state, static_cast<std::int64_t>(clock()));
}

void ClockGettime(State& state) {
    clockid_t host;
    switch (Integer(state, 0)) {
        case 0: host = CLOCK_REALTIME; break;
        case 1: host = CLOCK_MONOTONIC; break;
        case 2: host = CLOCK_PROCESS_CPUTIME_ID; break;
        case 3: host = CLOCK_THREAD_CPUTIME_ID; break;
        case 4: host = CLOCK_MONOTONIC_RAW; break;
        default:
            SetGuestErrno(22);
            ReturnInteger(state, -1);
            return;
    }
    ErrnoScope scope;
    timespec value {};
    const auto result = clock_gettime(host, &value);
    if (result == 0) {
        const std::int64_t fields[2] = {value.tv_sec, value.tv_nsec};
        std::memcpy(Pointer<void>(state, 1), fields, sizeof(fields));
    }
    ReturnInteger(state, result);
}

void Close(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, close(Integer(state, 0)));
}

void Open(State& state) {
    const auto flags = HostOpenFlags(Signed(state, 1));
    ErrnoScope scope;
    ReturnInteger(state, open(Text(state, 0), flags, static_cast<unsigned>(Argument(state, 2))));
}

void Opendir(State& state) {
    ErrnoScope scope;
    auto* directory = opendir(Text(state, 0));
    if (directory != nullptr) directoryEntries[directory].assign(280, 0);
    ReturnPointer(state, directory);
}

void Readdir(State& state) {
    auto* directory = Pointer<DIR>(state, 0);
    ErrnoScope scope;
    auto* entry = readdir(directory);
    if (entry == nullptr) {
        ReturnPointer(state, nullptr);
        return;
    }
    auto& buffer = directoryEntries.at(directory);
    std::fill(buffer.begin(), buffer.end(), 0);
    const std::uint64_t inode = entry->d_ino;
    const std::int64_t offset = 0;
    const std::uint16_t length = 280;
    std::memcpy(buffer.data(), &inode, 8);
    std::memcpy(buffer.data() + 8, &offset, 8);
    std::memcpy(buffer.data() + 16, &length, 2);
    buffer[18] = entry->d_type;
    std::memcpy(buffer.data() + 19, entry->d_name, std::min<std::size_t>(entry->d_namlen, 255));
    ReturnPointer(state, buffer.data());
}

void Closedir(State& state) {
    auto* directory = Pointer<DIR>(state, 0);
    directoryEntries.erase(directory);
    ErrnoScope scope;
    ReturnInteger(state, closedir(directory));
}

void ExitProvider(State& state) {
    Exit(Integer(state, 0));
}

void Fclose(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::fclose(Pointer<FILE>(state, 0)));
}

void Fdopen(State& state) {
    ErrnoScope scope;
    ReturnPointer(state, fdopen(Integer(state, 0), Text(state, 1)));
}

void Feof(State& state) {
    ReturnInteger(state, std::feof(Pointer<FILE>(state, 0)));
}

void Ferror(State& state) {
    ReturnInteger(state, std::ferror(Pointer<FILE>(state, 0)));
}

void Fflush(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::fflush(Pointer<FILE>(state, 0)));
}

void Fgets(State& state) {
    ErrnoScope scope;
    ReturnPointer(state, std::fgets(Pointer<char>(state, 0), Integer(state, 1), Pointer<FILE>(state, 2)));
}

void Fileno(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, fileno(Pointer<FILE>(state, 0)));
}

void Fopen(State& state) {
    ErrnoScope scope;
    ReturnPointer(state, std::fopen(Text(state, 0), Text(state, 1)));
}

void Fprintf(State& state) {
    WriteFormatted(state, Pointer<FILE>(state, 0), Text(state, 1), 2);
}

void Fputc(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::fputc(Integer(state, 0), Pointer<FILE>(state, 1)));
}

void Fputs(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::fputs(Text(state, 0), Pointer<FILE>(state, 1)));
}

void Fread(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, static_cast<std::int64_t>(std::fread(Pointer<void>(state, 0), Argument(state, 1), Argument(state, 2), Pointer<FILE>(state, 3))));
}

void Fseek(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::fseek(Pointer<FILE>(state, 0), static_cast<long>(Signed(state, 1)), Integer(state, 2)));
}

void Ftell(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::ftell(Pointer<FILE>(state, 0)));
}

void Fwrite(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, static_cast<std::int64_t>(std::fwrite(Pointer<const void>(state, 0), Argument(state, 1), Argument(state, 2), Pointer<FILE>(state, 3))));
}

void Getc(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::getc(Pointer<FILE>(state, 0)));
}

void Getenv(State& state) {
    ReturnPointer(state, std::getenv(Text(state, 0)));
}

void Isatty(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, isatty(Integer(state, 0)));
}









void Mkdir(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, mkdir(Text(state, 0), static_cast<mode_t>(Argument(state, 1))));
}

void Mmap(State& state) {
    const auto guestFlags = Integer(state, 3);
    if ((guestFlags & 1) != 0 || (guestFlags & 0x20) == 0) NativeAotGuest::PromoteSharedMemory();
    int flags = 0;
    if (guestFlags & 1) flags |= MAP_SHARED;
    if (guestFlags & 2) flags |= MAP_PRIVATE;
    if (guestFlags & 0x10) {
        NativeAotGuest::CheckImageMappingChange(Argument(state, 0), Argument(state, 1));
        flags |= MAP_FIXED;
    }
    if (guestFlags & 0x20) flags |= MAP_ANON;
    if (guestFlags & 0x4000) flags |= MAP_NORESERVE;
    if (guestFlags & ~(1 | 2 | 0x10 | 0x20 | 0x4000 | 0x8000)) Unsupported("unsupported glibc mmap flags");
    ErrnoScope scope;
    ReturnPointer(state, mmap(Pointer<void>(state, 0), Argument(state, 1), Integer(state, 2), flags, Integer(state, 4),
                              static_cast<off_t>(Signed(state, 5))));
}

void Munmap(State& state) {
    NativeAotGuest::CheckImageMappingChange(Argument(state, 0), Argument(state, 1));
    ErrnoScope scope;
    ReturnInteger(state, munmap(Pointer<void>(state, 0), Argument(state, 1)));
}

void Perror(State& state) {
    const auto* prefix = Text(state, 0);
    const auto* message = std::strerror(HostErrno(CurrentGuestErrno()));
    if (prefix != nullptr && *prefix != '\0') std::fprintf(stderr, "%s: %s\n", prefix, message);
    else std::fprintf(stderr, "%s\n", message);
}

struct Comparator {
    State* state;
    std::uint64_t function;
    std::uint64_t argument;
    bool withArgument;
};

int CompareGuest(void* context, const void* left, const void* right) {
    auto* comparator = static_cast<Comparator*>(context);
    comparator->state->Gpr[7] = reinterpret_cast<std::uint64_t>(left);
    comparator->state->Gpr[6] = reinterpret_cast<std::uint64_t>(right);
    if (comparator->withArgument) comparator->state->Gpr[2] = comparator->argument;
    return static_cast<int>(static_cast<std::uint32_t>(NativeAotGuest::Invoke(*comparator->state, comparator->function)));
}

void Qsort(State& state) {
    Comparator comparator{&state, Argument(state, 3), 0, false};
    qsort_r(Pointer<void>(state, 0), Argument(state, 1), Argument(state, 2), &comparator, CompareGuest);
}

void QsortR(State& state) {
    Comparator comparator{&state, Argument(state, 3), Argument(state, 4), true};
    qsort_r(Pointer<void>(state, 0), Argument(state, 1), Argument(state, 2), &comparator, CompareGuest);
}

void Raise(State& state) {
    const auto host = HostSignal(Integer(state, 0));
    ErrnoScope scope;
    ReturnInteger(state, raise(host));
}

void Remove(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::remove(Text(state, 0)));
}

void Setpriority(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, setpriority(Integer(state, 0), static_cast<id_t>(Argument(state, 1)), Integer(state, 2)));
}

void Setvbuf(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::setvbuf(Pointer<FILE>(state, 0), Pointer<char>(state, 1), Integer(state, 2), Argument(state, 3)));
}

void Strchr(State& state) {
    ReturnPointer(state, std::strchr(Text(state, 0), Integer(state, 1)));
}

void Strcmp(State& state) {
    ReturnInteger(state, std::strcmp(Text(state, 0), Text(state, 1)));
}

void Strcpy(State& state) {
    ReturnPointer(state, std::strcpy(Pointer<char>(state, 0), Text(state, 1)));
}

void Strdup(State& state) {
    ErrnoScope scope;
    ReturnPointer(state, strdup(Text(state, 0)));
}

void Strerror(State& state) {
    const auto host = HostErrno(Integer(state, 0));
    static thread_local char buffer[64];
    if (host < 0) {
        std::snprintf(buffer, sizeof(buffer), "Unknown error %d", Integer(state, 0));
        ReturnPointer(state, buffer);
        return;
    }
    ReturnPointer(state, std::strerror(host));
}



void Strncmp(State& state) {
    ReturnInteger(state, std::strncmp(Text(state, 0), Text(state, 1), Argument(state, 2)));
}

void Strrchr(State& state) {
    ReturnPointer(state, std::strrchr(Text(state, 0), Integer(state, 1)));
}

void Strstr(State& state) {
    ReturnPointer(state, std::strstr(Text(state, 0), Text(state, 1)));
}

void Strtol(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::strtol(Text(state, 0), Pointer<char*>(state, 1), Integer(state, 2)));
}

void Sysconf(State& state) {
    int host;
    switch (Integer(state, 0)) {
        case 2: host = _SC_CLK_TCK; break;
        case 30: host = _SC_PAGESIZE; break;
        case 83: host = _SC_NPROCESSORS_CONF; break;
        case 84: host = _SC_NPROCESSORS_ONLN; break;
        case 85: host = _SC_PHYS_PAGES; break;
        default: Unsupported("unsupported glibc sysconf name " + std::to_string(Integer(state, 0)));
    }
    ErrnoScope scope;
    ReturnInteger(state, sysconf(host));
}

void Utimensat(State& state) {
    const auto guestFlags = Integer(state, 3);
    if ((guestFlags & 1) != 0 || (guestFlags & 0x20) == 0) NativeAotGuest::PromoteSharedMemory();
    if (guestFlags & ~0x100) Unsupported("unsupported utimensat flags");
    timespec times[2];
    const auto* source = Pointer<const std::int64_t>(state, 2);
    if (source != nullptr) {
        for (int index = 0; index < 2; ++index) {
            times[index].tv_sec = source[2 * index];
            const auto nanoseconds = source[2 * index + 1];
            times[index].tv_nsec = nanoseconds == (1 << 30) - 1 ? UTIME_NOW : nanoseconds == (1 << 30) - 2 ? UTIME_OMIT : nanoseconds;
        }
    }
    ErrnoScope scope;
    ReturnInteger(state, utimensat(HostDirectory(Signed(state, 0)), Text(state, 1), source == nullptr ? nullptr : times,
                                   (guestFlags & 0x100) ? AT_SYMLINK_NOFOLLOW : 0));
}

void AlignedAlloc(State& state) {
    auto alignment = Argument(state, 0);
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        SetGuestErrno(22);
        ReturnPointer(state, nullptr);
        return;
    }
    alignment = std::max<std::uint64_t>(alignment, sizeof(void*));
    void* result = nullptr;
    const auto status = posix_memalign(&result, alignment, Argument(state, 1));
    if (status != 0) SetGuestErrno(GuestErrno(status));
    ReturnPointer(state, status == 0 ? result : nullptr);
}

void Bcmp(State& state) {
    ReturnInteger(state, std::memcmp(Pointer<const void>(state, 0), Pointer<const void>(state, 1), Argument(state, 2)) != 0);
}

void Memchr(State& state) {
    ReturnPointer(state, std::memchr(Pointer<const void>(state, 0), Integer(state, 1), Argument(state, 2)));
}

void Fseeko(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, fseeko(Pointer<FILE>(state, 0), static_cast<off_t>(Signed(state, 1)), Integer(state, 2)));
}

void Ftello(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, ftello(Pointer<FILE>(state, 0)));
}

void Setbuf(State& state) {
    auto* buffer = Pointer<char>(state, 1);
    std::setvbuf(Pointer<FILE>(state, 0), buffer, buffer == nullptr ? _IONBF : _IOFBF, 8192);
}

void Ungetc(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::ungetc(Integer(state, 0), Pointer<FILE>(state, 1)));
}

void Snprintf(State& state) {
    VarArgs arguments(state, 3);
    WriteBuffer(state, Pointer<char>(state, 0), Argument(state, 1), Format(Text(state, 2), arguments));
}

void Vsnprintf(State& state) {
    VarArgs arguments(Argument(state, 3));
    WriteBuffer(state, Pointer<char>(state, 0), Argument(state, 1), Format(Text(state, 2), arguments));
}

void Vfprintf(State& state) {
    VarArgs arguments(Argument(state, 2));
    WriteStream(state, Pointer<FILE>(state, 0), Format(Text(state, 1), arguments));
}

void Vasprintf(State& state) {
    VarArgs arguments(Argument(state, 2));
    const auto text = Format(Text(state, 1), arguments);
    auto* result = static_cast<char*>(std::malloc(text.size() + 1));
    if (result == nullptr) {
        SetGuestErrno(12);
        ReturnInteger(state, -1);
        return;
    }
    std::memcpy(result, text.c_str(), text.size() + 1);
    *Pointer<char*>(state, 0) = result;
    ReturnInteger(state, static_cast<std::int64_t>(text.size()));
}

void Sscanf(State& state) {
    VarArgs arguments(state, 2);
    ReturnInteger(state, Scan(Text(state, 0), Text(state, 1), arguments));
}

void Vsscanf(State& state) {
    VarArgs arguments(Argument(state, 2));
    ReturnInteger(state, Scan(Text(state, 0), Text(state, 1), arguments));
}

void StrerrorR(State& state) {
    const auto host = HostErrno(Integer(state, 0));
    auto* buffer = Pointer<char>(state, 1);
    const auto capacity = Argument(state, 2);
    if (host < 0) {
        if (capacity != 0) std::snprintf(buffer, capacity, "Unknown error %d", Integer(state, 0));
        ReturnPointer(state, buffer);
        return;
    }
    ReturnPointer(state, std::strerror(host));
}

std::mutex futexLock;
std::condition_variable futexWake;
std::map<std::uint64_t, std::uint64_t> futexGenerations;

std::int32_t GuestThreadId() {
    static std::atomic<std::int32_t> next{0};
    static const std::int32_t process = getpid();
    thread_local std::int32_t identifier = 0;
    if (identifier == 0) {
        const auto ordinal = next.fetch_add(1);
        identifier = ordinal == 0 ? process : process + ordinal;
    }
    return identifier;
}

void Syscall(State& state) {
    const auto number = Signed(state, 0);
    if (number == 186) {
        ReturnInteger(state, GuestThreadId());
        return;
    }
    if (number == 318) {
        auto* buffer = Pointer<void>(state, 1);
        const auto size = Argument(state, 2);
        arc4random_buf(buffer, size);
        ReturnInteger(state, static_cast<std::int64_t>(size));
        return;
    }
    if (number != 202) Unsupported("unsupported Linux system call " + std::to_string(number));
    const auto address = Argument(state, 1);
    const auto operation = Integer(state, 2) & ~128;
    if (operation == 1) {
        std::lock_guard<std::mutex> lock(futexLock);
        ++futexGenerations[address];
        futexWake.notify_all();
        ReturnInteger(state, 0);
        return;
    }
    if (operation != 0 || Argument(state, 4) != 0) Unsupported("unsupported futex operation");
    std::unique_lock<std::mutex> lock(futexLock);
    if (address % std::atomic_ref<std::int32_t>::required_alignment != 0) Unsupported("misaligned futex word");
    std::atomic_ref<std::int32_t> word(*reinterpret_cast<std::int32_t*>(address));
    const auto current = word.load(std::memory_order_acquire);
    if (current != Integer(state, 3)) {
        SetGuestErrno(11);
        ReturnInteger(state, -1);
        return;
    }
    const auto generation = futexGenerations[address];
    futexWake.wait(lock, [&] { return futexGenerations[address] != generation; });
    ReturnInteger(state, 0);
}

void CxaAtexit(State& state) {
    std::lock_guard<std::mutex> lock(exitLock);
    exitHandlers.emplace_back(Argument(state, 0), Argument(state, 1));
    ReturnInteger(state, 0);
}

void Wcslen(State& state) {
    ReturnInteger(state, static_cast<std::int64_t>(std::wcslen(Pointer<const wchar_t>(state, 0))));
}

void Wmemchr(State& state) {
    ReturnPointer(state, std::wmemchr(Pointer<const wchar_t>(state, 0), static_cast<wchar_t>(Argument(state, 1)), Argument(state, 2)));
}

void Fputwc(State& state) {
    const auto value = static_cast<std::uint32_t>(Argument(state, 0));
    if (value >= 128) {
        SetGuestErrno(84);
        ReturnInteger(state, static_cast<std::int64_t>(0xffffffffu));
        return;
    }
    ErrnoScope scope;
    const auto result = std::fputc(static_cast<int>(value), Pointer<FILE>(state, 1));
    ReturnInteger(state, result == EOF ? static_cast<std::int64_t>(0xffffffffu) : value);
}

void Getwc(State& state) {
    ErrnoScope scope;
    const auto value = std::getc(Pointer<FILE>(state, 0));
    if (value == EOF) {
        ReturnInteger(state, static_cast<std::int64_t>(0xffffffffu));
        return;
    }
    if (value >= 128) {
        SetGuestErrno(84);
        ReturnInteger(state, static_cast<std::int64_t>(0xffffffffu));
        return;
    }
    ReturnInteger(state, value);
}

void Ungetwc(State& state) {
    const auto value = static_cast<std::uint32_t>(Argument(state, 0));
    if (value >= 128) {
        ReturnInteger(state, static_cast<std::int64_t>(0xffffffffu));
        return;
    }
    ErrnoScope scope;
    const auto result = std::ungetc(static_cast<int>(value), Pointer<FILE>(state, 1));
    ReturnInteger(state, result == EOF ? static_cast<std::int64_t>(0xffffffffu) : value);
}

void Printf(State& state) {
    WriteFormatted(state, stdout, Text(state, 0), 1);
}

void Puts(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, std::puts(Text(state, 0)) == EOF ? -1 : 1);
}

template<class Result, Result (*Function)(const char*, char**, int)>
void IntegerParse(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, static_cast<std::int64_t>(Function(Text(state, 0), Pointer<char*>(state, 1), Integer(state, 2))));
}

template<class Result, Result (*Function)(const wchar_t*, wchar_t**, int)>
void WideIntegerParse(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, static_cast<std::int64_t>(Function(Pointer<const wchar_t>(state, 0), Pointer<wchar_t*>(state, 1), Integer(state, 2))));
}

void Strtod(State& state) {
    ErrnoScope scope;
    NativeAotGuest::ReturnDouble(state, std::strtod(Text(state, 0), Pointer<char*>(state, 1)));
}

void Strtof(State& state) {
    ErrnoScope scope;
    const float value = std::strtof(Text(state, 0), Pointer<char*>(state, 1));
    std::memset(state.Xmm[0], 0, sizeof(state.Xmm[0]));
    std::memcpy(state.Xmm[0], &value, sizeof(value));
}

void Wcstod(State& state) {
    ErrnoScope scope;
    NativeAotGuest::ReturnDouble(state, std::wcstod(Pointer<const wchar_t>(state, 0), Pointer<wchar_t*>(state, 1)));
}

void Wcstof(State& state) {
    ErrnoScope scope;
    const float value = std::wcstof(Pointer<const wchar_t>(state, 0), Pointer<wchar_t*>(state, 1));
    std::memset(state.Xmm[0], 0, sizeof(state.Xmm[0]));
    std::memcpy(state.Xmm[0], &value, sizeof(value));
}

void ExtendedParse(State&) {
    Unsupported("long double parsing requires an x87 extended-precision conversion");
}

void Swprintf(State& state) {
    const auto* wide = Pointer<const wchar_t>(state, 2);
    std::string format;
    for (; *wide != 0; ++wide) {
        if (*wide >= 128) Unsupported("swprintf format outside the C locale");
        format += static_cast<char>(*wide);
    }
    if (format.find("%ls") != std::string::npos || format.find("%lc") != std::string::npos || format.find("%S") != std::string::npos)
        Unsupported("swprintf wide string arguments");
    VarArgs arguments(state, 3);
    const auto text = Format(format.c_str(), arguments);
    auto* output = Pointer<wchar_t>(state, 0);
    const auto capacity = Argument(state, 1);
    if (text.size() >= capacity) {
        if (capacity != 0) output[0] = 0;
        SetGuestErrno(75);
        ReturnInteger(state, -1);
        return;
    }
    for (std::size_t index = 0; index < text.size(); ++index) output[index] = static_cast<unsigned char>(text[index]);
    output[text.size()] = 0;
    ReturnInteger(state, static_cast<std::int64_t>(text.size()));
}

void Strncpy(State& state) {
    ReturnPointer(state, std::strncpy(Pointer<char>(state, 0), Text(state, 1), Argument(state, 2)));
}

void Strcat(State& state) {
    ReturnPointer(state, std::strcat(Pointer<char>(state, 0), Text(state, 1)));
}

void Rewind(State& state) {
    ErrnoScope scope;
    std::rewind(Pointer<FILE>(state, 0));
}

void Utime(State& state) {
    ErrnoScope scope;
    struct utimbuf value{};
    if (Argument(state, 1)) {
        std::int64_t times[2];
        std::memcpy(times, Pointer<void>(state, 1), sizeof(times));
        value.actime = times[0];
        value.modtime = times[1];
    }
    ReturnInteger(state, ::utime(Text(state, 0), Argument(state, 1) ? &value : nullptr));
}

const NativeAotGuest::ProviderBinding Bindings[] = {
    {"fgetc", Getc, nullptr},
    {"fopen64", Fopen, nullptr},
    {"signal", SysvSignal, nullptr},
    {"strncpy", Strncpy, nullptr},
    {"open64", Open, nullptr},
    {"utime", Utime, nullptr},
    {"strcat", Strcat, nullptr},
    {"rewind", Rewind, nullptr},
    {"__lxstat64", LxStat, nullptr},
    {"__xstat64", XStat, nullptr},
    {"printf", Printf, nullptr, true, true},
    {"puts", Puts, nullptr, true, true},
    {"strtoul", IntegerParse<unsigned long, std::strtoul>, nullptr, true, true},
    {"strtoll", IntegerParse<long long, std::strtoll>, nullptr, true, true},
    {"strtoull", IntegerParse<unsigned long long, std::strtoull>, nullptr, true, true},
    {"strtod", Strtod, nullptr, true, true},
    {"strtof", Strtof, nullptr, true, true},
    {"strtold", ExtendedParse, nullptr, true, true},
    {"wcstol", WideIntegerParse<long, std::wcstol>, nullptr, true, true},
    {"wcstoul", WideIntegerParse<unsigned long, std::wcstoul>, nullptr, true, true},
    {"wcstoll", WideIntegerParse<long long, std::wcstoll>, nullptr, true, true},
    {"wcstoull", WideIntegerParse<unsigned long long, std::wcstoull>, nullptr, true, true},
    {"wcstod", Wcstod, nullptr, true, true},
    {"wcstof", Wcstof, nullptr, true, true},
    {"wcstold", ExtendedParse, nullptr, true, true},
    {"swprintf", Swprintf, nullptr, true, true},
    {"aligned_alloc", AlignedAlloc, nullptr, true, true},
    {"bcmp", Bcmp, nullptr, true, true},
    {"memchr", Memchr, nullptr, true, true},
    {"fseeko", Fseeko, nullptr, true, true},
    {"ftello", Ftello, nullptr, true, true},
    {"setbuf", Setbuf, nullptr, true, true},
    {"ungetc", Ungetc, nullptr, true, true},
    {"snprintf", Snprintf, nullptr, true, true},
    {"vsnprintf", Vsnprintf, nullptr, true, true},
    {"vfprintf", Vfprintf, nullptr, true, true},
    {"vasprintf", Vasprintf, nullptr, true, true},
    {"__isoc99_sscanf", Sscanf, nullptr, true, true},
    {"__isoc99_vsscanf", Vsscanf, nullptr, true, true},
    {"strerror_r", StrerrorR, nullptr, true, true},
    {"syscall", Syscall, nullptr, true, true},
    {"__cxa_atexit", CxaAtexit, nullptr, true, true},
    {"wcslen", Wcslen, nullptr, true, true},
    {"wmemchr", Wmemchr, nullptr, true, true},
    {"fputwc", Fputwc, nullptr, true, true},
    {"getwc", Getwc, nullptr, true, true},
    {"ungetwc", Ungetwc, nullptr, true, true},
    {"__errno_location", ErrnoLocation, nullptr, true, true},
    {"__fxstat", FxStat, nullptr, true, true},
    {"__xstat", XStat, nullptr, true, true},
    {"__lxstat", LxStat, nullptr, true, true},
    {"__libc_start_main", LibcStartMain, nullptr, true, true},
    {"__sysv_signal", SysvSignal, nullptr, true, true},
    {"abort", Abort, nullptr, true, true},
    {"backtrace", Backtrace, nullptr, true, true},
    {"backtrace_symbols", BacktraceSymbols, nullptr, true, true},
    {"calloc", ScalarProvider<NativeAotGlibcFastCalloc>, nullptr, true, true},
    {"chmod", Chmod, nullptr, true, true},
    {"chown", Chown, nullptr, true, true},
    {"clock", Clock, nullptr, true, true},
    {"clock_gettime", ClockGettime, nullptr, true, true},
    {"close", Close, nullptr, true, true},
    {"closedir", Closedir, nullptr, true, true},
    {"exit", ExitProvider, nullptr, true, true},
    {"fchmod", Fchmod, nullptr, true, true},
    {"fchown", Fchown, nullptr, true, true},
    {"fclose", Fclose, nullptr, true, true},
    {"fdopen", Fdopen, nullptr, true, true},
    {"feof", Feof, nullptr, true, true},
    {"ferror", Ferror, nullptr, true, true},
    {"fflush", Fflush, nullptr, true, true},
    {"fgets", Fgets, nullptr, true, true},
    {"fileno", Fileno, nullptr, true, true},
    {"fopen", Fopen, nullptr, true, true},
    {"fprintf", Fprintf, nullptr, true, true},
    {"fputc", Fputc, nullptr, true, true},
    {"fputs", Fputs, nullptr, true, true},
    {"fread", Fread, nullptr, true, true},
    {"free", ScalarProvider<NativeAotGlibcFastFree, false>, nullptr, true, true},
    {"fseek", Fseek, nullptr, true, true},
    {"ftell", Ftell, nullptr, true, true},
    {"fwrite", Fwrite, nullptr, true, true},
    {"getc", Getc, nullptr, true, true},
    {"getenv", Getenv, nullptr, true, true},
    {"isatty", Isatty, nullptr, true, true},
    {"malloc", ScalarProvider<NativeAotGlibcFastMalloc>, nullptr, true, true},
    {"memcmp", ScalarProvider<NativeAotGlibcFastMemcmp>, nullptr, true, true},
    {"memcpy", ScalarProvider<NativeAotGlibcFastMemcpy>, nullptr, true, true},
    {"memmove", ScalarProvider<NativeAotGlibcFastMemmove>, nullptr, true, true},
    {"memset", ScalarProvider<NativeAotGlibcFastMemset>, nullptr, true, true},
    {"mkdir", Mkdir, nullptr, true, true},
    {"mmap", Mmap, nullptr, true, true},
    {"munmap", Munmap, nullptr, true, true},
    {"open", Open, nullptr, true, true},
    {"opendir", Opendir, nullptr, true, true},
    {"perror", Perror, nullptr, true, true},
    {"qsort", Qsort, nullptr, true, true},
    {"qsort_r", QsortR, nullptr, true, true},
    {"raise", Raise, nullptr, true, true},
    {"readdir", Readdir, nullptr, true, true},
    {"realloc", ScalarProvider<NativeAotGlibcFastRealloc>, nullptr, true, true},
    {"remove", Remove, nullptr, true, true},
    {"setpriority", Setpriority, nullptr, true, true},
    {"setvbuf", Setvbuf, nullptr, true, true},
    {"stderr", nullptr, &guestStderr, true, true},
    {"stdin", nullptr, &guestStdin, true, true},
    {"stdout", nullptr, &guestStdout, true, true},
    {"strchr", Strchr, nullptr, true, true},
    {"strcmp", Strcmp, nullptr, true, true},
    {"strcpy", Strcpy, nullptr, true, true},
    {"strdup", Strdup, nullptr, true, true},
    {"strerror", Strerror, nullptr, true, true},
    {"strlen", ScalarProvider<NativeAotGlibcFastStrlen>, nullptr, true, true},
    {"strncmp", Strncmp, nullptr, true, true},
    {"strrchr", Strrchr, nullptr, true, true},
    {"strstr", Strstr, nullptr, true, true},
    {"strtol", Strtol, nullptr, true, true},
    {"sysconf", Sysconf, nullptr, true, true},
    {"utimensat", Utimensat, nullptr, true, true},
};

}

extern "C" bool NativeAotGlibcFastBinding(std::uint64_t address, std::uint64_t kind) {
    if (kind == 10 || kind == 11) return NativeAotGlibcThreadFastBinding(address, kind);
    const auto provider = NativeAotGuest::ImportedProvider(address);
    switch (kind) {
        case 1: return provider == ScalarProvider<NativeAotGlibcFastMalloc>;
        case 2: return provider == ScalarProvider<NativeAotGlibcFastCalloc>;
        case 3: return provider == ScalarProvider<NativeAotGlibcFastRealloc>;
        case 4: return provider == ScalarProvider<NativeAotGlibcFastFree, false>;
        case 5: return provider == ScalarProvider<NativeAotGlibcFastMemcpy>;
        case 6: return provider == ScalarProvider<NativeAotGlibcFastMemmove>;
        case 7: return provider == ScalarProvider<NativeAotGlibcFastMemset>;
        case 8: return provider == ScalarProvider<NativeAotGlibcFastMemcmp>;
        case 9: return provider == ScalarProvider<NativeAotGlibcFastStrlen>;
        default: return false;
    }
}

namespace NativeAotGlibc {

void Register() {
    NativeAotGlibcSupport::Register(Bindings, sizeof(Bindings) / sizeof(Bindings[0]));
    NativeAotGlibcSupport::RegisterLocale();
    NativeAotGlibcSupport::RegisterThreads();
    NativeAotGlibcSupport::RegisterDynamic();
    NativeAotGlibcSupport::RegisterMath();
    NativeAotGlibcSupport::RegisterPosix();
}

}

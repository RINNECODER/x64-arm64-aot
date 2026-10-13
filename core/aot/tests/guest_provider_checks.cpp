#include "native/NativeAotGlibc.hpp"
#include "native/NativeAotGuest.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cfenv>
#include <limits>
#include <thread>
#include <barrier>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {

NativeAotGuestState state;
std::uint64_t stack[4096];
int failures = 0;

void Check(bool condition, const char* label) {
    if (!condition) {
        std::printf("FAIL %s\n", label);
        ++failures;
    }
}

std::uint64_t Call(const char* name, std::initializer_list<std::uint64_t> arguments, std::initializer_list<std::uint64_t> extra = {}) {
    const auto* binding = NativeAotGuest::FindProviderBinding(name);
    if (binding == nullptr || binding->Function == nullptr) {
        std::printf("FAIL missing %s\n", name);
        std::exit(1);
    }
    const int order[6] = {7, 6, 2, 1, 8, 9};
    int index = 0;
    for (auto value : arguments) {
        if (index == 6) {
            std::printf("FAIL too many register arguments for %s\n", name);
            std::exit(1);
        }
        state.Gpr[order[index++]] = value;
    }
    auto* top = stack + 2048;
    std::uint64_t position = 1;
    for (auto value : extra) top[position++] = value;
    state.Gpr[4] = reinterpret_cast<std::uint64_t>(top);
    binding->Function(state);
    return state.Gpr[0];
}

template<class Value>
std::uint64_t Raw(Value value) {
    return static_cast<std::uint64_t>(value);
}

std::uint64_t Address(const void* pointer) {
    return reinterpret_cast<std::uint64_t>(pointer);
}

void Formatting() {
    char buffer[256];
    const double values[2] = {2.5, -0.125};
    std::memcpy(state.Xmm[0], &values[0], 8);
    std::memcpy(state.Xmm[1], &values[1], 8);
    const auto written = Call("snprintf", {Address(buffer), sizeof(buffer), Address("%d|%u|%x|%5ld|%-3s|%c|%p|%.2f|%e|%%|%hhd|%*d"),
                                           Raw(-7), Raw(4294967295u), Raw(255)},
                              {Raw(42), Address("ab"), Raw('Z'), 0, Raw(300), Raw(4), Raw(9)});
    Check(std::string(buffer) == "-7|4294967295|ff|   42|ab |Z|(nil)|2.50|-1.250000e-01|%|44|   9", "snprintf conversions");
    Check(written == std::strlen(buffer), "snprintf length");
    Call("snprintf", {Address(buffer), 4, Address("%s"), Address("truncated")});
    Check(std::string(buffer) == "tru", "snprintf truncation");
}

void Scanning() {
    int number = 0, hex = 0, consumed = 0;
    double real = 0;
    char word[16] = {}, set[16] = {};
    const auto assigned = Call("__isoc99_sscanf", {Address("  12 abc 3.5 0x1f xyz!"), Address("%d %s %lf %x %[a-z]%n"),
                                                   Address(&number), Address(word), Address(&real), Address(&hex)},
                               {Address(set), Address(&consumed)});
    Check(consumed == 21, "sscanf %n count");
    Check(assigned == 5 && number == 12 && std::string(word) == "abc" && real == 3.5 && hex == 31 && std::string(set) == "xyz" && consumed == 21,
          "sscanf conversions");
    Check(static_cast<int>(Call("__isoc99_sscanf", {Address(""), Address("%d"), Address(&number)})) == -1, "sscanf end of input");
    Check(Call("__isoc99_sscanf", {Address("7 8"), Address("%*d %d"), Address(&number)}) == 1 && number == 8, "sscanf suppression");
    Check(Call("__isoc99_sscanf", {Address("x"), Address("%d"), Address(&number)}) == 0, "sscanf mismatch");
}

void Errors() {
    auto* location = reinterpret_cast<int*>(Call("__errno_location", {}));
    Call("close", {Raw(-1)});
    Check(*location == 9, "close sets EBADF");
    Call("open", {Address("/definitely/missing/path"), 0, 0});
    Check(*location == 2, "open sets ENOENT");
    const auto* message = reinterpret_cast<const char*>(Call("strerror", {Raw(11)}));
    Check(std::string(message) == std::strerror(EAGAIN), "strerror uses glibc numbering");
}

void Files() {
    char path[] = "/tmp/anyps5-provider-XXXXXX";
    const int descriptor = mkstemp(path);
    write(descriptor, "hello", 5);
    close(descriptor);
    unlink(path);
    const auto created = static_cast<int>(Call("open", {Address(path), Raw(0100 | 0200 | 1), Raw(0600)}));
    Check(created >= 0, "open translates O_CREAT|O_EXCL|O_WRONLY");
    Check(static_cast<int>(Call("open", {Address(path), Raw(0100 | 0200 | 1), Raw(0600)})) == -1, "O_EXCL rejects existing file");
    write(created, "hello world", 11);
    close(created);
    std::uint8_t stat[144] = {};
    Check(Call("__xstat", {1, Address(path), Address(stat)}) == 0, "stat succeeds");
    std::int64_t size;
    std::uint32_t mode;
    std::memcpy(&size, stat + 48, 8);
    std::memcpy(&mode, stat + 24, 4);
    Check(size == 11 && (mode & 0170000) == 0100000 && (mode & 0777) == 0600, "glibc stat layout");
    std::int64_t times[4] = {1000, 0, 0, (1 << 30) - 2};
    Check(Call("utimensat", {Raw(-100), Address(path), Address(times), 0}) == 0, "utimensat translates AT_FDCWD and UTIME_OMIT");
    struct stat host {};
    ::stat(path, &host);
    Check(host.st_atimespec.tv_sec == 1000, "utimensat sets access time");
    unlink(path);
}

void Ctype() {
    auto** classes = reinterpret_cast<const unsigned short**>(Call("__ctype_b_loc", {}));
    auto** lower = reinterpret_cast<const std::int32_t**>(Call("__ctype_tolower_loc", {}));
    Check(((*classes)['a'] & 0x400) && ((*classes)['a'] & 0x200) && !((*classes)['A'] & 0x200), "ctype alpha/lower bits");
    Check(((*classes)['7'] & 0x800) && ((*classes)[' '] & 0x2000) && ((*classes)['\t'] & 0x1) && ((*classes)['!'] & 0x4), "ctype digit/space/blank/punct bits");
    Check((*classes)[-1] == 0 && (*classes)[200] == 0, "ctype EOF and high bytes");
    Check((*lower)['Q'] == 'q' && (*lower)['q'] == 'q' && (*lower)[-1] == -1, "tolower table");
    const auto locale = Call("newlocale", {Raw(0x1fbf), Address("C"), 0});
    std::uint64_t ctypeField;
    std::memcpy(&ctypeField, reinterpret_cast<const void*>(locale + 104), 8);
    Check(locale != 0 && ctypeField == Address(*classes), "glibc locale_t ctype field");
    Check(Call("newlocale", {Raw(0x1fbf), Address("xx_YY.UTF-8"), 0}) == 0, "missing locale returns null");
    std::int32_t wide = 0;
    Check(Call("mbrtowc", {Address(&wide), Address("A"), 1, 0}) == 1 && wide == 'A', "mbrtowc ASCII");
    Check(static_cast<std::int64_t>(Call("mbrtowc", {Address(&wide), Address("\xc3\xa9"), 2, 0})) == -1, "mbrtowc rejects non-ASCII in C locale");
}

void Numbers() {
    char* end = nullptr;
    Check(Call("strtol", {Address("-123x"), Address(&end), 10}) == Raw(-123) && *end == 'x', "strtol");
    Call("strtod", {Address("2.75"), 0});
    double value;
    std::memcpy(&value, state.Xmm[0], 8);
    Check(value == 2.75, "strtod returns xmm0");
    wchar_t buffer[32];
    Check(Call("swprintf", {Address(buffer), 32, Address(L"%d-%s"), Raw(5), Address("ok")}) == 4 && std::wcscmp(buffer, L"5-ok") == 0, "swprintf");
    void* aligned = reinterpret_cast<void*>(Call("aligned_alloc", {64, 100}));
    Check(aligned != nullptr && Address(aligned) % 64 == 0, "aligned_alloc alignment");
    std::free(aligned);
    Check(Call("syscall", {186}) == Raw(getpid()), "gettid of the main thread");
    std::int64_t time[2] = {};
    Check(Call("clock_gettime", {1, Address(time)}) == 0 && (time[0] > 0 || time[1] > 0), "CLOCK_MONOTONIC translation");
    Check(Call("sysconf", {84}) == Raw(sysconf(_SC_NPROCESSORS_ONLN)), "sysconf processor count");
}

double MathCall(const char* name, std::initializer_list<double> values, std::initializer_list<std::uint64_t> integers = {},
                std::initializer_list<std::uint64_t> extra = {}) {
    int index = 0;
    for (const auto value : values) std::memcpy(state.Xmm[index++], &value, 8);
    Call(name, integers, extra);
    double result;
    std::memcpy(&result, state.Xmm[0], 8);
    return result;
}

void Mathematics() {
    const auto rounding = std::fegetround();
    std::fesetround(FE_DOWNWARD);
    Check(MathCall("rint", {1.75}) == 1, "math uses current downward rounding");
    std::fesetround(FE_UPWARD);
    Check(MathCall("rint", {1.25}) == 2, "math uses current upward rounding");
    std::fesetround(rounding);

    Check(MathCall("sqrt", {81}) == 9, "sqrt floating argument and result");
    Check(MathCall("pow", {2, -3}) == 0.125, "pow two SSE arguments");
    Check(MathCall("fma", {0x1.0000000000001p0, 0x1.fffffffffffffp-1, -1}) == 0x1.ffffffffffffep-54, "fma single rounding");
    Check(MathCall("ldexp", {1.5}, {Raw(-2)}) == 0.375, "ldexp mixed integer/SSE arguments");
    int exponent = 0;
    Check(MathCall("frexp", {12}, {Address(&exponent)}) == 0.75 && exponent == 4, "frexp output pointer");
    double whole = 0;
    Check(MathCall("modf", {-3.25}, {Address(&whole)}) == -0.25 && whole == -3, "modf output pointer");
    auto* error = reinterpret_cast<int*>(Call("__errno_location", {}));
    *error = 19;
    Check(std::isnan(MathCall("sqrt", {-1})) && *error == 33, "math domain maps EDOM");
    *error = 19;
    Check(MathCall("sqrt", {4}) == 2 && *error == 19, "math success preserves guest errno");
    *error = 19;
    Check(std::isinf(MathCall("logb", {0})) && *error == 19, "logb pole preserves errno");
    Check(MathCall("nexttoward", {1}, {}, {0x8000000000000001ull, 0x3fff}) == 0x1.0000000000001p0,
          "nexttoward compares extended operand without rounding to double");
    Check(MathCall("nexttoward", {1}, {}, {0xffffffffffffffffull, 0x3ffe}) == 0x1.fffffffffffffp-1,
          "nexttoward extended value below one");
    Check(std::signbit(MathCall("nexttoward", {0}, {}, {0, 0x8000})), "nexttoward preserves target negative zero");
    Check(MathCall("nexttoward", {0}, {}, {1, 0}) == std::numeric_limits<double>::denorm_min(), "nexttoward extended subnormal");
}

void PosixData() {
    std::int64_t epoch = 0;
    alignas(8) std::uint8_t broken[56] = {};
    Check(Call("gmtime_r", {Address(&epoch), Address(broken)}) == Address(broken), "gmtime_r result pointer");
    std::int32_t year;
    std::memcpy(&year, broken + 20, 4);
    Check(year == 70, "guest tm year layout");
    char formatted[64] = {};
    Check(Call("strftime", {Address(formatted), sizeof(formatted), Address("%Y-%m-%dT%H:%M:%S"), Address(broken)}) == 19
          && std::string(formatted) == "1970-01-01T00:00:00", "strftime guest tm layout");
    Check(Call("timegm", {Address(broken)}) == 0, "timegm epoch");
    const char* date = "2024-02-29!";
    Check(Call("strptime", {Address(date), Address("%Y-%m-%d"), Address(broken)}) == Address(date + 10), "strptime return position");
    Check(Call("timegm", {Address(broken)}) == 1709164800, "timegm leap day");
    std::int64_t now[3] = {0, 0, 0x12345678};
    Check(Call("gettimeofday", {Address(now), 0}) == 0 && now[0] > 0 && now[1] >= 0 && now[1] < 1000000
          && now[2] == 0x12345678, "gettimeofday uses 64-bit microseconds and preserves canary");
    const char input[] = {'a', 0, 'b', 'c', 0, 'b'};
    const char needle[] = {0, 'b'};
    Check(Call("memmem", {Address(input), sizeof(input), Address(needle), sizeof(needle)}) == Address(input + 1), "memmem binary data");
    Check(Call("memmem", {Address(input), sizeof(input), Address(needle), 0}) == Address(input), "memmem empty needle");
    Check(Call("strspn", {Address("abcaZ"), Address("abc")}) == 4, "strspn prefix");
    Check(Call("stpcpy", {Address(formatted), Address("copied")}) == Address(formatted + 6) && std::string(formatted) == "copied", "stpcpy returns end");
}

void FileCompatibility() {
    char text[16];
    std::memset(text, 'X', sizeof(text));
    Check(Call("strncpy", {Address(text), Address("ab"), 5}) == Address(text) &&
          text[0] == 'a' && text[1] == 'b' && text[2] == 0 && text[4] == 0 && text[5] == 'X', "strncpy pads only bound");
    Call("strncpy", {Address(text), Address("abcd"), 2});
    Check(text[0] == 'a' && text[1] == 'b' && text[5] == 'X', "strncpy bounded prefix");
    text[2] = 0;
    Check(Call("strcat", {Address(text), Address("cd")}) == Address(text) && std::string(text) == "abcd", "strcat result");
    char path[] = "/tmp/aot-file-XXXXXX";
    const auto descriptor = mkstemp(path);
    Check(descriptor >= 0, "temporary file");
    if (descriptor < 0) return;
    write(descriptor, "az", 2);
    close(descriptor);
    const auto file = Call("fopen64", {Address(path), Address("r")});
    Check(file != 0, "fopen64 opens file");
    if (file) {
        Check(Call("fgetc", {file}) == 'a' && Call("fgetc", {file}) == 'z', "fgetc reads bytes");
        Check(static_cast<int>(Call("fgetc", {file})) == EOF, "fgetc end");
        Call("rewind", {file});
        Check(Call("feof", {file}) == 0 && Call("fgetc", {file}) == 'a', "rewind clears EOF and seeks");
        Call("fclose", {file});
    }
    const std::int64_t times[2] = {1650000000, 1660000000};
    Check(Call("utime", {Address(path), Address(times)}) == 0, "utime result");
    struct stat observed{};
    Check(stat(path, &observed) == 0 && observed.st_atime == times[0] && observed.st_mtime == times[1], "utime LP64 layout");
    const auto opened = static_cast<int>(Call("open64", {Address(path), 0, 0}));
    Check(opened >= 0, "open64 flags");
    if (opened >= 0) close(opened);
    unsigned char normal[144] = {}, large[144] = {};
    Check(Call("__xstat", {1, Address(path), Address(normal)}) == 0 &&
          Call("__xstat64", {1, Address(path), Address(large)}) == 0 && std::memcmp(normal, large, sizeof(normal)) == 0, "stat64 LP64 alias");
    const auto link = std::string(path) + "-link";
    Check(symlink(path, link.c_str()) == 0, "symlink setup");
    Check(Call("__lxstat", {1, Address(link.c_str()), Address(normal)}) == 0 &&
          Call("__lxstat64", {1, Address(link.c_str()), Address(large)}) == 0 && std::memcmp(normal, large, sizeof(normal)) == 0, "lstat64 preserves link");
    unlink(link.c_str());
    unlink(path);
    auto* guestError = reinterpret_cast<int*>(Call("__errno_location", {}));
    *guestError = 5;
    errno = ENOENT;
    Check(Call("fopen64", {Address(path), Address("r")}) == 0 && *reinterpret_cast<int*>(Call("__errno_location", {})) == 2, "fopen64 missing file errno");
    Check(errno == ENOENT, "provider restores host errno");
    *guestError = 12345;
    Check(Call("strtol", {Address("7"), 0, 10}) == 7 && *guestError == 12345,
          "successful conversion preserves arbitrary guest errno");
    const auto previous = Call("signal", {13, 1});
    Check(Call("signal", {13, previous}) == 1, "signal ignore round trip");
}

void ConcurrentKeyDeletion() {
    std::barrier phase(2);
    std::uint32_t key = 0;
    bool correct = true;
    std::thread worker([&] {
        for (unsigned iteration = 0; iteration < 64; ++iteration) {
            phase.arrive_and_wait();
            NativeAotGuestState local{};
            local.Gpr[7] = key;
            local.Gpr[6] = 123;
            NativeAotGuest::FindProviderBinding("pthread_setspecific")->Function(local);
            NativeAotGuest::FindProviderBinding("pthread_getspecific")->Function(local);
            correct = correct && local.Gpr[0] == 123;
            phase.arrive_and_wait();
            phase.arrive_and_wait();
            NativeAotGuest::FindProviderBinding("pthread_getspecific")->Function(local);
            correct = correct && local.Gpr[0] == 0;
            phase.arrive_and_wait();
        }
    });
    for (unsigned iteration = 0; iteration < 64; ++iteration) {
        Check(Call("pthread_key_create", {Address(&key), 0}) == 0, "concurrent key creation");
        phase.arrive_and_wait();
        phase.arrive_and_wait();
        Check(Call("pthread_key_delete", {key}) == 0, "concurrent key deletion");
        phase.arrive_and_wait();
        phase.arrive_and_wait();
    }
    worker.join();
    Check(correct, "thread-local value cannot survive completed key deletion");
}

void ThreadKeys() {
    std::uint32_t output[2] = {0, 0xfeedface};
    Check(Call("pthread_key_create", {Address(output), 0}) == 0 && output[1] == 0xfeedface, "TLS key writes only four bytes");
    const auto key = output[0];
    Check(Call("pthread_getspecific", {key}) == 0, "new TLS key is null");
    Check(Call("pthread_setspecific", {key, 123}) == 0 && Call("pthread_getspecific", {key}) == 123, "TLS key round trip");
    bool isolated = false;
    std::thread other([&] {
        NativeAotGuestState local{};
        local.Gpr[7] = key;
        NativeAotGuest::FindProviderBinding("pthread_getspecific")->Function(local);
        isolated = local.Gpr[0] == 0;
        local.Gpr[6] = 456;
        NativeAotGuest::FindProviderBinding("pthread_setspecific")->Function(local);
    });
    other.join();
    Check(isolated && Call("pthread_getspecific", {key}) == 123, "TLS keys are per thread");
    Check(Call("pthread_key_delete", {key}) == 0, "TLS key deletion");
    Check(Call("pthread_setspecific", {key, 321}) == 22, "deleted TLS key rejects write");
    Check(Call("pthread_key_create", {Address(output), 0}) == 0 && Call("pthread_getspecific", {output[0]}) == 0, "new key never inherits deleted values");
    Call("pthread_key_delete", {output[0]});
}

}

int main() {
    NativeAotGlibc::Register();
    Formatting();
    Scanning();
    Errors();
    Files();
    Ctype();
    Numbers();
    Mathematics();
    PosixData();
    ThreadKeys();
    ConcurrentKeyDeletion();
    FileCompatibility();
    std::printf(failures == 0 ? "ok\n" : "failed\n");
    return failures == 0 ? 0 : 1;
}

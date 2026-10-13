#include "native/NativeAotGlibcSupport.hpp"
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <xlocale.h>

namespace {

using namespace NativeAotGlibcSupport;
using NativeAotGuest::Argument;
using NativeAotGuest::Return;

constexpr unsigned short Upper = 0x100, Lower = 0x200, Alpha = 0x400, Digit = 0x800, Xdigit = 0x1000, Space = 0x2000,
                         Print = 0x4000, Graph = 0x8000, Blank = 0x1, Cntrl = 0x2, Punct = 0x4, Alnum = 0x8;

struct Tables {
    unsigned short classes[384];
    std::int32_t lower[384];
    std::int32_t upper[384];
    const unsigned short* classesBase;
    const std::int32_t* lowerBase;
    const std::int32_t* upperBase;

    Tables() {
        for (int index = 0; index < 384; ++index) {
            const int value = index - 128;
            unsigned short mask = 0;
            if (value >= 0 && value < 128) {
                if (value >= 'A' && value <= 'Z') mask |= Upper | Alpha | Alnum | Print | Graph;
                if (value >= 'a' && value <= 'z') mask |= Lower | Alpha | Alnum | Print | Graph;
                if (value >= '0' && value <= '9') mask |= Digit | Alnum | Print | Graph;
                if ((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')) mask |= Xdigit;
                if (value == ' ' || (value >= '\t' && value <= '\r')) mask |= Space;
                if (value == ' ' || value == '\t') mask |= Blank;
                if (value < 32 || value == 127) mask |= Cntrl;
                if (value == ' ') mask |= Print;
                if (value > 32 && value < 127 && !std::isalnum(value)) mask |= Punct | Print | Graph;
            }
            classes[index] = mask;
            lower[index] = value >= 'A' && value <= 'Z' ? value + 32 : value;
            upper[index] = value >= 'a' && value <= 'z' ? value - 32 : value;
        }
        lower[128 - 1] = -1;
        upper[128 - 1] = -1;
        classesBase = classes + 128;
        lowerBase = lower + 128;
        upperBase = upper + 128;
    }
};

const Tables& CTables() {
    static const Tables tables;
    return tables;
}

struct GuestLocale {
    const void* locales[13];
    const unsigned short* ctypeClasses;
    const std::int32_t* ctypeLower;
    const std::int32_t* ctypeUpper;
    const char* names[13];
};

struct GuestLconv {
    const char* strings[10];
    char values[14];
};

static_assert(sizeof(GuestLocale) == 232);
static_assert(sizeof(GuestLconv) == 96);

GuestLocale& CLocale() {
    static GuestLocale locale = [] {
        GuestLocale value{};
        value.ctypeClasses = CTables().classesBase;
        value.ctypeLower = CTables().lowerBase;
        value.ctypeUpper = CTables().upperBase;
        for (auto& name : value.names) name = "C";
        return value;
    }();
    return locale;
}

thread_local GuestLocale* currentLocale = nullptr;

locale_t HostC() {
    static locale_t host = newlocale(LC_ALL_MASK, "C", nullptr);
    return host;
}

bool IsCName(const char* name) {
    return name != nullptr && (std::strcmp(name, "C") == 0 || std::strcmp(name, "POSIX") == 0);
}

bool EnvironmentIsC(int category) {
    static const char* names[] = {"LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_ALL"};
    const char* all = std::getenv("LC_ALL");
    if (all != nullptr && *all != '\0') return IsCName(all);
    if (category >= 0 && category < 6) {
        const char* specific = std::getenv(names[category]);
        if (specific != nullptr && *specific != '\0') return IsCName(specific);
    } else if (category == 6) {
        for (int index = 0; index < 6; ++index) {
            const char* specific = std::getenv(names[index]);
            if (specific != nullptr && *specific != '\0' && !IsCName(specific)) return false;
        }
    }
    const char* language = std::getenv("LANG");
    return language == nullptr || *language == '\0' || IsCName(language);
}

void CtypeB(State& state) {
    static thread_local const unsigned short* pointer = CTables().classesBase;
    ReturnPointer(state, &pointer);
}

void CtypeLower(State& state) {
    static thread_local const std::int32_t* pointer = CTables().lowerBase;
    ReturnPointer(state, &pointer);
}

void CtypeUpper(State& state) {
    static thread_local const std::int32_t* pointer = CTables().upperBase;
    ReturnPointer(state, &pointer);
}

void MbCurMax(State& state) {
    ReturnInteger(state, 1);
}

void Newlocale(State& state) {
    const auto* name = Text(state, 1);
    auto* base = Pointer<GuestLocale>(state, 2);
    if (!IsCName(name) && !(name != nullptr && *name == '\0' && EnvironmentIsC(6))) {
        SetGuestErrno(2);
        ReturnPointer(state, nullptr);
        return;
    }
    if (base != nullptr && base != &CLocale()) {
        ReturnPointer(state, base);
        return;
    }
    ReturnPointer(state, new GuestLocale(CLocale()));
}

void Freelocale(State& state) {
    auto* locale = Pointer<GuestLocale>(state, 0);
    if (locale != nullptr && locale != &CLocale()) delete locale;
}

void Uselocale(State& state) {
    auto* requested = Pointer<GuestLocale>(state, 0);
    auto* previous = currentLocale == nullptr ? reinterpret_cast<GuestLocale*>(-1) : currentLocale;
    if (requested == reinterpret_cast<GuestLocale*>(-1)) currentLocale = nullptr;
    else if (requested != nullptr) currentLocale = requested;
    ReturnPointer(state, previous);
}

void Setlocale(State& state) {
    const auto category = Integer(state, 0);
    const auto* name = Text(state, 1);
    if (category < 0 || category > 12) {
        SetGuestErrno(22);
        ReturnPointer(state, nullptr);
        return;
    }
    if (name == nullptr || IsCName(name) || (*name == '\0' && EnvironmentIsC(category == 6 ? 6 : category))) {
        ReturnPointer(state, "C");
        return;
    }
    ReturnPointer(state, nullptr);
}

void Localeconv(State& state) {
    static GuestLconv conventions = [] {
        GuestLconv value{};
        value.strings[0] = ".";
        for (int index = 1; index < 10; ++index) value.strings[index] = "";
        std::memset(value.values, CHAR_MAX, sizeof(value.values));
        return value;
    }();
    ReturnPointer(state, &conventions);
}

int WideClass(std::uint32_t character, unsigned short mask) {
    return character < 128 && (CTables().classesBase[character] & mask) != 0;
}

template<unsigned short Mask>
void WideIs(State& state) {
    ReturnInteger(state, WideClass(static_cast<std::uint32_t>(Argument(state, 0)), Mask));
}

void Tolower(State& state) {
    const auto value = Integer(state, 0);
    ReturnInteger(state, value >= -128 && value < 256 ? CTables().lowerBase[value] : value);
}

void Toupper(State& state) {
    const auto value = Integer(state, 0);
    ReturnInteger(state, value >= -128 && value < 256 ? CTables().upperBase[value] : value);
}

void Towlower(State& state) {
    const auto value = static_cast<std::uint32_t>(Argument(state, 0));
    ReturnInteger(state, value >= 'A' && value <= 'Z' ? value + 32 : value);
}

void Towupper(State& state) {
    const auto value = static_cast<std::uint32_t>(Argument(state, 0));
    ReturnInteger(state, value >= 'a' && value <= 'z' ? value - 32 : value);
}

void Strcoll(State& state) {
    ReturnInteger(state, std::strcmp(Text(state, 0), Text(state, 1)));
}

void Strxfrm(State& state) {
    const auto* source = Text(state, 1);
    const auto length = std::strlen(source);
    const auto capacity = Argument(state, 2);
    if (length < capacity) std::memcpy(Pointer<char>(state, 0), source, length + 1);
    ReturnInteger(state, static_cast<std::int64_t>(length));
}

void Wcscoll(State& state) {
    ReturnInteger(state, std::wcscmp(Pointer<const wchar_t>(state, 0), Pointer<const wchar_t>(state, 1)));
}

void Wcsxfrm(State& state) {
    const auto* source = Pointer<const wchar_t>(state, 1);
    const auto length = std::wcslen(source);
    if (length < Argument(state, 2)) std::wmemcpy(Pointer<wchar_t>(state, 0), source, length + 1);
    ReturnInteger(state, static_cast<std::int64_t>(length));
}

void Strftime(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, static_cast<std::int64_t>(strftime_l(Pointer<char>(state, 0), Argument(state, 1), Text(state, 2),
                                                              Pointer<const std::tm>(state, 3), HostC())));
}

void Strtod(State& state) {
    ErrnoScope scope;
    NativeAotGuest::ReturnDouble(state, strtod_l(Text(state, 0), Pointer<char*>(state, 1), HostC()));
}

void Strtof(State& state) {
    ErrnoScope scope;
    const float value = strtof_l(Text(state, 0), Pointer<char*>(state, 1), HostC());
    std::memset(state.Xmm[0], 0, sizeof(state.Xmm[0]));
    std::memcpy(state.Xmm[0], &value, sizeof(value));
}

void Strtoll(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, strtoll_l(Text(state, 0), Pointer<char*>(state, 1), Integer(state, 2), HostC()));
}

void Strtoull(State& state) {
    ErrnoScope scope;
    ReturnInteger(state, static_cast<std::int64_t>(strtoull_l(Text(state, 0), Pointer<char*>(state, 1), Integer(state, 2), HostC())));
}

void Strtold(State&) {
    Unsupported("strtold_l requires an x87 extended-precision conversion");
}

void Btowc(State& state) {
    const auto value = Integer(state, 0);
    ReturnInteger(state, value >= 0 && value < 128 ? value : static_cast<std::int64_t>(0xffffffffu));
}

void Wctob(State& state) {
    const auto value = static_cast<std::uint32_t>(Argument(state, 0));
    ReturnInteger(state, value < 128 ? static_cast<int>(value) : -1);
}

void Mbrtowc(State& state) {
    auto* output = Pointer<std::int32_t>(state, 0);
    const auto* input = Pointer<const unsigned char>(state, 1);
    if (input == nullptr) {
        ReturnInteger(state, 0);
        return;
    }
    if (Argument(state, 2) == 0) {
        ReturnInteger(state, -2);
        return;
    }
    if (*input >= 128) {
        SetGuestErrno(84);
        ReturnInteger(state, -1);
        return;
    }
    if (output != nullptr) *output = *input;
    ReturnInteger(state, *input == 0 ? 0 : 1);
}

void Mbtowc(State& state) {
    auto* output = Pointer<std::int32_t>(state, 0);
    const auto* input = Pointer<const unsigned char>(state, 1);
    if (input == nullptr) {
        ReturnInteger(state, 0);
        return;
    }
    if (Argument(state, 2) == 0 || *input >= 128) {
        SetGuestErrno(84);
        ReturnInteger(state, -1);
        return;
    }
    if (output != nullptr) *output = *input;
    ReturnInteger(state, *input == 0 ? 0 : 1);
}

void Wcrtomb(State& state) {
    auto* output = Pointer<char>(state, 0);
    const auto value = static_cast<std::uint32_t>(Argument(state, 1));
    if (output == nullptr) {
        ReturnInteger(state, 1);
        return;
    }
    if (value >= 128) {
        SetGuestErrno(84);
        ReturnInteger(state, -1);
        return;
    }
    *output = static_cast<char>(value);
    ReturnInteger(state, 1);
}

void Mbsnrtowcs(State& state, bool bounded) {
    auto* output = Pointer<std::int32_t>(state, 0);
    auto** source = Pointer<const unsigned char*>(state, 1);
    const auto limit = bounded ? Argument(state, 2) : ~std::uint64_t{0};
    const auto capacity = Argument(state, bounded ? 3 : 2);
    const auto* cursor = *source;
    std::uint64_t written = 0;
    for (std::uint64_t consumed = 0; consumed < limit && (output == nullptr || written < capacity); ++consumed) {
        const auto byte = cursor[consumed];
        if (byte >= 128) {
            if (output != nullptr) *source = cursor + consumed;
            SetGuestErrno(84);
            ReturnInteger(state, -1);
            return;
        }
        if (output != nullptr) output[written] = byte;
        if (byte == 0) {
            if (output != nullptr) *source = nullptr;
            ReturnInteger(state, static_cast<std::int64_t>(written));
            return;
        }
        ++written;
    }
    if (output != nullptr) *source = cursor + written;
    ReturnInteger(state, static_cast<std::int64_t>(written));
}

void MbsnrtowcsProvider(State& state) {
    Mbsnrtowcs(state, true);
}

void MbsrtowcsProvider(State& state) {
    Mbsnrtowcs(state, false);
}

void Wcsnrtombs(State& state) {
    auto* output = Pointer<char>(state, 0);
    auto** source = Pointer<const std::int32_t*>(state, 1);
    const auto limit = Argument(state, 2);
    const auto capacity = Argument(state, 3);
    const auto* cursor = *source;
    std::uint64_t written = 0;
    for (std::uint64_t consumed = 0; consumed < limit && (output == nullptr || written < capacity); ++consumed) {
        const auto value = static_cast<std::uint32_t>(cursor[consumed]);
        if (value >= 128) {
            if (output != nullptr) *source = cursor + consumed;
            SetGuestErrno(84);
            ReturnInteger(state, -1);
            return;
        }
        if (output != nullptr) output[written] = static_cast<char>(value);
        if (value == 0) {
            if (output != nullptr) *source = nullptr;
            ReturnInteger(state, static_cast<std::int64_t>(written));
            return;
        }
        ++written;
    }
    if (output != nullptr) *source = cursor + written;
    ReturnInteger(state, static_cast<std::int64_t>(written));
}

void Catopen(State& state) {
    SetGuestErrno(2);
    ReturnInteger(state, -1);
}

void Catgets(State& state) {
    SetGuestErrno(9);
    ReturnPointer(state, Text(state, 3));
}

void Catclose(State& state) {
    SetGuestErrno(9);
    ReturnInteger(state, -1);
}

const NativeAotGuest::ProviderBinding Bindings[] = {
    {"__ctype_b_loc", CtypeB, nullptr, true, true},
    {"__ctype_tolower_loc", CtypeLower, nullptr, true, true},
    {"__ctype_toupper_loc", CtypeUpper, nullptr, true, true},
    {"__ctype_get_mb_cur_max", MbCurMax, nullptr, true, true},
    {"newlocale", Newlocale, nullptr, true, true},
    {"freelocale", Freelocale, nullptr, true, true},
    {"uselocale", Uselocale, nullptr, true, true},
    {"setlocale", Setlocale, nullptr, true, true},
    {"localeconv", Localeconv, nullptr, true, true},
    {"iswalpha_l", WideIs<Alpha>, nullptr, true, true},
    {"iswblank_l", WideIs<Blank>, nullptr, true, true},
    {"iswcntrl_l", WideIs<Cntrl>, nullptr, true, true},
    {"iswdigit_l", WideIs<Digit>, nullptr, true, true},
    {"iswlower_l", WideIs<Lower>, nullptr, true, true},
    {"iswprint_l", WideIs<Print>, nullptr, true, true},
    {"iswpunct_l", WideIs<Punct>, nullptr, true, true},
    {"iswspace_l", WideIs<Space>, nullptr, true, true},
    {"iswupper_l", WideIs<Upper>, nullptr, true, true},
    {"iswxdigit_l", WideIs<Xdigit>, nullptr, true, true},
    {"tolower_l", Tolower, nullptr, true, true},
    {"toupper_l", Toupper, nullptr, true, true},
    {"towlower_l", Towlower, nullptr, true, true},
    {"towupper_l", Towupper, nullptr, true, true},
    {"strcoll_l", Strcoll, nullptr, true, true},
    {"strxfrm_l", Strxfrm, nullptr, true, true},
    {"wcscoll_l", Wcscoll, nullptr, true, true},
    {"wcsxfrm_l", Wcsxfrm, nullptr, true, true},
    {"strftime_l", Strftime, nullptr, true, true},
    {"strtod_l", Strtod, nullptr, true, true},
    {"strtof_l", Strtof, nullptr, true, true},
    {"strtold_l", Strtold, nullptr, true, true},
    {"strtoll_l", Strtoll, nullptr, true, true},
    {"strtoull_l", Strtoull, nullptr, true, true},
    {"btowc", Btowc, nullptr, true, true},
    {"wctob", Wctob, nullptr, true, true},
    {"mbrtowc", Mbrtowc, nullptr, true, true},
    {"mbtowc", Mbtowc, nullptr, true, true},
    {"wcrtomb", Wcrtomb, nullptr, true, true},
    {"mbsnrtowcs", MbsnrtowcsProvider, nullptr, true, true},
    {"mbsrtowcs", MbsrtowcsProvider, nullptr, true, true},
    {"wcsnrtombs", Wcsnrtombs, nullptr, true, true},
    {"catopen", Catopen, nullptr, true, true},
    {"catgets", Catgets, nullptr, true, true},
    {"catclose", Catclose, nullptr, true, true},
};

}

namespace NativeAotGlibcSupport {

void RegisterLocale() {
    Register(Bindings, sizeof(Bindings) / sizeof(Bindings[0]));
}

}

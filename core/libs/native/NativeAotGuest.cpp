#include "native/NativeAotGuest.hpp"
#include "prx/libkernel/Pthread/include/GuestTlsMacOs.hpp"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mach/mach_time.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#include <map>
#include <memory>
#include <bit>

extern "C" {
alignas(16) std::uint8_t NativeAotGuestSharedMemory = 1;
}
static_assert(std::atomic_ref<std::uint8_t>::is_always_lock_free);
static_assert(std::atomic_ref<std::uint8_t>::required_alignment == 1);

namespace {

constexpr std::uint64_t PageSize = 16384;
constexpr std::uint64_t RelocationRelative = 8;
constexpr std::uint64_t RelocationGlobalData = 6;
constexpr std::uint64_t RelocationJumpSlot = 7;
constexpr std::uint64_t RelocationAbsolute = 1;
constexpr std::uint64_t RelocationNone = 0;
constexpr std::size_t Rsp = 4;
constexpr std::size_t ArgumentRegisters[6] = {7, 6, 2, 1, 8, 9};

const NativeAotGuestImage* loaded = nullptr;
std::uint64_t imageBase = 0;
std::uint64_t importRegion = 0;
std::uint64_t importRegionSize = 0;
std::vector<NativeAotGuest::Provider> importProviders;
pthread_t epochOwner{};
std::vector<NativeAotGuest::ProviderBinding> registry;
thread_local NativeAotGuestState* current = nullptr;

struct MappedImage {
    const NativeAotGuestImage* Image;
    std::uint64_t Base;
    std::uint64_t ImportBase;
    std::uint64_t ImportBytes;
    std::vector<std::uint64_t> Values;
    std::vector<NativeAotGuest::Provider> Providers;
    GuestTlsDescriptor* TlsModule;
    std::vector<bool> Qualified;
};
std::vector<MappedImage> mappedImages;
std::map<std::uint64_t, NativeAotGuest::Provider> nativeBindings;
std::map<std::uint64_t, std::string> opaqueBindings;
std::map<std::uint64_t, bool> qualifiedNativeBindings;

struct CurrentScope {
    NativeAotGuestState* Previous;
    explicit CurrentScope(NativeAotGuestState* state) : Previous(current) { current = state; }
    ~CurrentScope() { current = Previous; }
    CurrentScope(const CurrentScope&) = delete;
    CurrentScope& operator=(const CurrentScope&) = delete;
};

struct StackScope {
    NativeAotGuestState& State;
    std::uint64_t Saved;
    explicit StackScope(NativeAotGuestState& state) : State(state), Saved(state.Gpr[Rsp]) {}
    ~StackScope() { State.Gpr[Rsp] = Saved; }
    StackScope(const StackScope&) = delete;
    StackScope& operator=(const StackScope&) = delete;
};

const char* TrapName(std::uint64_t kind) {
    switch (kind) {
        case NativeAotGuest::UnknownTarget: return "control transfer to an address without converted code";
        case NativeAotGuest::UnexpectedReturn: return "guest return address does not match any converted caller";
        case NativeAotGuest::DivideError: return "divide error";
        case NativeAotGuest::UnknownEntry: return "converted unit entered at an unknown address";
        case NativeAotGuest::FallThrough: return "execution continued past the end of converted code";
        case NativeAotGuest::InvalidOpcode: return "invalid opcode";
        case NativeAotGuest::Halt: return "privileged halt instruction";
        case NativeAotGuest::MissingImport: return "missing import provider";
        case NativeAotGuest::UnsupportedRelocation: return "unsupported relocation";
        case NativeAotGuest::MisalignedVector: return "misaligned aligned vector access";
        case NativeAotGuest::SplitLock: return "locked access crosses its natural alignment";
        default: return "unsupported guest operation";
    }
}

int TrapSignal(std::uint64_t kind) {
    switch (kind) {
        case NativeAotGuest::DivideError: return SIGFPE;
        case NativeAotGuest::InvalidOpcode: return SIGILL;
        default: return SIGSEGV;
    }
}

[[noreturn]] void Fail(const std::string& message) {
    std::fprintf(stderr, "native AOT guest: %s\n", message.c_str());
    std::fflush(stderr);
    std::_Exit(127);
}

const NativeAotGuest::ProviderBinding* FindProvider(const char* name) {
    for (const auto& binding : registry)
        if (std::strcmp(binding.Name, name) == 0) return &binding;
    return nullptr;
}

void ProviderFence() {
    if (loaded != nullptr && loaded->Concurrent != 0 && std::atomic_ref<std::uint8_t>(NativeAotGuestSharedMemory).load(std::memory_order_acquire))
        std::atomic_thread_fence(std::memory_order_seq_cst);
}

std::uint64_t ImportThunk(NativeAotGuestState* state, std::uint64_t address) {
    NativeAotGuest::Provider provider = nullptr;
    bool qualified = false;
    if (const auto found = nativeBindings.find(address); found != nativeBindings.end()) provider = found->second;
    if (nativeBindings.contains(address)) qualified = qualifiedNativeBindings.at(address);
    if (provider == nullptr) {
        for (const auto& image : mappedImages) {
            if (address > image.ImportBase && address - image.ImportBase < image.ImportBytes && (address - image.ImportBase) % 16 == 0) {
                const auto index = (address - image.ImportBase) / 16 - 1;
                provider = image.Providers[index];
                qualified = image.Qualified[index];
                break;
            }
        }
    }
    if (provider == nullptr) NativeAotGuestTrap(NativeAotGuest::MissingImport, address, 0);
    CurrentScope scope(state);
    if (!qualified) NativeAotGuest::PromoteSharedMemory();
    ProviderFence();
    provider(*state);
    ProviderFence();
    const auto rsp = state->Gpr[Rsp];
    std::uint64_t target;
    std::memcpy(&target, reinterpret_cast<const void*>(rsp), sizeof(target));
    state->Gpr[Rsp] = rsp + 8;
    return target;
}

std::uint64_t OpaqueImportThunk(NativeAotGuestState*, std::uint64_t address) {
    Fail("native import has no qualified call ABI: " + opaqueBindings.at(address));
}

void ProtectImage(const NativeAotGuestImage& image, std::uint64_t span, std::uint64_t base) {
    std::vector<int> pages(span / PageSize, PROT_NONE);
    std::vector<bool> relro(span / PageSize, false);
    for (std::uint64_t index = 0; index < image.SegmentCount; ++index) {
        const auto& segment = image.Segments[index];
        if (segment.MemorySize == 0) continue;
        const auto protection = (segment.Flags & 2) ? PROT_READ | PROT_WRITE : (segment.Flags & 5) ? PROT_READ : PROT_NONE;
        for (auto page = segment.Address / PageSize; page <= (segment.Address + segment.MemorySize - 1) / PageSize; ++page)
            pages[page] |= protection;
    }
    if (image.RelroSize != 0) {
        const auto first = (image.RelroAddress + PageSize - 1) / PageSize;
        const auto last = (image.RelroAddress + image.RelroSize) / PageSize;
        for (auto page = first; page < last; ++page) relro[page] = true;
    }
    for (std::uint64_t page = 0; page < pages.size(); ++page) {
        const auto protection = relro[page] ? (pages[page] & ~PROT_WRITE) : pages[page];
        if (mprotect(reinterpret_cast<void*>(base + page * PageSize), PageSize, protection) != 0)
            Fail("cannot protect guest image memory");
    }
}

}

extern "C" [[noreturn]] void NativeAotGuestTrap(std::uint64_t kind, std::uint64_t address, std::uint64_t detail) {
    std::fprintf(stderr, "native AOT guest trap: %s at 0x%llx (image offset 0x%llx, detail 0x%llx)\n", TrapName(kind),
                 static_cast<unsigned long long>(address), static_cast<unsigned long long>(address - imageBase),
                 static_cast<unsigned long long>(detail));
    std::fflush(stderr);
    std::signal(TrapSignal(kind), SIG_DFL);
    std::raise(TrapSignal(kind));
    std::_Exit(128 + TrapSignal(kind));
}

extern "C" bool NativeAotGuestSingleThreadEpoch() {
    return !std::atomic_ref<std::uint8_t>(NativeAotGuestSharedMemory).load(std::memory_order_acquire);
}

extern "C" void NativeAotGuestFlushCacheLine(std::uint64_t address) {
    const auto line = address & ~std::uint64_t{63};
    const volatile auto value = *reinterpret_cast<const volatile std::uint8_t*>(address);
    static_cast<void>(value);
    std::atomic_thread_fence(std::memory_order_seq_cst);
    if (sys_cache_control(kCacheFunctionFlushDcache, reinterpret_cast<void*>(line), 64) != 0)
        NativeAotGuestTrap(NativeAotGuest::UnsupportedOperation, address, errno);
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

extern "C" NativeAotGuestFunction NativeAotGuestFind(std::uint64_t address) {
    if (loaded != nullptr && loaded->Concurrent >= 2 && !pthread_equal(epochOwner, pthread_self()))
        NativeAotGuest::PromoteSharedMemory();
    for (const auto& context : mappedImages) {
        const auto& image = *context.Image;
        if (address >= context.Base && address - context.Base < image.Span) {
            const auto offset = address - context.Base;
            const auto* begin = image.Entries;
            const auto* end = begin + image.EntryCount;
            const auto* found = std::lower_bound(begin, end, offset, [](const NativeAotGuestEntry& entry, std::uint64_t value) {
                return entry.Address < value;
            });
            if (found != end && found->Address == offset) return found->Function;
        }
        if (address > context.ImportBase && address - context.ImportBase < context.ImportBytes && (address - context.ImportBase) % 16 == 0)
            return ImportThunk;
    }
    if (nativeBindings.contains(address)) return ImportThunk;
    if (opaqueBindings.contains(address)) return OpaqueImportThunk;
    return nullptr;
}

extern "C" NativeAotGuestFunction NativeAotGuestLookup(std::uint64_t address) {
    if (const auto function = NativeAotGuestFind(address)) return function;
    NativeAotGuestTrap(NativeAotGuest::UnknownTarget, address, 0);
}

extern "C" void NativeAotGuestCpuid(NativeAotGuestState* state) {
    const auto leaf = static_cast<std::uint32_t>(state->Gpr[0]);
    const auto subleaf = static_cast<std::uint32_t>(state->Gpr[1]);
    std::uint32_t a = 0, b = 0, c = 0, d = 0;
    if (leaf == 0) {
        a = 7;
        std::memcpy(&b, "AnyP", 4);
        std::memcpy(&d, "S5Gu", 4);
        std::memcpy(&c, "estC", 4);
    } else if (leaf == 1) {
        a = 0x000906a0;
        c = (1u << 23);
        d = (1u << 0) | (1u << 4) | (1u << 8) | (1u << 15) | (1u << 25) | (1u << 26);
    } else if (leaf == 7 && subleaf == 0) {
        b = (1u << 3) | (1u << 8);
    }
    state->Gpr[0] = a;
    state->Gpr[3] = b;
    state->Gpr[1] = c;
    state->Gpr[2] = d;
}

extern "C" std::uint64_t NativeAotGuestReadTsc() {
    return mach_absolute_time();
}

namespace NativeAotGuest {

Provider ImportedProvider(std::uint64_t address) {
    if (const auto found = nativeBindings.find(address); found != nativeBindings.end()) return found->second;
    if (address <= importRegion || address - importRegion >= importRegionSize || (address - importRegion) % 16 != 0) return nullptr;
    const auto index = (address - importRegion) / 16 - 1;
    return index < importProviders.size() ? importProviders[index] : nullptr;
}

void RegisterProviders(const ProviderBinding* bindings, std::size_t count) {
    registry.insert(registry.end(), bindings, bindings + count);
}

const ProviderBinding* FindProviderBinding(const char* name) {
    return FindProvider(name);
}

std::uint64_t ProviderAddress(const char* name) {
    if (loaded == nullptr) return 0;
    for (std::uint64_t index = 0; index < loaded->SymbolCount; ++index)
        if (std::strcmp(loaded->Symbols[index], name) == 0 && importProviders[index] != nullptr)
            for (const auto& context : mappedImages) if (context.Image == loaded) return context.Values[index];
    const auto* binding = FindProvider(name);
    if (binding == nullptr || binding->Function == nullptr) return 0;
    Fail(std::string("provider is not imported by the guest image: ") + name);
}

void LoadBundle(std::span<const ImageBinding> images, std::size_t mainIndex) {
    if (loaded != nullptr) Fail("guest images are already loaded");
    if (images.empty() || images.size() > 64 || mainIndex >= images.size()) Fail("invalid closed image bundle");
    if (images.size() > 1 && images[mainIndex].StartupAbi != Abi::SceApplication) Fail("multiple images require an SCE application");
    mappedImages.reserve(images.size());
    bool privateEpoch = images[mainIndex].Image != nullptr && images[mainIndex].Image->Concurrent >= 2;
    std::map<std::string, std::uint64_t> exports;
    for (const auto& binding : images) {
        if (binding.Image == nullptr) Fail("null guest image");
        const auto& image = *binding.Image;
        if (image.Version != 9) Fail("unsupported guest image descriptor");
        if (image.Abi != static_cast<std::uint64_t>(binding.StartupAbi) || image.Abi > 2) Fail("guest image startup ABI does not match the launcher");
        if (image.Concurrent > 3) Fail("unsupported guest memory model");
        if (image.Concurrent >= 2 && binding.StartupAbi != Abi::Glibc) Fail("memory epochs require the glibc startup profile");
        if (images.size() > 1 && (&binding != &images[mainIndex]) && binding.StartupAbi != Abi::SceModule)
            Fail("secondary image is not a qualified SCE module");
        if (image.Span == 0 || image.Span > UINT64_MAX - PageSize) Fail("invalid guest image span");
        const auto span = (image.Span + PageSize - 1) & ~(PageSize - 1);
        auto* memory = mmap(nullptr, span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (memory == MAP_FAILED) Fail("cannot reserve guest image memory");
        const auto base = reinterpret_cast<std::uint64_t>(memory);
        for (std::uint64_t index = 0; index < image.SegmentCount; ++index) {
            const auto& segment = image.Segments[index];
            if (segment.Address > image.Span || segment.MemorySize > image.Span - segment.Address ||
                segment.FileSize > segment.MemorySize || segment.FileOffset > image.ByteCount || segment.FileSize > image.ByteCount - segment.FileOffset)
                Fail("guest segment exceeds the image");
            std::memcpy(reinterpret_cast<void*>(base + segment.Address), image.Bytes + segment.FileOffset, segment.FileSize);
        }
        if (image.SymbolCount > 1048576) Fail("too many guest imports");
        const auto importBytes = 16 * (image.SymbolCount + 1);
        const auto regionBytes = (importBytes + PageSize - 1) & ~(PageSize - 1);
        auto* region = mmap(nullptr, regionBytes, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (region == MAP_FAILED) Fail("cannot reserve guest import addresses");
        mappedImages.push_back({&image, base, reinterpret_cast<std::uint64_t>(region), importBytes,
            std::vector<std::uint64_t>(image.SymbolCount), std::vector<Provider>(image.SymbolCount),
            binding.TlsModule, std::vector<bool>(image.SymbolCount, false)});
        if (binding.TlsModule != nullptr) {
            if (binding.StartupAbi == Abi::Glibc || binding.TlsModule->version != 0 || image.TlsMemorySize == 0 ||
                image.TlsMemorySize > 1048576 || image.TlsFileSize > image.TlsMemorySize || image.TlsAlignment > 65536 ||
                !std::has_single_bit(image.TlsAlignment)) Fail("invalid closed-module TLS descriptor");
            bool readable = image.TlsFileSize == 0;
            for (std::uint64_t segment = 0; segment < image.SegmentCount; ++segment) {
                const auto& item = image.Segments[segment];
                if (image.TlsAddress >= item.Address && image.TlsAddress - item.Address <= item.FileSize &&
                    image.TlsFileSize <= item.FileSize - (image.TlsAddress - item.Address)) readable = true;
            }
            if (!readable) Fail("module TLS template is not file backed");
            *binding.TlsModule = {1, base + image.TlsAddress, image.TlsFileSize,
                (image.TlsMemorySize + image.TlsAlignment - 1) & ~(image.TlsAlignment - 1), image.TlsAlignment, 0};
        } else if (binding.StartupAbi == Abi::SceModule && image.TlsMemorySize != 0) Fail("module TLS requires a native descriptor");
        for (std::uint64_t index = 0; index < image.ExportCount; ++index) {
            const auto& symbol = image.Exports[index];
            if (symbol.Name == nullptr || symbol.Address >= image.Span) Fail("invalid guest export");
            if (!exports.emplace(symbol.Name, base + symbol.Address).second) Fail("ambiguous export in closed image bundle");
        }
    }
    for (auto& context : mappedImages) {
        const auto& image = *context.Image;
        std::string missing;
        for (std::uint64_t index = 0; index < image.SymbolCount; ++index) {
            const auto name = image.Symbols[index];
            if (const auto found = exports.find(name); found != exports.end()) {
                context.Values[index] = found->second;
                continue;
            }
            const auto* binding = FindProvider(name);
            if (binding == nullptr) {
                if ((image.SymbolFlags[index] & Weak) == 0) missing += std::string(missing.empty() ? "" : ", ") + name;
                continue;
            }
            if (image.Concurrent == 3 && !binding->StableImageMapping)
                Fail(std::string("unqualified image-mapping effects for provider: ") + name);
            context.Qualified[index] = binding->QualifiedMemoryEpoch;
            if (binding->Data != nullptr && !binding->QualifiedMemoryEpoch) privateEpoch = false;
            context.Providers[index] = binding->Function;
            if (binding->NativeAddress != nullptr) {
                const auto address = reinterpret_cast<std::uint64_t>(binding->NativeAddress);
                context.Values[index] = address;
                if (binding->Function != nullptr) {
                    const auto [found, inserted] = nativeBindings.emplace(address, binding->Function);
                    if (!inserted && found->second != binding->Function) Fail("conflicting native call ABI bindings");
                    const auto [qualification, added] = qualifiedNativeBindings.emplace(address, binding->QualifiedMemoryEpoch);
                    if (!added) qualification->second = qualification->second && binding->QualifiedMemoryEpoch;
                } else opaqueBindings.emplace(address, name);
            } else if (binding->Function != nullptr) {
                context.Values[index] = context.ImportBase + 16 * (index + 1);
            } else if (binding->Data != nullptr) context.Values[index] = reinterpret_cast<std::uint64_t>(binding->Data);
            else Fail("provider has no code or data binding");
        }
        if (!missing.empty()) Fail("missing import providers: " + missing);
        for (std::uint64_t index = 0; index < image.RelocationCount; ++index) {
            const auto& relocation = image.Relocations[index];
            if (relocation.Address > image.Span || 8 > image.Span - relocation.Address) Fail("guest relocation outside the image");
            std::uint64_t value;
            switch (relocation.Kind) {
                case RelocationNone: continue;
                case RelocationRelative: value = context.Base + static_cast<std::uint64_t>(relocation.Addend); break;
                case RelocationGlobalData:
                case RelocationJumpSlot:
                case RelocationAbsolute:
                    if (relocation.Symbol >= image.SymbolCount) Fail("guest relocation symbol out of range");
                    value = context.Values[relocation.Symbol] == 0 ? 0 : context.Values[relocation.Symbol] + static_cast<std::uint64_t>(relocation.Addend);
                    break;
                case 16:
                    if (image.Abi != static_cast<std::uint64_t>(Abi::SceModule) || context.TlsModule == nullptr || relocation.Symbol != 0 || relocation.Addend != 0)
                        Fail("module TLS relocation has no qualified descriptor token");
                    value = reinterpret_cast<std::uint64_t>(context.TlsModule);
                    break;
                default: Fail("unsupported guest relocation kind " + std::to_string(relocation.Kind));
            }
            std::memcpy(reinterpret_cast<void*>(context.Base + relocation.Address), &value, sizeof(value));
        }
        ProtectImage(image, (image.Span + PageSize - 1) & ~(PageSize - 1), context.Base);
        *image.Base = context.Base;
    }
    for (const auto& context : mappedImages)
        if (context.TlsModule != nullptr) Aps5GuestTlsRegister_nid_no_patch(context.TlsModule);
    const auto& primary = mappedImages[mainIndex];
    loaded = primary.Image;
    imageBase = primary.Base;
    importRegion = primary.ImportBase;
    importRegionSize = primary.ImportBytes;
    importProviders = primary.Providers;
    epochOwner = pthread_self();
    std::atomic_ref<std::uint8_t>(NativeAotGuestSharedMemory).store(!privateEpoch, std::memory_order_release);
}

std::uint64_t Load(const NativeAotGuestImage& image, Abi abi) {
    const ImageBinding binding{&image, abi};
    LoadBundle(std::span(&binding, 1), 0);
    return imageBase;
}

void CheckImageMappingChange(std::uint64_t address, std::uint64_t bytes) {
    if (loaded == nullptr || loaded->Concurrent != 3 || bytes == 0) return;
    const auto span = (loaded->Span + PageSize - 1) & ~(PageSize - 1);
    if (address > UINT64_MAX - bytes || (address < imageBase + span && address + bytes > imageBase))
        Fail("mapping change overlaps a lifetime-qualified guest image");
}

void PromoteSharedMemory() {
    if (loaded != nullptr && !std::atomic_ref<std::uint8_t>(NativeAotGuestSharedMemory).load(std::memory_order_acquire) && !pthread_equal(epochOwner, pthread_self()))
        Fail("a foreign guest entry requires promotion at an owning-thread call boundary");
    std::atomic_thread_fence(std::memory_order_seq_cst);
    std::atomic_ref<std::uint8_t>(NativeAotGuestSharedMemory).store(true, std::memory_order_release);
}

bool IsConvertedFunction(std::uint64_t address) {
    for (const auto& context : mappedImages) {
        if (address < context.Base || address - context.Base >= context.Image->Span) continue;
        const auto offset = address - context.Base;
        const auto* begin = context.Image->Entries;
        const auto* end = begin + context.Image->EntryCount;
        const auto* found = std::lower_bound(begin, end, offset, [](const NativeAotGuestEntry& entry, std::uint64_t value) {
            return entry.Address < value;
        });
        if (found != end && found->Address == offset) return true;
    }
    return false;
}

std::uint64_t ImageBase() {
    return imageBase;
}

std::uint64_t ImageSpan() {
    return loaded == nullptr ? 0 : loaded->Span;
}

std::uint64_t ExportAddress(const char* name) {
    if (loaded == nullptr || name == nullptr) return 0;
    for (std::uint64_t index = 0; index < loaded->ExportCount; ++index)
        if (std::strcmp(loaded->Exports[index].Name, name) == 0) return imageBase + loaded->Exports[index].Address;
    for (std::uint64_t index = 0; index < loaded->SymbolCount; ++index)
        if (std::strcmp(loaded->Symbols[index], name) == 0 && importProviders[index] != nullptr)
            for (const auto& context : mappedImages) if (context.Image == loaded) return context.Values[index];
    return 0;
}

NativeAotGuestState& CurrentState() {
    if (current == nullptr) Fail("no active guest state on this thread");
    return *current;
}

std::uint64_t ReturnSentinel() {
    return importRegion;
}

std::uint64_t Push(NativeAotGuestState& state, std::uint64_t value) {
    state.Gpr[Rsp] -= 8;
    std::memcpy(reinterpret_cast<void*>(state.Gpr[Rsp]), &value, sizeof(value));
    return state.Gpr[Rsp];
}

std::uint64_t Invoke(NativeAotGuestState& state, std::uint64_t target) {
    StackScope stack(state);
    state.Gpr[Rsp] &= ~std::uint64_t{15};
    Push(state, ReturnSentinel());
    CurrentScope scope(&state);
    ProviderFence();
    const auto result = NativeAotGuestLookup(target)(&state, target);
    ProviderFence();
    if (result != ReturnSentinel()) NativeAotGuestTrap(UnexpectedReturn, result, target);
    return state.Gpr[0];
}

std::uint64_t Argument(const NativeAotGuestState& state, std::size_t index) {
    if (index < 6) return state.Gpr[ArgumentRegisters[index]];
    std::uint64_t value;
    std::memcpy(&value, reinterpret_cast<const void*>(state.Gpr[Rsp] + 8 + 8 * (index - 6)), sizeof(value));
    return value;
}

double DoubleArgument(const NativeAotGuestState& state, std::size_t index) {
    if (index >= 8) Fail("stack floating-point arguments require a varargs or signature reader");
    double value;
    std::memcpy(&value, state.Xmm[index], sizeof(value));
    return value;
}

void Return(NativeAotGuestState& state, std::uint64_t value) {
    state.Gpr[0] = value;
}

void ReturnDouble(NativeAotGuestState& state, double value) {
    std::memset(state.Xmm[0], 0, sizeof(state.Xmm[0]));
    std::memcpy(state.Xmm[0], &value, sizeof(value));
}

std::uint64_t CreateThreadArea() {
    const auto segmentAlignment = std::max<std::uint64_t>(loaded == nullptr ? 1 : loaded->TlsAlignment, 1);
    const auto alignment = std::max<std::uint64_t>(segmentAlignment, 64);
    const auto block = loaded == nullptr ? 0 : (loaded->TlsMemorySize + segmentAlignment - 1) / segmentAlignment * segmentAlignment;
    const auto bytes = block + 2 * alignment + 0x100;
    auto* memory = static_cast<std::uint8_t*>(std::calloc(1, bytes));
    if (memory == nullptr) Fail("cannot allocate guest thread area");
    const auto start = reinterpret_cast<std::uint64_t>(memory);
    const auto pointer = (start + block + alignment - 1) / alignment * alignment;
    if (loaded != nullptr && loaded->TlsFileSize != 0)
        std::memcpy(reinterpret_cast<void*>(pointer - block), reinterpret_cast<const void*>(imageBase + loaded->TlsAddress), loaded->TlsFileSize);
    std::uint64_t guard[2];
    arc4random_buf(guard, sizeof(guard));
    guard[0] &= ~std::uint64_t{0xff};
    std::memcpy(reinterpret_cast<void*>(pointer), &pointer, 8);
    std::memcpy(reinterpret_cast<void*>(pointer + 0x10), &pointer, 8);
    std::memcpy(reinterpret_cast<void*>(pointer + 0x28), &guard[0], 8);
    std::memcpy(reinterpret_cast<void*>(pointer + 0x30), &guard[1], 8);
    std::memcpy(reinterpret_cast<void*>(pointer + 0xf0), &memory, sizeof(memory));
    return pointer;
}

void FreeThreadArea(std::uint64_t pointer) {
    void* memory;
    std::memcpy(&memory, reinterpret_cast<const void*>(pointer + 0xf0), sizeof(memory));
    std::free(memory);
}

bool ConcurrentMemory() {
    return loaded != nullptr && loaded->Concurrent != 0;
}

void FreeStack(std::uint64_t top, std::size_t bytes) {
    const auto size = (bytes + PageSize - 1) & ~(PageSize - 1);
    if (munmap(reinterpret_cast<void*>(top - size - PageSize), size + PageSize) != 0)
        Fail("cannot release guest stack");
}

std::uint64_t AllocateStack(std::size_t bytes) {
    const auto size = (bytes + PageSize - 1) & ~(PageSize - 1);
    auto* memory = mmap(nullptr, size + PageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) Fail("cannot allocate guest stack");
    if (mprotect(memory, PageSize, PROT_NONE) != 0) Fail("cannot protect guest stack guard");
    return reinterpret_cast<std::uint64_t>(memory) + size + PageSize;
}

void StartSceApplication(const NativeAotGuestImage& image, int argc, char** argv) {
    if (argc < 0 || (argc != 0 && argv == nullptr)) Fail("invalid SCE application arguments");
    if (loaded == nullptr) Load(image, Abi::SceApplication);
    else if (loaded != &image || image.Abi != static_cast<std::uint64_t>(Abi::SceApplication)) Fail("SCE startup image differs from the closed bundle main");
    NativeAotGuestState state{};
    state.Mxcsr = 0x1f80;
    state.X87Control = 0x37f;
    const auto top = AllocateStack(8 * 1024 * 1024);
    std::vector<std::uint64_t> parameters(static_cast<std::size_t>(argc) + 2, 0);
    parameters[0] = static_cast<std::uint64_t>(argc);
    for (int index = 0; index < argc; ++index) parameters[index + 1] = reinterpret_cast<std::uint64_t>(argv[index]);
    state.Gpr[Rsp] = top;
    state.Gpr[7] = reinterpret_cast<std::uint64_t>(parameters.data());
    state.Gpr[6] = 0;
    state.FsBase = CreateThreadArea();
    const auto entry = imageBase + image.EntryPoint;
    const auto result = Invoke(state, entry);
    FreeThreadArea(state.FsBase);
    FreeStack(top, 8 * 1024 * 1024);
    NativeAotGuestTrap(UnexpectedReturn, result, entry);
}

void Start(const NativeAotGuestImage& image, int argc, char** argv, char** envp) {
    Load(image);
    static NativeAotGuestState state;
    std::memset(&state, 0, sizeof(state));
    state.Mxcsr = 0x1f80;
    state.X87Control = 0x37f;
    auto top = AllocateStack(8 * 1024 * 1024);
    static std::uint8_t random[16];
    arc4random_buf(random, sizeof(random));
    std::size_t environment = 0;
    while (envp != nullptr && envp[environment] != nullptr) ++environment;
    const std::uint64_t auxiliary[] = {6, PageSize, 25, reinterpret_cast<std::uint64_t>(random), 9, imageBase + image.EntryPoint, 0, 0};
    const auto words = 1 + argc + 1 + environment + 1 + sizeof(auxiliary) / 8;
    top = (top - words * 8) & ~std::uint64_t{15};
    auto* cursor = reinterpret_cast<std::uint64_t*>(top);
    *cursor++ = static_cast<std::uint64_t>(argc);
    for (int index = 0; index < argc; ++index) *cursor++ = reinterpret_cast<std::uint64_t>(argv[index]);
    *cursor++ = 0;
    for (std::size_t index = 0; index < environment; ++index) *cursor++ = reinterpret_cast<std::uint64_t>(envp[index]);
    *cursor++ = 0;
    std::memcpy(cursor, auxiliary, sizeof(auxiliary));
    state.Gpr[Rsp] = top;
    state.Gpr[2] = 0;
    state.FsBase = CreateThreadArea();
    current = &state;
    const auto entry = imageBase + image.EntryPoint;
    ProviderFence();
    const auto result = NativeAotGuestLookup(entry)(&state, entry);
    ProviderFence();
    NativeAotGuestTrap(UnexpectedReturn, result, entry);
}

}

#include "native/NativeAotSce.hpp"
#include "SceTypes.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

extern "C" {
void _init_env_nid_postfix();
int atexit_nid_postfix(void (*)());
int __cxa_atexit_nid_postfix(void (*)(void*), void*, void*);
void exit_nid_postfix(int);
void* malloc_nid_postfix(std::size_t);
void free_nid_postfix(void*);
int posix_memalign_nid_postfix(void**, std::size_t, std::size_t);
int open_nid_postfix(const char*, int, int);
std::int64_t read_nid_postfix(int, void*, std::uint64_t);
int close_nid_postfix(int);
std::size_t strlen_nid_postfix(const char*);
int sceSystemServiceHideSplashScreen();
std::uint64_t sceKernelGetDirectMemorySize();
int sceKernelAllocateDirectMemory(std::int64_t, std::int64_t, std::uint64_t, std::uint64_t, int, std::int64_t*);
int sceKernelMapDirectMemory(void**, std::uint64_t, int, int, std::int64_t, std::uint64_t);
int sceVideoOutOpen(int, int, int, const void*);
int sceVideoOutSetFlipRate(int, int);
void sceVideoOutSetBufferAttribute2(VideoOutBufferAttribute2*, std::uint64_t, std::uint32_t, std::uint32_t, std::uint32_t, std::uint64_t, std::uint32_t, std::uint64_t);
int sceVideoOutRegisterBuffers2(int, int, int, const VideoOutBuffers*, int, const VideoOutBufferAttribute2*, int, void*);
int sceVideoOutSubmitFlip(int, int, int, std::int64_t);
int sceVideoOutWaitVblank(int);
int sceKernelSendNotificationRequest(int, const void*, std::size_t, int);
int sceKernelUsleep_nid_postfix(KernelUseconds);
void _sceKernelSetThreadDtors_nid_postfix(thread_dtors_func_t);
void _sceKernelSetThreadAtexitCount_nid_postfix(get_thread_atexit_count_func_t);
void _sceKernelSetThreadAtexitReport_nid_postfix(thread_atexit_report_func_t);
void _sceKernelRtldSetApplicationHeapAPI_nid_postfix(void*[]);
}

static_assert(sizeof(VideoOutBufferAttribute2) == 80);
static_assert(sizeof(VideoOutBuffers) == 32);
static_assert(sizeof(KernelModule) == 4 && sizeof(KernelUseconds) == 4);
static_assert(sizeof(std::size_t) == 8);

namespace {

using State = NativeAotGuestState;
NativeAotSce::BoundaryObserver observer = nullptr;
std::atomic<std::uint64_t> dtorsTarget{0}, countTarget{0}, reportTarget{0};

void Require(bool value, const char* reason) {
    if (!value) throw std::invalid_argument(reason);
}

template<class Value>
Value Argument(const State& state, std::size_t index) {
    static_assert((std::is_integral_v<Value> || std::is_pointer_v<Value>) && !std::is_function_v<std::remove_pointer_t<Value>>);
    const auto value = NativeAotGuest::Argument(state, index);
    if constexpr (std::is_pointer_v<Value>) return reinterpret_cast<Value>(value);
    else return static_cast<Value>(value);
}

template<class Result, class... Values, std::size_t... Indices>
void InvokeNative(State& state, Result (*function)(Values...), std::index_sequence<Indices...>) {
    if constexpr (std::is_void_v<Result>) function(Argument<Values>(state, Indices)...);
    else {
        const auto value = function(Argument<Values>(state, Indices)...);
        if constexpr (std::is_pointer_v<Result>) NativeAotGuest::Return(state, reinterpret_cast<std::uint64_t>(value));
        else {
            static_assert(std::is_integral_v<Result>);
            NativeAotGuest::Return(state, static_cast<std::uint64_t>(value));
        }
    }
}

template<class Result, class... Values>
void InvokeNative(State& state, Result (*function)(Values...)) {
    InvokeNative(state, function, std::index_sequence_for<Values...>{});
}

template<auto Function>
void Bridge(State& state) {
    InvokeNative(state, Function);
}

void WaitVblank(State& state) {
    InvokeNative(state, sceVideoOutWaitVblank);
    if (observer != nullptr) observer("sceVideoOutWaitVblank", state);
}

void Sleep(State& state) {
    InvokeNative(state, sceKernelUsleep_nid_postfix);
    if (observer != nullptr) observer("sceKernelUsleep", state);
}

void Init(State&) { _init_env_nid_postfix(); }

void Notification(State& state) {
    const auto size = static_cast<std::uint32_t>(NativeAotGuest::Argument(state, 2));
    NativeAotGuest::Return(state, static_cast<std::uint64_t>(sceKernelSendNotificationRequest(
        Argument<int>(state, 0), Argument<const void*>(state, 1), size, Argument<int>(state, 3))));
}

struct ExitTarget { std::uint64_t Address; };

void FinalizeGuest(void* raw) {
    std::unique_ptr<ExitTarget> target(static_cast<ExitTarget*>(raw));
    NativeAotSce::InvokeCallback(target->Address);
}

void AtExit(State& state) {
    const auto target = NativeAotGuest::Argument(state, 0);
    if (target == 0) { NativeAotGuest::Return(state, 0); return; }
    Require(NativeAotGuest::IsConvertedFunction(target), "atexit target has no converted entry");
    auto value = std::make_unique<ExitTarget>(ExitTarget{target});
    const auto status = __cxa_atexit_nid_postfix(FinalizeGuest, value.get(), nullptr);
    if (status == 0) static_cast<void>(value.release());
    NativeAotGuest::Return(state, static_cast<std::uint64_t>(status));
}

void ThreadDtors() { NativeAotSce::InvokeCallback(dtorsTarget.load()); }
int ThreadCount(KernelModule module) { return static_cast<int>(NativeAotSce::InvokeCallback(countTarget.load(), static_cast<std::uint32_t>(module))); }
void ThreadReport(KernelModule module) { NativeAotSce::InvokeCallback(reportTarget.load(), static_cast<std::uint32_t>(module)); }

void RegisterTarget(std::atomic<std::uint64_t>& slot, std::uint64_t target) {
    Require(target != 0 && NativeAotGuest::IsConvertedFunction(target), "thread callback has no converted entry");
    std::uint64_t expected = 0;
    Require(slot.compare_exchange_strong(expected, target), "thread callback is already registered");
}

void SetDtors(State& state) {
    RegisterTarget(dtorsTarget, NativeAotGuest::Argument(state, 0));
    try { _sceKernelSetThreadDtors_nid_postfix(ThreadDtors); }
    catch (...) { dtorsTarget.store(0); throw; }
}

void SetCount(State& state) {
    RegisterTarget(countTarget, NativeAotGuest::Argument(state, 0));
    try { _sceKernelSetThreadAtexitCount_nid_postfix(ThreadCount); }
    catch (...) { countTarget.store(0); throw; }
}

void SetReport(State& state) {
    RegisterTarget(reportTarget, NativeAotGuest::Argument(state, 0));
    try { _sceKernelSetThreadAtexitReport_nid_postfix(ThreadReport); }
    catch (...) { reportTarget.store(0); throw; }
}

struct Qualified {
    const char* Name;
    NativeAotGuest::Provider Provider;
    const void* Address;
};

const Qualified QualifiedBindings[] = {
    {"_init_env_nid_postfix", Init, reinterpret_cast<const void*>(_init_env_nid_postfix)},
    {"atexit_nid_postfix", AtExit, reinterpret_cast<const void*>(atexit_nid_postfix)},
    {"sceKernelSendNotificationRequest", Notification, reinterpret_cast<const void*>(sceKernelSendNotificationRequest)},
    {"_sceKernelSetThreadDtors_nid_postfix", SetDtors, reinterpret_cast<const void*>(_sceKernelSetThreadDtors_nid_postfix)},
    {"_sceKernelSetThreadAtexitCount_nid_postfix", SetCount, reinterpret_cast<const void*>(_sceKernelSetThreadAtexitCount_nid_postfix)},
    {"_sceKernelSetThreadAtexitReport_nid_postfix", SetReport, reinterpret_cast<const void*>(_sceKernelSetThreadAtexitReport_nid_postfix)},
    {"exit_nid_postfix", Bridge<exit_nid_postfix>, reinterpret_cast<const void*>(exit_nid_postfix)},
    {"malloc_nid_postfix", Bridge<malloc_nid_postfix>, reinterpret_cast<const void*>(malloc_nid_postfix)},
    {"free_nid_postfix", Bridge<free_nid_postfix>, reinterpret_cast<const void*>(free_nid_postfix)},
    {"posix_memalign_nid_postfix", Bridge<posix_memalign_nid_postfix>, reinterpret_cast<const void*>(posix_memalign_nid_postfix)},
    {"open_nid_postfix", Bridge<open_nid_postfix>, reinterpret_cast<const void*>(open_nid_postfix)},
    {"read_nid_postfix", Bridge<read_nid_postfix>, reinterpret_cast<const void*>(read_nid_postfix)},
    {"close_nid_postfix", Bridge<close_nid_postfix>, reinterpret_cast<const void*>(close_nid_postfix)},
    {"strlen_nid_postfix", Bridge<strlen_nid_postfix>, reinterpret_cast<const void*>(strlen_nid_postfix)},
    {"sceSystemServiceHideSplashScreen", Bridge<sceSystemServiceHideSplashScreen>, reinterpret_cast<const void*>(sceSystemServiceHideSplashScreen)},
    {"sceKernelGetDirectMemorySize", Bridge<sceKernelGetDirectMemorySize>, reinterpret_cast<const void*>(sceKernelGetDirectMemorySize)},
    {"sceKernelAllocateDirectMemory", Bridge<sceKernelAllocateDirectMemory>, reinterpret_cast<const void*>(sceKernelAllocateDirectMemory)},
    {"sceKernelMapDirectMemory", Bridge<sceKernelMapDirectMemory>, reinterpret_cast<const void*>(sceKernelMapDirectMemory)},
    {"sceVideoOutOpen", Bridge<sceVideoOutOpen>, reinterpret_cast<const void*>(sceVideoOutOpen)},
    {"sceVideoOutSetFlipRate", Bridge<sceVideoOutSetFlipRate>, reinterpret_cast<const void*>(sceVideoOutSetFlipRate)},
    {"sceVideoOutSetBufferAttribute2", Bridge<sceVideoOutSetBufferAttribute2>, reinterpret_cast<const void*>(sceVideoOutSetBufferAttribute2)},
    {"sceVideoOutRegisterBuffers2", Bridge<sceVideoOutRegisterBuffers2>, reinterpret_cast<const void*>(sceVideoOutRegisterBuffers2)},
    {"sceVideoOutSubmitFlip", Bridge<sceVideoOutSubmitFlip>, reinterpret_cast<const void*>(sceVideoOutSubmitFlip)},
    {"sceVideoOutWaitVblank", WaitVblank, reinterpret_cast<const void*>(sceVideoOutWaitVblank)},
    {"sceKernelUsleep_nid_postfix", Sleep, reinterpret_cast<const void*>(sceKernelUsleep_nid_postfix)},
    {"_sceKernelRtldSetApplicationHeapAPI_nid_postfix", Bridge<_sceKernelRtldSetApplicationHeapAPI_nid_postfix>, reinterpret_cast<const void*>(_sceKernelRtldSetApplicationHeapAPI_nid_postfix)},
};

}

namespace NativeAotSce {

void Register(std::span<const Binding> bindings) {
    std::vector<NativeAotGuest::ProviderBinding> providers;
    for (const auto& binding : bindings) {
        Require(binding.Identity != nullptr && binding.NativeName != nullptr && binding.Address != nullptr, "incomplete native SCE binding");
        NativeAotGuest::Provider function = nullptr;
        for (const auto& qualified : QualifiedBindings) {
            if (std::strcmp(binding.NativeName, qualified.Name) != 0) continue;
            Require(!binding.Data && binding.Address == qualified.Address, "native SCE binding identity changed");
            function = qualified.Provider;
        }
        providers.push_back({binding.Identity, function, binding.Data ? const_cast<void*>(binding.Address) : nullptr,
                             false, false, binding.Data ? nullptr : binding.Address});
    }
    NativeAotGuest::RegisterProviders(providers.data(), providers.size());
}

void SetBoundaryObserver(BoundaryObserver value) { observer = value; }

std::uint64_t InvokeCallback(std::uint64_t target, std::uint64_t argument) {
    Require(target != 0 && NativeAotGuest::IsConvertedFunction(target), "callback target has no converted entry");
    constexpr std::size_t bytes = 65536;
    struct Stack {
        std::uint64_t Top = NativeAotGuest::AllocateStack(bytes);
        ~Stack() { NativeAotGuest::FreeStack(Top, bytes); }
    } stack;
    NativeAotGuestState state{};
    state.Gpr[4] = stack.Top;
    state.Gpr[7] = argument;
    state.Mxcsr = 0x1f80;
    state.X87Control = 0x37f;
    return NativeAotGuest::Invoke(state, target);
}

}

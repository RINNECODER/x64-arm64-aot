#include "prx/libc/include/NativeAotBundle.hpp"
#include <array>
#include <stdexcept>
#include <vector>
#include <thread>

namespace {

std::vector<int> trace;
void Preinit() { trace.push_back(0); }
void InitLeaf() { trace.push_back(1); }
void InitMain() { trace.push_back(2); }
void FiniLeaf() { trace.push_back(3); }
void FiniMain() { trace.push_back(4); }
void FailInit() { trace.push_back(5); throw std::runtime_error("initialization failed"); }
void FailFini() { trace.push_back(6); throw std::runtime_error("finalization failed"); }

unsigned Step(unsigned value) { return value + 1; }
void Check(bool valid) { if (!valid) throw std::runtime_error("native bundle regression"); }

template<class Function>
void Reject(Function function) {
    try { function(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("invalid native bundle accepted");
}

}

int main() {
    unsigned shared = 42;
    const NativeAotDataRange data[]{ {&shared, sizeof(shared)} };
    const NativeAotModuleExport symbols[]{ {"step", reinterpret_cast<const void*>(&Step), 0, 1}, {"shared", &shared, sizeof(shared), 2} };
    const void* functions[]{reinterpret_cast<const void*>(&Step)};
    const NativeAotModuleDependency dependency[]{ {0, 3} };
    std::array<NativeAotModule, 2> modules{{ {3, "counter", 3, data, 1, symbols, 2, nullptr, 0, functions, 1},
        {3, "app", 7, nullptr, 0, nullptr, 0, dependency, 1, nullptr, 0} }};
    NativeAotBundleRegistry registry(modules, 1);
    Check(registry.MainIndex() == 1 && registry.InitializationOrder().size() == 2 && registry.InitializationOrder()[0] == 0);
    Check(registry.Find("counter", 3, "shared", 2) == &shared);
    const auto step = reinterpret_cast<unsigned (*)(unsigned)>(const_cast<void*>(registry.Find("counter", 3, "step", 1)));
    Check(step(41) == 42);
    Reject([&] { registry.Find("counter", 4, "shared", 2); });
    Reject([&] { registry.Find("counter", 3, "missing", 2); });
    Reject([&] { registry.Find("counter", 3, "shared", 1); });
    auto invalid = modules;
    invalid[0].moduleVersion = 4;
    Reject([&] { NativeAotBundleRegistry check(invalid, 1); });
    invalid = modules;
    invalid[1].id = "counter";
    Reject([&] { NativeAotBundleRegistry check(invalid, 1); });
    invalid = modules;
    invalid[1].ranges = data;
    invalid[1].rangeCount = 1;
    Reject([&] { NativeAotBundleRegistry check(invalid, 1); });
    const NativeAotModuleDependency cycle[]{ {1, 7} };
    invalid = modules;
    invalid[0].dependencies = cycle;
    invalid[0].dependencyCount = 1;
    Reject([&] { NativeAotBundleRegistry check(invalid, 1); });
    Reject([&] { NativeAotBundleRegistry check(modules, 0); });
    const NativeAotModuleExport escaped[]{ {"outside", reinterpret_cast<const char*>(&shared) + sizeof(shared), 1, 2} };
    invalid = modules;
    invalid[0].exports = escaped;
    invalid[0].exportCount = 1;
    Reject([&] { NativeAotBundleRegistry check(invalid, 1); });
    const void* leafFunctions[]{reinterpret_cast<const void*>(&InitLeaf), reinterpret_cast<const void*>(&FiniLeaf), reinterpret_cast<const void*>(&FailFini)};
    const void* appFunctions[]{reinterpret_cast<const void*>(&Preinit), reinterpret_cast<const void*>(&InitMain), reinterpret_cast<const void*>(&FiniMain), reinterpret_cast<const void*>(&FailInit)};
    const NativeAotLifecycleFunction leafInit[]{InitLeaf}, leafFini[]{FiniLeaf}, appPreinit[]{Preinit}, appInit[]{InitMain}, appFini[]{FiniMain};
    auto lifecycle = modules;
    lifecycle[0].exports = nullptr;
    lifecycle[0].exportCount = 0;
    lifecycle[0].functions = leafFunctions;
    lifecycle[0].functionCount = 3;
    lifecycle[0].initializers = leafInit;
    lifecycle[0].initializerCount = 1;
    lifecycle[0].finalizers = leafFini;
    lifecycle[0].finalizerCount = 1;
    lifecycle[1].functions = appFunctions;
    lifecycle[1].functionCount = 4;
    lifecycle[1].preinitializers = appPreinit;
    lifecycle[1].preinitializerCount = 1;
    lifecycle[1].initializers = appInit;
    lifecycle[1].initializerCount = 1;
    lifecycle[1].finalizers = appFini;
    lifecycle[1].finalizerCount = 1;
    NativeAotBundleRegistry initialized(lifecycle, 1);
    std::thread first([&] { initialized.Start(); });
    std::thread second([&] { initialized.Start(); });
    first.join();
    second.join();
    Check(trace == std::vector<int>({0, 1, 2}));
    initialized.Stop();
    initialized.Stop();
    Check(trace == std::vector<int>({0, 1, 2, 4, 3}));
    Reject([&] { initialized.Start(); });
    trace.clear();
    const NativeAotLifecycleFunction failing[]{FailInit};
    lifecycle[1].initializers = failing;
    NativeAotBundleRegistry rollback(lifecycle, 1);
    bool failed = false;
    try { rollback.Start(); } catch (const std::runtime_error&) { failed = true; }
    Check(failed && trace == std::vector<int>({0, 1, 5, 3}));
    Reject([&] { rollback.Start(); });
    Reject([&] { rollback.Stop(); });
    trace.clear();
    lifecycle[1].initializers = appInit;
    const NativeAotLifecycleFunction failingFinalizers[]{FailFini, FiniLeaf};
    lifecycle[0].finalizers = failingFinalizers;
    lifecycle[0].finalizerCount = 2;
    NativeAotBundleRegistry finishFailure(lifecycle, 1);
    finishFailure.Start();
    failed = false;
    try { finishFailure.Stop(); } catch (const std::runtime_error&) { failed = true; }
    Check(failed && trace == std::vector<int>({0, 1, 2, 4, 6, 3}));
    finishFailure.Stop();
    Check(trace.size() == 6);
    lifecycle[0].preinitializers = leafInit;
    lifecycle[0].preinitializerCount = 1;
    Reject([&] { NativeAotBundleRegistry invalidPreinit(lifecycle, 1); });
    return 0;
}

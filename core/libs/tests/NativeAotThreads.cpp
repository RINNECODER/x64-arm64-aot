#include "SceTypes.hpp"
#include "prx/libc/include/NativeAotBundle.hpp"
#include <atomic>
#include <barrier>
#include <exception>
#include <semaphore>
#include <stdexcept>
#include <thread>

extern "C" int NativeAotPthreadCreate_nid_no_patch(Pthread*, const PthreadAttr*, PthreadEntry, void*, const char*);
extern "C" int NativeAotPthreadJoin_nid_no_patch(Pthread, void**);

namespace {

NativeAotBundleRegistry* registry;
std::binary_semaphore proceed(0);
int createStatus = 0;
struct HostThread { std::thread thread; void* result = nullptr; };

void Check(bool value) { if (!value) throw std::runtime_error("native thread boundary regression"); }

template<class Function>
void Reject(Function function) {
    try { function(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("invalid native thread boundary accepted");
}

void* APS5_VABI Worker(void* argument) { proceed.acquire(); ++*static_cast<int*>(argument); return argument; }
void* APS5_VABI Failure(void*) { throw std::runtime_error("worker failed"); }
void* APS5_VABI Unknown(void* argument) { return argument; }

}

extern "C" NativeAotBundleRegistry* NativeAotCompiledBundle_nid_no_patch() { return registry; }

extern "C" int APS5_VABI scePthreadCreate(Pthread* output, const PthreadAttr*, PthreadEntry entry, void* argument, const char*) {
    if (createStatus) return createStatus;
    auto* host = new HostThread;
    host->thread = std::thread([=] { host->result = entry(argument); });
    *output = reinterpret_cast<Pthread>(host);
    return 0;
}

extern "C" int APS5_VABI scePthreadJoin(Pthread handle, void** output) {
    auto* host = reinterpret_cast<HostThread*>(handle);
    host->thread.join();
    if (output) *output = host->result;
    delete host;
    return 0;
}

int main() {
    const void* functions[]{reinterpret_cast<const void*>(&Worker), reinterpret_cast<const void*>(&Failure)};
    NativeAotModule module{};
    module.descriptorVersion = 3;
    module.id = "app";
    module.moduleVersion = 1;
    module.functions = functions;
    module.functionCount = 2;
    module.threadEntries = functions;
    module.threadEntryCount = 2;
    NativeAotBundleRegistry bundle(std::span(&module, 1), 0);
    registry = &bundle;
    Pthread thread = nullptr;
    int value = 0;
    Reject([&] { NativeAotPthreadCreate_nid_no_patch(&thread, nullptr, Worker, &value, "test"); });
    bundle.Start();
    Reject([&] { NativeAotPthreadCreate_nid_no_patch(&thread, nullptr, Unknown, &value, "test"); });
    Check(bundle.OutstandingThreads() == 0);
    createStatus = 42;
    Check(NativeAotPthreadCreate_nid_no_patch(&thread, nullptr, Worker, &value, "test") == 42);
    Check(bundle.OutstandingThreads() == 0 && thread == nullptr);
    createStatus = 0;
    Check(NativeAotPthreadCreate_nid_no_patch(&thread, nullptr, Worker, &value, "test") == 0);
    Check(bundle.OutstandingThreads() == 1);
    Reject([&] { bundle.Stop(); });
    std::atomic<int> joined{0}, rejected{0};
    std::barrier ready(3);
    const auto join = [&] {
        ready.arrive_and_wait();
        try {
            void* result = nullptr;
            Check(NativeAotPthreadJoin_nid_no_patch(thread, &result) == 0 && result == &value);
            ++joined;
        } catch (const std::invalid_argument&) { ++rejected; }
    };
    std::thread first(join), second(join);
    ready.arrive_and_wait();
    proceed.release();
    first.join();
    second.join();
    Check(joined == 1 && rejected == 1 && value == 1 && bundle.OutstandingThreads() == 0);
    Reject([&] { NativeAotPthreadJoin_nid_no_patch(thread, nullptr); });
    Check(NativeAotPthreadCreate_nid_no_patch(&thread, nullptr, Failure, nullptr, "failure") == 0);
    bool failed = false;
    try { NativeAotPthreadJoin_nid_no_patch(thread, nullptr); } catch (const std::runtime_error&) { failed = true; }
    Check(failed && bundle.OutstandingThreads() == 0);
    bundle.Stop();
    return 0;
}

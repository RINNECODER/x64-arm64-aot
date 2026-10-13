#include "SceTypes.hpp"
#include "prx/libc/include/NativeAotBundle.hpp"
#include <exception>
#include <memory>
#include <mutex>
#include <stdexcept>

extern "C" {
int APS5_VABI scePthreadCreate(Pthread*, const PthreadAttr*, PthreadEntry, void*, const char*);
int APS5_VABI scePthreadJoin(Pthread, void**);
NativeAotBundleRegistry* NativeAotCompiledBundle_nid_no_patch();
}

namespace {

struct Thread {
    NativeAotBundleRegistry* bundle;
    PthreadEntry entry;
    void* argument;
    Pthread handle = nullptr;
    std::exception_ptr failure;
    bool joining = false;
    Thread* next = nullptr;
};

struct Threads {
    std::mutex mutex;
    Thread* first = nullptr;
};

Threads& State() { static Threads state; return state; }

void* APS5_VABI Entry(void* opaque) {
    auto& thread = *static_cast<Thread*>(opaque);
    try { return thread.entry(thread.argument); }
    catch (...) { thread.failure = std::current_exception(); return nullptr; }
}

}

extern "C" int NativeAotPthreadCreate_nid_no_patch(Pthread* output, const PthreadAttr* attributes, PthreadEntry entry, void* argument, const char* name) {
    if (output == nullptr || entry == nullptr) throw std::invalid_argument("native AOT thread requires output and entry");
    if (attributes != nullptr && *attributes != nullptr) throw std::invalid_argument("native AOT threads require default joinable attributes");
    auto* bundle = NativeAotCompiledBundle_nid_no_patch();
    auto thread = std::make_unique<Thread>(Thread{bundle, entry, argument});
    bundle->ReserveThread(reinterpret_cast<const void*>(entry));
    int result;
    try { result = scePthreadCreate(&thread->handle, nullptr, Entry, thread.get(), name); }
    catch (...) { bundle->ReleaseThread(); throw; }
    if (result != 0) {
        bundle->ReleaseThread();
        return result;
    }
    auto& state = State();
    const std::lock_guard lock(state.mutex);
    *output = thread->handle;
    thread->next = state.first;
    state.first = thread.release();
    return result;
}

extern "C" int NativeAotPthreadJoin_nid_no_patch(Pthread handle, void** result) {
    auto& state = State();
    Thread* thread = nullptr;
    {
        const std::lock_guard lock(state.mutex);
        for (auto* item = state.first; item != nullptr; item = item->next)
            if (item->handle == handle) { thread = item; break; }
        if (thread == nullptr || thread->joining) throw std::invalid_argument("native AOT join requires an unclaimed owned thread");
        thread->joining = true;
    }
    int status;
    try { status = scePthreadJoin(handle, result); }
    catch (...) {
        const std::lock_guard lock(state.mutex);
        thread->joining = false;
        throw;
    }
    if (status != 0) {
        const std::lock_guard lock(state.mutex);
        thread->joining = false;
        return status;
    }
    {
        const std::lock_guard lock(state.mutex);
        auto** current = &state.first;
        while (*current != thread) current = &(*current)->next;
        *current = thread->next;
    }
    std::unique_ptr<Thread> completed(thread);
    thread->bundle->ReleaseThread();
    if (thread->failure) std::rethrow_exception(thread->failure);
    return status;
}

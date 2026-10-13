#include "native/NativeAotGlibcSupport.hpp"
#include <condition_variable>
#include <atomic>
#include <cerrno>
#include <map>
#include <memory>
#include <mutex>
#include <cstring>
#include <pthread.h>
#include <shared_mutex>
#include <vector>

extern "C" std::uint64_t NativeAotGlibcFastGetSpecific(std::uint64_t value);

namespace {

using namespace NativeAotGlibcSupport;

std::mutex tableLock;
std::map<std::uint64_t, std::unique_ptr<pthread_mutex_t>> mutexes;
std::map<std::uint64_t, std::unique_ptr<pthread_rwlock_t>> rwlocks;
std::map<std::uint64_t, std::unique_ptr<pthread_cond_t>> conditions;

template<class Object, class Create>
Object* Find(std::map<std::uint64_t, std::unique_ptr<Object>>& table, std::uint64_t address, Create create) {
    std::lock_guard<std::mutex> lock(tableLock);
    auto& slot = table[address];
    if (!slot) {
        slot = std::make_unique<Object>();
        create(slot.get());
    }
    return slot.get();
}

pthread_mutex_t* Mutex(std::uint64_t address) {
    return Find(mutexes, address, [](pthread_mutex_t* mutex) { pthread_mutex_init(mutex, nullptr); });
}

pthread_rwlock_t* Rwlock(std::uint64_t address) {
    return Find(rwlocks, address, [](pthread_rwlock_t* rwlock) { pthread_rwlock_init(rwlock, nullptr); });
}

pthread_cond_t* Condition(std::uint64_t address) {
    return Find(conditions, address, [](pthread_cond_t* condition) { pthread_cond_init(condition, nullptr); });
}

void RequireDefaultMutex(std::uint64_t address) {
    std::int32_t kind;
    std::memcpy(&kind, reinterpret_cast<const void*>(address + 16), sizeof(kind));
    if (kind != 0) Unsupported("only default glibc mutexes are supported");
}

void ReturnResult(State& state, int result) {
    ReturnInteger(state, result == 0 ? 0 : GuestErrno(result));
}

void MutexLock(State& state) {
    const auto address = NativeAotGuest::Argument(state, 0);
    RequireDefaultMutex(address);
    ReturnResult(state, pthread_mutex_lock(Mutex(address)));
}

void MutexUnlock(State& state) {
    ReturnResult(state, pthread_mutex_unlock(Mutex(NativeAotGuest::Argument(state, 0))));
}

void ReadLock(State& state) {
    ReturnResult(state, pthread_rwlock_rdlock(Rwlock(NativeAotGuest::Argument(state, 0))));
}

void WriteLock(State& state) {
    ReturnResult(state, pthread_rwlock_wrlock(Rwlock(NativeAotGuest::Argument(state, 0))));
}

void RwUnlock(State& state) {
    ReturnResult(state, pthread_rwlock_unlock(Rwlock(NativeAotGuest::Argument(state, 0))));
}

void CondBroadcast(State& state) {
    ReturnResult(state, pthread_cond_broadcast(Condition(NativeAotGuest::Argument(state, 0))));
}

void CondWait(State& state) {
    const auto mutex = NativeAotGuest::Argument(state, 1);
    RequireDefaultMutex(mutex);
    ReturnResult(state, pthread_cond_wait(Condition(NativeAotGuest::Argument(state, 0)), Mutex(mutex)));
}

struct GuestKey {
    std::uint64_t Destructor;
};
std::map<std::uint32_t, GuestKey> keys;
std::uint64_t nextKey = 0;
std::atomic<std::uint64_t> keyGeneration{0};
thread_local std::uint64_t observedKeyGeneration = UINT64_MAX;
thread_local std::map<std::uint32_t, std::uint64_t> keyValues;

void KeyCreate(State& state) {
    const auto target = NativeAotGuest::Argument(state, 1);
    if (target != 0 && NativeAotGuestFind(target) == nullptr) Unsupported("TLS destructor is not a converted entry");
    std::lock_guard<std::mutex> lock(tableLock);
    if (keys.size() >= 1024 || nextKey > UINT32_MAX) { ReturnResult(state, EAGAIN); return; }
    const auto key = static_cast<std::uint32_t>(nextKey++);
    keys.emplace(key, GuestKey{target});
    keyGeneration.fetch_add(1, std::memory_order_release);
    std::memcpy(Pointer<void>(state, 0), &key, sizeof(key));
    ReturnResult(state, 0);
}

void KeyDelete(State& state) {
    std::lock_guard<std::mutex> lock(tableLock);
    const auto removed = keys.erase(static_cast<std::uint32_t>(NativeAotGuest::Argument(state, 0)));
    if (removed) keyGeneration.fetch_add(1, std::memory_order_release);
    ReturnResult(state, removed ? 0 : EINVAL);
}

std::uint64_t SpecificValue(std::uint32_t key) {
    if (observedKeyGeneration != keyGeneration.load(std::memory_order_acquire)) {
        std::lock_guard<std::mutex> lock(tableLock);
        std::erase_if(keyValues, [](const auto& value) { return !keys.contains(value.first); });
        observedKeyGeneration = keyGeneration.load(std::memory_order_relaxed);
    }
    const auto found = keyValues.find(key);
    return found != keyValues.end() ? found->second : 0;
}

void GetSpecific(State& state) {
    NativeAotGuest::Return(state, NativeAotGlibcFastGetSpecific(NativeAotGuest::Argument(state, 0)));
}

void SetSpecific(State& state) {
    const auto key = static_cast<std::uint32_t>(NativeAotGuest::Argument(state, 0));
    std::lock_guard<std::mutex> lock(tableLock);
    if (!keys.contains(key)) { ReturnResult(state, EINVAL); return; }
    keyValues[key] = NativeAotGuest::Argument(state, 1);
    ReturnResult(state, 0);
}

void DestroyKeys(State& state) {
    for (unsigned pass = 0; pass < 4; ++pass) {
        std::vector<std::uint32_t> pending;
        for (const auto& [key, value] : keyValues) if (value != 0) pending.push_back(key);
        bool invoked = false;
        for (const auto key : pending) {
            std::uint64_t target = 0, value = 0;
            {
                std::lock_guard<std::mutex> lock(tableLock);
                const auto found = keys.find(key);
                if (found != keys.end()) target = found->second.Destructor;
                value = keyValues[key];
                if (target != 0 && value != 0) keyValues[key] = 0;
            }
            if (target != 0 && value != 0) {
                invoked = true;
                state.Gpr[7] = value;
                NativeAotGuest::Invoke(state, target);
            }
        }
        if (!invoked) break;
    }
    keyValues.clear();
}

constexpr std::size_t StackBytes = 8 * 1024 * 1024;

struct GuestThread {
    pthread_t Host{};
    NativeAotGuestState State{};
    std::uint64_t Id = 0;
    std::uint64_t Target = 0;
    std::uint64_t Top = 0;
    std::uint64_t Result = 0;
    bool Joining = false;
};

std::map<std::uint64_t, std::shared_ptr<GuestThread>> threads;
std::uint64_t nextThread = 2;
thread_local std::uint64_t threadId = 1;

void* RunThread(void* value) {
    auto& thread = *static_cast<GuestThread*>(value);
    threadId = thread.Id;
    thread.State.FsBase = NativeAotGuest::CreateThreadArea();
    thread.Result = NativeAotGuest::Invoke(thread.State, thread.Target);
    DestroyKeys(thread.State);
    NativeAotGuest::FreeThreadArea(thread.State.FsBase);
    return nullptr;
}

void ThreadCreate(State& state) {
    if (!NativeAotGuest::ConcurrentMemory()) Unsupported("pthread_create requires the ordered memory profile");
    if (NativeAotGuest::Argument(state, 1) != 0) Unsupported("only default joinable thread attributes are supported");
    const auto output = NativeAotGuest::Argument(state, 0);
    const auto target = NativeAotGuest::Argument(state, 2);
    if (output == 0 || NativeAotGuestFind(target) == nullptr) {
        ReturnResult(state, EINVAL);
        return;
    }
    auto thread = std::make_shared<GuestThread>();
    thread->Target = target;
    thread->Top = NativeAotGuest::AllocateStack(StackBytes);
    thread->State.Gpr[4] = thread->Top;
    thread->State.Gpr[7] = NativeAotGuest::Argument(state, 3);
    thread->State.Mxcsr = state.Mxcsr;
    thread->State.X87Control = state.X87Control;
    int result;
    {
        std::lock_guard<std::mutex> lock(tableLock);
        thread->Id = nextThread++;
        threads.emplace(thread->Id, thread);
        NativeAotGuest::PromoteSharedMemory();
        result = pthread_create(&thread->Host, nullptr, RunThread, thread.get());
        if (result != 0) threads.erase(thread->Id);
    }
    if (result != 0) NativeAotGuest::FreeStack(thread->Top, StackBytes);
    else std::memcpy(reinterpret_cast<void*>(output), &thread->Id, sizeof(thread->Id));
    ReturnResult(state, result);
}

void ThreadJoin(State& state) {
    const auto id = NativeAotGuest::Argument(state, 0);
    if (id == threadId) {
        ReturnResult(state, EDEADLK);
        return;
    }
    std::shared_ptr<GuestThread> thread;
    {
        std::lock_guard<std::mutex> lock(tableLock);
        const auto found = threads.find(id);
        if (found == threads.end()) {
            ReturnResult(state, ESRCH);
            return;
        }
        thread = found->second;
        if (thread->Joining) {
            ReturnResult(state, EINVAL);
            return;
        }
        thread->Joining = true;
    }
    const auto result = pthread_join(thread->Host, nullptr);
    if (result == 0) {
        const auto output = NativeAotGuest::Argument(state, 1);
        if (output != 0) std::memcpy(reinterpret_cast<void*>(output), &thread->Result, sizeof(thread->Result));
        NativeAotGuest::FreeStack(thread->Top, StackBytes);
    }
    {
        std::lock_guard<std::mutex> lock(tableLock);
        if (result == 0) threads.erase(id);
        else thread->Joining = false;
    }
    ReturnResult(state, result);
}

void ThreadSelf(State& state) {
    ReturnInteger(state, threadId);
}

void ThreadEqual(State& state) {
    ReturnInteger(state, NativeAotGuest::Argument(state, 0) == NativeAotGuest::Argument(state, 1));
}

void Once(State& state) {
    const auto address = NativeAotGuest::Argument(state, 0);
    const auto target = NativeAotGuest::Argument(state, 1);
    if (address % std::atomic_ref<std::uint32_t>::required_alignment != 0)
        Unsupported("pthread_once control is misaligned");
    std::atomic_ref<std::uint32_t> control(*reinterpret_cast<std::uint32_t*>(address));
    auto value = control.load();
    for (;;) {
        if (value == 2) break;
        if (value == 0 && control.compare_exchange_strong(value, 1)) {
            NativeAotGuest::Invoke(state, target);
            control.store(2);
            control.notify_all();
            break;
        }
        if (value > 2) Unsupported("unsupported pthread_once control");
        control.wait(1);
        value = control.load();
    }
    ReturnInteger(state, 0);
}

void MutexInit(State& state) {
    if (NativeAotGuest::Argument(state, 1) != 0) Unsupported("only default mutex attributes are supported");
    const auto address = NativeAotGuest::Argument(state, 0);
    std::lock_guard<std::mutex> lock(tableLock);
    if (mutexes.contains(address)) {
        ReturnResult(state, EBUSY);
        return;
    }
    auto object = std::make_unique<pthread_mutex_t>();
    const auto result = pthread_mutex_init(object.get(), nullptr);
    if (result == 0) {
        std::memset(reinterpret_cast<void*>(address), 0, 40);
        mutexes.emplace(address, std::move(object));
    }
    ReturnResult(state, result);
}

void MutexDestroy(State& state) {
    const auto address = NativeAotGuest::Argument(state, 0);
    std::lock_guard<std::mutex> lock(tableLock);
    const auto found = mutexes.find(address);
    if (found == mutexes.end()) {
        ReturnResult(state, EINVAL);
        return;
    }
    const auto result = pthread_mutex_destroy(found->second.get());
    if (result == 0) mutexes.erase(found);
    ReturnResult(state, result);
}

void CondInit(State& state) {
    if (NativeAotGuest::Argument(state, 1) != 0) Unsupported("only default condition attributes are supported");
    const auto address = NativeAotGuest::Argument(state, 0);
    std::lock_guard<std::mutex> lock(tableLock);
    if (conditions.contains(address)) {
        ReturnResult(state, EBUSY);
        return;
    }
    auto object = std::make_unique<pthread_cond_t>();
    const auto result = pthread_cond_init(object.get(), nullptr);
    if (result == 0) {
        std::memset(reinterpret_cast<void*>(address), 0, 48);
        conditions.emplace(address, std::move(object));
    }
    ReturnResult(state, result);
}

void CondDestroy(State& state) {
    const auto address = NativeAotGuest::Argument(state, 0);
    std::lock_guard<std::mutex> lock(tableLock);
    const auto found = conditions.find(address);
    if (found == conditions.end()) {
        ReturnResult(state, EINVAL);
        return;
    }
    const auto result = pthread_cond_destroy(found->second.get());
    if (result == 0) conditions.erase(found);
    ReturnResult(state, result);
}

void CondSignal(State& state) {
    ReturnResult(state, pthread_cond_signal(Condition(NativeAotGuest::Argument(state, 0))));
}

const NativeAotGuest::ProviderBinding Bindings[] = {
    {"pthread_key_create", KeyCreate, nullptr, true, true},
    {"pthread_key_delete", KeyDelete, nullptr, true, true},
    {"pthread_getspecific", GetSpecific, nullptr, true, true},
    {"pthread_setspecific", SetSpecific, nullptr, true, true},
    {"pthread_create", ThreadCreate, nullptr, true, true},
    {"pthread_join", ThreadJoin, nullptr, true, true},
    {"pthread_self", ThreadSelf, nullptr, true, true},
    {"pthread_equal", ThreadEqual, nullptr, true, true},
    {"pthread_once", Once, nullptr, true, true},
    {"pthread_mutex_init", MutexInit, nullptr, true, true},
    {"pthread_mutex_destroy", MutexDestroy, nullptr, true, true},
    {"pthread_cond_init", CondInit, nullptr, true, true},
    {"pthread_cond_destroy", CondDestroy, nullptr, true, true},
    {"pthread_cond_signal", CondSignal, nullptr, true, true},
    {"pthread_mutex_lock", MutexLock, nullptr, true, true},
    {"pthread_mutex_unlock", MutexUnlock, nullptr, true, true},
    {"pthread_rwlock_rdlock", ReadLock, nullptr, true, true},
    {"pthread_rwlock_wrlock", WriteLock, nullptr, true, true},
    {"pthread_rwlock_unlock", RwUnlock, nullptr, true, true},
    {"pthread_cond_broadcast", CondBroadcast, nullptr, true, true},
    {"pthread_cond_wait", CondWait, nullptr, true, true},
};

}

extern "C" std::uint64_t NativeAotGlibcFastGetSpecific(std::uint64_t value) {
    return SpecificValue(static_cast<std::uint32_t>(value));
}

extern "C" bool NativeAotGlibcOnceReady(std::uint64_t address) {
    if (address % std::atomic_ref<std::uint32_t>::required_alignment != 0) return false;
    return std::atomic_ref<std::uint32_t>(*reinterpret_cast<std::uint32_t*>(address)).load(std::memory_order_acquire) == 2;
}

extern "C" bool NativeAotGlibcThreadFastBinding(std::uint64_t address, std::uint64_t kind) {
    const auto provider = NativeAotGuest::ImportedProvider(address);
    return (kind == 10 && provider == GetSpecific) || (kind == 11 && provider == Once);
}

namespace NativeAotGlibcSupport {

void RegisterThreads() {
    Register(Bindings, sizeof(Bindings) / sizeof(Bindings[0]));
}

}

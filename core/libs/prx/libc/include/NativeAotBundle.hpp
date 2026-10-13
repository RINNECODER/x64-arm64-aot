#ifndef CORE_LIBS_PRX_LIBC_INCLUDE_NATIVEAOTBUNDLE_HPP
#define CORE_LIBS_PRX_LIBC_INCLUDE_NATIVEAOTBUNDLE_HPP

#include "NativeAotImage.hpp"
#include "prx/libkernel/Pthread/include/GuestTlsMacOs.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

struct NativeAotModuleExport {
    const char* name;
    const void* address;
    std::size_t bytes;
    std::uint64_t kind;
};

struct NativeAotModuleDependency {
    std::size_t index;
    std::uint64_t version;
};

using NativeAotLifecycleFunction = void (*)();

struct NativeAotModule {
    std::uint64_t descriptorVersion;
    const char* id;
    std::uint64_t moduleVersion;
    const NativeAotDataRange* ranges;
    std::size_t rangeCount;
    const NativeAotModuleExport* exports;
    std::size_t exportCount;
    const NativeAotModuleDependency* dependencies;
    std::size_t dependencyCount;
    const void* const* functions;
    std::size_t functionCount;
    const NativeAotLifecycleFunction* preinitializers;
    std::size_t preinitializerCount;
    const NativeAotLifecycleFunction* initializers;
    std::size_t initializerCount;
    const NativeAotLifecycleFunction* finalizers;
    std::size_t finalizerCount;
    const GuestTlsDescriptor* tls;
    std::size_t tlsBytes;
    const void* const* threadEntries;
    std::size_t threadEntryCount;
};

class NativeAotBundleRegistry {
public:
    NativeAotBundleRegistry(std::span<const NativeAotModule> modules, std::size_t mainIndex);
    ~NativeAotBundleRegistry();
    NativeAotBundleRegistry(const NativeAotBundleRegistry&) = delete;
    NativeAotBundleRegistry& operator=(const NativeAotBundleRegistry&) = delete;
    const void* Find(const char* module, std::uint64_t version, const char* symbol, std::uint64_t kind) const;
    std::span<const std::size_t> InitializationOrder() const;
    std::size_t MainIndex() const;
    void Start();
    void Stop();
    void ReserveThread(const void* entry);
    void ReleaseThread();
    std::size_t OutstandingThreads() const;
private:
    struct State;
    std::unique_ptr<State> state;
};

#endif

#include "prx/libc/include/NativeAotBundle.hpp"
#include <algorithm>
#include <functional>
#include <exception>
#include <mutex>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Require(bool valid, const char* reason) {
    if (!valid) throw std::invalid_argument(reason);
}

std::string Name(const char* value) {
    Require(value != nullptr, "native bundle name is null");
    std::size_t size = 0;
    while (size < 256 && value[size] != 0) ++size;
    Require(size > 0 && size < 256, "native bundle name is empty or too long");
    return {value, size};
}

bool Contains(std::span<const NativeAotDataRange> ranges, const void* pointer, std::size_t bytes) {
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    return std::any_of(ranges.begin(), ranges.end(), [&](const auto& range) {
        const auto start = reinterpret_cast<std::uintptr_t>(range.address);
        return address >= start && address - start <= range.bytes && bytes <= range.bytes - (address - start);
    });
}

}

struct NativeAotBundleRegistry::State {
    struct Module {
        std::string id;
        std::uint64_t version;
        std::vector<NativeAotDataRange> ranges;
        std::map<std::string, NativeAotModuleExport> exports;
        std::vector<NativeAotModuleDependency> dependencies;
        std::vector<const void*> functions;
        std::vector<NativeAotLifecycleFunction> preinitializers;
        std::vector<NativeAotLifecycleFunction> initializers;
        std::vector<NativeAotLifecycleFunction> finalizers;
        const GuestTlsDescriptor* tls = nullptr;
        std::size_t tlsBytes = 0;
        std::vector<const void*> threadEntries;
    };
    std::vector<Module> modules;
    std::vector<std::size_t> order;
    std::size_t mainIndex;
    enum class Phase { Created, Starting, Active, Stopping, Stopped, Failed };
    Phase phase = Phase::Created;
    std::recursive_mutex lifecycleMutex;
    std::vector<std::size_t> initialized;
    std::size_t outstandingThreads = 0;
};

NativeAotBundleRegistry::NativeAotBundleRegistry(std::span<const NativeAotModule> modules, std::size_t mainIndex)
    : state(std::make_unique<State>()) {
    Require(!modules.empty() && modules.size() <= 64 && mainIndex < modules.size(), "invalid native bundle dimensions");
    state->mainIndex = mainIndex;
    std::vector<std::pair<std::uintptr_t, std::uintptr_t>> ranges;
    for (const auto& source : modules) {
        Require(source.descriptorVersion == 3 && source.moduleVersion <= 65535, "unsupported native module descriptor");
        State::Module module{Name(source.id), source.moduleVersion, {}, {}, {}, {}, {}, {}, {}};
        Require(std::none_of(state->modules.begin(), state->modules.end(), [&](const auto& previous) { return previous.id == module.id; }),
            "duplicate native module id");
        Require(source.rangeCount <= 65536 && (source.rangeCount == 0 || source.ranges != nullptr), "invalid native module ranges");
        Require(source.exportCount <= 65536 && (source.exportCount == 0 || source.exports != nullptr), "invalid native module exports");
        Require(source.dependencyCount <= modules.size() && (source.dependencyCount == 0 || source.dependencies != nullptr), "invalid native dependencies");
        for (std::size_t index = 0; index < source.rangeCount; ++index) {
            const auto range = source.ranges[index];
            const auto start = reinterpret_cast<std::uintptr_t>(range.address);
            Require(start != 0 && range.bytes > 0 && range.bytes <= std::numeric_limits<std::uintptr_t>::max() - start,
                "invalid native module data extent");
            ranges.emplace_back(start, start + range.bytes);
            module.ranges.push_back(range);
        }
        Require(source.functionCount <= 65536 && (source.functionCount == 0 || source.functions != nullptr), "invalid native module functions");
        for (std::size_t index = 0; index < source.functionCount; ++index) {
            Require(source.functions[index] != nullptr, "null native module function");
            module.functions.push_back(source.functions[index]);
        }
        Require(source.threadEntryCount <= source.functionCount && (source.threadEntryCount == 0 || source.threadEntries != nullptr), "invalid native thread entry table");
        for (std::size_t index = 0; index < source.threadEntryCount; ++index) {
            const auto entry = source.threadEntries[index];
            Require(entry != nullptr && std::find(module.functions.begin(), module.functions.end(), entry) != module.functions.end(),
                "native thread entry does not belong to its module");
            module.threadEntries.push_back(entry);
        }
        module.tls = source.tls;
        module.tlsBytes = source.tlsBytes;
        Require((source.tls == nullptr && source.tlsBytes == 0) ||
            (source.tls != nullptr && source.tls->version == 1 && source.tlsBytes > 0 && source.tlsBytes <= source.tls->blockSize &&
             source.tls->templateSize <= source.tlsBytes), "invalid native module TLS layout");
        for (std::size_t index = 0; index < source.exportCount; ++index) {
            auto symbol = source.exports[index];
            const auto name = Name(symbol.name);
            bool validTls = false;
            if (symbol.kind == 3 && symbol.address != nullptr && module.tls != nullptr) {
                const auto& index = *static_cast<const GuestTlsIndex*>(symbol.address);
                validTls = index.module == module.tls && index.offset < module.tlsBytes && symbol.bytes > 0 && symbol.bytes <= module.tlsBytes - index.offset;
            }
            Require(symbol.address != nullptr && (validTls || (symbol.kind == 1 && symbol.bytes == 0 && std::find(module.functions.begin(), module.functions.end(), symbol.address) != module.functions.end()) ||
                (symbol.kind == 2 && symbol.bytes > 0 && Contains(module.ranges, symbol.address, symbol.bytes))), "invalid native module export");
            symbol.name = nullptr;
            Require(module.exports.emplace(name, symbol).second, "duplicate native export name");
        }
        for (std::size_t index = 0; index < source.dependencyCount; ++index) {
            const auto dependency = source.dependencies[index];
            Require(dependency.index < modules.size() && modules[dependency.index].moduleVersion == dependency.version,
                "native dependency version mismatch");
            Require(std::none_of(module.dependencies.begin(), module.dependencies.end(), [&](const auto& previous) {
                return previous.index == dependency.index;
            }), "duplicate native dependency");
            module.dependencies.push_back(dependency);
        }
        const auto callbacks = [&](const NativeAotLifecycleFunction* values, std::size_t count) {
            Require(count <= 4096 && (count == 0 || values != nullptr), "invalid native lifecycle array");
            std::vector<NativeAotLifecycleFunction> result;
            for (std::size_t index = 0; index < count; ++index) {
                const auto address = reinterpret_cast<const void*>(values[index]);
                Require(address != nullptr && std::find(module.functions.begin(), module.functions.end(), address) != module.functions.end(),
                    "native lifecycle callback does not belong to its module");
                result.push_back(values[index]);
            }
            return result;
        };
        module.preinitializers = callbacks(source.preinitializers, source.preinitializerCount);
        module.initializers = callbacks(source.initializers, source.initializerCount);
        module.finalizers = callbacks(source.finalizers, source.finalizerCount);
        Require(module.preinitializers.empty() || state->modules.size() == mainIndex, "only the main module may have preinitializers");
        state->modules.push_back(std::move(module));
    }
    std::sort(ranges.begin(), ranges.end());
    for (std::size_t index = 1; index < ranges.size(); ++index)
        Require(ranges[index - 1].second <= ranges[index].first, "native module data ownership overlaps");
    std::vector<unsigned char> visited(modules.size());
    std::function<void(std::size_t)> visit = [&](std::size_t index) {
        Require(visited[index] != 1, "cyclic native module dependencies");
        if (visited[index] == 2) return;
        visited[index] = 1;
        for (const auto dependency : state->modules[index].dependencies) visit(dependency.index);
        visited[index] = 2;
        state->order.push_back(index);
    };
    visit(mainIndex);
    Require(state->order.size() == modules.size(), "unreachable native module");
}

NativeAotBundleRegistry::~NativeAotBundleRegistry() = default;

const void* NativeAotBundleRegistry::Find(const char* module, std::uint64_t version, const char* symbol, std::uint64_t kind) const {
    const auto id = Name(module);
    const auto name = Name(symbol);
    const auto found = std::find_if(state->modules.begin(), state->modules.end(), [&](const auto& value) { return value.id == id; });
    Require(found != state->modules.end() && found->version == version, "native lookup module/version mismatch");
    const auto exported = found->exports.find(name);
    Require(exported != found->exports.end() && exported->second.kind == kind, "native lookup symbol/kind mismatch");
    if (kind == 3) {
        const std::lock_guard lock(state->lifecycleMutex);
        Require(state->phase == State::Phase::Active || state->phase == State::Phase::Starting || state->phase == State::Phase::Stopping, "native TLS lookup requires an active bundle");
        return Aps5GuestTlsGetAddr_nid_no_patch(static_cast<const GuestTlsIndex*>(exported->second.address));
    }
    return exported->second.address;
}

std::span<const std::size_t> NativeAotBundleRegistry::InitializationOrder() const { return state->order; }
std::size_t NativeAotBundleRegistry::MainIndex() const { return state->mainIndex; }

void NativeAotBundleRegistry::Start() {
    const std::lock_guard lock(state->lifecycleMutex);
    if (state->phase == State::Phase::Active) return;
    Require(state->phase == State::Phase::Created, "native bundle cannot start in its current state");
    state->phase = State::Phase::Starting;
    try {
        for (const auto callback : state->modules[state->mainIndex].preinitializers) callback();
        for (const auto index : state->order) {
            for (const auto callback : state->modules[index].initializers) callback();
            state->initialized.push_back(index);
        }
        state->phase = State::Phase::Active;
    } catch (...) {
        const auto failure = std::current_exception();
        state->phase = State::Phase::Stopping;
        std::size_t cleanupFailures = 0;
        for (auto current = state->initialized.rbegin(); current != state->initialized.rend(); ++current)
            for (const auto callback : state->modules[*current].finalizers)
                try { callback(); } catch (...) { ++cleanupFailures; }
        for (const auto& module : state->modules) if (module.tls) Aps5GuestTlsReleaseCurrentThread_nid_no_patch(module.tls);
        state->initialized.clear();
        state->phase = State::Phase::Failed;
        if (cleanupFailures != 0) std::throw_with_nested(std::runtime_error("native bundle initialization and rollback failed"));
        std::rethrow_exception(failure);
    }
}

void NativeAotBundleRegistry::Stop() {
    const std::lock_guard lock(state->lifecycleMutex);
    if (state->phase == State::Phase::Stopped) return;
    Require(state->phase == State::Phase::Active, "native bundle cannot stop in its current state");
    Require(state->outstandingThreads == 0, "native bundle still has unjoined guest threads");
    state->phase = State::Phase::Stopping;
    std::exception_ptr failure;
    for (auto current = state->initialized.rbegin(); current != state->initialized.rend(); ++current)
        for (const auto callback : state->modules[*current].finalizers)
            try { callback(); } catch (...) { if (!failure) failure = std::current_exception(); }
    for (const auto& module : state->modules) if (module.tls) Aps5GuestTlsReleaseCurrentThread_nid_no_patch(module.tls);
    state->initialized.clear();
    state->phase = State::Phase::Stopped;
    if (failure) std::rethrow_exception(failure);
}

void NativeAotBundleRegistry::ReserveThread(const void* entry) {
    const std::lock_guard lock(state->lifecycleMutex);
    Require(state->phase == State::Phase::Active, "guest thread requires an active native bundle");
    Require(state->outstandingThreads < 1024, "native bundle guest-thread bound exceeded");
    const bool found = std::any_of(state->modules.begin(), state->modules.end(), [&](const auto& module) {
        return std::find(module.threadEntries.begin(), module.threadEntries.end(), entry) != module.threadEntries.end();
    });
    Require(found, "guest thread entry has no qualified native pointer ABI");
    ++state->outstandingThreads;
}

void NativeAotBundleRegistry::ReleaseThread() {
    const std::lock_guard lock(state->lifecycleMutex);
    Require(state->outstandingThreads != 0, "native bundle thread accounting underflow");
    --state->outstandingThreads;
}

std::size_t NativeAotBundleRegistry::OutstandingThreads() const {
    const std::lock_guard lock(state->lifecycleMutex);
    return state->outstandingThreads;
}

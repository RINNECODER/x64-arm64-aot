#include "api.h"
#include "prx/libc/include/NativeAotBundle.hpp"
#include <array>
#include <barrier>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <sys/sysctl.h>
#include <cerrno>

extern "C" NativeAotBundleRegistry* NativeAotCompiledBundle_nid_no_patch();

#ifdef BUNDLE_REFERENCE
#define BundleRun app_run
#define CounterAddress counter_address
#define WorkerAddress worker_address
#else
extern "C" int aps5_app_app_run(BundleRequest*, BundleRequest*);
extern "C" unsigned* aps5_counter_counter_address();
extern "C" unsigned* aps5_worker_worker_address();
#define BundleRun aps5_app_app_run
#define CounterAddress aps5_counter_counter_address
#define WorkerAddress aps5_worker_worker_address
#endif

namespace {
std::barrier rendezvous(2);
std::vector<unsigned> trace;
bool failInitialization = false;
struct GuardedRequest {
    std::array<unsigned long, 2> before{0xa5a5a5a5a5a5a5a5ul, 0x1122334455667788ul};
    BundleRequest request{};
    std::array<unsigned long, 2> after{0x5a5a5a5a5a5a5a5aul, 0x8877665544332211ul};
};
static_assert(sizeof(BundleRequest) == 64 && offsetof(BundleRequest, digest) == 32);
static_assert(offsetof(GuardedRequest, request) == 16 && offsetof(GuardedRequest, after) == 80);
void Require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
}

extern "C" void record_event(unsigned value) {
    trace.push_back(value);
    if (failInitialization && value == 20) throw std::runtime_error("injected initializer failure");
}

extern "C" void wait_peers() { rendezvous.arrive_and_wait(); }

int main(int argc, char** argv) {
    int translated = 0;
    std::size_t size = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, nullptr, 0) != 0 && errno != ENOENT) return 90;
    if (translated != 0) return 91;
    std::printf("architecture=arm64 translated=0\n");
    failInitialization = argc == 2 && std::string(argv[1]) == "fail-init";
    auto* registry = NativeAotCompiledBundle_nid_no_patch();
    if (failInitialization) {
        bool failed = false;
        try { registry->Start(); } catch (const std::runtime_error&) { failed = true; }
        Require(failed && trace == std::vector<unsigned>({10, 20, 110}), "initializer rollback mismatch");
        Require(registry->OutstandingThreads() == 0, "thread escaped failed initialization");
        std::printf("rollback=10,20,110\n");
        return 0;
    }
    registry->Start();
    registry->Start();
    Require(trace == std::vector<unsigned>({10, 20, 30}), "initialization order mismatch");
    auto* counter = CounterAddress();
    auto* worker = WorkerAddress();
    Require(counter != worker && *counter == 7 && *worker == 20, "main TLS template mismatch");
    for (unsigned iteration = 0; iteration < 4; ++iteration) {
        GuardedRequest first, second;
        first.request.input = 2 + iteration;
        second.request.input = 100 + iteration;
        Require(BundleRun(&first.request, &second.request) == 0, "guest create/join or callback failed");
        const auto& a = first.request;
        const auto& b = second.request;
        Require(a.counter_address != b.counter_address && a.worker_address != b.worker_address &&
                a.counter_address != a.worker_address && b.counter_address != b.worker_address &&
                a.counter_address != reinterpret_cast<unsigned long>(counter) && b.counter_address != reinterpret_cast<unsigned long>(counter) &&
                a.worker_address != reinterpret_cast<unsigned long>(worker) && b.worker_address != reinterpret_cast<unsigned long>(worker), "TLS ownership mismatch");
        Require(*counter == 7 && *worker == 20 && registry->OutstandingThreads() == 0, "main TLS or joined-thread state changed");
        for (const auto* guarded : {&first, &second}) {
            const auto& request = guarded->request;
            Require(guarded->before == GuardedRequest{}.before && guarded->after == GuardedRequest{}.after, "request guard modified");
            Require(request.result == 227 + request.input && request.counter_zero == 0 && request.worker_zero == 0, "worker TLS initialization mismatch");
            std::printf("input=%u result=%u counter_zero=%u worker_zero=%u digest=", request.input, request.result, request.counter_zero, request.worker_zero);
            for (auto byte : request.digest) std::printf("%02x", byte);
            std::printf("\n");
        }
    }
    registry->Stop();
    registry->Stop();
    Require(trace == std::vector<unsigned>({10, 20, 30, 130, 120, 110}), "finalization order mismatch");
    std::printf("teardown=130,120,110 outstanding=0\n");
    return 0;
}

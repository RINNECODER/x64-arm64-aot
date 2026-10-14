#include "HleLog.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef __APPLE__
#include <sys/syscall.h>
#endif

namespace {

int logFd = -2;
pthread_mutex_t logLock = PTHREAD_MUTEX_INITIALIZER;
std::uint64_t nextSequence = 0;

std::once_flag openOnce;

void OpenLog() {
    const char* path = std::getenv("ANYPS5_HLE_LOG");
    if (path == nullptr || *path == '\0') {
        logFd = -1;
        return;
    }
    logFd = ::open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (logFd >= 0) {
        const std::uint32_t header[2] = {APS5_HLE_LOG_MAGIC, APS5_HLE_LOG_VERSION};
        (void)!::write(logFd, header, sizeof(header));
    }
}

// call_once publishes logFd to every caller; two threads can no longer both open with O_TRUNC.
void EnsureOpen() {
    std::call_once(openOnce, OpenLog);
}

std::uint64_t CurrentThread() {
    std::uint64_t thread = 0;
#ifdef __APPLE__
    pthread_threadid_np(nullptr, &thread);
#else
    thread = static_cast<std::uint64_t>(::syscall(SYS_gettid));
#endif
    return thread;
}

void WriteRecord(std::uint64_t sequence, std::uint32_t nameLength, std::uint32_t flags, const std::uint64_t* args, std::uint64_t result, const char* name) {
    const std::uint64_t thread = CurrentThread();
    std::uint64_t arguments[APS5_HLE_LOG_ARGS] = {0, 0, 0, 0, 0, 0};
    if (args != nullptr) std::memcpy(arguments, args, sizeof(arguments));
    pthread_mutex_lock(&logLock);
    (void)!::write(logFd, &sequence, sizeof(sequence));
    (void)!::write(logFd, &thread, sizeof(thread));
    (void)!::write(logFd, &nameLength, sizeof(nameLength));
    (void)!::write(logFd, &flags, sizeof(flags));
    (void)!::write(logFd, arguments, sizeof(arguments));
    (void)!::write(logFd, &result, sizeof(result));
    if (nameLength != 0) {
        (void)!::write(logFd, name, nameLength);
        static const std::uint8_t zeros[8] = {0};
        (void)!::write(logFd, zeros, (8 - (nameLength % 8)) % 8);
    }
    pthread_mutex_unlock(&logLock);
}

}

extern "C" int HleLogEnabled(void) {
    EnsureOpen();
    return logFd >= 0;
}

extern "C" std::uint64_t HleLogCall(const char* name, std::uint64_t a0, std::uint64_t a1, std::uint64_t a2, std::uint64_t a3, std::uint64_t a4, std::uint64_t a5) {
    EnsureOpen();
    if (logFd < 0) return 0;
    pthread_mutex_lock(&logLock);
    const std::uint64_t sequence = ++nextSequence;
    pthread_mutex_unlock(&logLock);
    const std::uint64_t args[APS5_HLE_LOG_ARGS] = {a0, a1, a2, a3, a4, a5};
    const std::uint32_t nameLength = name != nullptr ? static_cast<std::uint32_t>(std::strlen(name)) : 0;
    WriteRecord(sequence, nameLength, APS5_HLE_LOG_CALL, args, 0, name);
    return sequence;
}

extern "C" void HleLogReturn(std::uint64_t sequence, std::uint64_t result) {
    EnsureOpen();
    if (logFd < 0 || sequence == 0) return;
    WriteRecord(sequence, 0, APS5_HLE_LOG_RETURN, nullptr, result, nullptr);
}

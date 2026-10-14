// N threads making their first logged call at once must open the log exactly once.
#include "../HleLog.cpp"
#include <atomic>
#include <dirent.h>
#include <sys/wait.h>
#include <thread>
#include <vector>
#include <cstdio>

static int OpenDescriptors() {
    int count = 0;
    if (DIR* directory = ::opendir("/dev/fd")) {
        while (::readdir(directory) != nullptr) ++count;
        ::closedir(directory);
    }
    return count;
}

static int Trial(const char* path) {
    ::setenv("ANYPS5_HLE_LOG", path, 1);
    const int before = OpenDescriptors();
    constexpr int threads = 16;
    std::atomic<int> ready{0};
    std::vector<std::thread> pool;
    for (int index = 0; index < threads; ++index)
        pool.emplace_back([&] {
            ready.fetch_add(1);
            while (ready.load() < threads) {}
            HleLogEnabled();
        });
    for (auto& thread : pool) thread.join();
    // One log descriptor, plus the directory handle each OpenDescriptors() scan opens itself.
    if (OpenDescriptors() != before + 1) return 1;
    std::uint32_t header[2] = {0, 0};
    const int reader = ::open(path, O_RDONLY);
    const bool complete = reader >= 0 && ::pread(reader, header, sizeof(header), 0) == sizeof(header);
    if (reader >= 0) ::close(reader);
    if (!complete) return 2;
    if (header[0] != APS5_HLE_LOG_MAGIC || header[1] != APS5_HLE_LOG_VERSION) return 3;
    return 0;
}

int main() {
    char path[] = "/tmp/anyps5-hle-test-XXXXXX";
    ::close(::mkstemp(path));
    for (int trial = 0; trial < 100; ++trial) {
        const pid_t child = ::fork();
        if (child == 0) ::_exit(Trial(path));
        int status = 0;
        ::waitpid(child, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            std::fprintf(stderr, "hle log trial %d failed (status %d)\n", trial, status);
            ::unlink(path);
            return 1;
        }
    }
    ::unlink(path);
    std::puts("ok");
    return 0;
}

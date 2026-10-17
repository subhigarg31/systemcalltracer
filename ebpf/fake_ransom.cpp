// fake_ransom.cpp — SAFE ransomware simulator for testing.
//
// It ONLY touches files inside the test folder given on the command line,
// and refuses to run on any folder that does not start with /tmp/ransom_test.
// It "encrypts" each file by overwriting it with random bytes (no real crypto).
//
// Usage:
//   ./fake_ransom setup <dir> <num_files>          create test files
//   ./fake_ransom run   <dir> <num_files> <delay_ms> overwrite them one by one
//   ./fake_ransom count <dir> <num_files>          count damaged files
//
// Build: g++ -O2 -std=c++17 -o fake_ransom fake_ransom.cpp

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>

static const char *MARK = "ORIGINAL-SAFE-TEST-FILE\n";
static const size_t FILE_SIZE = 64 * 1024;   // 64 KB per file

static bool safe_dir(const std::string &d) {
    return d.rfind("/tmp/ransom_test", 0) == 0;
}

static std::string path_for(const std::string &dir, int i) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "/doc_%04d.txt", i);
    return dir + buf;
}

static int setup(const std::string &dir, int n) {
    mkdir(dir.c_str(), 0755);
    std::string body(FILE_SIZE, 'a');
    std::memcpy(&body[0], MARK, std::strlen(MARK));
    for (int i = 0; i < n; ++i) {
        int fd = open(path_for(dir, i).c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { std::perror("open"); return 1; }
        if (write(fd, body.data(), body.size()) < 0) std::perror("write");
        close(fd);
    }
    std::printf("created %d test files in %s\n", n, dir.c_str());
    return 0;
}

static int run(const std::string &dir, int n, int delay_ms) {
    std::mt19937 rng(std::random_device{}());
    std::string junk(FILE_SIZE, '\0');
    for (int i = 0; i < n; ++i) {
        for (auto &c : junk) c = static_cast<char>(rng());   // high-entropy data
        // O_WRONLY without O_TRUNC: the file is only damaged once write() runs.
        int fd = open(path_for(dir, i).c_str(), O_WRONLY);
        if (fd < 0) continue;
        if (write(fd, junk.data(), junk.size()) < 0) std::perror("write");
        close(fd);
        if (delay_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }
    std::printf("finished: overwrote all %d files\n", n);
    return 0;
}

static int count(const std::string &dir, int n) {
    int damaged = 0;
    size_t len = std::strlen(MARK);
    char buf[64];
    for (int i = 0; i < n; ++i) {
        int fd = open(path_for(dir, i).c_str(), O_RDONLY);
        if (fd < 0) continue;
        ssize_t r = read(fd, buf, len);
        close(fd);
        if (r != (ssize_t)len || std::memcmp(buf, MARK, len) != 0) ++damaged;
    }
    std::printf("%d\n", damaged);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s setup|run|count <dir> <num_files> [delay_ms]\n", argv[0]);
        return 1;
    }
    std::string cmd = argv[1], dir = argv[2];
    int n = std::atoi(argv[3]);
    if (!safe_dir(dir)) {
        std::fprintf(stderr, "refusing: directory must start with /tmp/ransom_test\n");
        return 1;
    }
    if (cmd == "setup") return setup(dir, n);
    if (cmd == "run")   return run(dir, n, argc > 4 ? std::atoi(argv[4]) : 0);
    if (cmd == "count") return count(dir, n);
    std::fprintf(stderr, "unknown command\n");
    return 1;
}

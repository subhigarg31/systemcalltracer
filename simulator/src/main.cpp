#include "generator.hpp"
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>
#include <csignal>
#include <algorithm>

static std::atomic<bool> g_running{true};
static std::atomic<int> g_interval_ms{200};
static std::atomic<int> g_threat_interval{25};
static std::atomic<SimulationMode> g_current_mode{SimulationMode::AUTOMATIC};

void signal_handler(int signum) {
    (void)signum;
    g_running = false;
}

SimulationMode parse_mode(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "suspicious") return SimulationMode::SUSPICIOUS;
    if (lower == "mixed") return SimulationMode::MIXED;
    if (lower == "normal") return SimulationMode::NORMAL;
    return SimulationMode::AUTOMATIC;
}

void stdin_reader() {
    std::string line;
    while (g_running && std::getline(std::cin, line)) {
        if (line.empty()) continue;
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line == "QUIT" || line == "STOP" || line == "EXIT") {
            g_running = false;
            break;
        } else if (line.rfind("MODE ", 0) == 0) {
            std::string mode_str = line.substr(5);
            g_current_mode = parse_mode(mode_str);
        } else if (line.rfind("INTERVAL ", 0) == 0) {
            try {
                int val = std::stoi(line.substr(9));
                if (val >= 10 && val <= 5000) {
                    g_interval_ms = val;
                }
            } catch (...) {}
        } else if (line.rfind("THREAT_INTERVAL ", 0) == 0) {
            try {
                int val = std::stoi(line.substr(16));
                if (val >= 5 && val <= 500) {
                    g_threat_interval = val;
                }
            } catch (...) {}
        }
    }
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    SimulationMode initial_mode = SimulationMode::AUTOMATIC;
    int interval = 200;
    int threat_interval = 25;
    int max_count = 0; // 0 = infinite

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--mode" && i + 1 < argc) {
            initial_mode = parse_mode(argv[++i]);
        } else if (arg == "--interval" && i + 1 < argc) {
            try {
                interval = std::stoi(argv[++i]);
            } catch (...) {}
        } else if (arg == "--threat-interval" && i + 1 < argc) {
            try {
                threat_interval = std::stoi(argv[++i]);
            } catch (...) {}
        } else if (arg == "--count" && i + 1 < argc) {
            try {
                max_count = std::stoi(argv[++i]);
            } catch (...) {}
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: syscall_tracer_sim [OPTIONS]\n"
                      << "Options:\n"
                      << "  --mode <auto|normal|suspicious|mixed>  Set initial simulation mode (default: auto)\n"
                      << "  --interval <ms>                        Set event interval in milliseconds (default: 200)\n"
                      << "  --threat-interval <n>                  Events between injected threat episodes in auto mode (default: 25)\n"
                      << "  --count <n>                            Emit n events and exit (default: 0 for continuous)\n"
                      << "  --help                                 Show this help message\n";
            return 0;
        }
    }

    g_current_mode = initial_mode;
    g_interval_ms = (interval > 0) ? interval : 200;
    g_threat_interval = (threat_interval >= 5) ? threat_interval : 25;

    EventGenerator generator(g_current_mode);
    generator.set_threat_interval(g_threat_interval.load());

    // Start background thread for interactive commands via stdin
    std::thread reader_th(stdin_reader);

    int count = 0;
    while (g_running) {
        // Sync mode if changed dynamically
        SimulationMode current = g_current_mode.load();
        if (generator.get_mode() != current) {
            generator.set_mode(current);
        }
        if (generator.get_threat_interval() != g_threat_interval.load()) {
            generator.set_threat_interval(g_threat_interval.load());
        }

        SyscallEvent ev = generator.next_event();
        std::cout << ev.to_json() << "\n";
        std::cout.flush();

        count++;
        if (max_count > 0 && count >= max_count) {
            g_running = false;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(g_interval_ms.load()));
    }

    // Detach stdin reader thread to allow immediate exit
    reader_th.detach();

    return 0;
}

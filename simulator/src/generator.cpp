#include "generator.hpp"
#include "utils.hpp"
#include <iostream>
#include <vector>
#include <string>

EventGenerator::EventGenerator(SimulationMode mode)
    : m_mode(mode),
      m_event_counter(0),
      m_threat_interval(25),
      m_auto_cycle_step(0),
      m_auto_threat_pattern(0),
      m_active_threat_remaining(0),
      m_active_threat_type(0),
      m_suspicious_step(0),
      m_ransom_file_idx(0),
      m_spawn_step(0) {}

void EventGenerator::set_mode(SimulationMode mode) {
    m_mode = mode;
}

SimulationMode EventGenerator::get_mode() const {
    return m_mode;
}

std::string EventGenerator::get_mode_string() const {
    switch (m_mode) {
        case SimulationMode::AUTOMATIC: return "automatic";
        case SimulationMode::NORMAL: return "normal";
        case SimulationMode::SUSPICIOUS: return "suspicious";
        case SimulationMode::MIXED: return "mixed";
        default: return "automatic";
    }
}

void EventGenerator::set_threat_interval(int interval) {
    if (interval >= 5 && interval <= 500) {
        m_threat_interval = interval;
    }
}

int EventGenerator::get_threat_interval() const {
    return m_threat_interval;
}

SyscallEvent EventGenerator::next_event() {
    m_event_counter++;
    if (m_mode == SimulationMode::AUTOMATIC) {
        return generate_automatic_event();
    } else if (m_mode == SimulationMode::NORMAL) {
        return generate_normal_event();
    } else if (m_mode == SimulationMode::SUSPICIOUS) {
        return generate_suspicious_event();
    } else { // MIXED
        // ~75% normal, 25% suspicious
        if (utils::random_double(0.0, 1.0) < 0.25) {
            return generate_suspicious_event();
        } else {
            return generate_normal_event();
        }
    }
}

SyscallEvent EventGenerator::generate_normal_event() {
    static const std::vector<std::pair<std::string, int>> normal_procs = {
        {"nginx", 1024},
        {"node_app", 1842},
        {"bash", 2055},
        {"postgres", 891},
        {"logrotate", 3110},
        {"systemd-journald", 412},
        {"python3_service", 2980},
        {"curl", 4015}
    };

    auto proc = normal_procs[utils::random_int(0, normal_procs.size() - 1)];
    int type = utils::random_int(0, 99);

    SyscallEvent ev;
    ev.timestamp = utils::get_iso8601_timestamp();
    ev.pid = proc.second;
    ev.process_name = proc.first;
    ev.scenario = get_mode_string();

    if (type < 45) { // Normal file read / close (45%)
        static const std::vector<std::string> normal_read_paths = {
            "/var/log/nginx/access.log",
            "/home/user/app/config.json",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/usr/lib/libSystem.B.dylib",
            "/home/user/assets/styles.css"
        };
        std::string path = normal_read_paths[utils::random_int(0, normal_read_paths.size() - 1)];
        int op = utils::random_int(0, 2);
        ev.category = "file";
        if (op == 0) {
            ev.syscall = "openat";
            ev.args = {{"dirfd", "AT_FDCWD"}, {"path", path}, {"flags", "O_RDONLY"}};
            ev.ret = utils::random_int(3, 9);
        } else if (op == 1) {
            ev.syscall = "read";
            ev.args = {{"fd", std::to_string(utils::random_int(3, 9))}, {"bytes", std::to_string(utils::random_int(64, 4096))}};
            ev.ret = utils::random_int(64, 4096);
        } else {
            ev.syscall = "close";
            ev.args = {{"fd", std::to_string(utils::random_int(3, 9))}};
            ev.ret = 0;
        }
    } else if (type < 65) { // Normal file write (20%)
        static const std::vector<std::string> normal_write_paths = {
            "/var/log/app.log",
            "/tmp/cache_store.tmp",
            "/var/log/nginx/error.log"
        };
        ev.category = "file";
        ev.syscall = "write";
        ev.args = {{"fd", "3"}, {"path", normal_write_paths[utils::random_int(0, normal_write_paths.size() - 1)]}, {"bytes", std::to_string(utils::random_int(128, 1024))}};
        ev.ret = utils::random_int(128, 1024);
    } else if (type < 85) { // Normal network connect (20%)
        static const std::vector<std::string> normal_ips = {
            "142.250.190.46", // Google
            "1.1.1.1",        // Cloudflare DNS
            "8.8.8.8",        // Google DNS
            "127.0.0.1",      // Localhost
            "10.0.0.12"       // Local intranet
        };
        static const std::vector<std::string> normal_ports = {
            "443", "80", "53", "3000", "5432"
        };
        ev.category = "network";
        ev.syscall = "connect";
        std::string ip = normal_ips[utils::random_int(0, normal_ips.size() - 1)];
        std::string port = normal_ports[utils::random_int(0, normal_ports.size() - 1)];
        ev.args = {{"addr", ip}, {"port", port}, {"protocol", "TCP"}};
        ev.ret = 0;
    } else if (type < 99) { // Normal network data read/write (14%)
        ev.category = "network";
        ev.syscall = (utils::random_int(0, 1) == 0) ? "read" : "write";
        ev.args = {{"sockfd", std::to_string(utils::random_int(10, 15))}, {"bytes", std::to_string(utils::random_int(128, 2048))}};
        ev.ret = utils::random_int(128, 2048);
    } else { // Normal occasional process execution (1%)
        ev.category = "process";
        ev.pid = proc.second;
        ev.process_name = proc.first;
        ev.syscall = "execve";
        ev.args = {{"filename", "/usr/bin/git"}, {"argv", "git status"}};
        ev.ret = 0;
    }

    return ev;
}

SyscallEvent EventGenerator::generate_suspicious_event() {
    // Cycle through 4 suspicious patterns:
    // 0: Sensitive file access (/etc/passwd, /etc/shadow)
    // 1: Ransomware-like rapid file write
    // 2: Suspicious outbound connection (C2 ports 4444, 1337)
    // 3: Abnormal process creation (rapid fork burst)
    int pattern = m_suspicious_step % 4;
    m_suspicious_step++;

    switch (pattern) {
        case 0: return generate_sensitive_file_event();
        case 1: return generate_ransomware_write_event();
        case 2: return generate_c2_connection_event();
        case 3: return generate_process_flood_event();
        default: return generate_sensitive_file_event();
    }
}

SyscallEvent EventGenerator::generate_sensitive_file_event() {
    SyscallEvent ev;
    ev.timestamp = utils::get_iso8601_timestamp();
    ev.pid = 6601 + utils::random_int(0, 3);
    ev.process_name = (utils::random_int(0, 1) == 0) ? "recon_agent" : "bash";
    ev.category = "file";
    ev.scenario = get_mode_string();

    static const std::vector<std::string> sensitive_targets = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/shadow",
        "/etc/passwd"
    };
    std::string path = sensitive_targets[utils::random_int(0, sensitive_targets.size() - 1)];

    int sub = utils::random_int(0, 2);
    if (sub == 0) {
        ev.syscall = "openat";
        ev.args = {{"dirfd", "AT_FDCWD"}, {"path", path}, {"flags", "O_RDONLY"}};
        ev.ret = 3;
    } else if (sub == 1) {
        ev.syscall = "read";
        ev.args = {{"fd", "3"}, {"target", path}, {"bytes", "4096"}};
        ev.ret = 4096;
    } else {
        ev.syscall = "close";
        ev.args = {{"fd", "3"}, {"target", path}};
        ev.ret = 0;
    }
    return ev;
}

SyscallEvent EventGenerator::generate_ransomware_write_event() {
    SyscallEvent ev;
    ev.timestamp = utils::get_iso8601_timestamp();
    ev.pid = 7710;
    ev.process_name = "ransom_crypt";
    ev.category = "file";
    ev.scenario = get_mode_string();

    static const std::vector<std::string> encrypted_files = {
        "/home/user/documents/financial_records.xlsx.locked",
        "/home/user/passwords_vault.kdbx.locked",
        "/home/user/customer_data.sql.locked",
        "/home/user/thesis_final.pdf.locked",
        "/home/user/personal_tax_2025.pdf.locked",
        "/home/user/corporate_backup.zip.locked",
        "/home/user/credentials.env.locked",
        "/home/user/ssh_keys_export.tar.locked"
    };

    std::string target = encrypted_files[m_ransom_file_idx % encrypted_files.size()];
    m_ransom_file_idx++;

    int sub = utils::random_int(0, 1);
    if (sub == 0) {
        ev.syscall = "openat";
        ev.args = {{"dirfd", "AT_FDCWD"}, {"path", target}, {"flags", "O_WRONLY|O_CREAT|O_TRUNC"}};
        ev.ret = 4;
    } else {
        ev.syscall = "write";
        ev.args = {{"fd", "4"}, {"path", target}, {"bytes", "65536"}, {"entropy", "high"}};
        ev.ret = 65536;
    }
    return ev;
}

SyscallEvent EventGenerator::generate_c2_connection_event() {
    SyscallEvent ev;
    ev.timestamp = utils::get_iso8601_timestamp();
    ev.pid = 8820;
    ev.process_name = "c2_beacon";
    ev.category = "network";
    ev.scenario = get_mode_string();

    static const std::vector<std::pair<std::string, std::string>> c2_destinations = {
        {"198.51.100.23", "4444"},  // Metasploit default
        {"203.0.113.88", "1337"},   // Elite hacker port
        {"185.220.101.5", "6667"},  // IRC botnet C2
        {"198.51.100.99", "31337"}, // Backdoor port
        {"45.33.32.156", "4444"}
    };

    auto dest = c2_destinations[utils::random_int(0, c2_destinations.size() - 1)];
    ev.syscall = "connect";
    ev.args = {{"addr", dest.first}, {"port", dest.second}, {"protocol", "TCP"}};
    ev.ret = 0;
    return ev;
}

SyscallEvent EventGenerator::generate_process_flood_event() {
    SyscallEvent ev;
    ev.timestamp = utils::get_iso8601_timestamp();
    ev.pid = 9930;
    ev.process_name = "fork_spawner";
    ev.category = "process";
    ev.scenario = get_mode_string();

    int step = m_spawn_step % 3;
    m_spawn_step++;

    if (step == 0) {
        ev.syscall = "fork";
        ev.args = {{"parent_pid", "9930"}};
        ev.ret = 9930 + utils::random_int(1, 100);
    } else if (step == 1) {
        ev.syscall = "clone";
        ev.args = {{"flags", "CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID"}};
        ev.ret = 9930 + utils::random_int(101, 200);
    } else {
        ev.syscall = "execve";
        ev.args = {{"filename", "/tmp/.hidden_worker"}, {"argv", "./worker --flood"}};
        ev.ret = 0;
    }
    return ev;
}

SyscallEvent EventGenerator::generate_automatic_event() {
    // If executing a multi-event threat pattern
    if (m_active_threat_remaining > 0) {
        m_active_threat_remaining--;
        switch (m_active_threat_type) {
            case 0: return generate_sensitive_file_event();
            case 1: return generate_ransomware_write_event();
            case 2: return generate_c2_connection_event();
            case 3: return generate_process_flood_event();
            default: return generate_sensitive_file_event();
        }
    }

    m_auto_cycle_step++;
    // When threat interval is reached, schedule the next rotating pattern
    if (m_auto_cycle_step >= m_threat_interval) {
        m_auto_cycle_step = 0;
        m_active_threat_type = m_auto_threat_pattern % 4;
        m_auto_threat_pattern++;

        switch (m_active_threat_type) {
            case 0: // Sensitive file access
                m_active_threat_remaining = 1;
                break;
            case 1: // Ransomware multi-file write burst (4 events)
                m_active_threat_remaining = 4;
                break;
            case 2: // C2 outbound connection
                m_active_threat_remaining = 1;
                break;
            case 3: // Process creation burst (5 events)
                m_active_threat_remaining = 5;
                break;
            default:
                m_active_threat_remaining = 1;
                break;
        }

        m_active_threat_remaining--;
        switch (m_active_threat_type) {
            case 0: return generate_sensitive_file_event();
            case 1: return generate_ransomware_write_event();
            case 2: return generate_c2_connection_event();
            case 3: return generate_process_flood_event();
            default: return generate_sensitive_file_event();
        }
    }

    // Baseline routine telemetry
    return generate_normal_event();
}

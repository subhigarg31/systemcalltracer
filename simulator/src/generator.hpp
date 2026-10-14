#ifndef GENERATOR_HPP
#define GENERATOR_HPP

#include "event.hpp"
#include <string>
#include <vector>

enum class SimulationMode {
    AUTOMATIC,
    NORMAL,
    SUSPICIOUS,
    MIXED
};

class EventGenerator {
public:
    explicit EventGenerator(SimulationMode mode = SimulationMode::AUTOMATIC);
    
    void set_mode(SimulationMode mode);
    SimulationMode get_mode() const;
    std::string get_mode_string() const;
    
    void set_threat_interval(int interval);
    int get_threat_interval() const;

    // Generates the next event
    SyscallEvent next_event();

private:
    SimulationMode m_mode;
    int m_event_counter;
    int m_threat_interval;
    int m_auto_cycle_step;
    int m_auto_threat_pattern;
    int m_active_threat_remaining;
    int m_active_threat_type;

    int m_suspicious_step;
    int m_ransom_file_idx;
    int m_spawn_step;

    SyscallEvent generate_normal_event();
    SyscallEvent generate_suspicious_event();
    SyscallEvent generate_automatic_event();
    
    // Specific suspicious event generators
    SyscallEvent generate_sensitive_file_event();
    SyscallEvent generate_ransomware_write_event();
    SyscallEvent generate_c2_connection_event();
    SyscallEvent generate_process_flood_event();
};

#endif // GENERATOR_HPP

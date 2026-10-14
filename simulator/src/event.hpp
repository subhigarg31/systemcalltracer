#ifndef EVENT_HPP
#define EVENT_HPP

#include <string>
#include <sstream>
#include <map>
#include "utils.hpp"

struct SyscallEvent {
    std::string timestamp;
    int pid;
    std::string process_name;
    std::string syscall;
    std::map<std::string, std::string> args;
    int ret;
    std::string category;
    std::string scenario;

    std::string to_json() const {
        std::ostringstream ss;
        ss << "{"
           << "\"timestamp\":\"" << utils::escape_json(timestamp) << "\","
           << "\"pid\":" << pid << ","
           << "\"process_name\":\"" << utils::escape_json(process_name) << "\","
           << "\"syscall\":\"" << utils::escape_json(syscall) << "\","
           << "\"category\":\"" << utils::escape_json(category) << "\","
           << "\"scenario\":\"" << utils::escape_json(scenario) << "\","
           << "\"ret\":" << ret << ","
           << "\"args\":{";

        bool first = true;
        for (const auto& pair : args) {
            if (!first) ss << ",";
            first = false;
            ss << "\"" << utils::escape_json(pair.first) << "\":\""
               << utils::escape_json(pair.second) << "\"";
        }

        ss << "}}";
        return ss.str();
    }
};

#endif // EVENT_HPP

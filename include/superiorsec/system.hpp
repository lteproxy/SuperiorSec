#pragma once

#include <cstdint>
#include <string>

namespace superiorsec {

struct SystemInfo {
    std::string hostname;
    std::string os;
    std::string kernel;
    std::string architecture;
    std::uint64_t uptime_seconds{};
    std::uint64_t memory_total_kib{};
    std::uint64_t memory_available_kib{};
    std::uint64_t root_total_bytes{};
    std::uint64_t root_available_bytes{};
};

SystemInfo inspect_system();
std::string system_json(const SystemInfo& info);
std::string system_text(const SystemInfo& info);

} // namespace superiorsec

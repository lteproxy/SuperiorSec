#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace superiorsec {

struct ProcessInfo {
    int pid{};
    int parent_pid{};
    char state{'?'};
    std::uint32_t uid{};
    std::string command;
};

std::vector<ProcessInfo> inspect_processes();
bool parse_process_stat(std::string_view line, int& parent_pid, char& state);
std::string processes_json(const std::vector<ProcessInfo>& processes);
std::string processes_text(const std::vector<ProcessInfo>& processes, std::size_t limit);

} // namespace superiorsec

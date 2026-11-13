#include "superiorsec/processes.hpp"

#include "superiorsec/common.hpp"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>

namespace superiorsec {
namespace {

bool numeric_pid(const std::string& name, int& pid) {
    const auto [end, error] = std::from_chars(name.data(), name.data() + name.size(), pid);
    return error == std::errc{} && end == name.data() + name.size() && pid > 0;
}

std::uint32_t process_uid(int pid) {
    std::istringstream status(read_text_file("/proc/" + std::to_string(pid) + "/status"));
    std::string key;
    while (status >> key) {
        if (key == "Uid:") {
            std::uint32_t uid{};
            status >> uid;
            return uid;
        }
        std::string rest;
        std::getline(status, rest);
    }
    return 0;
}

std::string process_command(int pid, std::string_view fallback) {
    std::ifstream input("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    std::string command((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    for (auto& ch : command) if (ch == '\0') ch = ' ';
    command = trim(std::move(command));
    return command.empty() ? std::string(fallback) : command;
}

} // namespace

bool parse_process_stat(std::string_view line, int& parent_pid, char& state) {
    const auto open = line.find('(');
    const auto close = line.rfind(')');
    if (open == std::string_view::npos || close == std::string_view::npos || close <= open || close + 2 >= line.size())
        return false;
    std::istringstream fields(std::string(line.substr(close + 1)));
    return static_cast<bool>(fields >> state >> parent_pid) && parent_pid >= 0;
}

std::vector<ProcessInfo> inspect_processes() {
    std::vector<ProcessInfo> processes;
    std::error_code error;
    for (std::filesystem::directory_iterator it("/proc", std::filesystem::directory_options::skip_permission_denied, error), end;
         it != end; it.increment(error)) {
        if (error) {
            error.clear();
            continue;
        }
        const auto name = it->path().filename().string();
        int pid{};
        if (!numeric_pid(name, pid)) continue;
        const auto stat = read_text_file("/proc/" + name + "/stat");
        int parent_pid{};
        char state{};
        if (stat.empty() || !parse_process_stat(stat, parent_pid, state)) continue;
        const auto start = stat.find('(');
        const auto finish = stat.rfind(')');
        const std::string_view comm = start != std::string::npos && finish > start
            ? std::string_view(stat).substr(start + 1, finish - start - 1) : std::string_view{};
        processes.push_back({pid, parent_pid, state, process_uid(pid), process_command(pid, comm)});
    }
    std::sort(processes.begin(), processes.end(), [](const auto& left, const auto& right) { return left.pid < right.pid; });
    return processes;
}

std::string processes_json(const std::vector<ProcessInfo>& processes) {
    std::ostringstream output;
    output << '[';
    for (std::size_t i = 0; i < processes.size(); ++i) {
        if (i != 0) output << ',';
        const auto& process = processes[i];
        output << "{\"pid\":" << process.pid << ",\"parent_pid\":" << process.parent_pid
               << ",\"state\":\"" << process.state << "\",\"uid\":" << process.uid
               << ",\"command\":\"" << json_escape(process.command) << "\"}";
    }
    output << ']';
    return output.str();
}

std::string processes_text(const std::vector<ProcessInfo>& processes, std::size_t limit) {
    std::ostringstream output;
    output << "PID      PPID     UID      STATE  COMMAND\n";
    const auto count = std::min(limit, processes.size());
    for (std::size_t i = 0; i < count; ++i) {
        const auto& process = processes[i];
        output << process.pid << "\t" << process.parent_pid << "\t" << process.uid << "\t"
               << process.state << "\t" << process.command << '\n';
    }
    output << "Showing " << count << " of " << processes.size() << " processes\n";
    return output.str();
}

} // namespace superiorsec

#include "superiorsec/audit.hpp"

#include "superiorsec/common.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace superiorsec {
namespace {

struct CommandResult {
    int status{-1};
    std::string output;
};

CommandResult capture(const std::filesystem::path& executable, const char* argument, const char* second = nullptr) {
    int pipes[2]{};
    if (::pipe2(pipes, O_CLOEXEC) != 0) return {};
    const pid_t child = ::fork();
    if (child < 0) {
        ::close(pipes[0]);
        ::close(pipes[1]);
        return {};
    }
    if (child == 0) {
        ::close(pipes[0]);
        if (::dup2(pipes[1], STDOUT_FILENO) < 0) _exit(126);
        if (::dup2(pipes[1], STDERR_FILENO) < 0) _exit(126);
        ::close(pipes[1]);
        if (second != nullptr)
            ::execl(executable.c_str(), executable.c_str(), argument, second, static_cast<char*>(nullptr));
        else
            ::execl(executable.c_str(), executable.c_str(), argument, static_cast<char*>(nullptr));
        _exit(127);
    }
    ::close(pipes[1]);
    CommandResult result;
    std::array<char, 4096> buffer{};
    for (;;) {
        const auto count = ::read(pipes[0], buffer.data(), buffer.size());
        if (count <= 0) break;
        const auto amount = static_cast<std::size_t>(count);
        if (result.output.size() < 1024 * 1024) {
            const auto kept = std::min(amount, 1024 * 1024 - result.output.size());
            result.output.append(buffer.data(), kept);
        }
    }
    ::close(pipes[0]);
    int wait_status{};
    if (::waitpid(child, &wait_status, 0) == child && WIFEXITED(wait_status)) result.status = WEXITSTATUS(wait_status);
    return result;
}

Check sysctl_check(const std::string& name, const std::string& path, const std::string& expected,
                   bool (*passes)(long)) {
    const auto raw = trim(read_text_file(path));
    if (raw.empty()) return {name, Severity::info, "unknown", "setting is unavailable or unreadable"};
    try {
        const auto value = std::stol(raw);
        const bool good = passes(value);
        return {name, good ? Severity::info : Severity::warning, good ? "pass" : "review",
                "current value " + raw + "; recommended " + expected};
    } catch (...) {
        return {name, Severity::info, "unknown", "could not parse value: " + raw};
    }
}

bool at_least_one(long value) { return value >= 1; }
bool at_least_two(long value) { return value >= 2; }
bool exactly_two(long value) { return value == 2; }
bool exactly_zero(long value) { return value == 0; }

Check ssh_permissions_check() {
    constexpr const char* path = "/etc/ssh/sshd_config";
    struct stat metadata {};
    if (::lstat(path, &metadata) != 0) return {"SSH server config", Severity::info, "skipped", "no local sshd_config found"};
    if (S_ISLNK(metadata.st_mode)) return {"SSH server config", Severity::warning, "review", "configuration path is a symlink"};
    const bool writable = (metadata.st_mode & (S_IWGRP | S_IWOTH)) != 0;
    const bool root_owned = metadata.st_uid == 0;
    const bool good = root_owned && !writable;
    std::string detail = root_owned ? "owned by root" : "not owned by root";
    detail += writable ? "; group or other users can write it" : "; not writable by group or other users";
    return {"SSH server config", good ? Severity::info : Severity::warning, good ? "pass" : "review", std::move(detail)};
}

Check firewall_check() {
    const std::array<std::filesystem::path, 2> nft_paths{"/usr/sbin/nft", "/usr/bin/nft"};
    for (const auto& path : nft_paths) {
        if (!std::filesystem::exists(path)) continue;
        const auto result = capture(path, "list", "ruleset");
        if (result.status != 0) continue;
        bool configured{};
        std::istringstream lines(result.output);
        std::string line;
        while (std::getline(lines, line)) {
            line = trim(std::move(line));
            if (line.find("policy drop") != std::string::npos || line.find("policy reject") != std::string::npos) {
                configured = true;
                break;
            }
            if (line.empty() || line == "}" || line.starts_with("table ") || line.starts_with("chain ") ||
                line.starts_with("type ") || line.starts_with("policy ") || line.starts_with("#")) continue;
            configured = true;
            break;
        }
        return {"nftables ruleset", configured ? Severity::info : Severity::warning,
                configured ? "found" : "review", configured ? "rule lines or a restrictive chain policy were found" : "no rules or restrictive chain policy were found"};
    }

    const std::array<std::filesystem::path, 2> iptables_paths{"/usr/sbin/iptables", "/usr/bin/iptables"};
    for (const auto& path : iptables_paths) {
        if (!std::filesystem::exists(path)) continue;
        const auto result = capture(path, "-S");
        if (result.status != 0) continue;
        std::istringstream lines(result.output);
        std::string line;
        bool configured{};
        while (std::getline(lines, line)) {
            line = trim(std::move(line));
            if (line.starts_with("-A ") || (line.starts_with("-P ") &&
                (line.ends_with(" DROP") || line.ends_with(" REJECT")))) {
                configured = true;
                break;
            }
        }
        return {"iptables ruleset", configured ? Severity::info : Severity::warning,
                configured ? "found" : "review", configured ? "rules or a restrictive default policy were found" : "no rules or restrictive default policy were found"};
    }
    return {"Firewall ruleset", Severity::info, "unknown", "nftables or iptables could not be inspected"};
}

} // namespace

std::vector<Check> run_audit() {
    std::vector<Check> checks;
    checks.push_back(sysctl_check("Address space randomization", "/proc/sys/kernel/randomize_va_space", "2", exactly_two));
    checks.push_back(sysctl_check("Kernel pointer exposure", "/proc/sys/kernel/kptr_restrict", "2", at_least_two));
    checks.push_back(sysctl_check("Kernel log access", "/proc/sys/kernel/dmesg_restrict", "1 or higher", at_least_one));
    checks.push_back(sysctl_check("Ptrace scope", "/proc/sys/kernel/yama/ptrace_scope", "1 or higher", at_least_one));
    checks.push_back(sysctl_check("Setuid core dumps", "/proc/sys/fs/suid_dumpable", "0", exactly_zero));
    checks.push_back(ssh_permissions_check());
    checks.push_back(firewall_check());
    return checks;
}

std::string audit_json(const std::vector<Check>& checks) {
    return checks_json(checks);
}

std::string audit_text(const std::vector<Check>& checks) {
    std::ostringstream output;
    for (const auto& check : checks)
        output << '[' << severity_name(check.severity) << "] " << check.name << ": " << check.status << " — " << check.detail << '\n';
    output << "Checks are informational; validate recommendations against your system and threat model.\n";
    return output.str();
}

} // namespace superiorsec

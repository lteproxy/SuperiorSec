#include "superiorsec/system.hpp"

#include "superiorsec/common.hpp"

#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>

namespace superiorsec {
namespace {

std::uint64_t numeric_value(const std::string& value) {
    std::uint64_t result{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), result);
    return error == std::errc{} && end == value.data() + value.size() ? result : 0;
}

std::string unquote(std::string value) {
    if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
        return value.substr(1, value.size() - 2);
    return value;
}

}

SystemInfo inspect_system() {
    SystemInfo result;
    std::array<char, 256> hostname{};
    if (::gethostname(hostname.data(), hostname.size() - 1) == 0) result.hostname = hostname.data();

    struct utsname uts {};
    if (::uname(&uts) == 0) {
        result.kernel = uts.release;
        result.architecture = uts.machine;
    }

    std::istringstream os_release(read_text_file("/etc/os-release"));
    std::string line;
    while (std::getline(os_release, line)) {
        if (line.starts_with("PRETTY_NAME=")) {
            result.os = unquote(line.substr(12));
            break;
        }
        if (line.starts_with("NAME=") && result.os.empty()) result.os = unquote(line.substr(5));
    }

    std::istringstream meminfo(read_text_file("/proc/meminfo"));
    std::string memory_line;
    while (std::getline(meminfo, memory_line)) {
        std::istringstream fields(memory_line);
        std::string key;
        std::string value;
        fields >> key >> value;
        if (key == "MemTotal:") result.memory_total_kib = numeric_value(value);
        else if (key == "MemAvailable:") result.memory_available_kib = numeric_value(value);
    }

    std::istringstream uptime(read_text_file("/proc/uptime"));
    double seconds{};
    if (uptime >> seconds && seconds >= 0.0 && seconds <= static_cast<double>(std::numeric_limits<std::uint64_t>::max()))
        result.uptime_seconds = static_cast<std::uint64_t>(seconds);

    struct statvfs disk {};
    if (::statvfs("/", &disk) == 0) {
        const auto unit = static_cast<std::uint64_t>(disk.f_frsize);
        result.root_total_bytes = unit * static_cast<std::uint64_t>(disk.f_blocks);
        result.root_available_bytes = unit * static_cast<std::uint64_t>(disk.f_bavail);
    }
    return result;
}

std::string system_json(const SystemInfo& info) {
    std::ostringstream output;
    output << "{\"hostname\":\"" << json_escape(info.hostname)
           << "\",\"os\":\"" << json_escape(info.os)
           << "\",\"kernel\":\"" << json_escape(info.kernel)
           << "\",\"architecture\":\"" << json_escape(info.architecture)
           << "\",\"uptime_seconds\":" << info.uptime_seconds
           << ",\"memory_total_kib\":" << info.memory_total_kib
           << ",\"memory_available_kib\":" << info.memory_available_kib
           << ",\"root_total_bytes\":" << info.root_total_bytes
           << ",\"root_available_bytes\":" << info.root_available_bytes << '}';
    return output.str();
}

std::string system_text(const SystemInfo& info) {
    std::ostringstream output;
    output << "host is " << (info.hostname.empty() ? "unknown" : info.hostname)
           << ".\nos is " << (info.os.empty() ? "unknown" : info.os)
           << ".\nkernel is " << (info.kernel.empty() ? "unknown" : info.kernel)
           << ".\narchitecture is " << (info.architecture.empty() ? "unknown" : info.architecture)
           << ".\nuptime is " << info.uptime_seconds << " seconds"
           << ".\nmemory has " << info.memory_available_kib << " KiB available of " << info.memory_total_kib << " KiB"
           << ".\nroot filesystem has " << info.root_available_bytes << " bytes available of " << info.root_total_bytes << " bytes.\n";
    return output.str();
}

}

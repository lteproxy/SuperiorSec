#include "superiorsec/report.hpp"

#include "superiorsec/audit.hpp"
#include "superiorsec/common.hpp"
#include "superiorsec/network.hpp"
#include "superiorsec/processes.hpp"
#include "superiorsec/system.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace superiorsec {
namespace {

std::string timestamp_utc() {
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm value{};
    if (::gmtime_r(&now, &value) == nullptr) return {};
    std::ostringstream output;
    output << std::put_time(&value, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

} // namespace

std::string build_report_json() {
    const auto system = inspect_system();
    const auto processes = inspect_processes();
    const auto sockets = inspect_network();
    const auto checks = run_audit();
    std::ostringstream output;
    output << "{\"schema_version\":1,\"generated_at\":\"" << timestamp_utc()
           << "\",\"system\":" << system_json(system)
           << ",\"process_count\":" << processes.size()
           << ",\"network_sockets\":" << network_json(sockets)
           << ",\"audit_checks\":" << audit_json(checks) << '}';
    return output.str();
}

std::string build_report_text() {
    const auto system = inspect_system();
    const auto processes = inspect_processes();
    const auto sockets = inspect_network();
    const auto checks = run_audit();
    std::ostringstream output;
    output << "SuperiorSec system report\nGenerated: " << timestamp_utc() << "\n\n"
           << system_text(system) << "\nProcesses: " << processes.size() << "\n\n"
           << network_text(sockets) << '\n' << audit_text(checks);
    return output.str();
}

} // namespace superiorsec

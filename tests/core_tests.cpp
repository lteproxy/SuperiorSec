#include "superiorsec/common.hpp"
#include "superiorsec/integrity.hpp"
#include "superiorsec/network.hpp"
#include "superiorsec/processes.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "test failure. " << message << '\n';
        std::exit(1);
    }
}

}

int main() {
    require(superiorsec::json_escape("a\n\"b") == "a\\n\\\"b", "JSON escaping");

    int parent{};
    char state{};
    require(superiorsec::parse_process_stat("42 (worker ) thread) S 7 0 0", parent, state), "parse process stat with right parenthesis");
    require(parent == 7 && state == 'S', "process stat fields");
    require(!superiorsec::parse_process_stat("broken", parent, state), "reject malformed process stat");

    constexpr std::string_view table =
        " sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"
        " 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1\n";
    const auto sockets = superiorsec::parse_socket_table(table, "tcp", false);
    require(sockets.size() == 1, "parse socket row");
    require(sockets[0].local_address == "127.0.0.1:8080", "decode IPv4 endpoint");
    require(sockets[0].state == "LISTEN" && sockets[0].uid == 1000, "decode socket state and uid");
    constexpr std::string_view ipv6_table =
        "sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"
        "0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 0:0 00:0 0 0 0 2\n";
    const auto ipv6_sockets = superiorsec::parse_socket_table(ipv6_table, "tcp6", true);
    require(ipv6_sockets.size() == 1 && ipv6_sockets[0].local_address == "[::1]:80", "decode IPv6 endpoint");
    const auto udp_sockets = superiorsec::parse_socket_table(
        "sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode\n"
        "0: 00000000:0035 00000000:0000 07 0:0 00:0 0 0 0 3\n", "udp", false);
    require(udp_sockets.size() == 1 && udp_sockets[0].state == "UNCONN", "decode UDP socket state");

    std::string pattern = (std::filesystem::temp_directory_path() / "superiorsec-test-XXXXXX").string();
    std::vector<char> temporary_path(pattern.begin(), pattern.end());
    temporary_path.push_back('\0');
    const auto* created_path = ::mkdtemp(temporary_path.data());
    require(created_path != nullptr, "create unique temporary test directory");
    const std::filesystem::path root(created_path);
    std::filesystem::create_directories(root / "tree");
    const auto target = root / "tree" / "sample file";
    const auto baseline = root / "baseline.sha256";
    { std::ofstream output(target); output << "before"; }
    auto created = superiorsec::create_integrity_baseline(root / "tree", baseline, false);
    require(created.errors.empty() && created.files.size() == 1, "create integrity baseline");
    auto unchanged = superiorsec::check_integrity_baseline(root / "tree", baseline);
    require(unchanged.errors.empty() && unchanged.files.size() == 1 && unchanged.files[0].status == "unchanged", "check unchanged integrity file");
    { std::ofstream output(target); output << "after"; }
    std::ofstream(root / "tree" / "added") << "new";
    const auto changed = superiorsec::check_integrity_baseline(root / "tree", baseline);
    bool saw_changed{}, saw_new{};
    for (const auto& file : changed.files) {
        saw_changed |= file.status == "changed";
        saw_new |= file.status == "new";
    }
    require(saw_changed && saw_new, "detect changed and new files");
    std::filesystem::remove(target);
    const auto missing = superiorsec::check_integrity_baseline(root / "tree", baseline);
    require(missing.files.size() == 2 && missing.files.back().status == "missing", "detect missing file");
    require(!superiorsec::create_integrity_baseline(root / "tree", baseline, false).errors.empty(), "refuse baseline overwrite");
    require(superiorsec::create_integrity_baseline(root / "tree", baseline, true).errors.empty(), "allow explicit baseline replacement");
    std::filesystem::remove_all(root);
    std::cout << "all core checks passed\n";
}

#include "superiorsec/audit.hpp"
#include "superiorsec/integrity.hpp"
#include "superiorsec/network.hpp"
#include "superiorsec/processes.hpp"
#include "superiorsec/report.hpp"
#include "superiorsec/system.hpp"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace {

constexpr std::string_view usage = R"(SuperiorSec 0.1.0
Read-only Linux security and privacy inspection tools.

Usage:
  superiorsec system [--json]
  superiorsec processes [--limit N] [--json]
  superiorsec network [--json]
  superiorsec audit [--json]
  superiorsec integrity init|check [--root DIR] [--baseline FILE] [--force] [--json]
  superiorsec report [--output FILE] [--json]
  superiorsec --help
  superiorsec --version
)";

bool flag(const std::vector<std::string_view>& args, std::string_view name) {
    for (const auto value : args) if (value == name) return true;
    return false;
}

std::optional<std::string_view> option(const std::vector<std::string_view>& args, std::string_view name) {
    for (std::size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == name) return args[i + 1];
    return std::nullopt;
}

int print_integrity(const superiorsec::IntegritySummary& summary, bool json, bool checking) {
    std::cout << (json ? superiorsec::integrity_json(summary) : superiorsec::integrity_text(summary));
    if (!summary.errors.empty()) return 1;
    if (checking) {
        for (const auto& file : summary.files)
            if (file.status == "changed" || file.status == "missing" || file.status == "new") return 1;
    }
    return 0;
}

int run(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << usage;
        return 2;
    }
    const std::string_view command(argv[1]);
    std::vector<std::string_view> args;
    for (int i = 2; i < argc; ++i) args.emplace_back(argv[i]);
    const bool json = flag(args, "--json");

    if (command == "--help" || command == "help") {
        std::cout << usage;
        return 0;
    }
    if (command == "--version" || command == "version") {
        std::cout << "SuperiorSec 0.1.0\n";
        return 0;
    }
    if (command == "system") {
        const auto info = superiorsec::inspect_system();
        std::cout << (json ? superiorsec::system_json(info) : superiorsec::system_text(info));
        if (json) std::cout << '\n';
        return 0;
    }
    if (command == "processes") {
        auto processes = superiorsec::inspect_processes();
        std::size_t limit = 50;
        if (const auto value = option(args, "--limit")) {
            const auto [end, error] = std::from_chars(value->data(), value->data() + value->size(), limit);
            if (error != std::errc{} || end != value->data() + value->size()) {
                std::cerr << "--limit must be a non-negative integer\n";
                return 2;
            }
        }
        if (json) {
            if (processes.size() > limit) processes.resize(limit);
            std::cout << superiorsec::processes_json(processes) << '\n';
        } else {
            std::cout << superiorsec::processes_text(processes, limit);
        }
        return 0;
    }
    if (command == "network") {
        const auto sockets = superiorsec::inspect_network();
        std::cout << (json ? superiorsec::network_json(sockets) : superiorsec::network_text(sockets));
        if (json) std::cout << '\n';
        return 0;
    }
    if (command == "audit") {
        const auto checks = superiorsec::run_audit();
        std::cout << (json ? superiorsec::audit_json(checks) : superiorsec::audit_text(checks));
        if (json) std::cout << '\n';
        return 0;
    }
    if (command == "integrity") {
        if (args.empty() || (args[0] != "init" && args[0] != "check")) {
            std::cerr << "integrity requires the init or check action\n";
            return 2;
        }
        const bool checking = args[0] == "check";
        const auto root = option(args, "--root").value_or(".");
        const auto baseline = option(args, "--baseline");
        const auto path = baseline ? std::filesystem::path(*baseline) : superiorsec::default_baseline_path();
        const auto summary = checking
            ? superiorsec::check_integrity_baseline(std::filesystem::path(root), path)
            : superiorsec::create_integrity_baseline(std::filesystem::path(root), path, flag(args, "--force"));
        return print_integrity(summary, json, checking);
    }
    if (command == "report") {
        const auto content = json ? superiorsec::build_report_json() : superiorsec::build_report_text();
        if (const auto destination = option(args, "--output")) {
            std::ofstream output(std::string(*destination), std::ios::binary | std::ios::trunc);
            if (!output || !(output << content << (json ? "\n" : ""))) {
                std::cerr << "could not write report to " << *destination << '\n';
                return 1;
            }
        } else {
            std::cout << content;
            if (json) std::cout << '\n';
        }
        return 0;
    }
    std::cerr << "unknown command: " << command << "\n\n" << usage;
    return 2;
}

} // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "SuperiorSec: " << error.what() << '\n';
        return 1;
    }
}

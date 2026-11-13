#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace superiorsec {

struct IntegrityResult {
    std::string path;
    std::string expected;
    std::string actual;
    std::string status;
};

struct IntegritySummary {
    std::filesystem::path root;
    std::filesystem::path baseline;
    std::vector<IntegrityResult> files;
    std::vector<std::string> errors;
};

std::filesystem::path default_baseline_path();
IntegritySummary create_integrity_baseline(const std::filesystem::path& root,
                                            const std::filesystem::path& baseline,
                                            bool force);
IntegritySummary check_integrity_baseline(const std::filesystem::path& root,
                                           const std::filesystem::path& baseline);
std::string integrity_json(const IntegritySummary& summary);
std::string integrity_text(const IntegritySummary& summary);

} // namespace superiorsec

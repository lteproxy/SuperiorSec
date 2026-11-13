#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace superiorsec {

enum class Severity { info, warning, critical };

struct Check {
    std::string name;
    Severity severity{Severity::info};
    std::string status;
    std::string detail;
};

std::string_view severity_name(Severity severity) noexcept;
std::string json_escape(std::string_view value);
std::string trim(std::string value);
std::string read_text_file(const std::string& path);
std::string checks_json(const std::vector<Check>& checks);

} // namespace superiorsec

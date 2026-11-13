#include "superiorsec/common.hpp"

#include <fstream>
#include <sstream>

namespace superiorsec {

std::string_view severity_name(Severity severity) noexcept {
    switch (severity) {
    case Severity::info: return "info";
    case Severity::warning: return "warning";
    case Severity::critical: return "critical";
    }
    return "info";
}

std::string json_escape(std::string_view value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() + 2);
    for (const unsigned char ch : value) {
        switch (ch) {
        case '"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (ch < 0x20) {
                result += "\\u00";
                result += hex[ch >> 4];
                result += hex[ch & 0x0f];
            } else {
                result += static_cast<char>(ch);
            }
        }
    }
    return result;
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string read_text_file(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::ostringstream contents;
    contents << input.rdbuf();
    return contents.str();
}

std::string checks_json(const std::vector<Check>& checks) {
    std::ostringstream output;
    output << '[';
    for (std::size_t index = 0; index < checks.size(); ++index) {
        if (index != 0) output << ',';
        const auto& check = checks[index];
        output << "{\"name\":\"" << json_escape(check.name)
               << "\",\"severity\":\"" << severity_name(check.severity)
               << "\",\"status\":\"" << json_escape(check.status)
               << "\",\"detail\":\"" << json_escape(check.detail) << "\"}";
    }
    output << ']';
    return output.str();
}

}

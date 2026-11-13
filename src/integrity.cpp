#include "superiorsec/integrity.hpp"

#include "superiorsec/common.hpp"

#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <system_error>

namespace superiorsec {
namespace {

std::string errno_message(std::string_view action, const std::filesystem::path& path) {
    return std::string(action) + " " + path.string() + ": " + std::strerror(errno);
}

std::string hex_encode(std::string_view input) {
    constexpr char digits[] = "0123456789abcdef";
    std::string encoded;
    encoded.reserve(input.size() * 2);
    for (const unsigned char byte : input) {
        encoded.push_back(digits[byte >> 4]);
        encoded.push_back(digits[byte & 0x0f]);
    }
    return encoded;
}

bool hex_decode(std::string_view input, std::string& decoded) {
    if (input.size() % 2 != 0) return false;
    decoded.clear();
    decoded.reserve(input.size() / 2);
    for (std::size_t i = 0; i < input.size(); i += 2) {
        unsigned byte{};
        const auto [end, error] = std::from_chars(input.data() + i, input.data() + i + 2, byte, 16);
        if (error != std::errc{} || end != input.data() + i + 2 || byte > 255) return false;
        decoded.push_back(static_cast<char>(byte));
    }
    return true;
}

bool hash_file(const std::filesystem::path& path, std::string& digest, std::string& error) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        error = errno_message("cannot open", path);
        return false;
    }
    struct stat metadata {};
    if (::fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        error = "not a regular file: " + path.string();
        ::close(fd);
        return false;
    }
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr || EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        error = "could not initialize SHA-256 for " + path.string();
        EVP_MD_CTX_free(context);
        ::close(fd);
        return false;
    }
    std::array<unsigned char, 16384> buffer{};
    bool good = true;
    for (;;) {
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            error = errno_message("cannot read", path);
            good = false;
            break;
        }
        if (EVP_DigestUpdate(context, buffer.data(), static_cast<std::size_t>(count)) != 1) {
            error = "SHA-256 update failed for " + path.string();
            good = false;
            break;
        }
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
    unsigned length{};
    if (good && EVP_DigestFinal_ex(context, bytes.data(), &length) == 1) {
        constexpr char digits[] = "0123456789abcdef";
        digest.reserve(static_cast<std::size_t>(length) * 2);
        for (unsigned i = 0; i < length; ++i) {
            digest.push_back(digits[bytes[i] >> 4]);
            digest.push_back(digits[bytes[i] & 0x0f]);
        }
    } else if (good) {
        error = "SHA-256 finalization failed for " + path.string();
        good = false;
    }
    EVP_MD_CTX_free(context);
    ::close(fd);
    return good;
}

bool write_all(int fd, std::string_view data) {
    while (!data.empty()) {
        const auto count = ::write(fd, data.data(), data.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (count == 0) return false;
        data.remove_prefix(static_cast<std::size_t>(count));
    }
    return true;
}

using Hashes = std::map<std::string, std::string>;

Hashes scan(const std::filesystem::path& root, const std::filesystem::path& baseline,
            IntegritySummary& summary) {
    Hashes hashes;
    std::error_code error;
    std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::none, error), end;
    if (error) {
        summary.errors.push_back("cannot scan " + root.string() + ": " + error.message());
        return hashes;
    }
    for (; it != end; it.increment(error)) {
        if (error) {
            summary.errors.push_back("directory traversal error: " + error.message());
            error.clear();
            continue;
        }
        const auto path = it->path();
        const auto status = it->symlink_status(error);
        if (error) {
            summary.errors.push_back("cannot inspect " + path.string() + ": " + error.message());
            error.clear();
            continue;
        }
        if (!std::filesystem::is_regular_file(status) || std::filesystem::absolute(path).lexically_normal() == baseline)
            continue;
        const auto relative = std::filesystem::relative(path, root, error);
        if (error) {
            summary.errors.push_back("cannot make path relative: " + path.string());
            error.clear();
            continue;
        }
        const auto key = relative.generic_string();
        std::string digest;
        std::string reason;
        if (!hash_file(path, digest, reason)) {
            summary.errors.push_back(std::move(reason));
            continue;
        }
        hashes.emplace(key, std::move(digest));
    }
    return hashes;
}

bool load_manifest(const std::filesystem::path& path, Hashes& hashes, std::vector<std::string>& errors) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        errors.push_back("cannot read baseline " + path.string());
        return false;
    }
    std::string line;
    if (!std::getline(input, line) || line != "# SuperiorSec SHA-256 baseline v1") {
        errors.push_back("baseline has an unsupported or invalid header");
        return false;
    }
    while (std::getline(input, line)) {
        const auto separator = line.find('\t');
        if (separator == std::string::npos || separator != 64) {
            errors.push_back("baseline contains a malformed entry");
            continue;
        }
        const auto digest = std::string_view(line).substr(0, separator);
        if (!std::all_of(digest.begin(), digest.end(), [](char ch) { return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'); })) {
            errors.push_back("baseline contains a malformed SHA-256 digest");
            continue;
        }
        std::string path_bytes;
        if (!hex_decode(std::string_view(line).substr(separator + 1), path_bytes)) {
            errors.push_back("baseline contains an invalid encoded path");
            continue;
        }
        if (!hashes.emplace(std::move(path_bytes), line.substr(0, separator)).second)
            errors.push_back("baseline contains a duplicate path");
    }
    return true;
}

bool write_manifest(const std::filesystem::path& path, const Hashes& hashes, bool force, std::string& error) {
    std::error_code fs_error;
    std::filesystem::create_directories(path.parent_path(), fs_error);
    if (fs_error) {
        error = "cannot create baseline directory: " + fs_error.message();
        return false;
    }
    const auto temp = path.string() + ".tmp." + std::to_string(::getpid());
    const int fd = ::open(temp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        error = errno_message("cannot create temporary baseline", temp);
        return false;
    }
    bool good = write_all(fd, "# SuperiorSec SHA-256 baseline v1\n");
    for (const auto& [relative, digest] : hashes) {
        if (!good) break;
        good = write_all(fd, digest + "\t" + hex_encode(relative) + "\n");
    }
    if (good && ::fsync(fd) != 0) good = false;
    const int close_result = ::close(fd);
    if (close_result != 0) good = false;
    if (!good) {
        error = errno_message("cannot write baseline", temp);
        ::unlink(temp.c_str());
        return false;
    }
    if (force) {
        if (::rename(temp.c_str(), path.c_str()) != 0) {
            error = errno_message("cannot replace baseline", path);
            ::unlink(temp.c_str());
            return false;
        }
    } else {
        if (::link(temp.c_str(), path.c_str()) != 0) {
            error = errno == EEXIST ? "baseline already exists; pass --force to replace it" : errno_message("cannot install baseline", path);
            ::unlink(temp.c_str());
            return false;
        }
        ::unlink(temp.c_str());
    }
    return true;
}

IntegritySummary compare(const std::filesystem::path& root, const std::filesystem::path& baseline,
                         Hashes& current, const Hashes& expected, std::vector<std::string> errors) {
    IntegritySummary summary{root, baseline, {}, std::move(errors)};
    for (const auto& [path, digest] : current) {
        const auto found = expected.find(path);
        if (found == expected.end()) summary.files.push_back({path, {}, digest, "new"});
        else summary.files.push_back({path, found->second, digest, found->second == digest ? "unchanged" : "changed"});
    }
    for (const auto& [path, digest] : expected)
        if (!current.contains(path)) summary.files.push_back({path, digest, {}, "missing"});
    return summary;
}

} // namespace

std::filesystem::path default_baseline_path() {
    const char* state_home = std::getenv("XDG_STATE_HOME");
    const char* home = std::getenv("HOME");
    std::filesystem::path base;
    if (state_home != nullptr && *state_home != '\0' && state_home[0] == '/') base = state_home;
    else if (home != nullptr && *home != '\0') base = std::filesystem::path(home) / ".local/state";
    else base = std::filesystem::temp_directory_path();
    return base / "superiorsec/integrity.sha256";
}

IntegritySummary create_integrity_baseline(const std::filesystem::path& root_path,
                                            const std::filesystem::path& baseline_path,
                                            bool force) {
    std::error_code error;
    const auto root = std::filesystem::canonical(root_path, error);
    if (error || !std::filesystem::is_directory(root))
        return {root_path, baseline_path, {}, {"root must be an accessible directory: " + root_path.string()}};
    const auto baseline = std::filesystem::absolute(baseline_path).lexically_normal();
    if (!force && std::filesystem::exists(baseline))
        return {root, baseline, {}, {"baseline already exists; pass --force to replace it"}};
    IntegritySummary summary{root, baseline, {}, {}};
    const auto hashes = scan(root, baseline, summary);
    if (!summary.errors.empty()) return summary;
    std::string error_text;
    if (!write_manifest(baseline, hashes, force, error_text)) summary.errors.push_back(std::move(error_text));
    for (const auto& [path, digest] : hashes) summary.files.push_back({path, {}, digest, "recorded"});
    return summary;
}

IntegritySummary check_integrity_baseline(const std::filesystem::path& root_path,
                                           const std::filesystem::path& baseline_path) {
    std::error_code error;
    const auto root = std::filesystem::canonical(root_path, error);
    if (error || !std::filesystem::is_directory(root))
        return {root_path, baseline_path, {}, {"root must be an accessible directory: " + root_path.string()}};
    const auto baseline = std::filesystem::absolute(baseline_path).lexically_normal();
    Hashes expected;
    std::vector<std::string> errors;
    if (!load_manifest(baseline, expected, errors)) return {root, baseline, {}, std::move(errors)};
    IntegritySummary scanned{root, baseline, {}, {}};
    auto current = scan(root, baseline, scanned);
    return compare(root, baseline, current, expected, std::move(scanned.errors));
}

std::string integrity_json(const IntegritySummary& summary) {
    std::ostringstream output;
    output << "{\"root\":\"" << json_escape(summary.root.string()) << "\",\"baseline\":\""
           << json_escape(summary.baseline.string()) << "\",\"files\":[";
    for (std::size_t i = 0; i < summary.files.size(); ++i) {
        if (i != 0) output << ',';
        const auto& file = summary.files[i];
        output << "{\"path\":\"" << json_escape(file.path) << "\",\"expected\":\""
               << json_escape(file.expected) << "\",\"actual\":\"" << json_escape(file.actual)
               << "\",\"status\":\"" << json_escape(file.status) << "\"}";
    }
    output << "],\"errors\":[";
    for (std::size_t i = 0; i < summary.errors.size(); ++i) {
        if (i != 0) output << ',';
        output << '"' << json_escape(summary.errors[i]) << '"';
    }
    output << "]}";
    return output.str();
}

std::string integrity_text(const IntegritySummary& summary) {
    std::ostringstream output;
    output << "Root: " << summary.root << "\nBaseline: " << summary.baseline << '\n';
    std::size_t changed{}, missing{}, added{}, recorded{};
    for (const auto& file : summary.files) {
        if (file.status == "changed") ++changed;
        else if (file.status == "missing") ++missing;
        else if (file.status == "new") ++added;
        else if (file.status == "recorded") ++recorded;
        if (file.status != "unchanged") output << file.status << "\t" << file.path << '\n';
    }
    output << "Files: " << summary.files.size() << ", recorded: " << recorded << ", changed: " << changed
           << ", missing: " << missing << ", new: " << added << '\n';
    for (const auto& error : summary.errors) output << "error: " << error << '\n';
    return output.str();
}

} // namespace superiorsec

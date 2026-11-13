#include "superiorsec/network.hpp"

#include "superiorsec/common.hpp"

#include <arpa/inet.h>

#include <array>
#include <bit>
#include <charconv>
#include <filesystem>
#include <sstream>
#include <vector>

namespace superiorsec {
namespace {

bool parse_hex(std::string_view text, std::uint32_t& value) {
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    return error == std::errc{} && end == text.data() + text.size();
}

std::string endpoint(std::string_view encoded, bool ipv6) {
    const auto separator = encoded.find(':');
    if (separator == std::string_view::npos) return "?";
    const auto address_hex = encoded.substr(0, separator);
    const auto port_hex = encoded.substr(separator + 1);
    std::uint32_t port{};
    if (!parse_hex(port_hex, port) || port > 65535) return "?";

    std::array<unsigned char, 16> bytes{};
    if (!ipv6) {
        std::uint32_t address{};
        if (address_hex.size() != 8 || !parse_hex(address_hex, address)) return "?";
        for (std::size_t i = 0; i < 4; ++i) bytes[i] = static_cast<unsigned char>((address >> (i * 8)) & 0xffU);
    } else {
        if (address_hex.size() != 32) return "?";
        for (std::size_t word = 0; word < 4; ++word) {
            std::uint32_t value{};
            if (!parse_hex(address_hex.substr(word * 8, 8), value)) return "?";
            for (std::size_t byte = 0; byte < 4; ++byte) {
                const auto shift = std::endian::native == std::endian::little ? byte * 8 : (3 - byte) * 8;
                bytes[word * 4 + byte] = static_cast<unsigned char>((value >> shift) & 0xffU);
            }
        }
    }
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (::inet_ntop(ipv6 ? AF_INET6 : AF_INET, bytes.data(), buffer.data(), static_cast<socklen_t>(buffer.size())) == nullptr)
        return "?";
    return ipv6 ? "[" + std::string(buffer.data()) + "]:" + std::to_string(port)
                : std::string(buffer.data()) + ":" + std::to_string(port);
}

std::string socket_state(std::string_view state) {
    if (state == "01") return "ESTABLISHED";
    if (state == "02") return "SYN_SENT";
    if (state == "03") return "SYN_RECV";
    if (state == "04") return "FIN_WAIT1";
    if (state == "05") return "FIN_WAIT2";
    if (state == "06") return "TIME_WAIT";
    if (state == "07") return "CLOSE";
    if (state == "08") return "CLOSE_WAIT";
    if (state == "09") return "LAST_ACK";
    if (state == "0A") return "LISTEN";
    if (state == "0B") return "CLOSING";
    return "UNKNOWN(" + std::string(state) + ")";
}

} // namespace

std::vector<SocketInfo> parse_socket_table(std::string_view contents, std::string protocol, bool ipv6) {
    std::vector<SocketInfo> sockets;
    std::istringstream lines{std::string(contents)};
    std::string line;
    std::getline(lines, line);
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        std::vector<std::string> columns;
        for (std::string value; fields >> value;) columns.push_back(std::move(value));
        if (columns.size() < 10) continue;
        unsigned uid{};
        const auto [end, error] = std::from_chars(columns[7].data(), columns[7].data() + columns[7].size(), uid);
        if (error != std::errc{} || end != columns[7].data() + columns[7].size()) uid = 0;
        const auto state = protocol.starts_with("udp") && columns[3] == "07"
            ? "UNCONN" : socket_state(columns[3]);
        sockets.push_back({protocol, endpoint(columns[1], ipv6), endpoint(columns[2], ipv6), state, uid});
    }
    return sockets;
}

std::vector<SocketInfo> inspect_network() {
    std::vector<SocketInfo> sockets;
    const std::array<std::pair<const char*, const char*>, 4> tables{{
        {"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"},
        {"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"}
    }};
    for (const auto& [path, protocol] : tables) {
        const auto contents = read_text_file(path);
        if (contents.empty()) continue;
        auto parsed = parse_socket_table(contents, protocol, std::string_view(protocol).ends_with('6'));
        sockets.insert(sockets.end(), std::make_move_iterator(parsed.begin()), std::make_move_iterator(parsed.end()));
    }
    return sockets;
}

std::string network_json(const std::vector<SocketInfo>& sockets) {
    std::ostringstream output;
    output << '[';
    for (std::size_t i = 0; i < sockets.size(); ++i) {
        if (i != 0) output << ',';
        const auto& socket = sockets[i];
        output << "{\"protocol\":\"" << json_escape(socket.protocol)
               << "\",\"local\":\"" << json_escape(socket.local_address)
               << "\",\"remote\":\"" << json_escape(socket.remote_address)
               << "\",\"state\":\"" << json_escape(socket.state)
               << "\",\"uid\":" << socket.uid << '}';
    }
    output << ']';
    return output.str();
}

std::string network_text(const std::vector<SocketInfo>& sockets) {
    std::ostringstream output;
    output << "PROTO  LOCAL                 REMOTE                STATE        UID\n";
    for (const auto& socket : sockets)
        output << socket.protocol << "\t" << socket.local_address << "\t" << socket.remote_address << "\t"
               << socket.state << "\t" << socket.uid << '\n';
    output << sockets.size() << " sockets\n";
    return output.str();
}

} // namespace superiorsec

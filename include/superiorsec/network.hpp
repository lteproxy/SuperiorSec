#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace superiorsec {

struct SocketInfo {
    std::string protocol;
    std::string local_address;
    std::string remote_address;
    std::string state;
    unsigned uid{};
};

std::vector<SocketInfo> inspect_network();
std::vector<SocketInfo> parse_socket_table(std::string_view contents, std::string protocol, bool ipv6);
std::string network_json(const std::vector<SocketInfo>& sockets);
std::string network_text(const std::vector<SocketInfo>& sockets);

}

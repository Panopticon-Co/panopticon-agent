#include "panopticon/officer/response/network_evidence.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <nlohmann/json.hpp>

#include <array>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace panopticon::officer::response {

namespace {

using nlohmann::json;

std::string ipv4_to_string(DWORD network_order_address) {
    IN_ADDR address{};
    address.S_un.S_addr = network_order_address;
    std::array<char, INET_ADDRSTRLEN> buffer{};
    if (InetNtopA(AF_INET, &address, buffer.data(), buffer.size()) == nullptr) return "";
    return std::string{buffer.data()};
}

std::string ipv6_to_string(const UCHAR (&bytes)[16]) {
    IN6_ADDR address{};
    std::copy(std::begin(bytes), std::end(bytes), std::begin(address.u.Byte));
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (InetNtopA(AF_INET6, &address, buffer.data(), buffer.size()) == nullptr) return "";
    return std::string{buffer.data()};
}

std::string tcp_state_name(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

std::uint16_t ntohs_port(DWORD raw_port) { return ntohs(static_cast<u_short>(raw_port)); }

bool append_tcp4(json& connections, std::size_t limit) {
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return true;
    std::vector<unsigned char> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return false;
    }
    const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries && connections.size() < limit; ++index) {
        const auto& row = table->table[index];
        connections.push_back(json{
            {"protocol", "tcp"},
            {"local_address", ipv4_to_string(row.dwLocalAddr)},
            {"local_port", ntohs_port(row.dwLocalPort)},
            {"remote_address", ipv4_to_string(row.dwRemoteAddr)},
            {"remote_port", ntohs_port(row.dwRemotePort)},
            {"state", tcp_state_name(row.dwState)},
            {"owner_pid", row.dwOwningPid},
        });
    }
    return true;
}

bool append_tcp6(json& connections, std::size_t limit) {
    ULONG size = 0;
    GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return true;
    std::vector<unsigned char> buffer(size);
    if (GetExtendedTcpTable(buffer.data(), &size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return false;
    }
    const auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries && connections.size() < limit; ++index) {
        const auto& row = table->table[index];
        connections.push_back(json{
            {"protocol", "tcp6"},
            {"local_address", ipv6_to_string(row.ucLocalAddr)},
            {"local_port", ntohs_port(row.dwLocalPort)},
            {"remote_address", ipv6_to_string(row.ucRemoteAddr)},
            {"remote_port", ntohs_port(row.dwRemotePort)},
            {"state", tcp_state_name(row.dwState)},
            {"owner_pid", row.dwOwningPid},
        });
    }
    return true;
}

bool append_udp4(json& connections, std::size_t limit) {
    ULONG size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (size == 0) return true;
    std::vector<unsigned char> buffer(size);
    if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        return false;
    }
    const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries && connections.size() < limit; ++index) {
        const auto& row = table->table[index];
        connections.push_back(json{
            {"protocol", "udp"},
            {"local_address", ipv4_to_string(row.dwLocalAddr)},
            {"local_port", ntohs_port(row.dwLocalPort)},
            {"remote_address", nullptr},
            {"remote_port", nullptr},
            {"state", "STATELESS"},
            {"owner_pid", row.dwOwningPid},
        });
    }
    return true;
}

bool append_udp6(json& connections, std::size_t limit) {
    ULONG size = 0;
    GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (size == 0) return true;
    std::vector<unsigned char> buffer(size);
    if (GetExtendedUdpTable(buffer.data(), &size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != NO_ERROR) {
        return false;
    }
    const auto* table = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD index = 0; index < table->dwNumEntries && connections.size() < limit; ++index) {
        const auto& row = table->table[index];
        connections.push_back(json{
            {"protocol", "udp6"},
            {"local_address", ipv6_to_string(row.ucLocalAddr)},
            {"local_port", ntohs_port(row.dwLocalPort)},
            {"remote_address", nullptr},
            {"remote_port", nullptr},
            {"state", "STATELESS"},
            {"owner_pid", row.dwOwningPid},
        });
    }
    return true;
}

}  // namespace

std::optional<std::string> collect_network_evidence(const std::size_t maximum_connections_per_table,
                                                      const std::size_t maximum_bytes, std::string& error_message) {
    if (maximum_connections_per_table == 0U || maximum_bytes == 0U) {
        error_message = "network evidence limits are invalid";
        return std::nullopt;
    }
    json connections = json::array();
    // Each table is bounded independently, and the array is also capped at
    // 4x the per-table bound as a hard ceiling in case future table classes
    // are added here without updating this comment's assumption.
    const std::size_t per_table_limit = maximum_connections_per_table;
    if (!append_tcp4(connections, per_table_limit) || !append_tcp6(connections, connections.size() + per_table_limit) ||
        !append_udp4(connections, connections.size() + per_table_limit) ||
        !append_udp6(connections, connections.size() + per_table_limit)) {
        error_message = "GetExtendedTcpTable/GetExtendedUdpTable failed";
        return std::nullopt;
    }
    json document = {{"connections", connections}};
    auto serialized = document.dump();
    if (serialized.size() > maximum_bytes) {
        error_message = "network evidence exceeds limit";
        return std::nullopt;
    }
    return serialized;
}

}  // namespace panopticon::officer::response

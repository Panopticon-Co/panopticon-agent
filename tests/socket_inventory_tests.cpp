#include "panopticon/officer/state/socket_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* text) { if (!value) throw std::runtime_error(text); }
struct OwnedSocket {
    SOCKET value = INVALID_SOCKET;
    ~OwnedSocket() { if (value != INVALID_SOCKET) closesocket(value); }
};
template<class Table, class Row> void parser_check(bool tcp, bool ipv6) {
    Row row{}; row.dwOwningPid = 4294967295u; row.dwLocalPort = 0xffff3412u;
    if constexpr (requires { row.dwState; }) row.dwState = 4294967295u;
    if constexpr (requires { row.ucLocalAddr; }) { row.ucLocalAddr[15] = 1; row.dwLocalScopeId = 4294967295u; }
    constexpr auto offset = offsetof(Table, table);
    std::vector<std::byte> bytes(offset + sizeof(Row)); const DWORD count = 1;
    std::memcpy(bytes.data(), &count, sizeof(count)); std::memcpy(bytes.data() + offset, &row, sizeof(row));
    Json rows = Json::array();
    auto result = state::detail::decode_socket_table(bytes, tcp, ipv6, [&](Json value) { rows.push_back(std::move(value)); return true; });
    require(result["table_rows_complete"] == true && rows.size() == 1, "one complete typed row decoded");
    require(rows[0]["reported_owner_pid"] == "4294967295" && rows[0]["process_reference"].is_null(), "PID retained without invented instance");
    require(rows[0]["local_port"]["reported_raw_dword"] == "4294915090" && rows[0]["local_port"]["decoded_low_16_network_order"] == "4660", "full port DWORD preserved separately from network-order low bits");
    if (tcp) require(rows[0]["tcp_state_symbol"].is_null() && result["state"] == "degraded", "unknown TCP state preserved without guessing");
    else require(rows[0]["remote_port"].is_null(), "UDP table cannot invent peer");
    bytes.pop_back();
    result = state::detail::decode_socket_table(bytes, tcp, ipv6, [](Json) { throw std::runtime_error("truncated row must never reach consumer"); return true; });
    require(result["state"] == "unavailable" && result["value"].is_null(), "truncated native count is rejected before row read");
}
int main(int argc, char** argv) {
    try {
        auto failure = state::detail::collect_socket_inventory_pages([](Json) { throw std::runtime_error("failed native tables cannot produce pages"); return true; },
            [](std::span<std::byte>, std::uint32_t&, bool, bool) { return ERROR_ACCESS_DENIED; });
        require(failure["state"] == "unavailable" && failure["entries_delivered"] == "0", "all native table failures stay unavailable");
        for (const auto& query : failure["tables"]) require(query["error_code"] == "5" && query["value"].is_null(), "exact independent native error retained");
        auto resizing = state::detail::collect_socket_inventory_pages([](Json) { return true; },
            [](std::span<std::byte> buffer, std::uint32_t& size, bool, bool) { size = static_cast<std::uint32_t>(buffer.size() + 1); return ERROR_INSUFFICIENT_BUFFER; });
        for (const auto& query : resizing["tables"]) require(query["native_calls"] == "3" && query["native_retry_bound_reached"] == true, "changing native required size cannot retry forever");
        auto oversized = state::detail::collect_socket_inventory_pages([](Json) { return true; },
            [](std::span<std::byte>, std::uint32_t& size, bool, bool) { size = 8 * 1024 * 1024 + 1; return ERROR_INSUFFICIENT_BUFFER; });
        for (const auto& query : oversized["tables"]) require(query["native_calls"] == "1" && query["native_buffer_bound_exceeded"] == true, "oversized native request is refused without allocation");
        std::size_t accepts = 0;
        auto partial = state::detail::collect_socket_inventory_pages([&](Json) { return ++accepts == 1; },
            [](std::span<std::byte> buffer, std::uint32_t& size, bool tcp, bool ipv6) {
                require(tcp && !ipv6, "later tables not queried after page refusal");
                const DWORD count = 513; const auto offset = offsetof(MIB_TCPTABLE_OWNER_PID, table);
                size = static_cast<std::uint32_t>(offset + count * sizeof(MIB_TCPROW_OWNER_PID));
                require(buffer.size() >= size, "synthetic table fits native bound");
                std::memcpy(buffer.data(), &count, sizeof(count));
                for (DWORD i = 0; i < count; ++i) { MIB_TCPROW_OWNER_PID row{}; row.dwState = MIB_TCP_STATE_LISTEN;
                    std::memcpy(buffer.data() + offset + i * sizeof(row), &row, sizeof(row)); }
                return ERROR_SUCCESS;
            });
        require(partial["consumer_refused"] == true && partial["entries_delivered"] == "256", "later page refusal retains only accepted prefix accounting");
        require(partial["tables"]["tcp4"]["rows_in_accepted_pages"] == "256" && partial["tables"]["tcp4"]["state"] == "degraded", "table query success cannot hide rejected rows");
        parser_check<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(true, false);
        parser_check<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(true, true);
        parser_check<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(false, false);
        parser_check<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(false, true);
        WSADATA data{}; require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "Winsock starts for owned loopback fixture");
        struct Cleanup { ~Cleanup() { WSACleanup(); } } cleanup;
        OwnedSocket tcp, udp; tcp.value = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); udp.value = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        require(tcp.value != INVALID_SOCKET && udp.value != INVALID_SOCKET, "owned IPv4 sockets created");
        sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        require(bind(tcp.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && listen(tcp.value, 1) == 0, "owned local TCP listener starts");
        require(bind(udp.value, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "owned UDP local endpoint binds");
        int length = sizeof(address); require(getsockname(tcp.value, reinterpret_cast<sockaddr*>(&address), &length) == 0, "owned TCP port queried"); const auto tcp_port = std::to_string(ntohs(address.sin_port));
        length = sizeof(address); require(getsockname(udp.value, reinterpret_cast<sockaddr*>(&address), &length) == 0, "owned UDP port queried"); const auto udp_port = std::to_string(ntohs(address.sin_port));
        OwnedSocket tcp6, udp6; tcp6.value = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); udp6.value = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        require(tcp6.value != INVALID_SOCKET && udp6.value != INVALID_SOCKET, "owned IPv6 sockets created on qualification host");
        sockaddr_in6 address6{}; address6.sin6_family = AF_INET6; address6.sin6_addr = in6addr_loopback;
        require(bind(tcp6.value, reinterpret_cast<sockaddr*>(&address6), sizeof(address6)) == 0 && listen(tcp6.value, 1) == 0, "owned IPv6 listener starts");
        require(bind(udp6.value, reinterpret_cast<sockaddr*>(&address6), sizeof(address6)) == 0, "owned IPv6 UDP endpoint binds");
        length = sizeof(address6); require(getsockname(tcp6.value, reinterpret_cast<sockaddr*>(&address6), &length) == 0, "owned IPv6 TCP port queried"); const auto tcp6_port = std::to_string(ntohs(address6.sin6_port));
        length = sizeof(address6); require(getsockname(udp6.value, reinterpret_cast<sockaddr*>(&address6), &length) == 0, "owned IPv6 UDP port queried"); const auto udp6_port = std::to_string(ntohs(address6.sin6_port));
        std::string error; const auto boot = core::query_native_boot_id(error);
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), boot, 1};
        auto begin = factory.state("socket_inventory_begin", {{"inventory_complete", false}});
        Json records = Json::array({begin}), ids = Json::array(); std::size_t count = 0, pages = 0; bool found_tcp = false, found_udp = false, found_tcp6 = false, found_udp6 = false;
        auto summary = state::collect_socket_inventory_pages([&](Json page) {
            require(page["page_index"] == std::to_string(pages++), "socket pages ordered");
            require(page["entries"].size() <= 256 && page["entries"].dump().size() <= 512 * 1024, "socket page bounds hold");
            for (const auto& row : page["entries"]) {
                ++count; require(row["process_reference"].is_null() && row["socket_instance_reference"].is_null(), "native owner PID is not an instance join");
                if (row["reported_owner_pid"] == std::to_string(GetCurrentProcessId()) && row["address_family"] == "ipv4") {
                    if (row["transport"] == "tcp" && row["local_port"]["decoded_low_16_network_order"] == tcp_port) found_tcp = true;
                    if (row["transport"] == "udp" && row["local_port"]["decoded_low_16_network_order"] == udp_port) found_udp = true;
                }
                if (row["reported_owner_pid"] == std::to_string(GetCurrentProcessId()) && row["address_family"] == "ipv6") {
                    if (row["transport"] == "tcp" && row["local_port"]["decoded_low_16_network_order"] == tcp6_port) found_tcp6 = true;
                    if (row["transport"] == "udp" && row["local_port"]["decoded_low_16_network_order"] == udp6_port) found_udp6 = true;
                }
            }
            page["capture_id"] = begin.at("record_id"); auto record = factory.state("socket_inventory_page", std::move(page));
            ids.push_back(record.at("record_id")); records.push_back(std::move(record)); return true;
        });
        require(found_tcp && found_udp, "actual native IPv4 tables include both owned loopback endpoints");
        require(found_tcp6 && found_udp6, "actual native IPv6 tables include both owned loopback endpoints");
        require(summary["entries_delivered"] == std::to_string(count) && summary["inventory_complete"] == false, "accepted rows accounted without full network coverage claim");
        for (const auto& query : summary["tables"]) require(query.contains("state") && query.contains("query_started_uptime_ms"), "all four native tables expose query state and time");
        summary["capture_id"] = begin.at("record_id"); summary["page_record_ids"] = ids; records.push_back(factory.state("socket_inventory", summary));
        if (argc == 2 && std::string{argv[1]} == "--emit-live") std::cout << records.dump() << '\n';
        else { const auto refused = state::collect_socket_inventory_pages([](Json) { return false; });
            require(refused["consumer_refused"] == true && refused["entries_delivered"] == "0", "refused pages never count as accepted rows"); }
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

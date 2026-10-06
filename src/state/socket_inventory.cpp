#include "panopticon/officer/state/socket_inventory.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <string>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
Json invalid(const char* reason) { return {{"state", "unavailable"}, {"value", nullptr}, {"error_domain", "validation"}, {"error_code", reason}}; }
std::string hex(const void* data, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef"; const auto* bytes = static_cast<const unsigned char*>(data);
    std::string result; result.reserve(size * 2);
    for (std::size_t index = 0; index < size; ++index) { result += digits[bytes[index] >> 4]; result += digits[bytes[index] & 15]; }
    return result;
}
Json port(DWORD raw) {
    const auto low = raw & 0xffffu;
    return {{"reported_raw_dword", std::to_string(raw)}, {"decoded_low_16_network_order", std::to_string(((low & 255u) << 8) | (low >> 8))}};
}
const char* tcp_symbol(DWORD raw) {
    switch (raw) {
    case MIB_TCP_STATE_CLOSED: return "CLOSED"; case MIB_TCP_STATE_LISTEN: return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT"; case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB: return "ESTABLISHED"; case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2"; case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING: return "CLOSING"; case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT"; case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
    default: return nullptr;
    }
}
template<class Row> Json row_value(const Row& row, bool tcp, bool ipv6) {
    Json value{{"reported_owner_pid", std::to_string(row.dwOwningPid)}, {"local_port", port(row.dwLocalPort)},
        {"process_reference", nullptr}, {"socket_instance_reference", nullptr}, {"reported_row_hex", hex(&row, sizeof(row))},
        {"owner_relation", "native owner PID only; process instance, socket object and activity association unverified"}};
    if constexpr (requires { row.ucLocalAddr; }) {
        value["local_address_network_bytes_hex"] = hex(row.ucLocalAddr, sizeof(row.ucLocalAddr));
        value["reported_local_scope_id"] = std::to_string(row.dwLocalScopeId);
    } else value["local_address_network_bytes_hex"] = hex(&row.dwLocalAddr, sizeof(row.dwLocalAddr));
    if constexpr (requires { row.dwRemotePort; }) {
        value["remote_port"] = port(row.dwRemotePort); value["reported_tcp_state"] = std::to_string(row.dwState);
        const auto symbol = tcp_symbol(row.dwState); value["tcp_state_symbol"] = symbol ? Json(symbol) : Json(nullptr);
        value["remote_endpoint_semantics"] = row.dwState == MIB_TCP_STATE_LISTEN
            ? "native remote address/port have no meaning for LISTEN; raw fields retained"
            : "reported remote fields; state-dependent interpretation and peer identity unverified";
        if constexpr (requires { row.ucRemoteAddr; }) {
            value["remote_address_network_bytes_hex"] = hex(row.ucRemoteAddr, sizeof(row.ucRemoteAddr));
            value["reported_remote_scope_id"] = std::to_string(row.dwRemoteScopeId);
        } else value["remote_address_network_bytes_hex"] = hex(&row.dwRemoteAddr, sizeof(row.dwRemoteAddr));
    } else { value["remote_port"] = nullptr; value["remote_address_network_bytes_hex"] = nullptr;
        value["tcp_state_symbol"] = nullptr; value["scope"] = "UDP local endpoint table does not report remote peer or connection state"; }
    value["transport"] = tcp ? "tcp" : "udp"; value["address_family"] = ipv6 ? "ipv6" : "ipv4";
    return value;
}
template<class Table, class Row> Json decode(std::span<const std::byte> buffer, bool tcp, bool ipv6, const std::function<bool(Json)>& consumer) {
    constexpr auto start = offsetof(Table, table);
    if (buffer.size() < start || buffer.size() > 8 * 1024 * 1024) return invalid("native_buffer_size_invalid");
    DWORD count = 0; std::memcpy(&count, buffer.data(), sizeof(count));
    if (count > (buffer.size() - start) / sizeof(Row)) return invalid("native_count_outside_buffer");
    std::size_t delivered = 0, unknown = 0; bool refused = false;
    for (DWORD index = 0; index < count && index < 65536; ++index) {
        Row row{}; std::memcpy(&row, buffer.data() + start + index * sizeof(Row), sizeof(Row));
        if constexpr (requires { row.dwState; }) if (!tcp_symbol(row.dwState)) ++unknown;
        auto value = row_value(row, tcp, ipv6); value["table_row_index"] = std::to_string(index);
        if (!consumer(std::move(value))) { refused = true; break; }
        ++delivered;
    }
    return {{"state", refused || count > 65536 || unknown ? "degraded" : "healthy"}, {"reported_rows", std::to_string(count)},
        {"rows_delivered_to_page_builder", std::to_string(delivered)}, {"unknown_tcp_states", std::to_string(unknown)},
        {"bound_exceeded", count > 65536}, {"consumer_refused", refused}, {"table_rows_complete", !refused && count <= 65536},
        {"scope", "one native available-to-caller owner-PID table; not continuous flow history or verified process/socket identity"}};
}
}
Json detail::decode_socket_table(std::span<const std::byte> buffer, bool tcp, bool ipv6, const std::function<bool(Json)>& consumer) {
    if (!consumer) throw std::invalid_argument("socket row consumer missing");
    if (tcp && ipv6) return decode<MIB_TCP6TABLE_OWNER_PID, MIB_TCP6ROW_OWNER_PID>(buffer, tcp, ipv6, consumer);
    if (tcp) return decode<MIB_TCPTABLE_OWNER_PID, MIB_TCPROW_OWNER_PID>(buffer, tcp, ipv6, consumer);
    if (ipv6) return decode<MIB_UDP6TABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID>(buffer, tcp, ipv6, consumer);
    return decode<MIB_UDPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID>(buffer, tcp, ipv6, consumer);
}
Json collect_socket_inventory_pages(const std::function<bool(Json)>& consumer) {
    return detail::collect_socket_inventory_pages(consumer, [](std::span<std::byte> buffer, std::uint32_t& size, bool tcp, bool ipv6) {
        DWORD native_size = size;
        const auto error = tcp ? GetExtendedTcpTable(buffer.data(), &native_size, FALSE, ipv6 ? AF_INET6 : AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            : GetExtendedUdpTable(buffer.data(), &native_size, FALSE, ipv6 ? AF_INET6 : AF_INET, UDP_TABLE_OWNER_PID, 0);
        size = native_size; return static_cast<std::uint32_t>(error);
    });
}
Json detail::collect_socket_inventory_pages(const std::function<bool(Json)>& consumer, const SocketTableQuery& native_query) {
    if (!consumer || !native_query) throw std::invalid_argument("socket page consumer/query missing");
    const auto started = GetTickCount64(); Json tables = Json::object(); std::size_t pages = 0, delivered = 0;
    bool refused = false, bounded = false; std::size_t encoded = 2; Json rows = Json::array();
    Json admitted = {{"tcp4", 0}, {"tcp6", 0}, {"udp4", 0}, {"udp6", 0}};
    const auto flush = [&]() {
        if (pages >= 4096) { bounded = true; return false; }
        Json counts = {{"tcp4", 0}, {"tcp6", 0}, {"udp4", 0}, {"udp6", 0}};
        for (const auto& row : rows) { const auto key = row.at("source_table").get<std::string>();
            counts[key] = counts[key].get<std::size_t>() + 1; }
        const auto count = rows.size(); auto page = Json{{"socket_state_version", "1.0"}, {"state", "degraded"},
            {"page_index", std::to_string(pages++)}, {"entries", std::move(rows)}, {"inventory_complete", false}, {"consistency", "non_atomic"}};
        if (!consumer(std::move(page))) { refused = true; return false; }
        for (auto it = counts.begin(); it != counts.end(); ++it)
            admitted[it.key()] = admitted[it.key()].get<std::size_t>() + it.value().get<std::size_t>();
        delivered += count; rows = Json::array(); encoded = 2; return true;
    };
    for (const bool tcp : {true, false}) for (const bool ipv6 : {false, true}) {
        const auto key = std::string(tcp ? "tcp" : "udp") + (ipv6 ? "6" : "4");
        const auto query_start = GetTickCount64(); Json query;
        if (refused || bounded) query = {{"state", "unavailable"}, {"value", nullptr}, {"reason", "not queried after page refusal/bound"}};
        else {
            std::vector<std::byte> buffer(65536); std::uint32_t size = 0, error = 0, calls = 0;
            for (; calls < 3;) {
                size = static_cast<DWORD>(buffer.size()); ++calls;
                error = native_query(buffer, size, tcp, ipv6);
                if (error != ERROR_INSUFFICIENT_BUFFER || size <= buffer.size() || size > 8 * 1024 * 1024 || calls == 3) break;
                buffer.assign(size, std::byte{0});
            }
            if (error) query = {{"state", error == ERROR_NOT_SUPPORTED ? "unsupported" : "unavailable"}, {"value", nullptr},
                {"error_domain", "Win32"}, {"error_code", std::to_string(error)}, {"reported_size", std::to_string(size)},
                {"native_buffer_bound_exceeded", size > 8 * 1024 * 1024},
                {"native_retry_bound_reached", error == ERROR_INSUFFICIENT_BUFFER && calls == 3},
                {"native_resize_not_advancing", error == ERROR_INSUFFICIENT_BUFFER && size <= buffer.size()}};
            else if (size > buffer.size()) query = invalid("native_success_size_exceeds_buffer");
            else query = detail::decode_socket_table(std::span<const std::byte>{buffer}.first(size), tcp, ipv6, [&](Json row) {
                row["source_table"] = key;
                auto size = row.dump().size() + (rows.empty() ? 0 : 1);
                if (rows.size() >= 256 || size > 512 * 1024 - encoded) {
                    if (!rows.empty() && !flush()) return false;
                    size = row.dump().size();
                    if (size > 512 * 1024 - encoded) { bounded = true; return false; }
                }
                encoded += size; rows.push_back(std::move(row)); return true;
            });
            query["native_calls"] = std::to_string(calls); query["native_buffer_limit"] = 8 * 1024 * 1024;
            query["native_reported_size"] = std::to_string(size);
            query["allocated_native_buffer_bytes"] = std::to_string(buffer.size());
            query["native_row_limit"] = 65536;
        }
        query["source"] = tcp ? "GetExtendedTcpTable/TCP_TABLE_OWNER_PID_ALL" : "GetExtendedUdpTable/UDP_TABLE_OWNER_PID";
        query["address_family"] = ipv6 ? "ipv6" : "ipv4";
        query["query_started_uptime_ms"] = std::to_string(query_start); query["query_completed_uptime_ms"] = std::to_string(GetTickCount64());
        tables[key] = std::move(query);
    }
    if (!refused && !bounded && !rows.empty()) (void)flush();
    for (auto it = tables.begin(); it != tables.end(); ++it) {
        auto& query = it.value();
        const auto accepted = admitted[it.key()].get<std::size_t>();
        query["rows_in_accepted_pages"] = std::to_string(accepted);
        query["reported_rows_in_accepted_pages"] = query.contains("reported_rows") &&
            query.at("reported_rows") == std::to_string(accepted);
        query["page_acceptance_scope"] = "consumer accepted pages; durability depends on the consumer contract";
        if (query["state"] == "healthy" && query["reported_rows_in_accepted_pages"] != true) query["state"] = "degraded";
    }
    bool any = false; for (const auto& query : tables) if (query.contains("reported_rows")) any = true;
    return {{"state", any ? "degraded" : "unavailable"}, {"socket_state_version", "1.0"}, {"format", "paged_socket_inventory_v1"},
        {"inventory_complete", false}, {"consistency", "non_atomic"}, {"tables", std::move(tables)},
        {"pages_produced", std::to_string(pages)}, {"entries_delivered", std::to_string(delivered)}, {"consumer_refused", refused},
        {"bound_exceeded", bounded}, {"page_limit", 4096}, {"collection_started_uptime_ms", std::to_string(started)},
        {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"scope", "four separately queried native TCP/UDP IPv4/IPv6 tables; no verified process/socket instances or continuous activity coverage"}};
}
}

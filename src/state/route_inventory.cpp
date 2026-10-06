#include "panopticon/officer/state/route_inventory.hpp"
#include "panopticon/officer/state/ip_interface.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cstring>
#include <memory>
#include <map>
#include <stdexcept>
#include <string>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
constexpr std::size_t row_limit = 65536, copy_limit = 8 * 1024 * 1024;
Json invalid(const char* reason) { return {{"state", "unavailable"}, {"value", nullptr}, {"error_domain", "validation"}, {"error_code", reason}}; }
std::string hex(const void* data, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef"; const auto* bytes = static_cast<const unsigned char*>(data);
    std::string result; result.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) { result += digits[bytes[i] >> 4]; result += digits[bytes[i] & 15]; }
    return result;
}
Json address(const SOCKADDR_INET& value) {
    Json result{{"reported_address_family", std::to_string(value.si_family)}};
    if (value.si_family == AF_INET) {
        result["address_family"] = "ipv4";
        result["network_bytes_hex"] = hex(&value.Ipv4.sin_addr, sizeof(value.Ipv4.sin_addr));
        result["reported_port_network_bytes_hex"] = hex(&value.Ipv4.sin_port, sizeof(value.Ipv4.sin_port));
    } else if (value.si_family == AF_INET6) {
        result["address_family"] = "ipv6";
        result["network_bytes_hex"] = hex(&value.Ipv6.sin6_addr, sizeof(value.Ipv6.sin6_addr));
        result["reported_scope_id"] = std::to_string(value.Ipv6.sin6_scope_id);
        result["reported_flow_info"] = std::to_string(value.Ipv6.sin6_flowinfo);
        result["reported_port_network_bytes_hex"] = hex(&value.Ipv6.sin6_port, sizeof(value.Ipv6.sin6_port));
    } else { result["state"] = "unavailable"; result["value"] = nullptr;
        result["reason"] = "unknown address family; inactive union and padding not interpreted"; }
    return result;
}
const char* protocol(std::uint32_t raw) {
    constexpr const char* symbols[] = {"OTHER", "LOCAL", "NETMGMT", "ICMP", "EGP", "GGP", "HELLO", "RIP", "IS_IS", "ES_IS", "CISCO", "BBN", "OSPF", "BGP", "IDPR", "EIGRP", "DVMRP", "RPL", "DHCP"};
    if (raw >= 1 && raw <= 19) return symbols[raw - 1];
    switch (raw) { case 10002: return "NT_AUTOSTATIC"; case 10006: return "NT_STATIC"; case 10007: return "NT_STATIC_NON_DOD"; default: return nullptr; }
}
const char* origin(std::uint32_t raw) {
    switch (raw) { case NlroManual: return "Manual"; case NlroWellKnown: return "WellKnown";
    case NlroDHCP: return "DHCP"; case NlroRouterAdvertisement: return "RouterAdvertisement";
    case Nlro6to4: return "6to4"; default: return nullptr; }
}
Json raw_bool(UCHAR raw) { return {{"reported_raw_byte", std::to_string(raw)}, {"value", raw <= 1 ? Json(raw == 1) : Json(nullptr)}}; }
detail::RouteTableResult native_query(bool ipv6) {
    MIB_IPFORWARD_TABLE2* table = nullptr;
    detail::RouteTableResult result;
    result.error = GetIpForwardTable2(ipv6 ? AF_INET6 : AF_INET, &table);
    const auto release = [](MIB_IPFORWARD_TABLE2* value) { if (value) FreeMibTable(value); };
    std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(release)> owner{table, release};
    if (result.error) return result;
    if (!table) { result.native_success_without_table = true; return result; }
    result.reported_rows = table->NumEntries;
    // API owns the allocation and does not expose its byte length. This limits
    // our copy/row reads, not the size of the native allocation already made.
    if (result.reported_rows > row_limit || result.reported_rows > copy_limit / sizeof(MIB_IPFORWARD_ROW2)) return result;
    result.rows.resize(static_cast<std::size_t>(result.reported_rows) * sizeof(MIB_IPFORWARD_ROW2));
    for (std::size_t i = 0; i < result.reported_rows; ++i)
        std::memcpy(result.rows.data() + i * sizeof(MIB_IPFORWARD_ROW2), &table->Table[i], sizeof(MIB_IPFORWARD_ROW2));
    return result;
}
}
Json detail::decode_route_row(std::span<const std::byte> bytes) {
    if (bytes.size() != sizeof(MIB_IPFORWARD_ROW2)) return invalid("native_route_row_size_invalid");
    MIB_IPFORWARD_ROW2 row{}; std::memcpy(&row, bytes.data(), sizeof(row));
    const auto route_protocol = static_cast<std::uint32_t>(row.Protocol), route_origin = static_cast<std::uint32_t>(row.Origin);
    const auto p = protocol(route_protocol), o = origin(route_origin);
    const auto family = row.DestinationPrefix.Prefix.si_family;
    const bool family_known = family == AF_INET || family == AF_INET6;
    const bool prefix_valid = family_known && row.DestinationPrefix.PrefixLength <= (family == AF_INET ? 32 : 128);
    // SitePrefixLength can contain the documented 255 invalid-value sentinel.
    const bool site_valid = family_known && row.SitePrefixLength <= (family == AF_INET ? 32 : 128);
    const bool consistent = family_known && row.NextHop.si_family == family;
    const bool booleans_known = row.Loopback <= 1 && row.AutoconfigureAddress <= 1 && row.Publish <= 1 && row.Immortal <= 1;
    return {{"state", p && o && prefix_valid && site_valid && consistent && booleans_known ? "healthy" : "degraded"},
        {"reported_interface_luid", std::to_string(row.InterfaceLuid.Value)}, {"reported_interface_index", std::to_string(row.InterfaceIndex)},
        {"interface_instance_reference", nullptr}, {"route_instance_reference", nullptr},
        {"interface_relation", "native reported route/interface association; interface lifetime and later adapter relationship unverified; index is not persistent"},
        {"destination", address(row.DestinationPrefix.Prefix)}, {"reported_destination_prefix_length", std::to_string(row.DestinationPrefix.PrefixLength)},
        {"destination_prefix_valid", prefix_valid}, {"next_hop", address(row.NextHop)}, {"address_families_consistent", consistent},
        {"reported_site_prefix_length", std::to_string(row.SitePrefixLength)}, {"site_prefix_valid", site_valid},
        {"valid_lifetime_seconds", std::to_string(row.ValidLifetime)}, {"preferred_lifetime_seconds", std::to_string(row.PreferredLifetime)},
        {"lifetime_scope", "raw native seconds; 4294967295 is the documented infinite sentinel; no wall-clock expiry inferred"},
        {"reported_metric_offset", std::to_string(row.Metric)}, {"effective_route_metric", nullptr},
        {"metric_scope", "route offset only; later interface metric and selected effective path not queried"},
        {"reported_protocol", std::to_string(route_protocol)}, {"protocol_symbol", p ? Json(p) : Json(nullptr)},
        {"reported_origin", std::to_string(route_origin)}, {"origin_symbol", o ? Json(o) : Json(nullptr)},
        {"loopback", raw_bool(row.Loopback)}, {"autoconfigure_address", raw_bool(row.AutoconfigureAddress)},
        {"publish", raw_bool(row.Publish)}, {"immortal", raw_bool(row.Immortal)}, {"reported_age_seconds", std::to_string(row.Age)},
        {"scope", "reported native route fields; no process actor, route lifetime, effective routing decision or original padding bytes"}};
}
Json collect_route_inventory_pages(const std::function<bool(Json)>& consumer) { return detail::collect_route_inventory_pages(consumer, native_query, query_ip_interface); }
Json detail::collect_route_inventory_pages(const std::function<bool(Json)>& consumer, const std::function<RouteTableResult(bool)>& query,
    const std::function<Json(bool, std::uint64_t, std::uint32_t)>& interface_query) {
    if (!consumer || !query) throw std::invalid_argument("route consumer/query missing");
    const auto started = GetTickCount64(); Json tables = Json::object(); std::size_t pages = 0, accepted = 0;
    bool refused = false, page_bounded = false; // Flush each family before releasing its bounded copied rows.
    std::map<std::string, Json> interface_cache;
    std::size_t interface_success = 0, interface_failed = 0, interface_unknown = 0, interface_reuse = 0, interface_unattempted = 0;
    for (bool ipv6 : {false, true}) {
        const std::string key = ipv6 ? "ipv6" : "ipv4"; const auto query_start = GetTickCount64();
        Json status; std::size_t delivered = 0, decoded = 0, unknown = 0;
        if (refused || page_bounded) status = {{"state", "unavailable"}, {"value", nullptr}, {"reason", "not queried after page refusal/bound"}};
        else {
            const auto result = query(ipv6);
            const auto query_end = GetTickCount64();
            status = {{"native_error_code", std::to_string(result.error)}, {"native_query_completed_uptime_ms", std::to_string(query_end)}};
            if (result.error) { status["state"] = result.error == ERROR_NOT_SUPPORTED ? "unsupported" : "unavailable";
                status["value"] = nullptr; status["error_domain"] = "Win32"; }
            else if (result.native_success_without_table) {
                status["state"] = "unavailable"; status["value"] = nullptr;
                status["error_domain"] = "validation"; status["error_code"] = "native_success_without_table";
            }
            else {
                status["reported_rows"] = std::to_string(result.reported_rows);
                const bool bounded = result.reported_rows > row_limit || result.reported_rows > copy_limit / sizeof(MIB_IPFORWARD_ROW2)
                    || result.rows.size() > copy_limit;
                if (bounded || result.rows.size() / sizeof(MIB_IPFORWARD_ROW2) != result.reported_rows || result.rows.size() % sizeof(MIB_IPFORWARD_ROW2)) {
                    status["state"] = "unavailable"; status["value"] = nullptr; status["bound_exceeded"] = bounded;
                    status["error_domain"] = "validation"; status["error_code"] = "native_route_count_copy_mismatch_or_bound";
                } else {
                    Json rows = Json::array(); std::size_t encoded = 2;
                    const auto flush = [&]() { const auto count = rows.size();
                        if (pages >= 4096) { page_bounded = true; return false; }
                        Json page{{"route_state_version", "1.1"}, {"page_index", std::to_string(pages++)}, {"source_table", key},
                            {"entries", std::move(rows)}, {"inventory_complete", false}, {"consistency", "non_atomic"}};
                        if (!consumer(std::move(page))) { refused = true; return false; }
                        delivered += count; accepted += count; encoded = 2; rows = Json::array(); return true; };
                    for (std::size_t index = 0; index < result.reported_rows; ++index) {
                        auto value = decode_route_row(std::span<const std::byte>{result.rows}.subspan(index * sizeof(MIB_IPFORWARD_ROW2), sizeof(MIB_IPFORWARD_ROW2)));
                        if (value["state"] != "healthy" || value["destination"]["address_family"] != key) { ++unknown; value["state"] = "degraded"; }
                        value["source_table"] = key; value["table_row_index"] = std::to_string(index); ++decoded;
                        MIB_IPFORWARD_ROW2 route{};
                        std::memcpy(&route, result.rows.data() + index * sizeof(route), sizeof(route));
                        const auto cache_key = key + ":" + std::to_string(route.InterfaceLuid.Value) + ":" + std::to_string(route.InterfaceLuid.Value ? 0 : route.InterfaceIndex);
                        Json later;
                        const auto found = interface_cache.find(cache_key);
                        if (found != interface_cache.end()) { later = found->second; ++interface_reuse; }
                        else if (!interface_query || interface_cache.size() >= 512 || (!route.InterfaceLuid.Value && !route.InterfaceIndex)
                            || route.DestinationPrefix.Prefix.si_family != (ipv6 ? AF_INET6 : AF_INET)) {
                            ++interface_unattempted;
                            later = {{"state", "unavailable"}, {"value", nullptr}, {"native_query_succeeded", false},
                                {"reason", "query not attempted: missing query backend, lookup key/family or 512-key capture bound"}};
                        } else {
                            later = interface_query(ipv6, route.InterfaceLuid.Value, route.InterfaceIndex);
                            if (later.value("native_query_succeeded", false)) { ++interface_success;
                                if (later.value("state", std::string{}) != "healthy") ++interface_unknown; }
                            else ++interface_failed;
                            interface_cache.emplace(cache_key, later);
                        }
                        later["route_relation"] = "later query cached per family/lookup key within capture; interface lifetime and route-to-later-object association unverified";
                        value["later_ip_interface_query"] = std::move(later);
                        value["reported_metric_sum"] = nullptr;
                        const auto& lookup = value["later_ip_interface_query"];
                        if (route.Metric != 4294967295u && lookup.value("lookup_key_matches_returned_fields", false)
                            && lookup.contains("value") && lookup["value"].is_object() && lookup["value"].contains("reported_metric"))
                            value["reported_metric_sum"] = std::to_string(static_cast<std::uint64_t>(route.Metric) + std::stoull(lookup["value"]["reported_metric"].get<std::string>()));
                        value["metric_scope"] = "raw route offset plus later reported interface metric when lookup fields match and offset is not unused sentinel; arithmetic is not effective path or verified lifetime";
                        auto size = value.dump().size() + (rows.empty() ? 0 : 1);
                        if (rows.size() >= 256 || size > 512 * 1024 - encoded) {
                            if (!rows.empty() && !flush()) break;
                            size = value.dump().size();
                            if (size > 512 * 1024 - encoded) { page_bounded = true; break; }
                        }
                        encoded += size; rows.push_back(std::move(value));
                    }
                    if (!refused && !page_bounded && !rows.empty()) (void)flush();
                    status["state"] = refused || page_bounded || unknown ? "degraded" : "healthy";
                    status["page_bound_exceeded"] = page_bounded;
                    status["reported_rows_in_accepted_pages"] = delivered == result.reported_rows;
                }
            }
            status["native_calls"] = "1";
        }
        status["rows_decoded"] = std::to_string(decoded); status["rows_in_accepted_pages"] = std::to_string(delivered);
        status["uninterpreted_or_invalid_rows"] = std::to_string(unknown); status["source"] = "GetIpForwardTable2";
        status["requested_address_family"] = key; status["query_started_uptime_ms"] = std::to_string(query_start);
        status["collection_completed_uptime_ms"] = std::to_string(GetTickCount64());
        status["scope"] = "one caller-context family query; compartment identity and all-compartment coverage unverified";
        tables[key] = std::move(status);
    }
    bool any = false; for (const auto& table : tables) if (table.contains("reported_rows")) any = true;
    Json interface_summary{{"state", !interface_success ? "unavailable" : interface_failed || interface_unknown || interface_unattempted ? "degraded" : "healthy"},
        {"successful_native_queries", std::to_string(interface_success)}, {"failed_native_queries", std::to_string(interface_failed)},
        {"uninterpreted_or_mismatched_results", std::to_string(interface_unknown)}, {"cached_row_reuses", std::to_string(interface_reuse)},
        {"row_queries_not_attempted", std::to_string(interface_unattempted)}, {"lookup_key_limit", 512},
        {"scope", "unique later native queries and row reuses including undelivered rows; not lost events or full interface coverage"}};
    return {{"state", any ? "degraded" : "unavailable"}, {"route_state_version", "1.1"}, {"format", "paged_route_inventory_v1"},
        {"ip_interface_query_summary", std::move(interface_summary)},
        {"inventory_complete", false}, {"consistency", "non_atomic"}, {"tables", std::move(tables)},
        {"entries_delivered", std::to_string(accepted)}, {"pages_produced", std::to_string(pages)}, {"consumer_refused", refused},
        {"page_bound_exceeded", page_bounded}, {"page_limit", 4096},
        {"native_row_limit", row_limit}, {"copied_native_bytes_limit", copy_limit}, {"native_allocation_bounded", false},
        {"compartment_reference", nullptr}, {"all_compartments_complete", false},
        {"collection_started_uptime_ms", std::to_string(started)}, {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"scope", "separate IPv4/IPv6 native route queries; no route/interface instance, effective path, actor or continuous change coverage"}};
}
}

#include "panopticon/officer/state/ip_interface_inventory.hpp"
#include "panopticon/officer/state/ip_interface.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <cstring>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
constexpr std::size_t row_limit = 65536, copy_limit = 8 * 1024 * 1024;
detail::IpInterfaceTableResult native_query(bool ipv6) {
    MIB_IPINTERFACE_TABLE* table = nullptr;
    detail::IpInterfaceTableResult result;
    result.error = GetIpInterfaceTable(ipv6 ? AF_INET6 : AF_INET, &table);
    const auto release = [](MIB_IPINTERFACE_TABLE* value) { if (value) FreeMibTable(value); };
    std::unique_ptr<MIB_IPINTERFACE_TABLE, decltype(release)> owner{table, release};
    if (result.error) return result;
    if (!table) { result.native_success_without_table = true; return result; }
    result.reported_rows = table->NumEntries;
    // OS allocation extent is not returned. Bound our reads and copy, not the
    // allocation already made by the API; use SDK array stride/alignment.
    if (result.reported_rows > row_limit || result.reported_rows > copy_limit / sizeof(MIB_IPINTERFACE_ROW)) return result;
    result.rows.resize(static_cast<std::size_t>(result.reported_rows) * sizeof(MIB_IPINTERFACE_ROW));
    for (std::size_t i = 0; i < result.reported_rows; ++i)
        std::memcpy(result.rows.data() + i * sizeof(MIB_IPINTERFACE_ROW), &table->Table[i], sizeof(MIB_IPINTERFACE_ROW));
    return result;
}
}
Json collect_ip_interface_inventory_pages(const std::function<bool(Json)>& consumer) {
    return detail::collect_ip_interface_inventory_pages(consumer, native_query);
}
Json detail::collect_ip_interface_inventory_pages(const std::function<bool(Json)>& consumer, const std::function<IpInterfaceTableResult(bool)>& query) {
    if (!consumer || !query) throw std::invalid_argument("IP interface consumer/query missing");
    const auto started = GetTickCount64(); Json tables = Json::object(); std::size_t pages = 0, accepted = 0;
    bool refused = false, page_bounded = false;
    for (bool ipv6 : {false, true}) {
        const std::string key = ipv6 ? "ipv6" : "ipv4"; const auto query_start = GetTickCount64();
        Json status; std::size_t delivered = 0, decoded = 0, unknown = 0;
        if (refused || page_bounded) status = {{"state", "unavailable"}, {"value", nullptr}, {"reason", "not queried after page refusal/bound"}};
        else {
            const auto result = query(ipv6);
            status = {{"native_error_code", std::to_string(result.error)}, {"native_query_completed_uptime_ms", std::to_string(GetTickCount64())}};
            if (result.error) { status["state"] = result.error == ERROR_NOT_SUPPORTED ? "unsupported" : "unavailable";
                status["value"] = nullptr; status["error_domain"] = "Win32"; }
            else if (result.native_success_without_table) {
                status["state"] = "unavailable"; status["value"] = nullptr;
                status["error_domain"] = "validation"; status["error_code"] = "native_success_without_table";
            }
            else {
                status["reported_rows"] = std::to_string(result.reported_rows);
                const bool bounded = result.reported_rows > row_limit || result.reported_rows > copy_limit / sizeof(MIB_IPINTERFACE_ROW) || result.rows.size() > copy_limit;
                if (bounded || result.rows.size() / sizeof(MIB_IPINTERFACE_ROW) != result.reported_rows || result.rows.size() % sizeof(MIB_IPINTERFACE_ROW)) {
                    status["state"] = "unavailable"; status["value"] = nullptr; status["bound_exceeded"] = bounded;
                    status["error_domain"] = "validation"; status["error_code"] = "native_ip_interface_count_copy_mismatch_or_bound";
                } else {
                    Json rows = Json::array(); std::size_t encoded = 2;
                    const auto flush = [&]() { const auto count = rows.size();
                        if (pages >= 4096) { page_bounded = true; return false; }
                        Json page{{"ip_interface_state_version", "1.0"}, {"page_index", std::to_string(pages++)}, {"source_table", key},
                            {"entries", std::move(rows)}, {"inventory_complete", false}, {"consistency", "non_atomic"}};
                        if (!consumer(std::move(page))) { refused = true; return false; }
                        delivered += count; accepted += count; encoded = 2; rows = Json::array(); return true; };
                    for (std::size_t index = 0; index < result.reported_rows; ++index) {
                        auto value = decode_ip_interface(std::span<const std::byte>{result.rows}.subspan(index * sizeof(MIB_IPINTERFACE_ROW), sizeof(MIB_IPINTERFACE_ROW)));
                        if (value["state"] != "healthy" || value["value"]["reported_address_family"] != std::to_string(ipv6 ? AF_INET6 : AF_INET)) { ++unknown; value["state"] = "degraded"; }
                        value["scope"] = "one reported IP interface table row; no route dependency, persistent lifetime, effective packet path or original padding bytes";
                        value["source"] = "GetIpInterfaceTable"; value["source_table"] = key; value["table_row_index"] = std::to_string(index); ++decoded;
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
        status["uninterpreted_or_invalid_rows"] = std::to_string(unknown); status["source"] = "GetIpInterfaceTable";
        status["requested_address_family"] = key; status["query_started_uptime_ms"] = std::to_string(query_start);
        status["collection_completed_uptime_ms"] = std::to_string(GetTickCount64());
        status["scope"] = "one caller-context family query; compartment identity and all-compartment coverage unverified";
        tables[key] = std::move(status);
    }
    bool any = false; for (const auto& table : tables) if (table.contains("reported_rows")) any = true;
    return {{"state", any ? "degraded" : "unavailable"}, {"ip_interface_state_version", "1.0"}, {"format", "paged_ip_interface_inventory_v1"},
        {"inventory_complete", false}, {"consistency", "non_atomic"}, {"tables", std::move(tables)},
        {"entries_delivered", std::to_string(accepted)}, {"pages_produced", std::to_string(pages)}, {"consumer_refused", refused},
        {"page_bound_exceeded", page_bounded}, {"page_limit", 4096},
        {"native_row_limit", row_limit}, {"copied_native_bytes_limit", copy_limit}, {"native_allocation_bounded", false},
        {"compartment_reference", nullptr}, {"all_compartments_complete", false}, {"interface_lifetimes_verified", false},
        {"collection_started_uptime_ms", std::to_string(started)}, {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"scope", "independent IPv4/IPv6 IP interface census in caller context; no route dependency, persistent lifetime, full compartment or continuous change coverage"}};
}
}

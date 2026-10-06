#include "panopticon/officer/state/route_inventory.hpp"
#include "panopticon/officer/state/ip_interface.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
state::detail::RouteTableResult table(bool ipv6, std::size_t count) {
    state::detail::RouteTableResult result; result.reported_rows = static_cast<std::uint32_t>(count);
    result.rows.resize(count * sizeof(MIB_IPFORWARD_ROW2));
    MIB_IPFORWARD_ROW2 row{}; row.DestinationPrefix.Prefix.si_family = ipv6 ? AF_INET6 : AF_INET;
    row.NextHop.si_family = row.DestinationPrefix.Prefix.si_family; row.Protocol = MIB_IPPROTO_LOCAL;
    row.Origin = NlroWellKnown; row.InterfaceLuid.Value = 18446744073709551615ull;
    row.InterfaceIndex = 4294967295u; row.ValidLifetime = 4294967295u; row.Metric = 4294967295u;
    for (std::size_t i = 0; i < count; ++i) std::memcpy(result.rows.data() + i * sizeof(row), &row, sizeof(row));
    return result;
}
int main(int argc, char** argv) {
    try {
        MIB_IPINTERFACE_ROW interface_row{}; interface_row.Family = AF_INET;
        interface_row.InterfaceLuid.Value = 18446744073709551615ull; interface_row.Metric = 4294967295u;
        interface_row.InterfaceIdentifier = 18446744073709551615ull; interface_row.ZoneIndices[ScopeLevelCount - 1] = 4294967295u;
        auto interface_fact = state::detail::decode_ip_interface(std::as_bytes(std::span{&interface_row, 1}));
        require(interface_fact["value"]["reported_metric"] == "4294967295" && interface_fact["value"]["reported_reserved_interface_identifier"] == "18446744073709551615", "interface DWORD/ULONG64 values preserve full width");
        require(interface_fact["value"]["reported_zone_indices"].back() == "4294967295" && interface_fact["value"]["interface_instance_reference"].is_null(), "zones retained without lifetime identity");
        interface_row.WeakHostSend = 255; interface_row.RouterDiscoveryBehavior = static_cast<NL_ROUTER_DISCOVERY_BEHAVIOR>(4294967295u);
        interface_fact = state::detail::decode_ip_interface(std::as_bytes(std::span{&interface_row, 1}));
        require(interface_fact["state"] == "degraded" && interface_fact["value"]["flags"]["weak_host_send"]["value"].is_null(), "noncanonical flag stays raw and uninterpreted");
        require(interface_fact["value"]["router_discovery_behavior"]["symbol"] == "Unchanged" && interface_fact["value"]["router_discovery_behavior"]["current_behavior_interpreted"] == false, "unchanged sentinel is not current behavior");
        require(state::detail::decode_ip_interface(std::as_bytes(std::span{&interface_row, 1}).first(sizeof(interface_row) - 1))["state"] == "unavailable", "truncated interface row refused");
        std::size_t interface_calls = 0;
        Json metric_rows = Json::array();
        const auto metric_capture = state::detail::collect_route_inventory_pages([&](Json page) {
            for (const auto& value : page["entries"]) metric_rows.push_back(value); return true;
        }, [](bool ipv6) { auto result = table(ipv6, ipv6 ? 0 : 513);
            for (std::size_t i = 0; i < result.reported_rows; ++i) { MIB_IPFORWARD_ROW2 raw{};
                std::memcpy(&raw, result.rows.data() + i * sizeof(raw), sizeof(raw)); raw.Metric = 4294967294u;
                std::memcpy(result.rows.data() + i * sizeof(raw), &raw, sizeof(raw)); } return result;
        }, [&](bool ipv6, std::uint64_t luid, std::uint32_t) {
            ++interface_calls; MIB_IPINTERFACE_ROW raw{}; raw.Family = ipv6 ? AF_INET6 : AF_INET;
            raw.InterfaceLuid.Value = luid; raw.Metric = 4294967295u;
            auto fact = state::detail::decode_ip_interface(std::as_bytes(std::span{&raw, 1}));
            fact["native_query_succeeded"] = true; fact["lookup_key_matches_returned_fields"] = true; return fact;
        });
        require(interface_calls == 1 && metric_capture["ip_interface_query_summary"]["cached_row_reuses"] == "512", "later query is cached once per capture key across pages");
        require(metric_rows[0]["reported_metric_sum"] == "8589934589" && metric_rows[0]["effective_route_metric"].is_null(), "metric arithmetic preserves 64-bit sum without effective route claim");
        const auto interface_denied = state::detail::collect_route_inventory_pages([](Json page) {
            require(page["entries"].size() == 1 && page["entries"][0]["later_ip_interface_query"]["value"].is_null(), "failed lookup does not erase route row"); return true;
        }, [](bool ipv6) { return table(ipv6, ipv6 ? 0 : 1); }, [](bool, std::uint64_t, std::uint32_t) {
            return Json{{"state", "unavailable"}, {"value", nullptr}, {"native_query_succeeded", false}, {"error_code", "5"}};
        });
        require(interface_denied["entries_delivered"] == "1" && interface_denied["ip_interface_query_summary"]["failed_native_queries"] == "1", "lookup failure accounted independently from durable route delivery");
        std::size_t bounded_calls = 0;
        const auto cache_bound = state::detail::collect_route_inventory_pages([](Json) { return true; },
            [](bool ipv6) { auto result = table(ipv6, ipv6 ? 0 : 514);
                for (std::size_t i = 0; i < result.reported_rows; ++i) { MIB_IPFORWARD_ROW2 raw{};
                    std::memcpy(&raw, result.rows.data() + i * sizeof(raw), sizeof(raw)); raw.InterfaceLuid.Value = i + 1;
                    std::memcpy(result.rows.data() + i * sizeof(raw), &raw, sizeof(raw)); } return result;
            }, [&](bool, std::uint64_t, std::uint32_t) { ++bounded_calls;
                return Json{{"state", "unavailable"}, {"value", nullptr}, {"native_query_succeeded", false}, {"error_code", "5"}};
            });
        require(bounded_calls == 512 && cache_bound["ip_interface_query_summary"]["row_queries_not_attempted"] == "2" && cache_bound["entries_delivered"] == "514", "unique lookup bound does not erase remaining route rows");
        auto bytes = table(false, 1);
        auto row = state::detail::decode_route_row(bytes.rows);
        require(row["reported_interface_luid"] == "18446744073709551615" && row["reported_interface_index"] == "4294967295", "native identity fields preserve full width");
        require(row["reported_metric_offset"] == "4294967295" && row["effective_route_metric"].is_null(), "offset cannot invent effective route metric");
        require(row["valid_lifetime_seconds"] == "4294967295" && row["interface_instance_reference"].is_null(), "infinite lifetime sentinel retained without instance identity");
        MIB_IPFORWARD_ROW2 native{}; std::memcpy(&native, bytes.rows.data(), sizeof(native));
        native.Protocol = static_cast<NL_ROUTE_PROTOCOL>(4294967295u); native.Origin = static_cast<NL_ROUTE_ORIGIN>(4294967295u);
        native.DestinationPrefix.PrefixLength = 33; native.SitePrefixLength = 255; native.Publish = 255;
        std::memcpy(bytes.rows.data(), &native, sizeof(native)); row = state::detail::decode_route_row(bytes.rows);
        require(row["state"] == "degraded" && row["protocol_symbol"].is_null() && row["reported_protocol"] == "4294967295", "unknown full-width protocol does not become a default");
        require(row["destination_prefix_valid"] == false && row["site_prefix_valid"] == false && row["publish"]["value"].is_null(), "invalid prefix and raw BOOLEAN retained without guessing");
        bytes.rows.pop_back(); require(state::detail::decode_route_row(bytes.rows)["state"] == "unavailable", "truncated row refused");
        const auto denied = state::detail::collect_route_inventory_pages([](Json) { throw std::runtime_error("native denial cannot emit pages"); return true; },
            [](bool) { state::detail::RouteTableResult result; result.error = ERROR_ACCESS_DENIED; return result; });
        require(denied["state"] == "unavailable" && denied["tables"]["ipv6"]["native_error_code"] == "5", "independent errors retained");
        const auto missing = state::detail::collect_route_inventory_pages([](Json) { throw std::runtime_error("missing successful route table cannot emit pages"); return true; },
            [](bool) { state::detail::RouteTableResult result; result.native_success_without_table = true; return result; });
        require(missing["tables"]["ipv4"]["native_error_code"] == "0" && missing["tables"]["ipv4"]["error_domain"] == "validation" && missing["state"] == "unavailable", "missing route table does not invent a Win32 failure");
        const auto bounded = state::detail::collect_route_inventory_pages([](Json) { throw std::runtime_error("bounded table cannot emit rows"); return true; },
            [](bool) { state::detail::RouteTableResult result; result.reported_rows = 65537; return result; });
        require(bounded["tables"]["ipv4"]["bound_exceeded"] == true && bounded["entries_delivered"] == "0", "reported native row bound enforced before reads");
        std::size_t attempts = 0, accepted_prefix = 0;
        const auto partial = state::detail::collect_route_inventory_pages([&](Json page) {
            if (++attempts == 1) { accepted_prefix = page.at("entries").size(); return true; } return false;
        },
            [](bool ipv6) { require(!ipv6, "next family not queried after refusal"); return table(false, 513); });
        require(accepted_prefix > 0 && partial["entries_delivered"] == std::to_string(accepted_prefix) && partial["consumer_refused"] == true && partial["tables"]["ipv4"]["reported_rows_in_accepted_pages"] == false, "refused page cannot count as accepted route rows");
        std::string error; const auto boot = core::query_native_boot_id(error);
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), boot, 1};
        auto begin = factory.state("route_inventory_begin", {{"inventory_complete", false}});
        Json records = Json::array({begin}), ids = Json::array(); std::size_t pages = 0, count = 0;
        auto summary = state::collect_route_inventory_pages([&](Json page) {
            require(page["page_index"] == std::to_string(pages++), "route pages ordered");
            require(page["entries"].size() <= 256 && page["entries"].dump().size() <= 512 * 1024, "route pages bounded");
            for (const auto& value : page["entries"]) { ++count;
                require(value["interface_instance_reference"].is_null() && value["route_instance_reference"].is_null() && value["effective_route_metric"].is_null(), "native route cannot invent lifetime or effective path"); }
            page["capture_id"] = begin.at("record_id"); auto record = factory.state("route_inventory_page", std::move(page));
            ids.push_back(record.at("record_id")); records.push_back(std::move(record)); return true;
        });
        require(summary["entries_delivered"] == std::to_string(count) && summary["inventory_complete"] == false && summary["all_compartments_complete"] == false, "actual accepted routes accounted without host/compartment census claim");
        for (const auto& query : summary["tables"]) {
            if (query["state"] == "healthy") require(query["reported_rows"] == query["rows_in_accepted_pages"], "healthy table has all reported rows accepted");
            else require(query["state"] == "degraded" || query["state"] == "unavailable" || query["state"] == "unsupported", "native table failures remain explicit");
        }
        summary["capture_id"] = begin.at("record_id"); summary["page_record_ids"] = ids;
        records.push_back(factory.state("route_inventory", summary));
        if (argc == 2 && std::string{argv[1]} == "--emit-live") std::cout << records.dump() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

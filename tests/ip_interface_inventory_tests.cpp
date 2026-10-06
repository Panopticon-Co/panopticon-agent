#include "panopticon/officer/state/ip_interface_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* text) { if (!value) throw std::runtime_error(text); }
state::detail::IpInterfaceTableResult table(bool ipv6, std::size_t count) {
    state::detail::IpInterfaceTableResult result; result.reported_rows = static_cast<std::uint32_t>(count);
    result.rows.resize(count * sizeof(MIB_IPINTERFACE_ROW));
    for (std::size_t i = 0; i < count; ++i) { MIB_IPINTERFACE_ROW row{};
        row.Family = ipv6 ? AF_INET6 : AF_INET; row.InterfaceLuid.Value = i + 1; row.ForwardingEnabled = 1;
        std::memcpy(result.rows.data() + i * sizeof(row), &row, sizeof(row)); }
    return result;
}
int main(int argc, char** argv) {
    try {
        std::size_t independent_count = 0;
        const auto independent = state::detail::collect_ip_interface_inventory_pages([&](Json page) {
            for (const auto& row : page["entries"]) { ++independent_count;
                require(row["value"]["flags"]["forwarding_enabled"]["value"] == true && row["value"]["interface_instance_reference"].is_null(), "independent interface posture retained without lifetime/route join"); }
            return true;
        }, [](bool ipv6) { return table(ipv6, 3); });
        require(independent_count == 6 && independent["entries_delivered"] == "6", "both interface families captured without any route source");
        const auto mismatched = state::detail::collect_ip_interface_inventory_pages([](Json) { throw std::runtime_error("malformed copy must not produce pages"); return true; },
            [](bool ipv6) { auto result = table(ipv6, 1); result.reported_rows = 2; return result; });
        require(mismatched["tables"]["ipv4"]["state"] == "unavailable" && mismatched["entries_delivered"] == "0", "count outside copied SDK rows refused before reads");
        const auto missing = state::detail::collect_ip_interface_inventory_pages([](Json) { throw std::runtime_error("missing successful table must not produce pages"); return true; },
            [](bool) { state::detail::IpInterfaceTableResult result; result.native_success_without_table = true; return result; });
        require(missing["state"] == "unavailable" && missing["tables"]["ipv4"]["native_error_code"] == "0" && missing["tables"]["ipv4"]["error_domain"] == "validation", "missing table preserves native success separately from validation refusal");
        const auto bounded = state::detail::collect_ip_interface_inventory_pages([](Json) { throw std::runtime_error("oversized native count must not produce pages"); return true; },
            [](bool) { state::detail::IpInterfaceTableResult result; result.reported_rows = 65537; return result; });
        require(bounded["tables"]["ipv6"]["bound_exceeded"] == true, "native count/copy bounds explicit");
        const auto failure = state::detail::collect_ip_interface_inventory_pages([](Json) { return true; },
            [](bool ipv6) { auto result = table(ipv6, 0); result.error = ipv6 ? ERROR_ACCESS_DENIED : ERROR_NOT_SUPPORTED; return result; });
        require(failure["tables"]["ipv4"]["state"] == "unsupported" && failure["tables"]["ipv6"]["native_error_code"] == "5", "independent family support and native errors retained");
        std::size_t attempts = 0, prefix = 0;
        const auto refused = state::detail::collect_ip_interface_inventory_pages([&](Json page) {
            if (++attempts == 1) { prefix = page["entries"].size(); return true; } return false;
        }, [](bool ipv6) { require(!ipv6, "later family not queried after refusal"); return table(false, 513); });
        require(prefix > 0 && refused["consumer_refused"] == true && refused["entries_delivered"] == std::to_string(prefix), "only accepted page prefix counts as delivered");
        std::string error; const auto boot = core::query_native_boot_id(error);
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), boot, 1};
        auto begin = factory.state("ip_interface_inventory_begin", {{"inventory_complete", false}});
        Json records = Json::array({begin}), ids = Json::array(); std::size_t pages = 0, count = 0;
        auto summary = state::collect_ip_interface_inventory_pages([&](Json page) {
            require(page["page_index"] == std::to_string(pages++), "interface pages ordered");
            require(page["entries"].size() <= 256 && page["entries"].dump().size() <= 512 * 1024, "interface page bounds hold");
            for (const auto& row : page["entries"]) { ++count; require(row["value"]["interface_instance_reference"].is_null(), "actual native table cannot invent interface lifetime"); }
            page["capture_id"] = begin.at("record_id"); auto record = factory.state("ip_interface_inventory_page", std::move(page));
            ids.push_back(record.at("record_id")); records.push_back(std::move(record)); return true;
        });
        require(summary["entries_delivered"] == std::to_string(count) && summary["inventory_complete"] == false && summary["native_allocation_bounded"] == false, "native caller census preserves count and allocation/coverage limitations");
        summary["capture_id"] = begin.at("record_id"); summary["page_record_ids"] = ids;
        records.push_back(factory.state("ip_interface_inventory", summary));
        if (argc == 2 && std::string{argv[1]} == "--emit-live") std::cout << records.dump() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

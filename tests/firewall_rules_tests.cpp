#include "panopticon/officer/state/firewall_rules.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void detached_rule_extensions() {
    require(SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)), "owned COM initialization");
    struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
    INetFwRule3* rule = nullptr;
    require(SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule3), reinterpret_cast<void**>(&rule))) && rule, "detached rule activation");
    struct Owner { INetFwRule3* value; ~Owner() { value->Release(); } } owner{rule};
    // This object is never added to INetFwRules; setters affect only the owned test object.
    require(SUCCEEDED(rule->put_EdgeTraversalOptions(3)), "detached edge option");
    require(SUCCEEDED(rule->put_SecureFlags(4)), "detached IPsec requirement");
    BSTR sid = SysAllocString(L"S-1-5-21-1-2-3-1001");
    require(sid != nullptr, "owned SID text");
    const auto set = rule->put_LocalUserOwner(sid); SysFreeString(sid);
    require(SUCCEEDED(set), "detached owner text");
    const auto values = state::detail::query_firewall_rule_fields(rule);
    require(values["fields"].size() == 25, "extended getter surface incomplete");
    require(values["fields"]["edge_traversal_options"]["value"] == "3" &&
        values["fields"]["secure_flags"]["value"] == "4", "extended enum values changed");
    require(values["fields"]["local_user_owner"]["value"] == "S-1-5-21-1-2-3-1001", "owner text changed");
    const auto failed = state::detail::query_firewall_rule_fields(rule,
        [](const char* name, void**) -> long {
            return std::string{name} == "QueryInterface(INetFwRule2)" ? E_NOINTERFACE : E_ACCESSDENIED;
        });
    require(failed["fields"]["edge_traversal_options"]["state"] == "unsupported" &&
        failed["fields"]["secure_flags"]["state"] == "unavailable", "unsupported/refused interfaces conflated");
    require(failed["fields"]["secure_flags"]["hresult_code"].is_null() &&
        failed["fields"]["secure_flags"]["query_attempted"] == false, "unattempted getter fabricated HRESULT");
    require(failed["extension_interface_queries"]["QueryInterface(INetFwRule3)"]["hresult_code"] == "2147942405",
        "interface refusal lost native error");
    require(failed["fields"]["enabled"]["query_attempted"] == true, "extension refusal suppressed base getters");
    const auto missing = state::detail::query_firewall_rule_fields(rule,
        [](const char*, void**) -> long { return S_OK; });
    require(missing["extension_interface_queries"]["QueryInterface(INetFwRule3)"]["hresult_code"] == "0" &&
        missing["extension_interface_queries"]["QueryInterface(INetFwRule3)"]["validation_error"] ==
            "native_success_without_interface", "missing interface fabricated native failure");
}
int main(int argc, char** argv) {
    try {
        detached_rule_extensions();
        std::vector<Json> pages;
        const auto fake = [](const std::function<bool(Json)>& consume) {
            unsigned rows = 0;
            for (unsigned i = 0; i < 150; ++i) {
                ++rows;
                if (!consume({{"enumeration_index", std::to_string(i)}, {"name", "same"}, {"rule_reference", nullptr},
                    {"payload", std::string(12000, 'a')}})) break;
            }
            return Json{{"state", "degraded"}, {"rows_queried", std::to_string(rows)}, {"enumeration_completed", rows == 150}};
        };
        const auto partial = state::detail::collect_firewall_rule_pages([&](Json page) {
            pages.push_back(page); return pages.size() != 2;
        }, fake);
        require(partial["consumer_refused"] == true && partial["pages_produced"] == "2", "consumer refusal not accounted");
        require(partial["entries_delivered"] == std::to_string(pages[0]["entries"].size()), "refused page credited accepted rows");
        require(pages[0]["entries"].size() < 64 && pages[0]["entries"].dump().size() <= 512 * 1024,
            "encoded byte bound ignored in favor of row count");
        pages.clear();
        const auto complete = state::detail::collect_firewall_rule_pages([&](Json page) { pages.push_back(page); return true; }, fake);
        require(complete["entries_delivered"] == "150" && complete["inventory_complete"] == false,
            "full accepted enumeration claimed full firewall inventory");
        const auto bounded = state::detail::collect_firewall_rule_pages([](Json) { return true; },
            [](const std::function<bool(Json)>& consume) {
                consume({{"payload", std::string(300000, 'x')}}); return Json{{"state", "degraded"}};
            });
        require(bounded["page_bound_exceeded"] == true && bounded["entries_delivered"] == "0", "oversized row falsely delivered");
        const auto unavailable = state::detail::collect_firewall_rule_pages([](Json) { return true; },
            [](const std::function<bool(Json)>&) { return Json{{"state", "unavailable"}, {"hresult_code", "2147942405"}}; });
        require(unavailable["state"] == "unavailable" && unavailable["native_enumeration"]["hresult_code"] == "2147942405",
            "unavailable enumeration became empty complete inventory");
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
        Json records = Json::array();
        const auto begin = factory.state("firewall_rule_inventory_begin", {{"inventory_complete", false}});
        const auto capture_id = begin.at("record_id");
        auto page_ids = Json::array(); records.push_back(begin);
        auto native = state::collect_firewall_rule_pages([&](Json page) {
            require(page["entries"].size() <= 64 && page["entries"].dump().size() <= 512 * 1024, "native page bounds");
            for (const auto& row : page["entries"]) {
                require(row["rule_reference"].is_null() && row["process_reference"].is_null(), "native rule fields became instance identity");
                if (!row["fields"].empty()) require(row["fields"].size() == 25, "native rule getter fields omitted");
            }
            page["capture_id"] = capture_id;
            const auto record = factory.state("firewall_rule_inventory_page", std::move(page));
            page_ids.push_back(record.at("record_id")); records.push_back(record); return true;
        });
        native["capture_id"] = capture_id; native["page_record_ids"] = page_ids;
        records.push_back(factory.state("firewall_rule_inventory", native));
        if (argc == 2 && std::string{argv[1]} == "--emit-live") { std::cout << records.dump() << '\n'; return 0; }
        std::cout << "Firewall rule paging/refusal/byte bounds and read-only native enumeration passed: "
            << native["entries_delivered"] << " rows\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

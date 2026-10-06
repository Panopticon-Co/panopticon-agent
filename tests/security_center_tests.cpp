#include "panopticon/officer/state/security_center.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool ok, const char* text) { if (!ok) throw std::runtime_error(text); }
Json platform_cases() {
    using state::detail::SecurityPlatformResult;
    const auto client = state::detail::security_center_platform({true, 0, 0, 10, 0, 26100, 1, 10, 11});
    const auto server = state::detail::security_center_platform({true, 0, 0, 10, 0, 26100, 3, 10, 11});
    const auto controller = state::detail::security_center_platform({true, 0, 0, 10, 0, 26100, 2, 10, 11});
    const auto unknown = state::detail::security_center_platform({true, 0, 0, 10, 0, 26100, 99, 10, 11});
    const auto failed = state::detail::security_center_platform({true, 0xc0000022u, 0, 10, 0, 26100, 3, 10, 11});
    const auto unresolved = state::detail::security_center_platform({false, 0, 127, 0, 0, 0, 0, 10, 11});
    const auto old = state::detail::security_center_platform({true, 0, 0, 5, 2, 3790, 1, 10, 11});
    const auto odd = state::detail::security_center_platform({true, 1, 0, 10, 0, 26100, 3, 10, 11});
    require(client["wsc_contract_supported"] == true && client["platform_qualified"] == false,
        "client eligibility became full qualification");
    require(server["state"] == "unsupported" && controller["state"] == "unsupported" && old["state"] == "unsupported",
        "unsupported contract platform misclassified");
    require(unknown["wsc_contract_supported"].is_null() && odd["wsc_contract_supported"].is_null(),
        "unknown/nonzero native version result guessed platform");
    require(failed["ntstatus_code"] == "3221225506" && failed["raw_version"].is_null() &&
        failed["wsc_contract_supported"].is_null(), "failed NTSTATUS output became server proof");
    require(unresolved["ntstatus_code"].is_null() && unresolved["resolver_error_code"] == "127",
        "resolver error fabricated NTSTATUS");
    unsigned calls = 0;
    const auto query = [&](std::uint32_t) { ++calls; return state::detail::SecurityHealthResult{0, 0, 12, 13}; };
    const auto retained = state::detail::collect_security_center_state(query, Json::object(), server);
    require(calls == 6 && retained["state"] == "unsupported" && retained["native_query_state"] == "degraded",
        "unsupported platform suppressed descriptive native queries");
    require(retained["fields"]["antivirus"]["reported_health"].is_null() &&
        retained["fields"]["antivirus"]["native_reported_health"] == "good" &&
        retained["fields"]["antivirus"]["raw_output"] == "0", "outside-contract native evidence lost or trusted");
    return Json::array({state::detail::collect_security_center_state(query, Json::object(), client),
        retained, state::detail::collect_security_center_state(query, Json::object(), unknown),
        state::detail::collect_security_center_state(query, Json::object(), failed)});
}
int main(int argc, char** argv) {
    try {
        const auto platform = platform_cases();
        std::vector<std::uint32_t> masks;
        const auto mixed = state::detail::collect_security_center_state([&](std::uint32_t mask) {
            masks.push_back(mask);
            if (mask == 1) return state::detail::SecurityHealthResult{0, 0, 10, 11};
            if (mask == 2) return state::detail::SecurityHealthResult{0, 1, 11, 12};
            if (mask == 4) return state::detail::SecurityHealthResult{1, 2, 12, 13};
            if (mask == 16) return state::detail::SecurityHealthResult{0x80070005u, 3, 13, 14};
            if (mask == 32) return state::detail::SecurityHealthResult{0, 99, 14, 15};
            return state::detail::SecurityHealthResult{0, 3, 15, 16};
        });
        require(masks == std::vector<std::uint32_t>{1, 2, 4, 16, 32, 64}, "category queries combined or legacy spyware queried");
        require(mixed["fields"]["antivirus"]["hresult_code"] == "1" &&
            mixed["fields"]["antivirus"]["reported_health"].is_null() &&
            mixed["fields"]["antivirus"]["raw_output"] == "2" &&
            mixed["fields"]["antivirus"]["state"] == "unavailable", "S_FALSE fallback became product health");
        require(mixed["fields"]["internet_settings"]["hresult_code"] == "2147942405" &&
            mixed["fields"]["internet_settings"]["raw_output"].is_null(), "failed getter output interpreted");
        require(mixed["fields"]["user_account_control"]["raw_output"] == "99" &&
            mixed["fields"]["user_account_control"]["reported_health"].is_null(), "unknown enum coerced");
        require(mixed["fields"]["security_center_service"]["reported_health"] == "snooze" &&
            mixed["fields"]["automatic_updates"]["reported_health"] == "not_monitored", "recognized reports lost");
        const auto absent = state::detail::collect_security_center_state({}, {{"error_domain", "WIN32"}, {"error_code", "126"}});
        require(absent["query_summary"]["queries_not_attempted"] == "6" && absent["state"] == "unavailable",
            "missing API became known empty protection");
        const auto sentinel = state::detail::collect_security_center_state([](std::uint32_t) {
            return state::detail::SecurityHealthResult{0, -1, 10, 11};
        });
        require(sentinel["query_summary"]["uninterpreted_outputs"] == "6", "unchanged sentinel accepted");
        const auto stopped = state::detail::collect_security_center_state([](std::uint32_t) {
            return state::detail::SecurityHealthResult{1, 2, 10, 11};
        });
        require(stopped["state"] == "unavailable" && stopped["query_summary"]["s_false_service_unavailable"] == "6",
            "stopped WSC reported protected");
        const auto poor = state::detail::collect_security_center_state([](std::uint32_t) {
            return state::detail::SecurityHealthResult{0, 2, 10, 11};
        });
        require(poor["fields"]["antivirus"]["state"] == "healthy" &&
            poor["fields"]["antivirus"]["reported_health"] == "poor" &&
            poor["fields"]["antivirus"]["protection_verified"] == false, "getter quality conflated with protection");
        const auto odd = state::detail::collect_security_center_state([](std::uint32_t) {
            return state::detail::SecurityHealthResult{2, 0, 10, 11};
        });
        require(odd["fields"]["antivirus"]["state"] == "degraded" &&
            odd["fields"]["antivirus"]["hresult_code"] == "2", "other success HRESULT flattened");
        const auto invalid_fallback = state::detail::collect_security_center_state([](std::uint32_t) {
            return state::detail::SecurityHealthResult{1, 99, 10, 11};
        });
        require(invalid_fallback["fields"]["antivirus"]["validation_error"] == "unexpected_s_false_output" &&
            invalid_fallback["fields"]["antivirus"]["reported_health"].is_null(), "invalid S_FALSE fallback guessed");
        const auto native = state::collect_security_center_state();
        require(native["fields"].size() == 6 && native["inventory_complete"] == false && native["protection_verified"] == false,
            "native category state claimed complete protection");
        if (argc == 2 && (std::string{argv[1]} == "--emit-fixtures" || std::string{argv[1]} == "--emit-platform")) {
            pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
            pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
            Json records = Json::array();
            if (std::string{argv[1]} == "--emit-platform")
                for (const auto& value : platform) records.push_back(factory.state("security_center_state", value));
            else for (const auto& value : {mixed, absent, sentinel, stopped, native}) records.push_back(factory.state("security_center_state", value));
            std::cout << records.dump() << '\n'; return 0;
        }
        std::cout << "Security Center category HRESULT/fallback/sentinel queries passed; native " << native["query_summary"].dump() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

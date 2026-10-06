#include "panopticon/officer/state/firewall_profiles.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <netfw.h>
#include <array>
#include <limits>
#include <stdexcept>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
using Field = detail::FirewallField;
struct Descriptor { Field field; const char* key; const char* method; };
constexpr std::array properties{
    Descriptor{Field::enabled, "locally_enabled", "get_FirewallEnabled"},
    Descriptor{Field::block_inbound, "block_all_inbound_traffic", "get_BlockAllInboundTraffic"},
    Descriptor{Field::notifications_disabled, "notifications_disabled", "get_NotificationsDisabled"},
    Descriptor{Field::unicast_responses_disabled, "unicast_responses_to_multicast_broadcast_disabled", "get_UnicastResponsesToMulticastBroadcastDisabled"},
    Descriptor{Field::default_inbound, "default_inbound_action", "get_DefaultInboundAction"},
    Descriptor{Field::default_outbound, "default_outbound_action", "get_DefaultOutboundAction"}
};
Json base() {
    return {{"collector", "native_firewall_profiles"}, {"collector_version", "1.1"},
        {"state", "unavailable"}, {"inventory_complete", false}, {"effective_packet_policy_verified", false},
        {"atomic_policy_snapshot", false}, {"rules_collected", false}, {"excluded_interfaces_collected", false},
        {"scope", "sequential caller-visible INetFwPolicy2 selected profile getters; not rule/filter coverage or effective packet enforcement"},
        {"profiles", Json::array()}};
}
Json failure(const char* stage, HRESULT error) {
    auto result = base();
    result["initialization"] = {{"state", "unavailable"}, {"stage", stage},
        {"error_domain", "HRESULT"}, {"hresult_code", std::to_string(static_cast<std::uint32_t>(error))}};
    result["exclusion_query_summary"] = {{"successful_queries", "0"}, {"failed_queries", "0"},
        {"incomplete_queries", "0"}, {"queries_not_attempted", "3"}};
    result["query_summary"] = {{"successful_queries", "0"}, {"failed_queries", "0"},
        {"uninterpreted_queries", "0"}, {"queries_not_attempted", "20"}};
    return result;
}
}
Json detail::collect_firewall_profile_state(const FirewallQuery& query, const FirewallExclusionQuery& exclusions) {
    if (!query) throw std::invalid_argument("firewall query backend missing");
    auto result = base();
    unsigned successful = 0, failed = 0, invalid = 0;
    const auto read = [&](Field field, std::uint32_t profile, const char* method) {
        const auto native = query(field, profile);
        Json fact{{"source", std::string{"INetFwPolicy2::"} + method},
            {"requested_profile_type", std::to_string(profile)}, {"error_domain", "HRESULT"},
            {"hresult_code", std::to_string(native.hresult)},
            {"query_started_uptime_ms", std::to_string(native.started_uptime_ms)},
            {"query_completed_uptime_ms", std::to_string(native.completed_uptime_ms)},
            {"output_write_verified", false}, {"raw_output", nullptr}, {"value", nullptr}};
        if (native.hresult & 0x80000000u) { ++failed; fact["state"] = "unavailable"; return fact; }
        ++successful;
        fact["raw_output"] = std::to_string(native.output);
        bool known = true;
        switch (field) {
        case Field::current_profiles:
            known = native.output >= 0 && (native.output & ~7) == 0;
            if (known) fact["value"] = {{"domain", (native.output & 1) != 0},
                {"private", (native.output & 2) != 0}, {"public", (native.output & 4) != 0}};
            break;
        case Field::modify_state:
            known = native.output >= 0 && native.output <= 2;
            if (known) fact["value"] = native.output == 0 ? "ok" : native.output == 1 ? "group_policy_override" : "inbound_blocked";
            break;
        case Field::default_inbound: case Field::default_outbound:
            known = native.output == 0 || native.output == 1;
            if (known) fact["value"] = native.output == 0 ? "block" : "allow";
            break;
        default:
            known = native.output == VARIANT_FALSE || native.output == VARIANT_TRUE;
            if (known) fact["value"] = native.output == VARIANT_TRUE;
            break;
        }
        if (!known || native.hresult != 0) ++invalid;
        fact["state"] = known && native.hresult == 0 ? "healthy" : "degraded";
        fact["scope"] = "selected getter output only; invalid sentinel may remain unchanged; no effective policy or atomic snapshot claim";
        return fact;
    };
    result["reported_current_profile_types"] = read(Field::current_profiles, 0, "get_CurrentProfileTypes");
    result["reported_local_policy_modify_state"] = read(Field::modify_state, 0, "get_LocalPolicyModifyState");
    unsigned exclusion_success = 0, exclusion_failure = 0, exclusion_incomplete = 0;
    for (const auto profile : {1u, 2u, 4u}) {
        Json row{{"profile_type", std::to_string(profile)},
            {"profile_name", profile == 1 ? "domain" : profile == 2 ? "private" : "public"},
            {"interface_reference", nullptr}, {"fields", Json::object()}};
        for (const auto& property : properties)
            row["fields"][property.key] = read(property.field, profile, property.method);
        if (exclusions) {
            auto fact = exclusions(profile);
            if (fact.at("hresult_code").get<std::string>().empty()) throw std::logic_error("missing exclusion HRESULT");
            const auto code = std::stoull(fact.at("hresult_code").get<std::string>());
            if (code & 0x80000000u) ++exclusion_failure;
            else { ++exclusion_success; if (fact.at("state") != "healthy") ++exclusion_incomplete; }
            row["fields"]["excluded_interfaces"] = std::move(fact);
        } else row["fields"]["excluded_interfaces"] = {{"state", "unavailable"}, {"value", nullptr},
            {"source", "INetFwPolicy2::get_ExcludedInterfaces"}, {"query_attempted", false}};
        result["profiles"].push_back(std::move(row));
    }
    result["query_summary"] = {{"successful_queries", std::to_string(successful)},
        {"failed_queries", std::to_string(failed)}, {"uninterpreted_queries", std::to_string(invalid)},
        {"queries_not_attempted", "0"}};
    result["exclusion_query_summary"] = {{"successful_queries", std::to_string(exclusion_success)},
        {"failed_queries", std::to_string(exclusion_failure)}, {"incomplete_queries", std::to_string(exclusion_incomplete)},
        {"queries_not_attempted", exclusions ? "0" : "3"}};
    result["excluded_interfaces_collected"] = exclusion_success == 3 && exclusion_incomplete == 0;
    result["state"] = successful || exclusion_success ? "degraded" : "unavailable";
    return result;
}
Json collect_firewall_profile_state() {
    const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized)) return failure("CoInitializeEx", initialized);
    struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
    INetFwPolicy2* policy = nullptr;
    const auto created = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&policy));
    struct Policy { INetFwPolicy2* value; ~Policy() { if (value) value->Release(); } } owner{policy};
    if (FAILED(created)) return failure("CoCreateInstance(INetFwPolicy2)", created);
    if (!policy) {
        auto result = failure("CoCreateInstance(INetFwPolicy2)", created);
        result["initialization"]["validation_error"] = "native_success_without_interface";
        return result;
    }
    auto result = detail::collect_firewall_profile_state([&](Field field, std::uint32_t profile) {
        detail::FirewallQueryResult value;
        value.started_uptime_ms = GetTickCount64();
        const auto type = static_cast<NET_FW_PROFILE_TYPE2>(profile);
        VARIANT_BOOL boolean = 2;
        NET_FW_ACTION action = NET_FW_ACTION_MAX;
        long mask = std::numeric_limits<long>::min();
        NET_FW_MODIFY_STATE modification = static_cast<NET_FW_MODIFY_STATE>(-1);
        HRESULT status;
        switch (field) {
        case Field::current_profiles: status = policy->get_CurrentProfileTypes(&mask); value.output = mask; break;
        case Field::modify_state: status = policy->get_LocalPolicyModifyState(&modification); value.output = modification; break;
        case Field::enabled: status = policy->get_FirewallEnabled(type, &boolean); value.output = boolean; break;
        case Field::block_inbound: status = policy->get_BlockAllInboundTraffic(type, &boolean); value.output = boolean; break;
        case Field::notifications_disabled: status = policy->get_NotificationsDisabled(type, &boolean); value.output = boolean; break;
        case Field::unicast_responses_disabled: status = policy->get_UnicastResponsesToMulticastBroadcastDisabled(type, &boolean); value.output = boolean; break;
        case Field::default_inbound: status = policy->get_DefaultInboundAction(type, &action); value.output = action; break;
        case Field::default_outbound: status = policy->get_DefaultOutboundAction(type, &action); value.output = action; break;
        default: throw std::logic_error("unknown firewall query selector");
        }
        value.hresult = static_cast<std::uint32_t>(status);
        value.completed_uptime_ms = GetTickCount64();
        return value;
    }, [&](std::uint32_t profile) {
        VARIANT variant; VariantInit(&variant); variant.vt = VT_ERROR; variant.scode = E_UNEXPECTED;
        struct Clear { VARIANT* value; ~Clear() { if (value) VariantClear(value); } } clear{&variant};
        const auto started = GetTickCount64();
        const auto status = policy->get_ExcludedInterfaces(static_cast<NET_FW_PROFILE_TYPE2>(profile), &variant);
        const auto completed = GetTickCount64();
        auto fact = SUCCEEDED(status) ? detail::decode_firewall_exclusions(&variant) :
            Json{{"state", "unavailable"}, {"value", nullptr}, {"complete", false}};
        fact["source"] = "INetFwPolicy2::get_ExcludedInterfaces";
        fact["requested_profile_type"] = std::to_string(profile); fact["error_domain"] = "HRESULT";
        fact["hresult_code"] = std::to_string(static_cast<std::uint32_t>(status));
        fact["query_started_uptime_ms"] = std::to_string(started); fact["query_completed_uptime_ms"] = std::to_string(completed);
        if (SUCCEEDED(status) && status != S_OK) fact["state"] = "degraded";
        const auto cleared = VariantClear(&variant); clear.value = nullptr;
        fact["variant_clear_hresult_code"] = std::to_string(static_cast<std::uint32_t>(cleared));
        if (FAILED(cleared) && SUCCEEDED(status)) fact["state"] = "degraded";
        return fact;
    });
    result["initialization"] = {{"state", "healthy"}, {"error_domain", "HRESULT"},
        {"coinitialize_hresult_code", std::to_string(static_cast<std::uint32_t>(initialized))},
        {"cocreate_hresult_code", std::to_string(static_cast<std::uint32_t>(created))},
        {"scope", "COM initialization/registered local class activation only; server integrity not attested"}};
    return result;
}
}

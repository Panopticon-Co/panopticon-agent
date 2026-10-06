#include "panopticon/officer/state/security_center.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wscapi.h>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
struct Provider { const char* name; std::uint32_t mask; };
constexpr Provider providers[]{{"firewall", 1}, {"automatic_updates", 2}, {"antivirus", 4},
    {"internet_settings", 16}, {"user_account_control", 32}, {"security_center_service", 64}};
Json native_platform() {
    detail::SecurityPlatformResult result;
    result.started_uptime_ms = GetTickCount64();
    const auto module = GetModuleHandleW(L"ntdll.dll"); // Borrowed core module; do not release it.
    if (!module) result.resolver_error = GetLastError();
    else {
        using Version = LONG(WINAPI*)(OSVERSIONINFOEXW*);
        const auto version = reinterpret_cast<Version>(GetProcAddress(module, "RtlGetVersion"));
        if (!version) result.resolver_error = GetLastError();
        else {
            OSVERSIONINFOEXW value{}; value.dwOSVersionInfoSize = sizeof(value);
            result.attempted = true; result.ntstatus = static_cast<std::uint32_t>(version(&value));
            result.major = value.dwMajorVersion; result.minor = value.dwMinorVersion;
            result.build = value.dwBuildNumber; result.product_type = value.wProductType;
        }
    }
    result.completed_uptime_ms = GetTickCount64();
    return detail::security_center_platform(result);
}
}
Json detail::security_center_platform(const SecurityPlatformResult& result) {
    Json fact{{"source", "RtlGetVersion/OSVERSIONINFOEXW"}, {"query_attempted", result.attempted},
        {"state", "unavailable"}, {"ntstatus_error_domain", "NTSTATUS"},
        {"ntstatus_code", result.attempted ? Json(std::to_string(result.ntstatus)) : Json(nullptr)},
        {"resolver_error_domain", "WIN32"}, {"resolver_error_code", std::to_string(result.resolver_error)},
        {"query_started_uptime_ms", std::to_string(result.started_uptime_ms)},
        {"query_completed_uptime_ms", std::to_string(result.completed_uptime_ms)},
        {"raw_version", nullptr}, {"wsc_contract_supported", nullptr}, {"platform_qualified", false}};
    if (!result.attempted) { fact["reason"] = "native_version_api_unavailable"; return fact; }
    if (result.ntstatus & 0x80000000u) { fact["reason"] = "native_version_query_failed"; return fact; }
    fact["raw_version"] = {{"major", std::to_string(result.major)}, {"minor", std::to_string(result.minor)},
        {"build", std::to_string(result.build)}, {"product_type", std::to_string(result.product_type)}};
    if (result.ntstatus != 0 || result.major == 0 || result.product_type < 1 || result.product_type > 3) {
        fact["state"] = "degraded"; fact["reason"] = "native_version_output_uninterpreted"; return fact;
    }
    if (result.product_type != 1 || result.major < 6) {
        fact["state"] = "unsupported"; fact["wsc_contract_supported"] = false;
        fact["reason"] = result.product_type != 1 ? "wsc_api_has_no_supported_server_contract" : "wsc_api_requires_vista_or_later_client";
    } else {
        fact["state"] = "healthy"; fact["wsc_contract_supported"] = true;
        fact["reason"] = "client_meets_documented_minimum_not_full_qualification";
    }
    return fact;
}
Json detail::collect_security_center_state(const SecurityHealthQuery& query, Json availability, Json platform) {
    Json fields = Json::object(); unsigned ok = 0, stopped = 0, failed = 0, other = 0, unknown = 0, unattempted = 0;
    for (const auto& provider : providers) {
        Json field{{"source", "WscGetSecurityProviderHealth"}, {"requested_provider_mask", std::to_string(provider.mask)},
            {"query_attempted", static_cast<bool>(query)}, {"state", "unavailable"}, {"error_domain", "HRESULT"},
            {"hresult_code", nullptr}, {"raw_output", nullptr}, {"reported_health", nullptr},
            {"query_started_uptime_ms", nullptr}, {"query_completed_uptime_ms", nullptr},
            {"protection_verified", false}, {"scope", "WSC aggregate category report; not individual product inventory or verified protection"}};
        if (!query) { ++unattempted; field["reason"] = "native_api_unavailable"; }
        else {
            const auto result = query(provider.mask);
            field["hresult_code"] = std::to_string(result.hresult);
            field["query_started_uptime_ms"] = std::to_string(result.started_uptime_ms);
            field["query_completed_uptime_ms"] = std::to_string(result.completed_uptime_ms);
            if (result.hresult & 0x80000000u) ++failed;
            else {
                field["raw_output"] = std::to_string(result.output);
                if (result.hresult == 1) {
                    ++stopped; field["reason"] = "wsc_service_unavailable_s_false";
                    // Documented fallback POOR is not evidence about any product's health.
                    if (result.output != 2) field["validation_error"] = "unexpected_s_false_output";
                } else {
                    if (result.hresult == 0) ++ok; else ++other;
                    constexpr const char* names[]{"good", "not_monitored", "poor", "snooze"};
                    if (result.output >= 0 && result.output <= 3) {
                        field["reported_health"] = names[result.output];
                        field["state"] = result.hresult == 0 ? "healthy" : "degraded";
                    } else { ++unknown; field["state"] = "degraded"; field["validation_error"] = "unknown_or_unchanged_health_output"; }
                }
            }
        }
        fields[provider.name] = std::move(field);
    }
    Json result{{"format", "security_center_category_health_v1"}, {"collector_version", "1.1"},
        {"state", ok || other ? "degraded" : "unavailable"}, {"fields", std::move(fields)}, {"native_api_availability", std::move(availability)},
        {"query_summary", {{"s_ok_results", std::to_string(ok)}, {"s_false_service_unavailable", std::to_string(stopped)},
            {"failed_hresult_results", std::to_string(failed)}, {"other_success_hresult_results", std::to_string(other)},
            {"uninterpreted_outputs", std::to_string(unknown)}, {"queries_not_attempted", std::to_string(unattempted)}}},
        {"inventory_complete", false}, {"protection_verified", false}, {"individual_products_collected", false},
        {"consistency", "non_atomic"}, {"legacy_antispyware_queried", false},
        {"scope", "six selected WSC category reports; deprecated legacy anti-spyware omitted; client API with no supported server contract; Defender/ASR/SmartScreen/tamper/exclusions and individual products unverified"}};
    result["platform_compatibility"] = std::move(platform);
    if (result["platform_compatibility"].value("state", "unavailable") == "unsupported") {
        result["native_query_state"] = result["state"]; result["state"] = "unsupported";
        for (auto& field : result["fields"]) {
            field["native_query_state"] = field["state"]; field["state"] = "unsupported";
            field["native_reported_health"] = field["reported_health"]; field["reported_health"] = nullptr;
            field["compatibility_reason"] = result["platform_compatibility"]["reason"];
        }
    }
    return result;
}
Json collect_security_center_state() {
    // Optional API: missing WSC must not prevent the endpoint from starting.
    const auto platform = native_platform();
    const auto started = GetTickCount64();
    const auto module = LoadLibraryExW(L"wscapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    const auto loaded_error = module ? 0 : GetLastError();
    Json availability{{"source", "LoadLibraryExW/System32/wscapi.dll"}, {"error_domain", "WIN32"},
        {"error_code", std::to_string(loaded_error)}, {"query_started_uptime_ms", std::to_string(started)},
        {"query_completed_uptime_ms", std::to_string(GetTickCount64())}, {"module_loaded", module != nullptr}};
    if (!module) return detail::collect_security_center_state({}, std::move(availability), platform);
    struct Module { HMODULE value; ~Module() { FreeLibrary(value); } } owner{module};
    using Query = HRESULT(WINAPI*)(DWORD, PWSC_SECURITY_PROVIDER_HEALTH);
    const auto function = reinterpret_cast<Query>(GetProcAddress(module, "WscGetSecurityProviderHealth"));
    const auto resolved_error = function ? 0 : GetLastError();
    availability["procedure_error_code"] = std::to_string(resolved_error);
    availability["procedure_available"] = function != nullptr;
    if (!function) return detail::collect_security_center_state({}, std::move(availability), platform);
    return detail::collect_security_center_state([&](std::uint32_t mask) {
        auto value = static_cast<WSC_SECURITY_PROVIDER_HEALTH>(-1);
        const auto begin = GetTickCount64(); const auto hr = function(mask, &value); const auto end = GetTickCount64();
        return detail::SecurityHealthResult{static_cast<std::uint32_t>(hr), static_cast<std::int32_t>(value), begin, end};
    }, std::move(availability), platform);
}
}

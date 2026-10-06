#include "panopticon/officer/state/firewall_rules.hpp"
#include "panopticon/officer/state/firewall_profiles.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>
#include <limits>
#include <stdexcept>
#include <string>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
template<class T> struct Com {
    T* value = nullptr;
    ~Com() { if (value) value->Release(); }
};
struct Variant { VARIANT value; Variant() { VariantInit(&value); } ~Variant() { VariantClear(&value); } };
Json fact(const char* method, HRESULT hr, std::uint64_t started) {
    return {{"source", method}, {"error_domain", "HRESULT"},
        {"hresult_code", std::to_string(static_cast<std::uint32_t>(hr))},
        {"query_started_uptime_ms", std::to_string(started)},
        {"query_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"state", FAILED(hr) ? "unavailable" : hr == S_OK ? "healthy" : "degraded"}, {"value", nullptr}};
}
Json text(BSTR value, std::size_t& budget) {
    Json result{{"value", nullptr}, {"state", "degraded"}};
    if (!value) { result["validation_error"] = "null_bstr"; return result; }
    const auto bytes = SysStringByteLen(value), units = SysStringLen(value);
    result["reported_bstr_bytes"] = std::to_string(bytes); result["reported_utf16_units"] = std::to_string(units);
    if (bytes > 8192 || bytes > 65536 - budget) { result["validation_error"] = "rule_text_copy_bound"; return result; }
    budget += bytes;
    if (!(bytes % 2)) {
        const auto length = units ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(units), nullptr, 0, nullptr, nullptr) : 0;
        const auto error = units && !length ? GetLastError() : 0;
        if (!units || length > 0) {
            std::string output(length, '\0');
            if (!length || WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
                static_cast<int>(units), output.data(), length, nullptr, nullptr) == length) {
                result["value"] = std::move(output); result["state"] = "healthy"; return result;
            }
            result["conversion_error_code"] = std::to_string(GetLastError());
        } else result["conversion_error_code"] = std::to_string(error);
    } else result["validation_error"] = "bstr_odd_byte_length";
    std::string hex; constexpr char digits[] = "0123456789abcdef";
    const auto* raw = reinterpret_cast<const unsigned char*>(value);
    for (UINT i = 0; i < bytes; ++i) { hex += digits[raw[i] >> 4]; hex += digits[raw[i] & 15]; }
    result["value"] = {{"encoding", bytes % 2 ? "bstr_bytes_hex" : "utf16le_hex"}, {"bytes", std::move(hex)}};
    return result;
}
Json rule_fields(INetFwRule* rule, const detail::FirewallExtensionQuery& query = {}) {
    Json fields = Json::object(); std::size_t text_bytes = 0;
    const auto string = [&](const char* key, const char* source, auto* object, auto method) {
        const auto started = GetTickCount64(); BSTR value = nullptr;
        const auto hr = (object->*method)(&value);
        struct Free { BSTR value; ~Free() { SysFreeString(value); } } owner{value};
        auto field = fact(source, hr, started);
        if (SUCCEEDED(hr)) {
            const auto decoded = text(value, text_bytes);
            field.update(decoded); if (hr != S_OK && field["state"] == "healthy") field["state"] = "degraded";
        }
        fields[key] = std::move(field);
    };
#define OFFICER_RULE_TEXT(key, method) string(key, "INetFwRule::" #method, rule, &INetFwRule::method)
    OFFICER_RULE_TEXT("name", get_Name); OFFICER_RULE_TEXT("description", get_Description); OFFICER_RULE_TEXT("application_name", get_ApplicationName);
    OFFICER_RULE_TEXT("service_name", get_ServiceName); OFFICER_RULE_TEXT("local_ports", get_LocalPorts); OFFICER_RULE_TEXT("remote_ports", get_RemotePorts);
    OFFICER_RULE_TEXT("local_addresses", get_LocalAddresses); OFFICER_RULE_TEXT("remote_addresses", get_RemoteAddresses);
    OFFICER_RULE_TEXT("icmp_types_and_codes", get_IcmpTypesAndCodes); OFFICER_RULE_TEXT("interface_types", get_InterfaceTypes); OFFICER_RULE_TEXT("grouping", get_Grouping);
#undef OFFICER_RULE_TEXT
    const auto boolean = [&](const char* key, const char* source, auto method) {
        const auto started = GetTickCount64(); VARIANT_BOOL value = 2; const auto hr = (rule->*method)(&value);
        auto field = fact(source, hr, started);
        if (SUCCEEDED(hr)) { field["raw_output"] = std::to_string(value);
            if (value == VARIANT_FALSE || value == VARIANT_TRUE) field["value"] = value == VARIANT_TRUE;
            else field["state"] = "degraded"; }
        fields[key] = std::move(field);
    };
    boolean("enabled", "INetFwRule::get_Enabled", &INetFwRule::get_Enabled);
    boolean("edge_traversal", "INetFwRule::get_EdgeTraversal", &INetFwRule::get_EdgeTraversal);
    const auto number = [&](const char* key, const char* source, auto* object, auto method, auto sentinel, auto valid) {
        const auto started = GetTickCount64(); auto value = sentinel; const auto hr = (object->*method)(&value);
        auto field = fact(source, hr, started);
        if (SUCCEEDED(hr)) { field["raw_output"] = std::to_string(value);
            if (valid(value)) field["value"] = std::to_string(value); else field["state"] = "degraded"; }
        fields[key] = std::move(field);
    };
    number("protocol", "INetFwRule::get_Protocol", rule, &INetFwRule::get_Protocol, -1L, [](long v) { return v >= 0 && v <= 256; });
    number("profiles", "INetFwRule::get_Profiles", rule, &INetFwRule::get_Profiles, -1L,
        [](long v) { return v == NET_FW_PROFILE2_ALL || (v >= 0 && (v & ~7) == 0); });
    number("direction", "INetFwRule::get_Direction", rule, &INetFwRule::get_Direction, NET_FW_RULE_DIR_MAX,
        [](NET_FW_RULE_DIRECTION v) { return v == NET_FW_RULE_DIR_IN || v == NET_FW_RULE_DIR_OUT; });
    number("action", "INetFwRule::get_Action", rule, &INetFwRule::get_Action, NET_FW_ACTION_MAX,
        [](NET_FW_ACTION v) { return v == NET_FW_ACTION_BLOCK || v == NET_FW_ACTION_ALLOW; });
    Variant interfaces; interfaces.value.vt = VT_ERROR; interfaces.value.scode = E_UNEXPECTED;
    const auto started = GetTickCount64(); const auto hr = rule->get_Interfaces(&interfaces.value);
    auto field = fact("INetFwRule::get_Interfaces", hr, started);
    if (SUCCEEDED(hr)) {
        field.update(detail::decode_firewall_exclusions(&interfaces.value));
        if (hr != S_OK && field["state"] == "healthy") field["state"] = "degraded";
    }
    const auto cleared = VariantClear(&interfaces.value);
    field["variant_clear_hresult_code"] = std::to_string(static_cast<std::uint32_t>(cleared));
    if (FAILED(cleared) && SUCCEEDED(hr)) field["state"] = "degraded";
    fields["interfaces"] = std::move(field);
    Json queries = Json::object();
    const auto extension = [&](const char* name, auto& object, const auto& iid) {
        const auto start = GetTickCount64();
        const auto queried = query ? query(name, reinterpret_cast<void**>(&object.value)) :
            rule->QueryInterface(iid, reinterpret_cast<void**>(&object.value));
        auto result = fact(name, queried, start);
        result["interface_available"] = SUCCEEDED(queried) && object.value != nullptr;
        if (queried == E_NOINTERFACE) result["state"] = "unsupported";
        if (SUCCEEDED(queried) && !object.value) {
            result["state"] = "degraded"; result["validation_error"] = "native_success_without_interface";
        }
        queries[name] = std::move(result);
        return SUCCEEDED(queried) && object.value != nullptr;
    };
    const auto unattempted = [&](const char* key, const char* source, const char* dependency) {
        fields[key] = {{"source", source}, {"query_attempted", false}, {"hresult_code", nullptr},
            {"error_domain", "HRESULT"}, {"value", nullptr},
            {"state", queries[dependency]["state"] == "unsupported" ? "unsupported" : "unavailable"},
            {"unattempted_reason", "extension_interface_unavailable"}, {"interface_dependency", dependency}};
    };
    Com<INetFwRule2> second; Com<INetFwRule3> third;
    if (extension("QueryInterface(INetFwRule2)", second, __uuidof(INetFwRule2))) {
        number("edge_traversal_options", "INetFwRule2::get_EdgeTraversalOptions", second.value,
            &INetFwRule2::get_EdgeTraversalOptions, -1L, [](long v) { return v >= 0 && v <= 3; });
    } else unattempted("edge_traversal_options", "INetFwRule2::get_EdgeTraversalOptions", "QueryInterface(INetFwRule2)");
    if (extension("QueryInterface(INetFwRule3)", third, __uuidof(INetFwRule3))) {
#define OFFICER_RULE3_TEXT(key, method) string(key, "INetFwRule3::" #method, third.value, &INetFwRule3::method)
        OFFICER_RULE3_TEXT("local_app_package_id", get_LocalAppPackageId);
        OFFICER_RULE3_TEXT("local_user_owner", get_LocalUserOwner);
        OFFICER_RULE3_TEXT("local_user_authorized_list", get_LocalUserAuthorizedList);
        OFFICER_RULE3_TEXT("remote_user_authorized_list", get_RemoteUserAuthorizedList);
        OFFICER_RULE3_TEXT("remote_machine_authorized_list", get_RemoteMachineAuthorizedList);
#undef OFFICER_RULE3_TEXT
        number("secure_flags", "INetFwRule3::get_SecureFlags", third.value,
            &INetFwRule3::get_SecureFlags, -1L, [](long v) { return v >= 0 && v <= 4; });
    } else {
        unattempted("local_app_package_id", "INetFwRule3::get_LocalAppPackageId", "QueryInterface(INetFwRule3)");
        unattempted("local_user_owner", "INetFwRule3::get_LocalUserOwner", "QueryInterface(INetFwRule3)");
        unattempted("local_user_authorized_list", "INetFwRule3::get_LocalUserAuthorizedList", "QueryInterface(INetFwRule3)");
        unattempted("remote_user_authorized_list", "INetFwRule3::get_RemoteUserAuthorizedList", "QueryInterface(INetFwRule3)");
        unattempted("remote_machine_authorized_list", "INetFwRule3::get_RemoteMachineAuthorizedList", "QueryInterface(INetFwRule3)");
        unattempted("secure_flags", "INetFwRule3::get_SecureFlags", "QueryInterface(INetFwRule3)");
    }
    for (auto& entry : fields) if (!entry.contains("query_attempted")) entry["query_attempted"] = true;
    return {{"fields", std::move(fields)}, {"extension_interface_queries", std::move(queries)}};
}
Json native_enumerate(const std::function<bool(Json)>& consumer) {
    Json status{{"state", "unavailable"}, {"enumeration_completed", false}, {"rows_queried", "0"}};
    const auto finish = [&]() {
        status["field_query_summary_scope"] = "native getters on queried objects including undelivered rows; not source event loss or full rule coverage";
        if (status.contains("field_query_summary")) for (auto& summary : status["field_query_summary"])
            for (const auto* key : {"successful_queries", "failed_queries", "uninterpreted_results", "unattempted_queries"})
                summary[key] = std::to_string(summary.value(key, 0u));
        if (status.contains("interpreted_rule_objects"))
            status["interpreted_rule_objects"] = std::to_string(status.at("interpreted_rule_objects").get<unsigned>());
        return status;
    };
    const auto stage = [&](const char* name, HRESULT hr) {
        if (std::string_view{name} != "IEnumVARIANT::Next")
            status["setup_steps"].push_back({{"source", name}, {"hresult_code", std::to_string(static_cast<std::uint32_t>(hr))}});
        status["last_stage"] = name; status["hresult_code"] = std::to_string(static_cast<std::uint32_t>(hr));
        return SUCCEEDED(hr);
    };
    const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (!stage("CoInitializeEx", initialized)) return finish();
    struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
    Com<INetFwPolicy2> policy;
    if (!stage("CoCreateInstance", CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&policy.value)))) return finish();
    if (!policy.value) { status["validation_error"] = "native_success_without_policy"; return finish(); }
    Com<INetFwRules> rules;
    if (!stage("INetFwPolicy2::get_Rules", policy.value->get_Rules(&rules.value))) return finish();
    if (!rules.value) { status["validation_error"] = "native_success_without_rules"; return finish(); }
    long count = -1;
    const auto counted = rules.value->get_Count(&count);
    status["count_raw_output"] = SUCCEEDED(counted) ? Json(std::to_string(count)) : Json(nullptr);
    if (SUCCEEDED(counted) && count < 0) status["count_validation_error"] = "negative_or_unchanged_count";
    status["count_hresult_code"] = std::to_string(static_cast<std::uint32_t>(counted));
    status["reported_rule_count"] = SUCCEEDED(counted) && count >= 0 ? Json(std::to_string(count)) : Json(nullptr);
    Com<IUnknown> unknown; Com<IEnumVARIANT> iterator;
    if (!stage("INetFwRules::get__NewEnum", rules.value->get__NewEnum(&unknown.value))) return finish();
    if (!unknown.value) { status["validation_error"] = "native_success_without_enumerator"; return finish(); }
    if (!stage("QueryInterface(IEnumVARIANT)", unknown.value->QueryInterface(__uuidof(IEnumVARIANT), reinterpret_cast<void**>(&iterator.value)))) return finish();
    if (!iterator.value) { status["validation_error"] = "native_success_without_enum_interface"; return finish(); }
    status["state"] = "degraded";
    for (unsigned index = 0; index <= 8192; ++index) {
        Json row; ULONG fetched = 0; HRESULT next;
        {
            Variant value; next = iterator.value->Next(1, &value.value, &fetched);
            status["native_next_calls"] = std::to_string(index + 1);
            stage("IEnumVARIANT::Next", next); status["last_fetched"] = std::to_string(fetched);
            if (FAILED(next)) return finish();
            if (next == S_FALSE && fetched == 0) { status["enumeration_completed"] = true; break; }
            if (next != S_OK || fetched != 1) { status["validation_error"] = "native_enumeration_progress_uninterpreted"; return finish(); }
            if (index == 8192) { status["row_bound_exceeded"] = true; break; }
            row = {{"enumeration_index", std::to_string(index)}, {"variant_type", std::to_string(value.value.vt)},
                {"rule_reference", nullptr}, {"process_reference", nullptr}, {"fields", Json::object()}, {"state", "degraded"}};
            Com<INetFwRule> rule; HRESULT queried = E_NOINTERFACE; bool attempted = false;
            if (value.value.vt == VT_DISPATCH && value.value.pdispVal) { attempted = true;
                queried = value.value.pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rule.value)); }
            if (value.value.vt == VT_UNKNOWN && value.value.punkVal) { attempted = true;
                queried = value.value.punkVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rule.value)); }
            row["rule_interface_query_attempted"] = attempted;
            row["rule_interface_hresult_code"] = attempted ? Json(std::to_string(static_cast<std::uint32_t>(queried))) : Json(nullptr);
            if (attempted && SUCCEEDED(queried) && rule.value) row.update(rule_fields(rule.value));
            else row["validation_error"] = "uninterpreted_or_unavailable_rule_object";
            if (row["fields"].empty()) {
                status["uninterpreted_rule_objects"] = std::to_string(index + 1 - status.value("interpreted_rule_objects", 0u));
            } else {
                status["interpreted_rule_objects"] = status.value("interpreted_rule_objects", 0u) + 1;
                for (auto it = row["fields"].begin(); it != row["fields"].end(); ++it) {
                    auto& summary = status["field_query_summary"][it.key()];
                    if (summary.is_null()) summary = Json::object();
                    if (!it.value().value("query_attempted", true)) {
                        summary["unattempted_queries"] = summary.value("unattempted_queries", 0u) + 1;
                        continue;
                    }
                    const auto hr = std::stoull(it.value().at("hresult_code").get<std::string>());
                    const auto key = hr & 0x80000000u ? "failed_queries" : "successful_queries";
                    summary[key] = summary.value(key, 0u) + 1;
                    if (!(hr & 0x80000000u) && it.value().at("state") != "healthy")
                        summary["uninterpreted_results"] = summary.value("uninterpreted_results", 0u) + 1;
                }
            }
            status["rows_queried"] = std::to_string(index + 1);
        } // Row COM references are released before consumer journal I/O.
        if (!consumer(std::move(row))) { status["consumer_stopped"] = true; break; }
    }
    return finish();
}
}
Json detail::query_firewall_rule_fields(INetFwRule* rule, const FirewallExtensionQuery& query) {
    if (!rule) throw std::invalid_argument("firewall rule missing");
    return rule_fields(rule, query);
}
Json collect_firewall_rule_pages(const std::function<bool(Json)>& consumer) {
    return detail::collect_firewall_rule_pages(consumer, native_enumerate);
}
Json detail::collect_firewall_rule_pages(const std::function<bool(Json)>& consumer, const FirewallRuleEnumerator& enumerate) {
    if (!consumer || !enumerate) throw std::invalid_argument("firewall rule consumer/enumerator missing");
    Json rows = Json::array(); std::size_t encoded = 2, produced = 0, accepted = 0, decoded = 0;
    bool refused = false, bounded = false;
    const auto flush = [&] {
        if (produced >= 256) { bounded = true; return false; }
        const auto count = rows.size();
        Json page{{"page_index", std::to_string(produced++)}, {"entries", std::move(rows)},
            {"inventory_complete", false}, {"consistency", "non_atomic"}};
        if (!consumer(std::move(page))) { refused = true; return false; }
        accepted += count; rows = Json::array(); encoded = 2; return true;
    };
    const auto status = enumerate([&](Json row) {
        if (decoded >= 8192) { bounded = true; return false; }
        ++decoded; const auto bytes = row.dump().size();
        if (bytes > 256 * 1024) { bounded = true; return false; }
        if (rows.size() >= 64 || bytes + (rows.empty() ? 0 : 1) > 512 * 1024 - encoded)
            if (!rows.empty() && !flush()) return false;
        encoded += bytes + (rows.empty() ? 0 : 1); rows.push_back(std::move(row)); return true;
    });
    if (!refused && !bounded && !rows.empty()) (void)flush();
    return {{"state", status.value("state", "unavailable") == "unavailable" && !accepted ? "unavailable" : "degraded"}, {"format", "paged_firewall_rule_inventory_v1"}, {"collector_version", "1.1"},
        {"inventory_complete", false}, {"effective_packet_policy_verified", false}, {"consistency", "non_atomic"},
        {"native_enumeration", status}, {"rows_decoded", std::to_string(decoded)}, {"entries_delivered", std::to_string(accepted)},
        {"pages_produced", std::to_string(produced)}, {"consumer_refused", refused}, {"page_bound_exceeded", bounded},
        {"row_limit", "8192"}, {"page_limit", "256"}, {"page_row_limit", "64"}, {"page_entries_byte_limit", "524288"},
        {"row_encoded_byte_limit", "262144"}, {"native_allocation_bounded", false},
        {"scope", "caller-visible INetFwRules enumeration and sequential INetFwRule/2/3 getters where interfaces are available; no rule lifetime, effective filters, policy provenance or continuous changes"}};
}
}

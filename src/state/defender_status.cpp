#include "panopticon/officer/state/defender_status.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <string>
#include <string_view>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
template<class T> struct Com { T* value = nullptr; ~Com() { if (value) value->Release(); } };
struct Variant { VARIANT value; Variant() { VariantInit(&value); } ~Variant() { VariantClear(&value); } };
struct Text { BSTR value; explicit Text(const wchar_t* text) : value(SysAllocString(text)) {} ~Text() { SysFreeString(value); } };
struct Property { const wchar_t* name; const char* key; CIMTYPE type; bool modern_optional = false; };
constexpr const char* modern_names[]{"AMRunningMode", "IsTamperProtected", "TamperProtectionSource"};
constexpr Property properties[]{
    {L"__RELPATH", "__RELPATH", CIM_STRING}, {L"ComputerID", "ComputerID", CIM_STRING},
    {L"ComputerState", "ComputerState", CIM_UINT32}, {L"AMProductVersion", "AMProductVersion", CIM_STRING},
    {L"AMServiceVersion", "AMServiceVersion", CIM_STRING}, {L"AMEngineVersion", "AMEngineVersion", CIM_STRING},
    {L"AntispywareSignatureVersion", "AntispywareSignatureVersion", CIM_STRING},
    {L"AntispywareSignatureAge", "AntispywareSignatureAge", CIM_UINT32},
    {L"AntispywareSignatureLastUpdated", "AntispywareSignatureLastUpdated", CIM_DATETIME},
    {L"AntivirusSignatureVersion", "AntivirusSignatureVersion", CIM_STRING},
    {L"AntivirusSignatureAge", "AntivirusSignatureAge", CIM_UINT32},
    {L"AntivirusSignatureLastUpdated", "AntivirusSignatureLastUpdated", CIM_DATETIME},
    {L"NISSignatureVersion", "NISSignatureVersion", CIM_STRING}, {L"NISSignatureAge", "NISSignatureAge", CIM_UINT32},
    {L"NISSignatureLastUpdated", "NISSignatureLastUpdated", CIM_DATETIME},
    {L"NISEngineVersion", "NISEngineVersion", CIM_STRING},
    {L"FullScanStartTime", "FullScanStartTime", CIM_DATETIME}, {L"FullScanEndTime", "FullScanEndTime", CIM_DATETIME},
    {L"FullScanAge", "FullScanAge", CIM_UINT32}, {L"LastFullScanSource", "LastFullScanSource", CIM_UINT8},
    {L"QuickScanStartTime", "QuickScanStartTime", CIM_DATETIME}, {L"QuickScanEndTime", "QuickScanEndTime", CIM_DATETIME},
    {L"QuickScanAge", "QuickScanAge", CIM_UINT32}, {L"LastQuickScanSource", "LastQuickScanSource", CIM_UINT8},
    {L"RealTimeScanDirection", "RealTimeScanDirection", CIM_UINT8},
    {L"AMServiceEnabled", "AMServiceEnabled", CIM_BOOLEAN}, {L"OnAccessProtectionEnabled", "OnAccessProtectionEnabled", CIM_BOOLEAN},
    {L"IoavProtectionEnabled", "IoavProtectionEnabled", CIM_BOOLEAN}, {L"BehaviorMonitorEnabled", "BehaviorMonitorEnabled", CIM_BOOLEAN},
    {L"AntivirusEnabled", "AntivirusEnabled", CIM_BOOLEAN}, {L"AntispywareEnabled", "AntispywareEnabled", CIM_BOOLEAN},
    {L"RealTimeProtectionEnabled", "RealTimeProtectionEnabled", CIM_BOOLEAN}, {L"NISEnabled", "NISEnabled", CIM_BOOLEAN},
    {L"AMRunningMode", "AMRunningMode", CIM_STRING, true},
    {L"IsTamperProtected", "IsTamperProtected", CIM_BOOLEAN, true},
    {L"TamperProtectionSource", "TamperProtectionSource", CIM_STRING, true}
};
}
Json detail::decode_defender_property(const void* borrowed, std::uint32_t expected, std::uint32_t reported, std::size_t& copied) {
    Json result{{"state", "degraded"}, {"value", nullptr}, {"raw_scalar", nullptr},
        {"expected_cim_type", std::to_string(expected)}, {"reported_cim_type", std::to_string(reported)}};
    if (!borrowed) { result["validation_error"] = "missing_variant"; return result; }
    const auto& value = *static_cast<const VARIANT*>(borrowed);
    result["variant_type"] = std::to_string(value.vt);
    if (value.vt == VT_BOOL) result["raw_scalar"] = std::to_string(value.boolVal);
    if (value.vt == VT_I4) result["raw_scalar"] = std::to_string(value.lVal);
    if (value.vt == VT_UI4) result["raw_scalar"] = std::to_string(value.ulVal);
    if (value.vt == VT_UI1) result["raw_scalar"] = std::to_string(value.bVal);
    if (value.vt == VT_BSTR && value.bstrVal) {
        const auto bytes = SysStringByteLen(value.bstrVal), units = SysStringLen(value.bstrVal);
        result["reported_bstr_bytes"] = std::to_string(bytes); result["reported_utf16_units"] = std::to_string(units);
        if (bytes > 8192 || copied > 32768 || bytes > 32768 - copied) {
            result["validation_error"] = "text_copy_bound"; return result;
        }
        copied += bytes;
        const auto length = bytes % 2 ? 0 : units ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            value.bstrVal, static_cast<int>(units), nullptr, 0, nullptr, nullptr) : 0;
        if (!(bytes % 2) && units && !length) {
            const auto error = GetLastError();
            result["text_conversion_error_domain"] = "WIN32";
            result["text_conversion_error_code"] = std::to_string(error);
        }
        if (!(bytes % 2) && (!units || length > 0)) {
            std::string text(length, '\0');
            const auto converted = length ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.bstrVal,
                static_cast<int>(units), text.data(), length, nullptr, nullptr) : 0;
            if (!length || converted == length) result["raw_text"] = std::move(text);
            else if (!converted) {
                const auto error = GetLastError();
                result["text_conversion_error_domain"] = "WIN32";
                result["text_conversion_error_code"] = std::to_string(error);
            } else result["validation_error"] = "text_conversion_length_mismatch";
        }
        if (!result.contains("raw_text")) {
            std::string hex; constexpr char digits[] = "0123456789abcdef";
            const auto* raw = reinterpret_cast<const unsigned char*>(value.bstrVal);
            for (UINT index = 0; index < bytes; ++index) { hex += digits[raw[index] >> 4]; hex += digits[raw[index] & 15]; }
            result["raw_text"] = {{"encoding", "bstr_bytes_hex"}, {"bytes", std::move(hex)}};
            result["validation_error"] = "text_encoding_uninterpreted";
        }
    }
    if (reported != expected) { result["validation_error"] = "cim_type_mismatch"; return result; }
    if (expected == CIM_BOOLEAN && value.vt == VT_BOOL && (value.boolVal == 0 || value.boolVal == -1)) result["value"] = value.boolVal == -1;
    else if (expected == CIM_UINT32 && value.vt == VT_I4) result["value"] = std::to_string(static_cast<std::uint32_t>(value.lVal));
    else if (expected == CIM_UINT8 && value.vt == VT_UI1) result["value"] = std::to_string(value.bVal);
    else if ((expected == CIM_STRING || expected == CIM_DATETIME) && value.vt == VT_BSTR && result.contains("raw_text") && result["raw_text"].is_string()) {
        result["value"] = result["raw_text"]; if (expected == CIM_DATETIME) result["timestamp_normalized"] = false;
    } else { if (!result.contains("validation_error")) result["validation_error"] = "variant_value_uninterpreted"; return result; }
    result["state"] = "healthy"; return result;
}
Json detail::decode_defender_query_result(const char* property, bool optional, std::uint32_t raw_hr,
    const void* value, std::uint32_t expected, std::uint32_t reported, std::size_t& copied) {
    Json result{{"source", "IWbemClassObject::Get/MSFT_MpComputerStatus"}, {"property", property},
        {"hresult_code", std::to_string(raw_hr)}, {"error_domain", "HRESULT"}, {"value", nullptr},
        {"state", "unavailable"}, {"protection_verified", false},
        {"contract_group", optional ? "modern_optional" : "selected_base_and_object_path"}};
    const std::string_view name{property};
    if (name == "AMRunningMode") result["reported_mode"] = nullptr;
    else if (name == "IsTamperProtected") result["reported_tamper_state"] = nullptr;
    else if (name == "TamperProtectionSource") result["policy_authority_verified"] = false;
    const auto hr = static_cast<HRESULT>(raw_hr);
    if (FAILED(hr)) {
        result["property_availability"] = hr == WBEM_E_NOT_FOUND ? "not_exposed_by_object" : "query_refused";
        return result;
    }
    result["property_availability"] = "reported";
    result.update(decode_defender_property(value, expected, reported, copied));
    if (hr != S_OK && result["state"] == "healthy") result["state"] = "degraded";
    if (name == "AMRunningMode") {
        result["reported_mode"] = nullptr;
        if (hr == S_OK && result["state"] == "healthy" && result["value"].is_string()) {
            const auto mode = result["value"].get<std::string>();
            if (mode == "Normal" || mode == "Passive" || mode == "EDR Block Mode") result["reported_mode"] = mode;
            else { result["state"] = "degraded"; result["validation_error"] = "running_mode_uninterpreted"; }
        }
    } else if (name == "IsTamperProtected") {
        result["reported_tamper_state"] = nullptr;
        if (hr == S_OK && result["state"] == "healthy" && result["value"].is_boolean())
            result["reported_tamper_state"] = result["value"] == true ? "enabled" : "disabled";
    } else if (name == "TamperProtectionSource") result["policy_authority_verified"] = false;
    return result;
}
Json detail::defender_modern_property_quality(const Json& entries) {
    auto result = Json::object();
    for (const auto* name : modern_names) {
        std::uint64_t healthy = 0, degraded = 0, unavailable = 0, missing = 0;
        for (const auto& row : entries) {
            const auto fields = row.find("fields");
            if (fields == row.end() || !fields->is_object() || !fields->contains(name)) { ++missing; continue; }
            const auto& field = fields->at(name);
            if (field.value("state", "unavailable") == "healthy") ++healthy;
            else if (field.value("state", "unavailable") == "degraded") ++degraded;
            else ++unavailable;
        }
        result[name] = {{"state", healthy && !degraded && !unavailable && !missing ? "healthy" :
            healthy || degraded ? "degraded" : "unavailable"}, {"healthy_captured_rows", std::to_string(healthy)},
            {"degraded_captured_rows", std::to_string(degraded)}, {"unavailable_captured_rows", std::to_string(unavailable)},
            {"missing_field_captured_rows", std::to_string(missing)}, {"protection_verified", false},
            {"scope", "getter and interpretation quality in retained rows only; not complete inventory, effective protection or policy authority"}};
    }
    return result;
}
Json collect_defender_status() {
    Json result{{"format", "defender_computer_status_v1"}, {"collector_version", "1.1"}, {"state", "unavailable"},
        {"namespace", "Root\\Microsoft\\Windows\\Defender"}, {"query", "SELECT * FROM MSFT_MpComputerStatus"},
        {"entries", Json::array()}, {"inventory_complete", false}, {"protection_verified", false},
        {"selected_base_and_object_path_properties", "33"}, {"selected_modern_optional_properties", "3"},
        {"modern_property_quality", detail::defender_modern_property_quality(Json::array())},
        {"enumeration_completed", false}, {"row_limit", "8"}, {"enumeration_timeout_ms", "1000"},
        {"row_text_copy_byte_limit", "32768"}, {"capture_entries_byte_limit", "655360"},
        {"native_allocation_bounded", false}, {"collection_deadline_enforced", false},
        {"connect_max_wait_ms", "120000"}, {"consistency", "non_atomic"},
        {"scope", "caller-visible local Defender status properties; provider and timestamps unverified; no product/process/device lifetime or policy enforcement proof"}};
    const auto stage = [&](const char* source, HRESULT hr, std::uint64_t start) {
        result["native_steps"].push_back({{"source", source}, {"error_domain", "HRESULT"}, {"hresult_code", std::to_string(static_cast<std::uint32_t>(hr))},
            {"query_started_uptime_ms", std::to_string(start)}, {"query_completed_uptime_ms", std::to_string(GetTickCount64())}});
        return SUCCEEDED(hr);
    };
    auto start = GetTickCount64(); const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (!stage("CoInitializeEx", initialized, start)) return result;
    struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
    Com<IWbemLocator> locator; start = GetTickCount64();
    if (!stage("CoCreateInstance/WbemLocator", CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<void**>(&locator.value)), start)) return result;
    if (!locator.value) { result["validation_error"] = "success_without_locator"; return result; }
    Text space{L"\\\\.\\root\\Microsoft\\Windows\\Defender"}, language{L"WQL"}, query{L"SELECT * FROM MSFT_MpComputerStatus"};
    if (!space.value || !language.value || !query.value) { result["validation_error"] = "bstr_allocation_failed"; return result; }
    Com<IWbemServices> services; start = GetTickCount64();
    if (!stage("IWbemLocator::ConnectServer", locator.value->ConnectServer(space.value, nullptr, nullptr, nullptr,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &services.value), start)) return result;
    if (!services.value) { result["validation_error"] = "success_without_services"; return result; }
    const auto blanket = [&](IUnknown* proxy, const char* source) {
        const auto begun = GetTickCount64();
        return stage(source, CoSetProxyBlanket(proxy, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE), begun);
    };
    if (!blanket(services.value, "CoSetProxyBlanket/IWbemServices")) return result;
    Com<IEnumWbemClassObject> enumerator; start = GetTickCount64();
    if (!stage("IWbemServices::ExecQuery", services.value->ExecQuery(language.value, query.value,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, nullptr, &enumerator.value), start)) return result;
    if (!enumerator.value) { result["validation_error"] = "success_without_enumerator"; return result; }
    if (!blanket(enumerator.value, "CoSetProxyBlanket/IEnumWbemClassObject")) return result;
    unsigned successful = 0, failed = 0, unknown = 0; std::size_t encoded = 2;
    for (unsigned index = 0; index <= 8; ++index) {
        Com<IWbemClassObject> object; ULONG fetched = 0; start = GetTickCount64();
        const auto hr = enumerator.value->Next(1000, 1, &object.value, &fetched);
        stage("IEnumWbemClassObject::Next", hr, start); result["last_fetched"] = std::to_string(fetched);
        if (hr == WBEM_S_FALSE && fetched == 0 && !object.value) { result["enumeration_completed"] = true; result["state"] = "degraded"; break; }
        if (hr == WBEM_S_TIMEDOUT && fetched == 0 && !object.value) { result["enumeration_timed_out"] = true; break; }
        if (FAILED(hr)) break;
        if ((hr != S_OK && hr != WBEM_S_FALSE) || fetched != 1 || !object.value) { result["validation_error"] = "enumeration_progress_uninterpreted"; break; }
        if (index == 8) { result["row_bound_exceeded"] = true; break; }
        Json row{{"enumeration_index", std::to_string(index)}, {"product_reference", nullptr}, {"process_reference", nullptr},
            {"device_reference", nullptr}, {"fields", Json::object()}, {"state", "degraded"}};
        std::size_t copied = 0;
        for (const auto& property : properties) {
            Variant value; CIMTYPE type = 0; start = GetTickCount64();
            const auto queried = object.value->Get(property.name, 0, &value.value, &type, nullptr);
            const auto completed = GetTickCount64();
            auto field = detail::decode_defender_query_result(property.key, property.modern_optional,
                static_cast<std::uint32_t>(queried), &value.value, property.type, type, copied);
            field["query_started_uptime_ms"] = std::to_string(start);
            field["query_completed_uptime_ms"] = std::to_string(completed);
            if (FAILED(queried)) ++failed;
            else ++successful;
            const auto cleared = VariantClear(&value.value); field["variant_clear_hresult_code"] = std::to_string(static_cast<std::uint32_t>(cleared));
            if (FAILED(cleared) && SUCCEEDED(queried)) field["state"] = "degraded";
            if (SUCCEEDED(queried) && field["state"] != "healthy") ++unknown;
            row["fields"][property.key] = std::move(field);
        }
        const auto bytes = row.dump().size();
        if (bytes + 1 > 655360 - encoded) { result["encoded_bound_exceeded"] = true; break; }
        encoded += bytes + 1; result["entries"].push_back(std::move(row)); result["state"] = "degraded";
        if (hr == WBEM_S_FALSE) { result["enumeration_completed"] = true; break; }
    }
    result["query_summary"] = {{"successful_getters", std::to_string(successful)}, {"failed_getters", std::to_string(failed)},
        {"uninterpreted_results", std::to_string(unknown)}, {"scope", "queried objects including undelivered rows; not source event loss"}};
    result["modern_property_quality"] = detail::defender_modern_property_quality(result["entries"]);
    return result;
}
}

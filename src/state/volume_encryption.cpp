#include "panopticon/officer/state/volume_encryption.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>

#include <array>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
constexpr unsigned kMaxVolumes = 64;
constexpr std::size_t kMaxStringBytes = 4096;
constexpr std::size_t kMaxOutputBytes = 524288;
std::string ascii(const wchar_t* value) {
    std::string out;
    if (!value) return out;
    for (; *value; ++value) {
        if (static_cast<unsigned int>(*value) > 0x7fU) return {};
        out.push_back(static_cast<char>(*value));
    }
    return out;
}

template<class T> struct Com {
    T* value = nullptr;
    ~Com() { if (value) value->Release(); }
    Com() = default;
    Com(const Com&) = delete;
    Com& operator=(const Com&) = delete;
};
struct Bstr {
    BSTR value = nullptr;
    explicit Bstr(const wchar_t* source) : value(SysAllocString(source)) {}
    ~Bstr() { SysFreeString(value); }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
};
struct Variant {
    VARIANT value;
    Variant() { VariantInit(&value); }
    ~Variant() { VariantClear(&value); }
    Variant(const Variant&) = delete;
    Variant& operator=(const Variant&) = delete;
};
struct Apartment {
    bool initialized = false;
    ~Apartment() { if (initialized) CoUninitialize(); }
};

Json hr_fact(const char* source, HRESULT hr, std::uint64_t started) {
    return {{"source", source}, {"error_domain", "HRESULT"},
        {"hresult_code", std::to_string(static_cast<std::uint32_t>(hr))},
        {"query_started_uptime_ms", std::to_string(started)},
        {"query_completed_uptime_ms", std::to_string(GetTickCount64())},
        {"state", FAILED(hr) ? "unavailable" : hr == S_OK ? "healthy" : "degraded"},
        {"value", nullptr}};
}

std::string utf8_string(BSTR value, std::size_t max_bytes, bool& valid) {
    valid = false;
    if (!value) return {};
    const auto bytes = SysStringByteLen(value);
    const auto units = SysStringLen(value);
    if (bytes > max_bytes || bytes > static_cast<UINT>(std::numeric_limits<int>::max()) ||
        units > static_cast<UINT>(std::numeric_limits<int>::max()) || bytes % sizeof(wchar_t) != 0 ||
        std::wstring_view{value, units}.find(L'\0') != std::wstring_view::npos) return {};
    if (!units) { valid = true; return {}; }
    const auto length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(units), nullptr, 0, nullptr, nullptr);
    if (length <= 0 || static_cast<std::size_t>(length) > max_bytes) return {};
    std::string result(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(units),
        result.data(), length, nullptr, nullptr) != length) return {};
    valid = true;
    return result;
}

Json string_property(IWbemClassObject* object, const wchar_t* property, const char* key,
    bool nullable = false) {
    const auto started = GetTickCount64();
    Variant value;
    const auto hr = object->Get(property, 0, &value.value, nullptr, nullptr);
    auto field = hr_fact((std::string{"IWbemClassObject::Get/"} + key).c_str(), hr, started);
    if (FAILED(hr)) return field;
    if (value.value.vt == VT_NULL && nullable) {
        field["state"] = hr == S_OK ? "healthy" : "degraded";
        field["value"] = nullptr;
        field["null_reported"] = true;
        return field;
    }
    if (value.value.vt != VT_BSTR || !value.value.bstrVal) {
        field["state"] = "degraded";
        field["variant_type"] = std::to_string(value.value.vt);
        field["validation_error"] = "expected_nonnull_bstr";
        return field;
    }
    bool valid = false;
    const auto text = utf8_string(value.value.bstrVal, kMaxStringBytes, valid);
    field["reported_utf16_units"] = std::to_string(SysStringLen(value.value.bstrVal));
    if (!valid) {
        field["state"] = "degraded";
        field["validation_error"] = "bounded_utf16_conversion_failed";
        return field;
    }
    field["value"] = text;
    if (hr != S_OK) field["state"] = "degraded";
    return field;
}

Json uint32_output(IWbemClassObject* object, const wchar_t* property, const char* key,
    const char* source) {
    const auto started = GetTickCount64();
    Variant value;
    const auto hr = object->Get(property, 0, &value.value, nullptr, nullptr);
    auto field = hr_fact(source, hr, started);
    if (FAILED(hr)) return field;
    std::uint32_t raw = 0;
    if (value.value.vt == VT_UI4) raw = value.value.ulVal;
    else if (value.value.vt == VT_I4) raw = static_cast<std::uint32_t>(value.value.lVal);
    else {
        field["state"] = "degraded";
        field["variant_type"] = std::to_string(value.value.vt);
        field["validation_error"] = "expected_uint32_variant";
        return field;
    }
    field["raw_output"] = std::to_string(raw);
    field["value"] = std::to_string(raw);
    if (hr != S_OK) field["state"] = "degraded";
    (void)key;
    return field;
}

const char* protection_label(std::uint32_t value) {
    switch (value) { case 0: return "protection_off"; case 1: return "protection_on";
        case 2: return "protection_unknown"; default: return nullptr; }
}
const char* conversion_label(std::uint32_t value) {
    switch (value) { case 0: return "fully_decrypted"; case 1: return "fully_encrypted";
        case 2: return "encryption_in_progress"; case 3: return "decryption_in_progress";
        case 4: return "encryption_paused"; case 5: return "decryption_paused"; default: return nullptr; }
}
const char* encryption_label(std::uint32_t value) {
    switch (value) { case 0: return "not_encrypted"; case 1: return "aes_128_with_diffuser";
        case 2: return "aes_256_with_diffuser"; case 3: return "aes_128"; case 4: return "aes_256";
        case 5: return "hardware_encryption"; case 6: return "xts_aes_128";
        case 7: return "xts_aes_256"; case 0xffffffffu: return "unknown_encryption_method";
        default: return nullptr; }
}

Json call_method(IWbemServices* services, const BSTR object_path, IWbemClassObject* class_object,
    const wchar_t* method_name, std::uint32_t volume_index) {
    Json result{{"method", ascii(method_name)},
        {"volume_index", std::to_string(volume_index)}, {"state", "unavailable"},
        {"method_call_attempted", false}, {"method_hresult_code", nullptr},
        {"provider_return_value", nullptr}, {"outputs", Json::object()}, {"read_only_method", true}};
    const auto method_started = GetTickCount64();
    Bstr wide_method{method_name};
    Com<IWbemClassObject> input_signature, output_signature;
    HRESULT signature_hr = class_object->GetMethod(method_name, 0, &input_signature.value, &output_signature.value);
    result["method_signature_hresult_code"] = std::to_string(static_cast<std::uint32_t>(signature_hr));
    if (FAILED(signature_hr) || !output_signature.value) {
        result["method_query_started_uptime_ms"] = std::to_string(method_started);
        result["method_query_completed_uptime_ms"] = std::to_string(GetTickCount64());
        result["validation_error"] = "method_signature_unavailable";
        return result;
    }
    Com<IWbemClassObject> input;
    if (std::wstring_view{method_name} == L"GetConversionStatus") {
        if (!input_signature.value || FAILED(input_signature.value->SpawnInstance(0, &input.value)) || !input.value) {
            result["validation_error"] = "conversion_input_instance_unavailable";
            result["method_query_started_uptime_ms"] = std::to_string(method_started);
            result["method_query_completed_uptime_ms"] = std::to_string(GetTickCount64());
            return result;
        }
        Variant precision;
        precision.value.vt = VT_I4;
        precision.value.lVal = 0; // documented PrecisionFactor range is 0..4
        const auto put = input.value->Put(L"PrecisionFactor", 0, &precision.value, 0);
        result["precision_factor_put_hresult_code"] = std::to_string(static_cast<std::uint32_t>(put));
        if (FAILED(put)) {
            result["validation_error"] = "precision_factor_input_failed";
            result["method_query_started_uptime_ms"] = std::to_string(method_started);
            result["method_query_completed_uptime_ms"] = std::to_string(GetTickCount64());
            return result;
        }
    }
    Com<IWbemClassObject> output;
    const auto method_hr = services->ExecMethod(object_path, wide_method.value, 0, nullptr,
        input.value, &output.value, nullptr);
    result["method_call_attempted"] = true;
    result["method_hresult_code"] = std::to_string(static_cast<std::uint32_t>(method_hr));
    result["method_hresult_exact_success"] = method_hr == S_OK;
    result["method_query_started_uptime_ms"] = std::to_string(method_started);
    result["method_query_completed_uptime_ms"] = std::to_string(GetTickCount64());
    if (FAILED(method_hr) || !output.value) {
        if (SUCCEEDED(method_hr)) result["validation_error"] = "native_success_without_output_object";
        else result["state"] = "unavailable";
        return result;
    }
    auto return_value = uint32_output(output.value, L"ReturnValue", "return_value", "IWbemClassObject::Get/ReturnValue");
    result["provider_return_value"] = return_value;
    const bool provider_success = return_value.value("raw_output", std::string{}) == "0" &&
        return_value.value("state", std::string{}) == "healthy";
    const auto add_output = [&](const wchar_t* property, const char* key, const char* source) {
        result["outputs"][key] = uint32_output(output.value, property, key, source);
    };
    if (std::wstring_view{method_name} == L"GetProtectionStatus") {
        add_output(L"ProtectionStatus", "protection_status", "Win32_EncryptableVolume::GetProtectionStatus/ProtectionStatus");
        auto& value = result["outputs"]["protection_status"];
        if (value.contains("raw_output")) {
            const auto raw = static_cast<std::uint32_t>(std::stoul(value["raw_output"].get<std::string>()));
            if (const auto* label = protection_label(raw)) value["meaning"] = label;
            else value["state"] = "degraded";
        }
    } else if (std::wstring_view{method_name} == L"GetConversionStatus") {
        add_output(L"ConversionStatus", "conversion_status", "Win32_EncryptableVolume::GetConversionStatus/ConversionStatus");
        add_output(L"EncryptionPercentage", "encryption_percentage", "Win32_EncryptableVolume::GetConversionStatus/EncryptionPercentage");
        add_output(L"EncryptionFlags", "encryption_flags", "Win32_EncryptableVolume::GetConversionStatus/EncryptionFlags");
        add_output(L"WipingStatus", "wiping_status", "Win32_EncryptableVolume::GetConversionStatus/WipingStatus");
        add_output(L"WipingPercentage", "wiping_percentage", "Win32_EncryptableVolume::GetConversionStatus/WipingPercentage");
        auto& conversion = result["outputs"]["conversion_status"];
        if (conversion.contains("raw_output")) {
            const auto raw = static_cast<std::uint32_t>(std::stoul(conversion["raw_output"].get<std::string>()));
            if (const auto* label = conversion_label(raw)) conversion["meaning"] = label;
            else conversion["state"] = "degraded";
        }
        for (const auto* key : {"encryption_percentage", "wiping_percentage"}) {
            auto& percentage = result["outputs"][key];
            if (percentage.contains("raw_output") && std::stoul(percentage["raw_output"].get<std::string>()) > 100)
                percentage["state"] = "degraded";
        }
    } else if (std::wstring_view{method_name} == L"GetEncryptionMethod") {
        add_output(L"EncryptionMethod", "encryption_method", "Win32_EncryptableVolume::GetEncryptionMethod/EncryptionMethod");
        auto& encryption = result["outputs"]["encryption_method"];
        if (encryption.contains("raw_output")) {
            const auto raw = static_cast<std::uint32_t>(std::stoul(encryption["raw_output"].get<std::string>()));
            if (const auto* label = encryption_label(raw)) encryption["meaning"] = label;
            else encryption["state"] = "degraded";
        }
        const auto started = GetTickCount64();
        Variant self_encryption;
        const auto string_hr = output.value->Get(L"SelfEncryptionDriveEncryptionMethod", 0, &self_encryption.value, nullptr, nullptr);
        auto field = hr_fact("Win32_EncryptableVolume::GetEncryptionMethod/SelfEncryptionDriveEncryptionMethod", string_hr, started);
        if (SUCCEEDED(string_hr)) {
            if (self_encryption.value.vt == VT_BSTR) {
                if (!self_encryption.value.bstrVal) {
                    field["value"] = nullptr; field["null_reported"] = true;
                } else {
                    bool valid = false;
                    const auto text = utf8_string(self_encryption.value.bstrVal, kMaxStringBytes, valid);
                    field["reported_utf16_units"] = std::to_string(SysStringLen(self_encryption.value.bstrVal));
                    if (valid) field["value"] = text;
                    else { field["state"] = "degraded"; field["validation_error"] = "bounded_utf16_conversion_failed"; }
                }
            } else if (self_encryption.value.vt == VT_NULL) {
                field["value"] = nullptr; field["null_reported"] = true;
            } else {
                field["state"] = "degraded"; field["variant_type"] = std::to_string(self_encryption.value.vt);
                field["validation_error"] = "expected_bstr_or_null";
            }
        }
        result["outputs"]["self_encryption_drive_method"] = std::move(field);
    }
    bool outputs_healthy = true;
    for (const auto& [_, output] : result["outputs"].items())
        if (!output.is_object() || output.value("state", std::string("unavailable")) != "healthy") outputs_healthy = false;
    result["state"] = method_hr == S_OK && provider_success && outputs_healthy ? "healthy" : "degraded";
    result["method_return_success"] = provider_success;
    result["scope"] = "read-only WMI method output; no key protectors or escrow material queried";
    return result;
}

bool value_u32(const Json& method, const char* key, std::uint32_t& value) {
    if (!method.contains("outputs") || !method["outputs"].contains(key)) return false;
    const auto& field = method["outputs"][key];
    if (!field.contains("raw_output") || !field["raw_output"].is_string()) return false;
    try { const auto parsed = std::stoull(field["raw_output"].get<std::string>());
        if (parsed > std::numeric_limits<std::uint32_t>::max()) return false;
        value = static_cast<std::uint32_t>(parsed); return true; }
    catch (...) { return false; }
}

} // namespace

Json collect_volume_encryption_state() {
    const auto begun = GetTickCount64();
    Json result{{"format", "volume_encryption_state_v1"}, {"collector", "win32_encryptable_volume"},
        {"collector_version", "1.0"}, {"state", "unavailable"},
        {"namespace", "ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption"},
        {"class", "Win32_EncryptableVolume"},
        {"query", "SELECT DeviceID, DriveLetter, PersistentVolumeID, __RELPATH FROM Win32_EncryptableVolume"},
        {"entries", Json::array()}, {"row_limit", std::to_string(kMaxVolumes)},
        {"string_limit_bytes", std::to_string(kMaxStringBytes)}, {"encoded_entries_limit_bytes", std::to_string(kMaxOutputBytes)},
        {"inventory_complete", false}, {"protection_verified", false}, {"escrow_verified", false},
        {"state_changing_methods_called", false}, {"methods_invoked", Json::array()},
        {"collection_deadline_enforced", false},
        {"scope", "caller-visible local Win32_EncryptableVolume volume identifiers and selected read-only status methods; no disk encryption enforcement, hardware attestation, key protector, recovery or escrow claim"},
        {"collection_started_uptime_ms", std::to_string(begun)}};
    const auto finish = [&]() { result["collection_completed_uptime_ms"] = std::to_string(GetTickCount64()); return result; };
    const auto step = [&](const char* source, HRESULT hr) {
        result["native_steps"].push_back({{"source", source}, {"error_domain", "HRESULT"},
            {"hresult_code", std::to_string(static_cast<std::uint32_t>(hr))}});
        return SUCCEEDED(hr);
    };
    const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (!step("CoInitializeEx", initialized)) return finish();
    Apartment apartment; apartment.initialized = true;
    Com<IWbemLocator> locator;
    if (!step("CoCreateInstance(CLSID_WbemLocator)", CoCreateInstance(CLSID_WbemLocator, nullptr,
        CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&locator.value))) || !locator.value) return finish();
    Bstr space{L"\\\\.\\root\\CIMV2\\Security\\MicrosoftVolumeEncryption"};
    Bstr language{L"WQL"};
    Bstr query{L"SELECT DeviceID, DriveLetter, PersistentVolumeID, __RELPATH FROM Win32_EncryptableVolume"};
    if (!space.value || !language.value || !query.value) { result["validation_error"] = "bstr_allocation_failed"; return finish(); }
    Com<IWbemServices> services;
    const auto connected = locator.value->ConnectServer(space.value, nullptr, nullptr, nullptr,
        WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &services.value);
    if (!step("IWbemLocator::ConnectServer", connected) || !services.value) return finish();
    const auto blanket = CoSetProxyBlanket(services.value, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (!step("CoSetProxyBlanket(IWbemServices)", blanket)) return finish();
    Com<IWbemClassObject> class_object;
    Bstr class_name{L"Win32_EncryptableVolume"};
    if (!class_name.value) { result["validation_error"] = "bstr_allocation_failed"; return finish(); }
    const auto class_hr = services.value->GetObject(class_name.value, 0, nullptr,
        &class_object.value, nullptr);
    if (!step("IWbemServices::GetObject(Win32_EncryptableVolume)", class_hr) || !class_object.value) return finish();
    Com<IEnumWbemClassObject> rows;
    const auto query_hr = services.value->ExecQuery(language.value, query.value,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, nullptr, &rows.value);
    if (!step("IWbemServices::ExecQuery", query_hr) || !rows.value) return finish();
    const auto enum_blanket = CoSetProxyBlanket(rows.value, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
        nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (!step("CoSetProxyBlanket(IEnumWbemClassObject)", enum_blanket)) return finish();

    unsigned output_failures = 0, output_degraded = 0;
    std::size_t encoded_bytes = 2;
    result["enumeration_completed"] = false;
    for (unsigned index = 0; index <= kMaxVolumes; ++index) {
        Com<IWbemClassObject> object;
        ULONG fetched = 0;
        const auto next_started = GetTickCount64();
        const auto next_hr = rows.value->Next(1000, 1, &object.value, &fetched);
        auto next = hr_fact("IEnumWbemClassObject::Next", next_hr, next_started);
        next["fetched"] = std::to_string(fetched);
        result["enumeration_status"] = std::move(next);
        if (next_hr == WBEM_S_FALSE && fetched == 0 && !object.value) {
            result["enumeration_completed"] = true;
            break;
        }
        if (FAILED(next_hr) || (next_hr != S_OK && next_hr != WBEM_S_FALSE) || fetched != 1 || !object.value) {
            result["enumeration_incomplete"] = true;
            break;
        }
        if (index == kMaxVolumes) { result["row_bound_exceeded"] = true; break; }
        Json row{{"enumeration_index", std::to_string(index)}, {"state", "degraded"}, {"fields", Json::object()},
            {"methods", Json::object()}, {"read_only_methods_only", true}};
        row["fields"]["device_id"] = string_property(object.value, L"DeviceID", "DeviceID");
        row["fields"]["drive_letter"] = string_property(object.value, L"DriveLetter", "DriveLetter", true);
        row["fields"]["persistent_volume_id"] = string_property(object.value, L"PersistentVolumeID", "PersistentVolumeID", true);
        auto path_field = string_property(object.value, L"__RELPATH", "__RELPATH");
        if (path_field.value("state", "unavailable") == "healthy" && path_field["value"].is_string()) {
            const auto path_utf8 = path_field["value"].get<std::string>();
            int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path_utf8.data(),
                static_cast<int>(path_utf8.size()), nullptr, 0);
            std::wstring path(static_cast<std::size_t>(std::max(needed, 0)), L'\0');
            if (needed > 0 && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path_utf8.data(),
                static_cast<int>(path_utf8.size()), path.data(), needed) == needed) {
                BSTR native_path = SysAllocStringLen(path.data(), static_cast<UINT>(path.size()));
                if (native_path) {
                    constexpr std::array methods{L"GetProtectionStatus", L"GetConversionStatus", L"GetEncryptionMethod"};
                    for (const auto* method : methods) {
                        const auto method_json = call_method(services.value, native_path, class_object.value, method, index);
                        row["methods"][ascii(method)] = method_json;
                        result["methods_invoked"].push_back(ascii(method));
                        if (method_json.value("method_return_success", false) == false) ++output_failures;
                        for (const auto& [_, field] : method_json.value("outputs", Json::object()).items())
                            if (field.value("state", "unavailable") != "healthy") ++output_degraded;
                    }
                    SysFreeString(native_path);
                } else row["path_validation_error"] = "method_object_path_allocation_failed";
            } else row["path_validation_error"] = "method_object_path_utf8_conversion_failed";
        } else row["path_validation_error"] = "method_object_path_unavailable";
        // The object path is a call input only and is never emitted.
        std::uint32_t status_value = 0;
        const auto& protection = row["methods"]["GetProtectionStatus"];
        if (value_u32(protection, "protection_status", status_value)) row["reported_protection_on"] = status_value == 1;
        std::size_t bytes = row.dump().size();
        if (bytes > 32768 || bytes + 1 > kMaxOutputBytes - encoded_bytes) {
            result["row_encoded_bound_exceeded"] = true;
            break;
        }
        encoded_bytes += bytes + 1;
        row["state"] = row["fields"]["device_id"].value("state", "unavailable") == "healthy" ? "degraded" : "unavailable";
        result["entries"].push_back(std::move(row));
        if (next_hr == WBEM_S_FALSE) { result["enumeration_completed"] = true; break; }
    }
    result["entries_returned"] = std::to_string(result["entries"].size());
    result["output_failures"] = std::to_string(output_failures);
    result["output_degraded_fields"] = std::to_string(output_degraded);
    result["encoded_output_bytes"] = std::to_string(encoded_bytes);
    result["state"] = result["entries"].empty() ? "unavailable" : "degraded";
    return finish();
}
}

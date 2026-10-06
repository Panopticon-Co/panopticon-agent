#include "panopticon/officer/state/defender_status.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wbemidl.h>
#include <oleauto.h>
#include <iostream>
#include <stdexcept>
#include <string_view>
using Json = nlohmann::json;
using namespace panopticon::officer;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char** argv) {
    try {
        Json cases = Json::array(); std::size_t copied = 0;
        VARIANT value; VariantInit(&value);
        const auto decode = [&](CIMTYPE expected, CIMTYPE reported) {
            auto field = state::detail::decode_defender_property(&value, expected, reported, copied);
            cases.push_back(field); return field;
        };
        value.vt = VT_BOOL; value.boolVal = VARIANT_FALSE;
        require(decode(CIM_BOOLEAN, CIM_BOOLEAN)["value"] == false, "reported false became unknown");
        value.boolVal = VARIANT_TRUE;
        require(decode(CIM_BOOLEAN, CIM_BOOLEAN)["value"] == true, "reported true lost");
        value.boolVal = 1;
        auto odd = decode(CIM_BOOLEAN, CIM_BOOLEAN);
        require(odd["value"].is_null() && odd["raw_scalar"] == "1", "invalid bool coerced");
        value.vt = VT_I4; value.lVal = -1;
        require(decode(CIM_UINT32, CIM_UINT32)["value"] == "4294967295", "uint32 high bits lost");
        value.lVal = 65535;
        require(decode(CIM_UINT32, CIM_UINT32)["value"] == "65535", "age sentinel rewritten");
        auto mismatch = decode(CIM_UINT32, CIM_SINT32);
        require(mismatch["value"].is_null() && mismatch["raw_scalar"] == "65535", "CIM mismatch guessed");
        value.vt = VT_UI1; value.bVal = 255;
        require(decode(CIM_UINT8, CIM_UINT8)["value"] == "255", "uint8 narrowed");
        value.vt = VT_NULL;
        require(decode(CIM_STRING, CIM_STRING)["value"].is_null(), "NULL inferred empty string");
        value.vt = VT_BSTR | VT_BYREF; value.pbstrVal = nullptr;
        require(decode(CIM_STRING, CIM_STRING)["value"].is_null(), "BYREF dereferenced");
        value.vt = VT_BSTR | VT_ARRAY; value.parray = nullptr;
        require(decode(CIM_STRING, CIM_STRING)["value"].is_null(), "array coerced");
        value.vt = VT_BSTR; value.bstrVal = SysAllocStringLen(L"a\0b", 3);
        require(value.bstrVal != nullptr, "BSTR allocation failed");
        require(decode(CIM_STRING, CIM_STRING)["value"] == std::string("a\0b", 3), "embedded NUL lost");
        VariantClear(&value); value.vt = VT_BSTR; value.bstrVal = SysAllocString(L"");
        require(decode(CIM_STRING, CIM_STRING)["value"] == "", "known empty became NULL");
        VariantClear(&value); value.vt = VT_BSTR; value.bstrVal = SysAllocString(L"20261006123456.000000+***");
        auto date = decode(CIM_DATETIME, CIM_DATETIME);
        require(date["value"] == "20261006123456.000000+***" && date["timestamp_normalized"] == false,
            "provider datetime invented UTC");
        VariantClear(&value); value.vt = VT_BSTR;
        const wchar_t invalid[]{0xd800}; value.bstrVal = SysAllocStringLen(invalid, 1);
        auto invalid_text = decode(CIM_STRING, CIM_STRING);
        require(invalid_text["value"].is_null() && invalid_text["raw_text"]["bytes"] == "00d8" &&
            invalid_text["text_conversion_error_code"] == std::to_string(ERROR_NO_UNICODE_TRANSLATION),
            "invalid UTF16 or native conversion error lost");
        VariantClear(&value); value.vt = VT_BSTR; value.bstrVal = SysAllocStringByteLen("abc", 3);
        require(decode(CIM_STRING, CIM_STRING)["raw_text"]["bytes"] == "616263", "odd BSTR bytes lost");
        VariantClear(&value); value.vt = VT_BSTR; value.bstrVal = SysAllocStringLen(nullptr, 4097);
        require(decode(CIM_STRING, CIM_STRING)["validation_error"] == "text_copy_bound", "string bound ignored");
        VariantClear(&value); value.vt = VT_BSTR; value.bstrVal = SysAllocString(L"x"); copied = 32768;
        require(decode(CIM_STRING, CIM_STRING)["validation_error"] == "text_copy_bound" && copied == 32768,
            "aggregate text bound ignored");
        VariantClear(&value);
        Json modern = Json::array(); copied = 0;
        const auto modern_query = [&](const char* name, HRESULT hr, CIMTYPE expected, CIMTYPE reported) {
            auto field = state::detail::decode_defender_query_result(name, true,
                static_cast<std::uint32_t>(hr), &value, expected, reported, copied);
            modern.push_back(field); return field;
        };
        for (const auto* mode : {L"Normal", L"Passive", L"EDR Block Mode", L"FutureMode"}) {
            value.vt = VT_BSTR; value.bstrVal = SysAllocString(mode);
            const auto field = modern_query("AMRunningMode", S_OK, CIM_STRING, CIM_STRING);
            if (std::wstring_view{mode} == L"FutureMode") require(field["value"] == "FutureMode" &&
                field["reported_mode"].is_null() && field["state"] == "degraded", "future mode guessed");
            else require(field["reported_mode"] == field["value"] && field["protection_verified"] == false,
                "documented provider mode lost or attested");
            VariantClear(&value);
        }
        value.vt = VT_BOOL; value.boolVal = VARIANT_FALSE;
        auto tamper = modern_query("IsTamperProtected", S_OK, CIM_BOOLEAN, CIM_BOOLEAN);
        require(tamper["value"] == false && tamper["reported_tamper_state"] == "disabled" &&
            tamper["state"] == "healthy", "known tamper false conflated with missing query");
        value.boolVal = VARIANT_TRUE;
        require(modern_query("IsTamperProtected", S_OK, CIM_BOOLEAN, CIM_BOOLEAN)["reported_tamper_state"] == "enabled",
            "known tamper true lost");
        value.boolVal = 1;
        require(modern_query("IsTamperProtected", S_OK, CIM_BOOLEAN, CIM_BOOLEAN)["reported_tamper_state"].is_null(),
            "invalid tamper Boolean guessed");
        value.vt = VT_BSTR; value.bstrVal = SysAllocString(L"DescriptiveOnly");
        require(modern_query("TamperProtectionSource", S_OK, CIM_STRING, CIM_STRING)["policy_authority_verified"] == false,
            "descriptive tamper source became verified policy authority");
        VariantClear(&value);
        auto absent = modern_query("AMRunningMode", WBEM_E_NOT_FOUND, CIM_STRING, CIM_STRING);
        require(absent["property_availability"] == "not_exposed_by_object" && absent["value"].is_null() &&
            absent["reported_mode"].is_null() && absent["hresult_code"] == "2147749890", "absent modern property guessed");
        auto denied = modern_query("IsTamperProtected", E_ACCESSDENIED, CIM_BOOLEAN, CIM_BOOLEAN);
        require(denied["property_availability"] == "query_refused" && denied["reported_tamper_state"].is_null(),
            "refusal became false tamper state");
        value.vt = VT_BSTR; value.bstrVal = SysAllocString(L"Passive");
        require(modern_query("AMRunningMode", 2, CIM_STRING, CIM_STRING)["reported_mode"].is_null(),
            "unusual success HRESULT granted trusted mode");
        require(modern_query("AMRunningMode", S_OK, CIM_STRING, CIM_BOOLEAN)["reported_mode"].is_null(),
            "CIM mismatch granted trusted mode");
        VariantClear(&value);
        Json retained_rows = Json::array({{{"fields", {{"AMRunningMode", modern[0]},
            {"IsTamperProtected", modern[4]}, {"TamperProtectionSource", modern[7]}}}}});
        const auto healthy_quality = state::detail::defender_modern_property_quality(retained_rows);
        require(healthy_quality["IsTamperProtected"]["state"] == "healthy", "reported false degraded getter quality");
        retained_rows.push_back({{"fields", {{"AMRunningMode", absent}, {"IsTamperProtected", denied}}}});
        const auto partial_quality = state::detail::defender_modern_property_quality(retained_rows);
        require(partial_quality["AMRunningMode"]["state"] == "degraded" &&
            partial_quality["TamperProtectionSource"]["missing_field_captured_rows"] == "1", "partial rows claimed full getter quality");
        require(state::detail::defender_modern_property_quality(Json::array())["AMRunningMode"]["state"] == "unavailable",
            "empty provider result inferred a running mode");
        const auto native = state::collect_defender_status();
        require(native["inventory_complete"] == false && native["protection_verified"] == false &&
            native["entries"].size() <= 8 && native["entries"].dump().size() <= 655360,
            "native capture claimed full protection or exceeded encoded bounds");
        for (const auto& row : native["entries"]) require(row["fields"].size() == 36 &&
            row["process_reference"].is_null() && row["device_reference"].is_null(), "native row invented identity");
        const auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        require(SUCCEEDED(initialized), "test STA setup failed");
        const auto incompatible = state::collect_defender_status();
        require(incompatible["state"] == "unavailable" && incompatible["native_steps"][0]["hresult_code"] ==
            std::to_string(static_cast<std::uint32_t>(RPC_E_CHANGED_MODE)), "incompatible apartment error lost");
        const auto still_sta = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        require(still_sta == S_FALSE, "collector uninitialized caller apartment");
        CoUninitialize(); CoUninitialize();
        if (argc == 2 && std::string(argv[1]) == "--emit-fixtures") {
            pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
            pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
            Json records = Json::array({factory.state("defender_status", native),
                factory.state("defender_status", incompatible), factory.state("defender_status", {
                    {"state", "degraded"}, {"decoder_cases", cases}, {"inventory_complete", false}, {"protection_verified", false}}),
                factory.state("defender_status", {{"state", "degraded"}, {"modern_query_cases", modern},
                    {"modern_property_quality", partial_quality}, {"inventory_complete", false}, {"protection_verified", false}})});
            std::cout << records.dump() << '\n'; return 0;
        }
        std::cout << "Defender typed properties, malformed data, copy bounds and COM ownership passed; native " << native.dump() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

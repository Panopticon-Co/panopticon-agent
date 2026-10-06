#include "panopticon/officer/state/firewall_profiles.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <iostream>
#include <stdexcept>
using namespace panopticon::officer;
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
struct OwnedVariant {
    VARIANT value;
    OwnedVariant() { VariantInit(&value); }
    ~OwnedVariant() { VariantClear(&value); }
};
void exclusion_arrays() {
    OwnedVariant mixed;
    mixed.value.vt = VT_ARRAY | VT_VARIANT;
    mixed.value.parray = SafeArrayCreateVector(VT_VARIANT, -7, 4);
    require(mixed.value.parray != nullptr, "owned variant array allocation");
    VARIANT* entries = nullptr;
    require(SUCCEEDED(SafeArrayAccessData(mixed.value.parray, reinterpret_cast<void**>(&entries))), "owned data access");
    const wchar_t embedded[]{L'a', 0, L'b'};
    entries[0].vt = VT_BSTR; entries[0].bstrVal = SysAllocStringLen(embedded, 3);
    const wchar_t surrogate[]{static_cast<wchar_t>(0xd800)};
    entries[1].vt = VT_BSTR; entries[1].bstrVal = SysAllocStringLen(surrogate, 1);
    entries[2].vt = VT_I4; entries[2].lVal = 17;
    entries[3].vt = VT_BSTR | VT_BYREF; entries[3].pbstrVal = nullptr;
    require(SUCCEEDED(SafeArrayUnaccessData(mixed.value.parray)), "owned data unlock");
    const auto decoded = state::detail::decode_firewall_exclusions(&mixed.value);
    require(decoded["reported_items"] == "4" && decoded["array_lower_bound"] == "-7" &&
        !decoded["complete"].get<bool>(), "mixed array became complete or lower bound lost");
    require(decoded["value"][0]["reported_name"].get<std::string>() == std::string{"a\0b", 3}, "BSTR embedded NUL lost");
    require(decoded["value"][1]["reported_name"]["bytes"] == "00d8", "malformed UTF16 replaced or lost");
    require(decoded["value"][2]["reported_name"].is_null() && decoded["value"][3]["reported_name"].is_null(),
        "nontext/BYREF variant was coerced or dereferenced");
    require(decoded["value"][2]["raw_scalar"] == "17", "uninterpreted integer evidence lost");
    require(mixed.value.parray->cLocks == 0 && entries[0].bstrVal[2] == L'b', "borrowed array changed or remained locked");
    OwnedVariant empty;
    empty.value.vt = VT_ARRAY | VT_BSTR; empty.value.parray = SafeArrayCreateVector(VT_BSTR, 0, 0);
    require(empty.value.parray != nullptr, "owned empty array allocation");
    const auto zero = state::detail::decode_firewall_exclusions(&empty.value);
    require(zero["complete"].get<bool>() && zero["value"].empty(), "typed empty array became unknown");
    unsigned exclusion_calls = 0;
    const auto partial = state::detail::collect_firewall_profile_state(
        [](state::detail::FirewallField, std::uint32_t) { return state::detail::FirewallQueryResult{0, 0, 1, 2}; },
        [&](std::uint32_t profile) {
            ++exclusion_calls;
            auto fact = zero;
            fact["hresult_code"] = profile == 2 ? "2147942405" : "0";
            if (profile == 2) { fact["state"] = "unavailable"; fact["value"] = nullptr; fact["complete"] = false; }
            return fact;
        });
    require(exclusion_calls == 3 && partial["exclusion_query_summary"]["successful_queries"] == "2" &&
        partial["exclusion_query_summary"]["failed_queries"] == "1" &&
        !partial["excluded_interfaces_collected"].get<bool>() &&
        partial["profiles"][1]["fields"]["excluded_interfaces"]["value"].is_null(),
        "partial exclusion refusal became empty or suppressed other profile queries");
    OwnedVariant oversized;
    oversized.value.vt = VT_ARRAY | VT_VARIANT; oversized.value.parray = SafeArrayCreateVector(VT_VARIANT, 0, 129);
    require(oversized.value.parray != nullptr, "owned oversized array allocation");
    require(state::detail::decode_firewall_exclusions(&oversized.value)["validation_error"] == "array_item_bound" &&
        oversized.value.parray->cLocks == 0, "array bound checked after native data access");
    OwnedVariant names;
    names.value.vt = VT_ARRAY | VT_BSTR; names.value.parray = SafeArrayCreateVector(VT_BSTR, 3, 4);
    BSTR* strings = nullptr;
    require(names.value.parray && SUCCEEDED(SafeArrayAccessData(names.value.parray, reinterpret_cast<void**>(&strings))), "owned names access");
    strings[0] = SysAllocStringByteLen("x", 1);
    const std::wstring large(4097, L'x'); strings[1] = SysAllocStringLen(large.data(), 4097);
    strings[2] = SysAllocString(L"same"); strings[3] = SysAllocString(L"same");
    require(SUCCEEDED(SafeArrayUnaccessData(names.value.parray)), "owned names unlock");
    const auto bounded = state::detail::decode_firewall_exclusions(&names.value);
    require(bounded["value"][0]["reported_name"]["bytes"] == "78", "odd-length BSTR silently lost trailing byte");
    require(bounded["value"][1]["validation_error"] == "string_copy_bound" &&
        bounded["value"][1]["reported_name"].is_null(), "oversized name copied or fabricated");
    require(bounded["value"][2]["reported_name"] == "same" && bounded["value"][3]["reported_name"] == "same" &&
        bounded["value"][2]["interface_reference"].is_null(), "duplicate names collapsed or joined to invented interface");
    VARIANT unknown; VariantInit(&unknown);
    require(state::detail::decode_firewall_exclusions(&unknown)["value"].is_null(), "VT_EMPTY claimed zero exclusions");
    OwnedVariant aggregate;
    aggregate.value.vt = VT_ARRAY | VT_BSTR; aggregate.value.parray = SafeArrayCreateVector(VT_BSTR, 0, 3);
    BSTR* aggregate_names = nullptr;
    require(aggregate.value.parray && SUCCEEDED(SafeArrayAccessData(aggregate.value.parray,
        reinterpret_cast<void**>(&aggregate_names))), "owned aggregate access");
    const std::wstring maximum(4096, L'x');
    for (int i = 0; i < 3; ++i) aggregate_names[i] = SysAllocStringLen(maximum.data(), 4096);
    require(SUCCEEDED(SafeArrayUnaccessData(aggregate.value.parray)), "owned aggregate unlock");
    const auto charged = state::detail::decode_firewall_exclusions(&aggregate.value);
    require(charged["copied_utf16_bytes"] == "16384" && charged["value"].size() == 3 &&
        charged["value"][2]["validation_error"] == "string_copy_bound", "aggregate string bound lost row or exceeded capacity");
    SAFEARRAYBOUND bounds[2]{{1, 0}, {1, 0}};
    OwnedVariant multidimensional;
    multidimensional.value.vt = VT_ARRAY | VT_VARIANT;
    multidimensional.value.parray = SafeArrayCreate(VT_VARIANT, 2, bounds);
    require(multidimensional.value.parray && state::detail::decode_firewall_exclusions(&multidimensional.value)
        ["validation_error"] == "array_dimension_uninterpreted", "multidimensional array traversed as flat names");
}
int main(int argc, char** argv) {
    try {
        exclusion_arrays();
        using Field = state::detail::FirewallField;
        unsigned calls = 0;
        const auto snapshot = state::detail::collect_firewall_profile_state([&](Field field, std::uint32_t profile) {
            ++calls;
            require(profile == 0 || profile == 1 || profile == 2 || profile == 4, "combined profile mask sent to getter");
            std::int32_t output = -1;
            std::uint32_t status = 0;
            if (field == Field::current_profiles) output = 5;
            if (field == Field::modify_state) output = 1;
            if (field == Field::default_inbound) output = 0;
            if (field == Field::default_outbound) output = 1;
            if (field == Field::enabled && profile == 2) { status = 0x80070005u; output = 0; }
            if (field == Field::enabled && profile == 4) output = 0;
            if (field == Field::notifications_disabled && profile == 1) output = 1;
            if (field == Field::default_inbound && profile == 4) output = 2;
            if (field == Field::block_inbound && profile == 4) { status = 1; output = -1; }
            return state::detail::FirewallQueryResult{status, output, 10, 20};
        });
        require(calls == 20 && snapshot["query_summary"]["successful_queries"] == "19" &&
            snapshot["query_summary"]["failed_queries"] == "1" &&
            snapshot["query_summary"]["uninterpreted_queries"] == "3", "independent getter accounting");
        require(snapshot["reported_current_profile_types"]["value"] == nlohmann::json{
            {"domain", true}, {"private", false}, {"public", true}}, "active profile mask collapsed");
        require(snapshot["reported_local_policy_modify_state"]["value"] == "group_policy_override", "modify state lost");
        const auto& denied = snapshot["profiles"][1]["fields"]["locally_enabled"];
        require(denied["hresult_code"] == "2147942405" && denied["raw_output"].is_null() &&
            denied["value"].is_null() && denied["state"] == "unavailable", "HRESULT refusal became disabled firewall");
        require(snapshot["profiles"][2]["fields"]["locally_enabled"]["value"] == false,
            "successful false output became unknown");
        require(snapshot["profiles"][0]["fields"]["notifications_disabled"]["value"].is_null() &&
            snapshot["profiles"][0]["fields"]["notifications_disabled"]["raw_output"] == "1",
            "noncanonical VARIANT_BOOL became true");
        require(snapshot["profiles"][2]["fields"]["default_inbound_action"]["value"].is_null(), "sentinel action became allow/block");
        require(snapshot["profiles"][2]["fields"]["block_all_inbound_traffic"]["state"] == "degraded" &&
            snapshot["profiles"][2]["fields"]["block_all_inbound_traffic"]["hresult_code"] == "1", "nonzero successful HRESULT erased");
        const auto unsupported = state::detail::collect_firewall_profile_state([](Field, std::uint32_t) {
            return state::detail::FirewallQueryResult{0x80004001u, 0, 1, 2};
        });
        require(unsupported["state"] == "unavailable" && unsupported["query_summary"]["failed_queries"] == "20",
            "unavailable native getters manufactured posture");
        const auto unknown = state::detail::collect_firewall_profile_state([](Field, std::uint32_t) {
            return state::detail::FirewallQueryResult{0, 0x7fffffff, 1, 2};
        });
        require(unknown["reported_current_profile_types"]["value"].is_null() &&
            unknown["reported_local_policy_modify_state"]["value"].is_null(), "unknown mask/enum interpreted");
        const auto native = state::collect_firewall_profile_state();
        require(!native["inventory_complete"].get<bool>() && !native["effective_packet_policy_verified"].get<bool>(),
            "profile getter coverage presented as full enforcement");
        {
            const auto initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            require(SUCCEEDED(initialized), "owned STA initialization failed");
            struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
            const auto conflicting = state::collect_firewall_profile_state();
            require(conflicting["initialization"]["stage"] == "CoInitializeEx" &&
                conflicting["initialization"]["hresult_code"] == std::to_string(static_cast<std::uint32_t>(RPC_E_CHANGED_MODE)) &&
                conflicting["profiles"].empty() && conflicting["query_summary"]["queries_not_attempted"] == "20",
                "incompatible apartment lost HRESULT or invented queried profiles");
            const auto probe = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            if (SUCCEEDED(probe)) CoUninitialize();
            require(probe == S_FALSE, "failed collector initialization uninitialized caller apartment");
        }
        if (argc == 2 && std::string{argv[1]} == "--emit-live") {
            pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
            pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
            std::cout << factory.state("firewall_profile_state", native).dump() << '\n'; return 0;
        }
        std::cout << "Firewall profile independent getter failures, raw output, masks, HRESULTs and actual read-only native capture passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

#include "panopticon/officer/state/firewall_profiles.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <oleauto.h>
#include <string>
namespace panopticon::officer::state::detail {
using Json = nlohmann::json;
Json decode_firewall_exclusions(const void* borrowed) {
    Json result{{"state", "degraded"}, {"value", nullptr}, {"complete", false},
        {"item_limit", "128"}, {"string_unit_limit", "4096"}, {"copied_utf16_byte_limit", "16384"},
        {"native_allocation_bounded", false}, {"interface_lifetime_verified", false}};
    const auto refuse = [&](const char* reason) { result["validation_error"] = reason; return result; };
    if (!borrowed) return refuse("missing_variant");
    const auto& input = *static_cast<const VARIANT*>(borrowed);
    result["variant_type"] = std::to_string(input.vt);
    if (input.vt != (VT_ARRAY | VT_BSTR) && input.vt != (VT_ARRAY | VT_VARIANT))
        return refuse("uninterpreted_variant_type");
    auto* array = input.parray;
    if (!array) return refuse("null_array");
    result["dimensions"] = std::to_string(SafeArrayGetDim(array));
    if (SafeArrayGetDim(array) != 1) return refuse("array_dimension_uninterpreted");
    VARTYPE type = VT_EMPTY;
    auto error = SafeArrayGetVartype(array, &type);
    result["array_vartype_hresult_code"] = std::to_string(static_cast<std::uint32_t>(error));
    if (FAILED(error)) return refuse("array_type_query_failed");
    result["array_element_type"] = std::to_string(type);
    if ((input.vt & VT_TYPEMASK) != type) return refuse("array_type_mismatch");
    const auto size = SafeArrayGetElemsize(array);
    result["array_element_bytes"] = std::to_string(size);
    if (size != (type == VT_BSTR ? sizeof(BSTR) : sizeof(VARIANT))) return refuse("array_element_size_mismatch");
    LONG lower = 0, upper = 0;
    error = SafeArrayGetLBound(array, 1, &lower);
    result["array_lower_bound_hresult_code"] = std::to_string(static_cast<std::uint32_t>(error));
    if (FAILED(error)) return refuse("array_lower_bound_query_failed");
    error = SafeArrayGetUBound(array, 1, &upper);
    result["array_upper_bound_hresult_code"] = std::to_string(static_cast<std::uint32_t>(error));
    if (FAILED(error)) return refuse("array_upper_bound_query_failed");
    result["array_lower_bound"] = std::to_string(lower); result["array_upper_bound"] = std::to_string(upper);
    const auto count = static_cast<std::int64_t>(upper) - lower + 1;
    if (count < 0) return refuse("array_bounds_invalid");
    result["reported_items"] = std::to_string(count);
    if (count > 128) return refuse("array_item_bound");
    auto items = Json::array();
    if (!count) { result["value"] = items; result["complete"] = true; result["state"] = "healthy"; return result; }
    void* data = nullptr;
    error = SafeArrayAccessData(array, &data);
    result["array_access_hresult_code"] = std::to_string(static_cast<std::uint32_t>(error));
    if (FAILED(error)) return refuse("array_access_failed");
    struct Unlock { SAFEARRAY* array; ~Unlock() { if (array) SafeArrayUnaccessData(array); } } unlock{array};
    if (!data) return refuse("native_success_without_array_data");
    bool complete = true;
    std::size_t copied_bytes = 0;
    for (std::int64_t index = 0; index < count; ++index) {
        Json item{{"array_index", std::to_string(static_cast<std::int64_t>(lower) + index)},
            {"interface_reference", nullptr}, {"reported_name", nullptr}, {"state", "degraded"}};
        BSTR name = nullptr;
        VARTYPE element_type = VT_BSTR;
        if (type == VT_BSTR) name = static_cast<BSTR*>(data)[index];
        else { const auto& element = static_cast<VARIANT*>(data)[index]; element_type = element.vt;
            switch (element_type) {
            case VT_BSTR: name = element.bstrVal; break;
            case VT_I4: item["raw_scalar"] = std::to_string(element.lVal); break;
            case VT_UI4: item["raw_scalar"] = std::to_string(element.ulVal); break;
            case VT_I8: item["raw_scalar"] = std::to_string(element.llVal); break;
            case VT_UI8: item["raw_scalar"] = std::to_string(element.ullVal); break;
            case VT_BOOL: item["raw_scalar"] = std::to_string(element.boolVal); break;
            case VT_ERROR: item["raw_scalar"] = std::to_string(static_cast<std::uint32_t>(element.scode)); break;
            default: break;
            }
        }
        item["variant_type"] = std::to_string(element_type);
        if (element_type != VT_BSTR || !name) {
            complete = false; item["validation_error"] = element_type == VT_BSTR ? "null_bstr" : "uninterpreted_element_type";
        } else {
            const auto units = SysStringLen(name);
            const auto byte_length = SysStringByteLen(name);
            item["reported_utf16_units"] = std::to_string(units);
            item["reported_bstr_bytes"] = std::to_string(byte_length);
            if (units > 4096 || byte_length > 8192 || byte_length > 16384 - copied_bytes) {
                complete = false; item["validation_error"] = "string_copy_bound";
            } else {
                copied_bytes += byte_length;
                if (byte_length % sizeof(wchar_t)) {
                    std::string hex; constexpr char digits[] = "0123456789abcdef";
                    const auto* bytes = reinterpret_cast<const unsigned char*>(name);
                    for (UINT i = 0; i < byte_length; ++i) { hex += digits[bytes[i] >> 4]; hex += digits[bytes[i] & 15]; }
                    item["reported_name"] = {{"encoding", "bstr_bytes_hex"}, {"bytes", std::move(hex)}};
                    item["validation_error"] = "bstr_odd_byte_length"; complete = false;
                    items.push_back(std::move(item)); continue;
                }
                const auto length = units ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name,
                    static_cast<int>(units), nullptr, 0, nullptr, nullptr) : 0;
                const auto conversion_error = units && !length ? GetLastError() : 0;
                if (!units || length > 0) {
                    std::string text(length, '\0');
                    if (length && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name,
                        static_cast<int>(units), text.data(), length, nullptr, nullptr) != length) {
                        const auto error_code = GetLastError();
                        complete = false; item["validation_error"] = "utf8_conversion_failed";
                        item["conversion_error_code"] = std::to_string(error_code);
                    } else { item["reported_name"] = std::move(text); item["state"] = "healthy"; }
                } else {
                    std::string hex; constexpr char digits[] = "0123456789abcdef";
                    for (UINT i = 0; i < units; ++i) {
                        const auto word = static_cast<std::uint16_t>(name[i]);
                        for (const auto byte : {word & 255u, static_cast<unsigned>(word) >> 8}) { hex += digits[byte >> 4]; hex += digits[byte & 15]; }
                    }
                    item["reported_name"] = {{"encoding", "utf16le_hex"}, {"bytes", std::move(hex)}};
                    item["conversion_error_code"] = std::to_string(conversion_error);
                    item["state"] = "healthy"; // Raw text retained; no name/lifetime resolution claim.
                }
            }
        }
        items.push_back(std::move(item));
    }
    error = SafeArrayUnaccessData(array); unlock.array = nullptr;
    result["array_unaccess_hresult_code"] = std::to_string(static_cast<std::uint32_t>(error));
    if (FAILED(error)) complete = false;
    result["copied_utf16_bytes"] = std::to_string(copied_bytes);
    result["value"] = std::move(items); result["complete"] = complete;
    result["state"] = complete ? "healthy" : "degraded";
    return result;
}
}

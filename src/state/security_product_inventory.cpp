#include "panopticon/officer/state/security_product_inventory.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <iwscapi.h>
#include <wscapi.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>

namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
template<class T> struct Com {
    T* value = nullptr;
    Com() = default;
    Com(const Com&) = delete;
    Com& operator=(const Com&) = delete;
    ~Com() { if (value) value->Release(); }
};
struct Bstr { BSTR value = nullptr; ~Bstr() { SysFreeString(value); } };
struct Apartment {
    HRESULT status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ~Apartment() { if (SUCCEEDED(status)) CoUninitialize(); }
};
struct Provider { const char* name; ULONG mask; };
constexpr Provider providers[]{
    {"firewall", WSC_SECURITY_PROVIDER_FIREWALL},
    {"antivirus", WSC_SECURITY_PROVIDER_ANTIVIRUS},
    {"antispyware", WSC_SECURITY_PROVIDER_ANTISPYWARE}
};
constexpr std::size_t kProductLimit = 64;
constexpr std::size_t kStringLimit = 4096;
constexpr std::size_t kTotalStringLimit = 64 * 1024;

Json hex_bytes(const unsigned char* bytes, std::size_t size) {
    constexpr char digits[] = "0123456789abcdef";
    std::string output; output.reserve(size * 2);
    for (std::size_t i = 0; i < size; ++i) { output += digits[bytes[i] >> 4]; output += digits[bytes[i] & 15]; }
    return output;
}
Json bstr_value(BSTR value, std::size_t& copied) {
    if (!value) return { {"state", "degraded"}, {"value", nullptr}, {"reason", "null_bstr"} };
    const auto bytes = static_cast<std::size_t>(SysStringByteLen(value));
    Json fact{{"reported_bytes", std::to_string(bytes)}, {"state", "degraded"}, {"value", nullptr}};
    if (bytes > kStringLimit || copied > kTotalStringLimit || bytes > kTotalStringLimit - copied) {
        fact["bound_exceeded"] = true; fact["reason"] = "string_copy_limit"; return fact;
    }
    copied += bytes;
    if (bytes % sizeof(wchar_t)) {
        fact["raw_bytes_hex"] = hex_bytes(reinterpret_cast<const unsigned char*>(value), bytes);
        fact["reason"] = "odd_bstr_byte_length"; return fact;
    }
    const auto units = SysStringLen(value);
    const auto length = units ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value,
        static_cast<int>(units), nullptr, 0, nullptr, nullptr) : 0;
    if (units && !length) {
        fact["raw_bytes_hex"] = hex_bytes(reinterpret_cast<const unsigned char*>(value), bytes);
        fact["reason"] = "invalid_utf16"; fact["conversion_error_code"] = std::to_string(GetLastError()); return fact;
    }
    std::string text(static_cast<std::size_t>(length), '\0');
    if (length && WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(units),
            text.data(), length, nullptr, nullptr) != length) {
        fact["raw_bytes_hex"] = hex_bytes(reinterpret_cast<const unsigned char*>(value), bytes);
        fact["reason"] = "conversion_length_mismatch"; fact["conversion_error_code"] = std::to_string(GetLastError()); return fact;
    }
    fact["state"] = "healthy"; fact["value"] = std::move(text); return fact;
}
Json hresult_fact(const char* api, HRESULT hr) {
    return {{"source", api}, {"state", hr == S_OK ? "healthy" : FAILED(hr) ? "unavailable" : "degraded"},
        {"error_domain", "HRESULT"}, {"hresult_code", std::to_string(static_cast<std::uint32_t>(hr))}, {"value", nullptr}};
}
Json text_query(IWscProduct* product, const char* label, HRESULT (STDMETHODCALLTYPE IWscProduct::*getter)(BSTR*),
    std::size_t& copied) {
    Bstr text; const auto hr = (product->*getter)(&text.value);
    auto fact = hresult_fact(label, hr);
    if (SUCCEEDED(hr)) {
        fact.update(bstr_value(text.value, copied));
        if (hr != S_OK && fact["state"] == "healthy") fact["state"] = "degraded";
    }
    return fact;
}
Json state_query(IWscProduct* product, const char* label,
    HRESULT (STDMETHODCALLTYPE IWscProduct::*getter)(WSC_SECURITY_PRODUCT_STATE*)) {
    WSC_SECURITY_PRODUCT_STATE raw = static_cast<WSC_SECURITY_PRODUCT_STATE>(-1);
    const auto hr = (product->*getter)(&raw); auto fact = hresult_fact(label, hr);
    if (FAILED(hr)) return fact;
    fact["raw_value"] = std::to_string(static_cast<std::int32_t>(raw));
    if (hr != S_OK) fact["state"] = "degraded";
    constexpr const char* names[]{"on", "off", "snoozed", "expired"};
    const auto value = static_cast<std::int32_t>(raw);
    if (value >= 0 && value < 4) fact["reported_state"] = names[value];
    else { fact["state"] = "degraded"; fact["reported_state"] = nullptr; fact["validation_error"] = "unknown_product_state"; }
    fact["value"] = nullptr; fact["protection_verified"] = false;
    return fact;
}
Json signature_query(IWscProduct* product, std::size_t& copied) {
    WSC_SECURITY_SIGNATURE_STATUS raw = static_cast<WSC_SECURITY_SIGNATURE_STATUS>(-1);
    const auto hr = product->get_SignatureStatus(&raw); auto fact = hresult_fact("IWscProduct::get_SignatureStatus", hr);
    if (FAILED(hr)) return fact;
    fact["raw_value"] = std::to_string(static_cast<std::int32_t>(raw));
    if (hr != S_OK) fact["state"] = "degraded";
    if (raw == WSC_SECURITY_PRODUCT_OUT_OF_DATE) fact["reported_status"] = "out_of_date";
    else if (raw == WSC_SECURITY_PRODUCT_UP_TO_DATE) fact["reported_status"] = "up_to_date";
    else { fact["state"] = "degraded"; fact["reported_status"] = nullptr; fact["validation_error"] = "unknown_signature_status"; }
    fact["value"] = nullptr;
    fact["scope"] = "Windows Security Center reported signature status; not direct signature verification";
    (void)copied;
    return fact;
}
Json default_query(IWscProduct* product) {
    BOOL raw = -1; const auto hr = product->get_ProductIsDefault(&raw);
    auto fact = hresult_fact("IWscProduct::get_ProductIsDefault", hr);
    if (FAILED(hr)) return fact;
    fact["raw_value"] = std::to_string(raw);
    if (hr != S_OK) fact["state"] = "degraded";
    if (raw == FALSE || raw == TRUE) fact["reported_default"] = raw == TRUE;
    else { fact["state"] = "degraded"; fact["reported_default"] = nullptr; fact["validation_error"] = "noncanonical_bool"; }
    fact["value"] = nullptr; return fact;
}
Json product_row(IWscProduct* product, const char* provider, std::size_t index) {
    Json row{{"provider", provider}, {"enumeration_index", std::to_string(index)},
        {"state", "degraded"}, {"fields", Json::object()}, {"product_reference", nullptr},
        {"signer_verified", false}, {"protection_verified", false},
        {"scope", "caller-visible WSC registration report; product identity, binary and enforcement are not independently verified"}};
    const auto blanket = CoSetProxyBlanket(product, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    row["proxy_security"] = hresult_fact("CoSetProxyBlanket/IWscProduct", blanket);
    if (FAILED(blanket)) { row["state"] = "unavailable"; return row; }
    std::size_t copied = 0;
    auto& fields = row["fields"];
    fields["product_name"] = text_query(product, "IWscProduct::get_ProductName", &IWscProduct::get_ProductName, copied);
    fields["product_guid"] = text_query(product, "IWscProduct::get_ProductGuid", &IWscProduct::get_ProductGuid, copied);
    fields["remediation_path"] = text_query(product, "IWscProduct::get_RemediationPath", &IWscProduct::get_RemediationPath, copied);
    fields["state_timestamp"] = text_query(product, "IWscProduct::get_ProductStateTimestamp", &IWscProduct::get_ProductStateTimestamp, copied);
    fields["product_state"] = state_query(product, "IWscProduct::get_ProductState", &IWscProduct::get_ProductState);
    fields["signature_status"] = signature_query(product, copied);
    fields["is_default"] = default_query(product);
    std::size_t healthy = 0;
    for (auto it = fields.begin(); it != fields.end(); ++it) {
        if (it.value().value("state", "unavailable") == "healthy") ++healthy;
    }
    const auto incomplete = fields.size() - healthy;
    row["state"] = healthy ? "degraded" : "unavailable";
    row["healthy_getter_count"] = std::to_string(healthy);
    row["unavailable_or_degraded_getter_count"] = std::to_string(incomplete);
    row["copied_text_bytes"] = std::to_string(copied);
    return row;
}
}

Json collect_security_product_inventory() {
    Json result{{"format", "security_product_registration_v1"}, {"collector_version", "1.0"},
        {"state", "unavailable"}, {"categories", Json::array()}, {"products", Json::array()},
        {"inventory_complete", false}, {"protection_verified", false}, {"signer_verified", false},
        {"platform_contract", "WSC product list documents client support from Windows 8 and no supported server contract"},
        {"platform_qualified", false}, {"native_calls_hard_deadline_enforced", false},
        {"product_limit_per_category", kProductLimit}, {"product_string_limit_bytes", kStringLimit},
        {"product_total_string_limit_bytes", kTotalStringLimit},
        {"scope", "caller-visible WSC firewall, antivirus and antispyware registrations; WSC reports are not independent product verification or effective protection"}};
    result["collection_started_uptime_ms"] = std::to_string(GetTickCount64());
    Apartment apartment;
    if (FAILED(apartment.status)) {
        result["initialization"] = hresult_fact("CoInitializeEx/COINIT_MULTITHREADED", apartment.status);
        result["collection_completed_uptime_ms"] = std::to_string(GetTickCount64()); return result;
    }
    result["initialization"] = hresult_fact("CoInitializeEx/COINIT_MULTITHREADED", apartment.status);
    unsigned completed = 0, partial = 0, failed = 0; std::size_t total_products = 0;
    for (const auto& provider : providers) {
        Json category{{"provider", provider.name}, {"provider_mask", std::to_string(provider.mask)},
            {"state", "unavailable"}, {"enumeration_complete", false}, {"reported_count", nullptr},
            {"item_query_failures", "0"}, {"products_returned", "0"},
            {"query_started_uptime_ms", std::to_string(GetTickCount64())}};
        Com<IWSCProductList> list;
        auto hr = CoCreateInstance(__uuidof(WSCProductList), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(IWSCProductList), reinterpret_cast<void**>(&list.value));
        bool canonical_succeeded = hr == S_OK;
        category["creation"] = hresult_fact("CoCreateInstance/WSCProductList", hr);
        if (SUCCEEDED(hr) && !list.value) {
            category["state"] = "unavailable";
            category["creation"]["validation_error"] = "success_without_interface";
        }
        if (SUCCEEDED(hr) && list.value) {
            hr = CoSetProxyBlanket(list.value, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
            canonical_succeeded &= hr == S_OK;
            category["proxy_security"] = hresult_fact("CoSetProxyBlanket/IWSCProductList", hr);
            if (SUCCEEDED(hr)) {
                hr = list.value->Initialize(provider.mask);
                canonical_succeeded &= hr == S_OK;
                category["initialize"] = hresult_fact("IWSCProductList::Initialize", hr);
            }
            if (SUCCEEDED(hr)) {
                LONG count = -1; hr = list.value->get_Count(&count);
                canonical_succeeded &= hr == S_OK;
                category["count_query"] = hresult_fact("IWSCProductList::get_Count", hr);
                if (SUCCEEDED(hr) && count >= 0) {
                    category["reported_count"] = std::to_string(count);
                    const auto bounded = std::min<std::size_t>(static_cast<std::size_t>(count), kProductLimit);
                    unsigned item_failures = 0, products_returned = 0;
                    for (std::size_t index = 0; index < bounded; ++index) {
                        Com<IWscProduct> product;
                        const auto item_hr = list.value->get_Item(static_cast<ULONG>(index), &product.value);
                        if (item_hr != S_OK || !product.value) {
                            ++item_failures;
                            auto item_query = hresult_fact("IWSCProductList::get_Item", item_hr);
                            if (SUCCEEDED(item_hr) && !product.value) {
                                item_query["state"] = "degraded";
                                item_query["validation_error"] = "success_without_product";
                            }
                            result["products"].push_back({{"provider", provider.name}, {"enumeration_index", std::to_string(index)},
                                {"state", "unavailable"}, {"item_query", std::move(item_query)},
                                {"product_reference", nullptr}, {"protection_verified", false}, {"signer_verified", false}});
                            continue;
                        }
                        auto row = product_row(product.value, provider.name, index);
                        row["item_query"] = hresult_fact("IWSCProductList::get_Item", item_hr);
                        result["products"].push_back(std::move(row)); ++products_returned; ++total_products;
                    }
                    category["item_query_failures"] = std::to_string(item_failures);
                    category["items_attempted"] = std::to_string(bounded);
                    category["products_returned"] = std::to_string(products_returned);
                    category["enumeration_complete"] = canonical_succeeded &&
                        static_cast<std::size_t>(count) <= kProductLimit && !item_failures;
                    category["limit_exceeded"] = static_cast<std::size_t>(count) > kProductLimit;
                    category["state"] = category["enumeration_complete"] == true || bounded > 0 ? "degraded" : "unavailable";
                    if (category["enumeration_complete"] == true) ++completed;
                    else if (bounded > 0) ++partial;
                    else ++failed;
                } else {
                    category["state"] = "unavailable";
                    if (SUCCEEDED(hr) && count < 0) category["count_query"]["validation_error"] = "negative_product_count";
                    ++failed;
                }
            } else { category["state"] = "unavailable"; ++failed; }
        } else ++failed;
        category["query_completed_uptime_ms"] = std::to_string(GetTickCount64());
        result["categories"].push_back(std::move(category));
    }
    result["product_count"] = std::to_string(total_products);
    result["query_summary"] = {{"categories_complete", completed}, {"categories_partial", partial}, {"categories_unavailable", failed}};
    result["state"] = completed || partial ? "degraded" : "unavailable";
    result["enumeration_completed"] = completed == std::size(providers);
    result["collection_completed_uptime_ms"] = std::to_string(GetTickCount64());
    return result;
}
}

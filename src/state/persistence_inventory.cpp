#include "persistence_native.hpp"
#include <tinyxml2.h>
#include <cmath>
#include <stdexcept>

namespace panopticon::officer::state {
using namespace native_persistence;
const char* persistence_source_name(PersistenceSource source) {
    switch (source) {
    case PersistenceSource::scheduled_tasks: return "scheduled_task_inventory";
    case PersistenceSource::wmi_subscriptions: return "wmi_subscription_inventory";
    case PersistenceSource::startup: return "startup_inventory";
    }
    throw std::invalid_argument("unknown persistence source");
}
Json collect_persistence_inventory_pages(PersistenceSource source, const std::function<bool(Json)>& consumer,
    PersistenceLimits limits, const std::function<bool()>& cancelled) {
    if (!consumer || !limits.page_entries || limits.page_entries > 4096 || limits.encoded_bytes < 4096 || limits.encoded_bytes > 512 * 1024
        || !limits.total_entries || limits.total_entries > 65536 || !limits.pages || limits.pages > 1024
        || !limits.field_bytes || limits.field_bytes > 128 * 1024 || !limits.soft_budget_ms || limits.soft_budget_ms > 300000)
        throw std::invalid_argument("invalid persistence inventory limits");
    Pager pager{limits, persistence_source_name(source), consumer, cancelled};
    switch (source) {
    case PersistenceSource::scheduled_tasks: return tasks(pager);
    case PersistenceSource::wmi_subscriptions: return wmi(pager);
    case PersistenceSource::startup: return startup(pager);
    }
    throw std::invalid_argument("unknown persistence source");
}
Json detail::persistence_variant(const void* borrowed, std::size_t limit) {
    if (!borrowed) return failure("WMI property/VARIANT", ERROR_INVALID_PARAMETER, "validation");
    const auto& value = *static_cast<const VARIANT*>(borrowed);
    Json result{{"state", "healthy"}, {"variant_type", std::to_string(value.vt)}, {"value", nullptr}};
    if (value.vt == VT_EMPTY || value.vt == VT_NULL) { result["representation"] = value.vt == VT_EMPTY ? "empty" : "null"; return result; }
    if (value.vt == VT_BSTR) { result.update(bstr(value.bstrVal, limit)); return result; }
    switch (value.vt) {
    case VT_BOOL:
        result["raw_scalar"] = std::to_string(value.boolVal);
        if (value.boolVal == VARIANT_TRUE || value.boolVal == VARIANT_FALSE) result["value"] = value.boolVal == VARIANT_TRUE;
        else { result["state"] = "degraded"; result["reason"] = "invalid_variant_bool"; }
        return result;
    case VT_I4: result["value"] = std::to_string(value.lVal); return result;
    case VT_UI4: result["value"] = std::to_string(value.ulVal); return result;
    case VT_I8: result["value"] = std::to_string(value.llVal); return result;
    case VT_UI8: result["value"] = std::to_string(value.ullVal); return result;
    case VT_UI1: result["value"] = std::to_string(value.bVal); return result;
    default: break;
    }
    if (value.vt == (VT_ARRAY | VT_UI1) && value.parray && SafeArrayGetDim(value.parray) == 1) {
        LONG lower = 0, upper = 0; VARTYPE type = VT_EMPTY;
        auto status = SafeArrayGetVartype(value.parray, &type);
        if (SUCCEEDED(status) && type == VT_UI1) status = SafeArrayGetLBound(value.parray, 1, &lower);
        if (SUCCEEDED(status) && type == VT_UI1) status = SafeArrayGetUBound(value.parray, 1, &upper);
        const auto count = static_cast<std::int64_t>(upper) - lower + 1;
        if (SUCCEEDED(status) && type == VT_UI1 && count >= 0 && static_cast<std::uint64_t>(count) <= limit) {
            BYTE* data = nullptr; status = SafeArrayAccessData(value.parray, reinterpret_cast<void**>(&data));
            if (SUCCEEDED(status)) {
                result["lower_bound"] = std::to_string(lower);
                result["byte_length"] = std::to_string(count);
                result["value"] = hex({reinterpret_cast<const std::byte*>(data), static_cast<std::size_t>(count)});
                result["encoding"] = "byte_array_hex";
                const auto unlocked = SafeArrayUnaccessData(value.parray);
                if (FAILED(unlocked)) { result["state"] = "degraded"; result["unlock_hresult"] = std::to_string(static_cast<std::uint32_t>(unlocked)); }
                return result;
            }
        }
        result["array_hresult"] = std::to_string(static_cast<std::uint32_t>(status));
        result["reported_element_count"] = std::to_string(count);
        result["reported_element_type"] = std::to_string(type);
        result["bound_exceeded"] = count >= 0 && static_cast<std::uint64_t>(count) > limit;
    }
    result["state"] = "degraded"; result["reason"] = "unsupported_or_invalid_variant_representation";
    return result;
}
Json detail::persistence_registry_data(std::uint32_t type, std::span<const std::byte> bytes) {
    Json result{{"state", "healthy"}, {"registry_type", std::to_string(type)}, {"raw_bytes_hex", hex(bytes)},
        {"byte_length", std::to_string(bytes.size())}, {"value", nullptr}};
    if ((type == REG_DWORD || type == REG_DWORD_BIG_ENDIAN) && bytes.size() == 4) {
        std::uint32_t value = 0;
        if (type == REG_DWORD) std::memcpy(&value, bytes.data(), sizeof(value));
        else for (auto b : bytes) value = (value << 8) | std::to_integer<unsigned>(b);
        result["value"] = std::to_string(value);
    } else if (type == REG_QWORD && bytes.size() == 8) {
        std::uint64_t value = 0; std::memcpy(&value, bytes.data(), sizeof(value)); result["value"] = std::to_string(value);
    } else if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) {
        if (bytes.size() % sizeof(wchar_t)) { result["state"] = "degraded"; result["reason"] = "odd_utf16_byte_length"; return result; }
        std::wstring raw(bytes.size() / sizeof(wchar_t), L'\0');
        if (!bytes.empty()) std::memcpy(raw.data(), bytes.data(), bytes.size());
        result["raw_text"] = text(raw.data(), raw.size());
        const auto terminated = !raw.empty() && raw.back() == L'\0';
        const auto multi_terminated = raw.size() >= 2 && raw[raw.size() - 2] == L'\0' && terminated;
        result["terminated"] = terminated; result["multi_terminated"] = type == REG_MULTI_SZ ? Json(multi_terminated) : Json(nullptr);
        if (!terminated || (type == REG_MULTI_SZ && !multi_terminated) || !result["raw_text"].is_string()) {
            result["state"] = "degraded"; result["reason"] = "unterminated_or_invalid_registry_text";
        } else if (type != REG_MULTI_SZ) {
            raw.pop_back(); result["value"] = text(raw.data(), raw.size());
            result["embedded_nul"] = raw.find(L'\0') != std::wstring::npos;
        }
        result["environment_expanded"] = false;
    } else if (type != REG_BINARY && type != REG_NONE) {
        result["state"] = "degraded"; result["reason"] = "unknown_type_or_scalar_size_mismatch";
    }
    return result;
}
Json detail::persistence_task_xml(std::string_view xml) {
    Json result{{"state", "degraded"}, {"sections", Json::array()},
        {"scope", "source XML sections only; configured actions/triggers/principals are not execution or effective authorization"}};
    if (xml.find('\0') != std::string_view::npos || xml.find("<!DOCTYPE") != std::string_view::npos) {
        result["reason"] = "embedded_nul_or_doctype"; return result;
    }
    tinyxml2::XMLDocument document;
    if (document.Parse(xml.data(), xml.size()) != tinyxml2::XML_SUCCESS || !document.RootElement()) {
        result["reason"] = "invalid_xml"; return result;
    }
    const auto* root = document.RootElement();
    if (std::string_view{root->Name()} != "Task" || document.FirstChildElement() != document.LastChildElement()
        || !root->Attribute("xmlns") || std::string_view{root->Attribute("xmlns")} != "http://schemas.microsoft.com/windows/2004/02/mit/task") {
        result["reason"] = "unqualified_task_namespace_or_multiple_roots"; return result;
    }
    result["reported_version"] = root->Attribute("version") ? Json(root->Attribute("version")) : Json(nullptr);
    for (const auto* child = root->FirstChildElement(); child; child = child->NextSiblingElement()) {
        tinyxml2::XMLPrinter printer; child->Accept(&printer);
        result["sections"].push_back({{"qualified_name", child->Name()}, {"xml", printer.CStr()}});
    }
    result["reason"] = "unassembled_definition_sections; qualified_names_and_source_xml_retained";
    return result;
}
}

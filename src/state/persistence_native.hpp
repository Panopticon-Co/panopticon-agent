#pragma once
#include "panopticon/officer/state/persistence_inventory.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace panopticon::officer::state::native_persistence {
using Json = nlohmann::json;
template<class T> struct Com {
    T* value = nullptr;
    Com() = default;
    Com(const Com&) = delete; Com& operator=(const Com&) = delete;
    Com(Com&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    Com& operator=(Com&& other) noexcept {
        if (this != &other) { if (value) value->Release(); value = std::exchange(other.value, nullptr); }
        return *this;
    }
    ~Com() { if (value) value->Release(); }
};
struct Apartment {
    HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ~Apartment() { if (SUCCEEDED(result)) CoUninitialize(); }
};
struct Bstr {
    BSTR value = nullptr;
    Bstr() = default;
    explicit Bstr(const wchar_t* text) : value(SysAllocString(text)) { if (!value) throw std::bad_alloc(); }
    ~Bstr() { SysFreeString(value); }
    Bstr(const Bstr&) = delete; Bstr& operator=(const Bstr&) = delete;
};
struct Variant {
    VARIANT value;
    Variant() { VariantInit(&value); }
    ~Variant() { VariantClear(&value); }
};
inline Json failure(const char* api, std::uint32_t code, const char* domain = "HRESULT") {
    return {{"state", "unavailable"}, {"source", api}, {"error_domain", domain},
        {"error_code", std::to_string(code)}, {"value", nullptr}};
}
inline std::string hex(std::span<const std::byte> bytes) {
    constexpr char digits[] = "0123456789abcdef"; std::string result;
    result.reserve(bytes.size() * 2);
    for (auto value : bytes) { const auto b = std::to_integer<unsigned>(value); result += digits[b >> 4]; result += digits[b & 15]; }
    return result;
}
inline Json text(const wchar_t* value, std::size_t units) {
    if (!units) return "";
    const auto needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(units), nullptr, 0, nullptr, nullptr);
    if (needed > 0) {
        std::string result(static_cast<std::size_t>(needed), '\0');
        if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, static_cast<int>(units), result.data(), needed, nullptr, nullptr) == needed) return result;
    }
    return {{"encoding", "utf16le_hex"}, {"bytes", hex({reinterpret_cast<const std::byte*>(value), units * sizeof(wchar_t)})}};
}
inline Json bstr(BSTR value, std::size_t limit) {
    if (!value) return {{"state", "degraded"}, {"value", nullptr}, {"representation", "null_bstr"}};
    const auto bytes = SysStringByteLen(value);
    if (bytes > limit) return {{"state", "degraded"}, {"value", nullptr}, {"bound_exceeded", true}, {"reported_bytes", std::to_string(bytes)}};
    if (bytes % sizeof(wchar_t)) return {{"state", "degraded"}, {"value", nullptr},
        {"raw_bytes_hex", hex({reinterpret_cast<const std::byte*>(value), bytes})}, {"reason", "odd_bstr_byte_length"}};
    auto result = text(value, SysStringLen(value));
    return {{"state", result.is_string() ? "healthy" : "degraded"}, {"value", std::move(result)}, {"reported_bytes", std::to_string(bytes)}};
}
class Pager {
public:
    PersistenceLimits limits;
    const char* source;
    const std::function<bool(Json)>& consumer;
    const std::function<bool()>& cancelled;
    const std::uint64_t started = GetTickCount64();
    std::uint64_t failures = 0, fields_refused = 0;
    Json partitions = Json::array();
    const char* version_key;
    Pager(PersistenceLimits bounds, const char* name, const std::function<bool(Json)>& sink, const std::function<bool()>& cancel,
        const char* version = "persistence_state_version")
        : limits(bounds), source(name), consumer(sink), cancelled(cancel), version_key(version) {}
    bool active() {
        if (stopped_) return false;
        if (cancelled && cancelled()) { cancelled_ = true; stopped_ = true; }
        if (GetTickCount64() - started > limits.soft_budget_ms) { timed_out_ = true; stopped_ = true; }
        return !stopped_;
    }
    bool add(Json row) {
        if (!active()) return false;
        if (delivered_ + rows_.size() >= limits.total_entries) { bounded_ = true; stopped_ = true; return false; }
        const auto bytes = row.dump().size();
        // Reserve bounded page metadata; the configured limit covers the page,
        // not merely the sum of row payloads.
        if (bytes + 1024 > limits.encoded_bytes) {
            ++fields_refused; bounded_ = true;
            row = {{"entry_kind", "row_copy_refusal"}, {"state", "degraded"}, {"original_encoded_bytes", std::to_string(bytes)},
                {"reason", "row_exceeds_page_byte_limit"}, {"lost_native_events", nullptr}};
        }
        const auto retained_bytes = row.dump().size();
        if (!rows_.empty() && (rows_.size() >= limits.page_entries || encoded_ + retained_bytes + 1024 > limits.encoded_bytes))
            if (!flush()) return false;
        rows_.push_back(std::move(row)); encoded_ += retained_bytes + 1; return true;
    }
    void field(const Json& value) {
        if (value.value("state", "unavailable") != "healthy") ++failures;
        if (value.value("bound_exceeded", false)) ++fields_refused;
    }
    bool flush() {
        if (rows_.empty()) return true;
        if (pages_ >= limits.pages) { bounded_ = true; stopped_ = true; return false; }
        const auto count = rows_.size();
        Json page{{"state", "degraded"}, {version_key, "1.0"}, {"source", source},
            {"page_index", std::to_string(pages_)}, {"entries", std::move(rows_)}, {"inventory_complete", false},
            {"consistency", "non_atomic"}, {"collection_started_uptime_ms", std::to_string(started)}};
        ++pages_; rows_ = Json::array(); encoded_ = 2;
        if (!consumer(std::move(page))) { refused_ = true; stopped_ = true; return false; }
        delivered_ += count; return true;
    }
    Json finish(const char* scope, bool complete) {
        if (!refused_) flush();
        return {{"state", "degraded"}, {version_key, "1.0"}, {"source", source}, {"scope", scope},
            {"inventory_complete", false}, {"enumeration_complete", complete && !stopped_ && !bounded_},
            {"query_failure_count", std::to_string(failures)}, {"copy_refusal_count", std::to_string(fields_refused)},
            {"partitions", std::move(partitions)}, {"pages_produced", std::to_string(pages_)}, {"entries_delivered", std::to_string(delivered_)},
            {"bound_exceeded", bounded_ || fields_refused != 0}, {"consumer_refused", refused_}, {"cancelled", cancelled_},
            {"soft_budget_exceeded", timed_out_}, {"soft_budget_ms", std::to_string(limits.soft_budget_ms)},
            {"collection_started_uptime_ms", std::to_string(started)}, {"collection_completed_uptime_ms", std::to_string(GetTickCount64())},
            {"consistency", "non_atomic; no lifetime, effective policy, execution or complete domain coverage assertion"},
            {"limits", {{"page_entries", limits.page_entries}, {"page_encoded_bytes", limits.encoded_bytes},
                {"total_entries", limits.total_entries}, {"pages", limits.pages}, {"field_bytes", limits.field_bytes}}},
            {"resource_scope", "bounded application copies/pages; native COM/RPC allocations and calls have no hard memory/time bound"}};
    }
private:
    Json rows_ = Json::array();
    std::size_t encoded_ = 2, pages_ = 0, delivered_ = 0;
    bool stopped_ = false, bounded_ = false, refused_ = false, cancelled_ = false, timed_out_ = false;
};
Json tasks(Pager& pager);
Json wmi(Pager& pager);
Json startup(Pager& pager);
}

#include "panopticon/officer/state/driver_inventory.hpp"
#include "panopticon/officer/state/service_inventory.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#define PSAPI_VERSION 2
#include <psapi.h>
#include <vector>
#include <stdexcept>
namespace panopticon::officer::state {
namespace {
using Json = nlohmann::json;
Json failed(const char* source, DWORD error) {
    return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "Win32"}, {"error_code", std::to_string(error)}};
}
Json name(void* address, bool path, std::uint64_t& failures) {
    std::vector<wchar_t> bytes(32768);
    const auto length = path ? K32GetDeviceDriverFileNameW(address, bytes.data(), static_cast<DWORD>(bytes.size()))
        : K32GetDeviceDriverBaseNameW(address, bytes.data(), static_cast<DWORD>(bytes.size()));
    const auto* source = path ? "K32GetDeviceDriverFileNameW" : "K32GetDeviceDriverBaseNameW";
    if (!length) { const auto error = GetLastError(); ++failures; return failed(source, error); }
    if (length >= bytes.size() - 1 || bytes[length] != 0) {
        const auto raw = std::as_bytes(std::span{bytes}); constexpr char digits[] = "0123456789abcdef"; std::string hex;
        hex.reserve(raw.size() * 2);
        for (const auto byte : raw) { const auto value = std::to_integer<unsigned char>(byte); hex += digits[value >> 4]; hex += digits[value & 15]; }
        ++failures; return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "collection_bound"},
            {"error_code", "possibly_truncated_native_string"}, {"reported_character_count", std::to_string(length)},
            {"captured_initialized_buffer_utf16le_hex", std::move(hex)}};
    }
    auto result = detail::service_text(std::as_bytes(std::span{bytes}), bytes.data(), 32767);
    result["source"] = source; result["scope"] = "later address lookup; raw text, not verified file/service/module instance";
    if (result["state"] == "unavailable") ++failures;
    return result;
}
}
Json detail::driver_address_visibility(std::span<const std::uintptr_t> addresses) {
    std::size_t nulls = 0; for (const auto address : addresses) if (!address) ++nulls;
    return {{"state", !addresses.empty() && nulls == addresses.size() ? "blind" : "degraded"},
        {"reported_slots", std::to_string(addresses.size())}, {"null_address_slots", std::to_string(nulls)},
        {"non_null_address_slots", std::to_string(addresses.size() - nulls)},
        {"all_reported_addresses_null", !addresses.empty() && nulls == addresses.size()},
        {"scope", "native reported slots only; Windows 11 24H2 can succeed with all NULL addresses without enabled SeDebugPrivilege; cause not proven; no privilege adjustment"}};
}
Json collect_loaded_driver_pages(const std::function<bool(Json)>& consumer) {
    if (!consumer) throw std::invalid_argument("loaded driver consumer missing");
    const auto started = GetTickCount64(); std::vector<void*> addresses(4096); DWORD needed = 0;
    const auto refusal = [&](Json result) {
        result["inventory_complete"] = false; result["enumeration_complete"] = false;
        result["driver_state_version"] = "1.0"; result["format"] = "paged_loaded_driver_inventory_v1";
        result["collection_started_uptime_ms"] = std::to_string(started);
        result["collection_completed_uptime_ms"] = std::to_string(GetTickCount64());
        return result;
    };
    if (!K32EnumDeviceDrivers(addresses.data(), static_cast<DWORD>(addresses.size() * sizeof(void*)), &needed)) {
        const auto error = GetLastError(); return refusal(failed("K32EnumDeviceDrivers", error));
    }
    if (needed > addresses.size() * sizeof(void*) || needed % sizeof(void*))
        return refusal({{"state", "unavailable"}, {"value", nullptr}, {"source", "K32EnumDeviceDrivers"}, {"error_domain", "collection_bound"},
            {"error_code", "native_size_exceeds_buffer_or_not_pointer_aligned"}, {"reported_required_bytes", std::to_string(needed)}, {"native_slot_limit", "4096"}});
    addresses.resize(needed / sizeof(void*)); std::vector<std::uintptr_t> raw; raw.reserve(addresses.size());
    for (const auto address : addresses) raw.push_back(reinterpret_cast<std::uintptr_t>(address));
    auto result = detail::driver_address_visibility(raw);
    std::size_t pages = 0, delivered = 0, encoded = 2; std::uint64_t failures = 0;
    bool refused = false, bounded = false; Json rows = Json::array();
    const auto flush = [&]() {
        const auto count = rows.size();
        auto page = Json{{"state", result["state"]}, {"driver_state_version", "1.0"}, {"page_index", std::to_string(pages++)},
            {"entries", std::move(rows)}, {"inventory_complete", false}, {"consistency", "non_atomic"}};
        if (!consumer(std::move(page))) { refused = true; return false; }
        delivered += count; rows = Json::array(); encoded = 2; return true;
    };
    for (std::size_t index = 0; index < addresses.size(); ++index) {
        auto address = addresses[index]; Json row{{"reported_slot_index", std::to_string(index)},
            {"reported_image_base", std::to_string(raw[index])}, {"source", "K32EnumDeviceDrivers"},
            {"module_instance_reference", nullptr}, {"service_instance_reference", nullptr}, {"file_reference", nullptr},
            {"address_lookup_relation", "unverified; driver unload/address reuse can occur before later queries"}};
        const auto query_start = GetTickCount64();
        if (address) { row["later_base_name"] = name(address, false, failures); row["later_file_name"] = name(address, true, failures); }
        else { row["later_base_name"] = {{"state", "unavailable"}, {"value", nullptr}, {"reason", "not queried; NULL native address"}}; row["later_file_name"] = row["later_base_name"]; }
        row["query_started_uptime_ms"] = std::to_string(query_start); row["query_completed_uptime_ms"] = std::to_string(GetTickCount64());
        auto size = row.dump().size() + (rows.empty() ? 0 : 1);
        if (rows.size() >= 256 || size > 512 * 1024 - encoded) {
            if (!rows.empty() && !flush()) break;
            size = row.dump().size();
            if (size > 512 * 1024 - encoded) { bounded = true; break; }
        }
        encoded += size; rows.push_back(std::move(row));
    }
    if (!refused && !rows.empty()) (void)flush();
    result["inventory_complete"] = false; result["driver_state_version"] = "1.0";
    result["format"] = "paged_loaded_driver_inventory_v1"; result["consistency"] = "non_atomic";
    result["enumeration_complete"] = !refused && !bounded; result["consumer_refused"] = refused; result["bound_exceeded"] = bounded;
    result["enumeration_scope"] = "native returned address slots; not loaded-module visibility or lifecycle completeness";
    result["pages_produced"] = std::to_string(pages); result["entries_delivered"] = std::to_string(delivered);
    result["name_query_failures"] = std::to_string(failures); result["address_lookup_objects_not_attempted"] = result["null_address_slots"];
    result["query_failure_scope"] = "later address lookups including queried undelivered rows; null slot count is not attempted objects, not lost events";
    result["collection_started_uptime_ms"] = std::to_string(started); result["collection_completed_uptime_ms"] = std::to_string(GetTickCount64());
    result["native_slot_limit"] = 4096; result["page_entry_limit"] = 256; result["page_byte_limit"] = 512 * 1024;
    return result;
}
}

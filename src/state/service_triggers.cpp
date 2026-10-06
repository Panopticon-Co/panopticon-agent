#include "panopticon/officer/state/service_inventory.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>
#include <cstring>
#include <optional>
#include <string>
#include <cstdio>

namespace panopticon::officer::state::detail {
namespace {
using Json = nlohmann::json;
constexpr const char* source = "QueryServiceConfig2W/SERVICE_CONFIG_TRIGGER_INFO";
Json fact(Json value) { return {{"state", "healthy"}, {"value", std::move(value)}, {"source", source}, {"error_code", nullptr}}; }
Json invalid(const char* reason) { return {{"state", "unavailable"}, {"value", nullptr}, {"source", source}, {"error_domain", "validation"}, {"error_code", reason}}; }
std::optional<std::size_t> range(std::span<const std::byte> buffer, const void* pointer, std::size_t count, std::size_t unit, std::size_t alignment) {
    const auto base = reinterpret_cast<std::uintptr_t>(buffer.data()), address = reinterpret_cast<std::uintptr_t>(pointer);
    if (!pointer || address < base || address - base >= buffer.size() || address % alignment
        || count > (buffer.size() - (address - base)) / unit) return std::nullopt;
    return static_cast<std::size_t>(address - base);
}
std::string hex(std::span<const std::byte> buffer) {
    constexpr char digits[] = "0123456789abcdef"; std::string result; result.reserve(buffer.size() * 2);
    for (const auto byte : buffer) { const auto value = std::to_integer<unsigned char>(byte); result += digits[value >> 4]; result += digits[value & 15]; }
    return result;
}
const char* type_symbol(DWORD code) {
    switch (code) {
    case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL: return "SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL";
    case SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY: return "SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY";
    case SERVICE_TRIGGER_TYPE_DOMAIN_JOIN: return "SERVICE_TRIGGER_TYPE_DOMAIN_JOIN";
    case SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT: return "SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT";
    case SERVICE_TRIGGER_TYPE_GROUP_POLICY: return "SERVICE_TRIGGER_TYPE_GROUP_POLICY";
    case SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT: return "SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT";
    case SERVICE_TRIGGER_TYPE_CUSTOM: return "SERVICE_TRIGGER_TYPE_CUSTOM";
#ifdef SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE
    case SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE: return "SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE";
#endif
#ifdef SERVICE_TRIGGER_TYPE_AGGREGATE
    case SERVICE_TRIGGER_TYPE_AGGREGATE: return "SERVICE_TRIGGER_TYPE_AGGREGATE";
#endif
    default: return nullptr;
    }
}
const char* data_symbol(DWORD code) {
    switch (code) {
    case SERVICE_TRIGGER_DATA_TYPE_BINARY: return "SERVICE_TRIGGER_DATA_TYPE_BINARY";
    case SERVICE_TRIGGER_DATA_TYPE_STRING: return "SERVICE_TRIGGER_DATA_TYPE_STRING";
    case SERVICE_TRIGGER_DATA_TYPE_LEVEL: return "SERVICE_TRIGGER_DATA_TYPE_LEVEL";
    case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY: return "SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY";
    case SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL: return "SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL";
    default: return nullptr;
    }
}
}
Json service_triggers(std::span<const std::byte> buffer) {
    if (buffer.size() > 8192 || buffer.size() < sizeof(SERVICE_TRIGGER_INFO)) return invalid("native_buffer_size_invalid");
    SERVICE_TRIGGER_INFO info{}; std::memcpy(&info, buffer.data(), sizeof(info));
    Json value{{"reported_trigger_count", std::to_string(info.cTriggers)}, {"reserved_pointer_reported_null", info.pReserved == nullptr}};
    if (info.pReserved) value["reserved_pointer_status"] = invalid("reserved_pointer_non_null");
    std::uint64_t failures = info.pReserved ? 1 : 0; bool unknown = false, bounded = false;
    std::size_t total_items = 0, total_bytes = 0, total_segments = 0;
    const auto finish = [&](Json triggers) {
        value["triggers"] = std::move(triggers); auto result = fact(std::move(value));
        if (failures || unknown || bounded) result["state"] = "degraded";
        result["validation_failure_count"] = std::to_string(failures);
        result["bound_exceeded"] = bounded; result["trigger_limit"] = 128;
        result["aggregate_item_limit"] = 256; result["aggregate_payload_byte_limit"] = 32768;
        result["aggregate_text_segment_limit"] = 256;
        result["scope"] = "configured triggers only; GUIDs/text remain unresolved; no observed trigger history, service instance, effective policy or actor association";
        return result;
    };
    if (!info.cTriggers) return finish(fact(Json::array())); // Array pointer is unused at zero count.
    if (info.cTriggers > 128) { bounded = true; return finish(invalid("trigger_count_limit_exceeded")); }
    const auto start = range(buffer, info.pTriggers, info.cTriggers, sizeof(SERVICE_TRIGGER), alignof(SERVICE_TRIGGER));
    if (!start) { ++failures; return finish(invalid("trigger_array_outside_buffer_or_unaligned")); }
    Json triggers = Json::array();
    for (DWORD index = 0; index < info.cTriggers; ++index) {
        SERVICE_TRIGGER trigger{}; std::memcpy(&trigger, buffer.data() + *start + index * sizeof(trigger), sizeof(trigger));
        const auto symbol = type_symbol(trigger.dwTriggerType);
        const bool documented_type = (trigger.dwTriggerType >= SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL
            && trigger.dwTriggerType <= SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT) || trigger.dwTriggerType == SERVICE_TRIGGER_TYPE_CUSTOM;
        const char* action = trigger.dwAction == SERVICE_TRIGGER_ACTION_SERVICE_START ? "SERVICE_TRIGGER_ACTION_SERVICE_START"
            : trigger.dwAction == SERVICE_TRIGGER_ACTION_SERVICE_STOP ? "SERVICE_TRIGGER_ACTION_SERVICE_STOP" : nullptr;
        if (!symbol || !action || !documented_type) unknown = true;
        Json row{{"reported_type", std::to_string(trigger.dwTriggerType)}, {"type_symbol", symbol ? Json(symbol) : Json(nullptr)},
            {"reported_action", std::to_string(trigger.dwAction)}, {"action_symbol", action ? Json(action) : Json(nullptr)},
            {"reported_data_item_count", std::to_string(trigger.cDataItems)},
            {"type_semantics_state", documented_type ? "documented_type_only" : "uninterpreted"}};
        if (!trigger.pTriggerSubtype) row["subtype_guid"] = fact(nullptr);
        else if (const auto position = range(buffer, trigger.pTriggerSubtype, 1, sizeof(GUID), alignof(GUID))) {
            GUID guid{}; std::memcpy(&guid, buffer.data() + *position, sizeof(guid));
            char text[37]{};
            std::snprintf(text, sizeof(text), "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                static_cast<unsigned long>(guid.Data1), static_cast<unsigned>(guid.Data2), static_cast<unsigned>(guid.Data3),
                static_cast<unsigned>(guid.Data4[0]), static_cast<unsigned>(guid.Data4[1]), static_cast<unsigned>(guid.Data4[2]),
                static_cast<unsigned>(guid.Data4[3]), static_cast<unsigned>(guid.Data4[4]), static_cast<unsigned>(guid.Data4[5]),
                static_cast<unsigned>(guid.Data4[6]), static_cast<unsigned>(guid.Data4[7]));
            row["subtype_guid"] = fact(text);
        } else { row["subtype_guid"] = invalid("subtype_guid_outside_buffer_or_unaligned"); ++failures; }
        if (!trigger.cDataItems) row["data_items"] = fact(Json::array());
        else if (trigger.cDataItems > 256 - total_items) { bounded = true; row["data_items"] = invalid("aggregate_item_limit_exceeded"); }
        else if (const auto position = range(buffer, trigger.pDataItems, trigger.cDataItems, sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM), alignof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM))) {
            Json items = Json::array(); total_items += trigger.cDataItems;
            for (DWORD item_index = 0; item_index < trigger.cDataItems; ++item_index) {
                SERVICE_TRIGGER_SPECIFIC_DATA_ITEM item{};
                std::memcpy(&item, buffer.data() + *position + item_index * sizeof(item), sizeof(item));
                const auto data_type = data_symbol(item.dwDataType); if (!data_type) unknown = true;
                Json data{{"reported_type", std::to_string(item.dwDataType)}, {"type_symbol", data_type ? Json(data_type) : Json(nullptr)},
                    {"reported_byte_count", std::to_string(item.cbData)}, {"data_pointer_reported_null", item.pData == nullptr}};
                if (item.cbData > 1024 || item.cbData > 32768 - total_bytes) {
                    bounded = true; data["payload"] = invalid("payload_or_aggregate_byte_limit_exceeded");
                } else if (!item.cbData) {
                    data["payload"] = fact({{"encoding", "hex"}, {"bytes", ""}});
                    if (item.dwDataType != SERVICE_TRIGGER_DATA_TYPE_BINARY) {
                        data["decoded_value"] = invalid("zero_byte_typed_payload_not_interpreted"); ++failures;
                    }
                }
                else if (const auto payload_start = range(buffer, item.pData, item.cbData, 1, 1)) {
                    const auto payload = buffer.subspan(*payload_start, item.cbData); total_bytes += item.cbData;
                    data["payload"] = fact({{"encoding", "hex"}, {"bytes", hex(payload)}});
                    if (item.dwDataType == SERVICE_TRIGGER_DATA_TYPE_LEVEL) {
                        if (payload.size() == 1) data["decoded_level"] = fact(std::to_string(std::to_integer<unsigned>(payload[0])));
                        else { data["decoded_level"] = invalid("level_requires_one_byte"); ++failures; }
                    } else if (item.dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY || item.dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL) {
                        if (payload.size() == sizeof(std::uint64_t)) { std::uint64_t keyword = 0; std::memcpy(&keyword, payload.data(), sizeof(keyword)); data["decoded_keyword"] = fact(std::to_string(keyword)); }
                        else { data["decoded_keyword"] = invalid("keyword_requires_eight_bytes"); ++failures; }
                    } else if (item.dwDataType == SERVICE_TRIGGER_DATA_TYPE_STRING) {
                        if (payload.size() % sizeof(wchar_t)) { data["decoded_strings"] = invalid("odd_utf16_byte_count"); ++failures; }
                        else {
                            Json strings = Json::array(); std::size_t segment = 0; bool text_bounded = false;
                            for (std::size_t cursor = 0; cursor < payload.size(); cursor += sizeof(wchar_t)) {
                                wchar_t unit = 0; std::memcpy(&unit, payload.data() + cursor, sizeof(unit));
                                if (!unit) {
                                    if (total_segments >= 256) { bounded = true; text_bounded = true; break; }
                                    ++total_segments; auto text = service_text(payload, payload.data() + segment, 512);
                                    if (text["state"] == "unavailable") ++failures;
                                    strings.push_back(std::move(text)); segment = cursor + sizeof(wchar_t); }
                            }
                            if (text_bounded) data["decoded_strings"] = invalid("aggregate_text_segment_limit_exceeded");
                            else if (segment != payload.size()) { data["decoded_strings"] = invalid("missing_final_utf16_terminator"); ++failures; }
                            else data["decoded_strings"] = fact(std::move(strings));
                        }
                    }
                } else { data["payload"] = invalid("payload_outside_buffer"); ++failures; }
                items.push_back(std::move(data));
            }
            row["data_items"] = fact(std::move(items));
        } else { row["data_items"] = invalid("data_item_array_outside_buffer_or_unaligned"); ++failures; }
        triggers.push_back(std::move(row));
    }
    return finish(fact(std::move(triggers)));
}
}

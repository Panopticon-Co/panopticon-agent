#include "panopticon/officer/state/service_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsvc.h>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <map>
#include <algorithm>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void security_buffer_checks() {
    alignas(DWORD) std::array<std::byte, 256> bytes{};
    SECURITY_DESCRIPTOR_RELATIVE descriptor{}; descriptor.Revision = SECURITY_DESCRIPTOR_REVISION;
    descriptor.Control = SE_SELF_RELATIVE | SE_DACL_PRESENT; descriptor.Owner = 20; descriptor.Group = 20; descriptor.Dacl = 48;
    bytes[20] = std::byte{1}; bytes[21] = std::byte{1}; bytes[27] = std::byte{5};
    DWORD authority = 32; std::memcpy(bytes.data() + 28, &authority, sizeof(authority));
    ACL acl{}; acl.AclRevision = ACL_REVISION; acl.AclSize = 8;
    const auto store = [&]() { std::memcpy(bytes.data(), &descriptor, sizeof(descriptor)); std::memcpy(bytes.data() + 48, &acl, sizeof(acl)); };
    store(); auto result = state::detail::service_security_descriptor(bytes);
    require(result["state"] == "degraded" && result["validation_failure_count"] == "0"
        && result["value"]["owner"]["value"]["reported_identifier_authority"] == "5"
        && result["value"]["owner"]["value"]["sub_authorities"] == Json::array({"32"})
        && result["value"]["dacl"]["value"]["representation"] == "acl"
        && result["value"]["dacl"]["value"]["reported_ace_count"] == "0", "selected SID fields and empty ACL remain exact without access decisions");
    descriptor.Dacl = 0; store();
    require(state::detail::service_security_descriptor(bytes)["value"]["dacl"]["value"]["representation"] == "null_acl", "null DACL is not confused with an empty ACL");
    descriptor.Control = SE_SELF_RELATIVE; store();
    require(state::detail::service_security_descriptor(bytes)["value"]["dacl"]["value"]["representation"] == "not_present", "absent DACL is not confused with null DACL");
    descriptor.Dacl = 48; store();
    require(state::detail::service_security_descriptor(bytes)["validation_failure_count"] == "1", "DACL offset without present flag remains explicit validation refusal");
    descriptor.Control = SE_SELF_RELATIVE | SE_DACL_PRESENT; descriptor.Owner = 255; store();
    result = state::detail::service_security_descriptor(bytes);
    require(result["value"]["owner"]["value"].is_null() && result["value"]["captured_buffer_hex"].get<std::string>().size() == bytes.size() * 2, "outside SID refusal preserves captured buffer instead of dropping source bytes");
    descriptor.Owner = 20; bytes[21] = std::byte{255}; store();
    require(state::detail::service_security_descriptor(bytes)["validation_failure_count"] == "2", "shared malformed SID count is refused independently for both fields");
    bytes[21] = std::byte{1}; acl.AclSize = 255; store();
    require(state::detail::service_security_descriptor(bytes)["validation_failure_count"] == "1", "ACL length beyond native buffer is refused");
    acl.AclSize = 12; acl.AceCount = 1; store(); ACE_HEADER ace{}; ace.AceType = 255; ace.AceFlags = 255; ace.AceSize = 4;
    std::memcpy(bytes.data() + 56, &ace, sizeof(ace)); result = state::detail::service_security_descriptor(bytes);
    require(result["value"]["dacl"]["value"]["aces"]["value"][0]["reported_type"] == "255"
        && result["value"]["dacl"]["value"]["aces"]["value"][0]["binary_hex"] == "ffff0400", "opaque unknown ACE bytes/type/flags are retained without interpretation");
    ace.AceSize = 0; std::memcpy(bytes.data() + 56, &ace, sizeof(ace));
    require(state::detail::service_security_descriptor(bytes)["validation_failure_count"] == "1", "zero ACE size cannot loop or invent an empty ACL");
    acl.AceCount = 257; store(); result = state::detail::service_security_descriptor(bytes);
    require(result["value"]["dacl"]["bound_exceeded"] == true && result["value"]["dacl"]["value"]["binary_hex"].is_string(), "ACE detail cap retains complete bounded ACL evidence");
    descriptor.Control = 0; store();
    require(state::detail::service_security_descriptor(bytes)["validation_failure_count"] == "1", "absolute descriptor is not dereferenced as relative pointers");
    const auto invalid = state::query_service_security(nullptr, L"unused");
    require(invalid["value"].is_null() && invalid["error_domain"] == "validation", "missing query manager does not fall back to another object");
}
void trigger_buffer_checks() {
    alignas(SERVICE_TRIGGER_INFO) std::array<std::byte, 8192> bytes{};
    SERVICE_TRIGGER_INFO info{}; info.cTriggers = 1; info.pTriggers = reinterpret_cast<SERVICE_TRIGGER*>(bytes.data() + 64);
    SERVICE_TRIGGER trigger{}; trigger.dwTriggerType = SERVICE_TRIGGER_TYPE_CUSTOM;
    trigger.dwAction = SERVICE_TRIGGER_ACTION_SERVICE_START; trigger.pTriggerSubtype = reinterpret_cast<GUID*>(bytes.data() + 160);
    trigger.cDataItems = 1; trigger.pDataItems = reinterpret_cast<SERVICE_TRIGGER_SPECIFIC_DATA_ITEM*>(bytes.data() + 2048);
    SERVICE_TRIGGER_SPECIFIC_DATA_ITEM item{}; item.dwDataType = SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY;
    item.cbData = 8; item.pData = reinterpret_cast<BYTE*>(bytes.data() + 4096);
    const GUID guid{0x12345678, 0xabcd, 0xef01, {0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01}};
    const auto store = [&]() { std::memcpy(bytes.data(), &info, sizeof(info));
        std::memcpy(bytes.data() + 64, &trigger, sizeof(trigger));
        std::memcpy(bytes.data() + 160, &guid, sizeof(guid));
        std::memcpy(bytes.data() + 2048, &item, sizeof(item)); };
    store(); const std::uint64_t keyword = 0xffffffffffffffffull; std::memcpy(bytes.data() + 4096, &keyword, sizeof(keyword));
    auto result = state::detail::service_triggers(bytes);
    auto row = result["value"]["triggers"]["value"][0];
    require(result["state"] == "healthy" && row["subtype_guid"]["value"] == "12345678-abcd-ef01-2345-6789abcdef01"
        && row["data_items"]["value"][0]["decoded_keyword"]["value"] == "18446744073709551615"
        && row["data_items"]["value"][0]["payload"]["value"]["bytes"] == "ffffffffffffffff",
        "trigger GUID formatting and full-width keyword preserve exact bounded native facts");
    trigger.dwTriggerType = 0xffffffffu; trigger.dwAction = 0xffffffffu; item.dwDataType = 0xffffffffu; store();
    result = state::detail::service_triggers(bytes); row = result["value"]["triggers"]["value"][0];
    require(result["state"] == "degraded" && row["type_symbol"].is_null() && row["action_symbol"].is_null()
        && row["data_items"]["value"][0]["type_symbol"].is_null()
        && row["data_items"]["value"][0]["payload"]["value"]["bytes"] == "ffffffffffffffff", "unknown types/actions retain exact raw payload instead of inferred semantics");
#ifdef SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE
    trigger.dwTriggerType = SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE; trigger.dwAction = SERVICE_TRIGGER_ACTION_SERVICE_START;
    item.dwDataType = SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY; store();
    result = state::detail::service_triggers(bytes); row = result["value"]["triggers"]["value"][0];
    require(result["state"] == "degraded" && row["type_symbol"] == "SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE"
        && row["type_semantics_state"] == "uninterpreted", "SDK symbol alone does not qualify undocumented trigger semantics");
#endif
    trigger.dwTriggerType = SERVICE_TRIGGER_TYPE_CUSTOM; trigger.dwAction = SERVICE_TRIGGER_ACTION_SERVICE_START;
    item.dwDataType = SERVICE_TRIGGER_DATA_TYPE_STRING; item.cbData = 6;
    const wchar_t malformed[]{static_cast<wchar_t>(0xd800), 0, 0};
    std::memcpy(bytes.data() + 4096, malformed, sizeof(malformed)); store();
    result = state::detail::service_triggers(bytes); row = result["value"]["triggers"]["value"][0];
    require(row["data_items"]["value"][0]["payload"]["value"]["bytes"] == "00d800000000"
        && row["data_items"]["value"][0]["decoded_strings"]["value"][0]["value"]["bytes"] == "00d8",
        "malformed trigger UTF-16 and terminators remain lossless");
    item.cbData = 3; store(); result = state::detail::service_triggers(bytes);
    require(result["validation_failure_count"] == "1" && result["value"]["triggers"]["value"][0]["data_items"]["value"][0]["payload"]["value"]["bytes"] == "00d800", "odd UTF-16 refuses text interpretation and retains all bytes");
    item.cbData = 0; item.dwDataType = SERVICE_TRIGGER_DATA_TYPE_LEVEL; store();
    require(state::detail::service_triggers(bytes)["state"] == "degraded", "zero-byte level is not a fabricated zero value");
    item.cbData = 4; item.pData = reinterpret_cast<BYTE*>(bytes.data() + bytes.size() - 2); store();
    require(state::detail::service_triggers(bytes)["validation_failure_count"] == "1", "payload extending beyond buffer is refused");
    trigger.cDataItems = 0xffffffffu; store();
    require(state::detail::service_triggers(bytes)["bound_exceeded"] == true, "huge item count cannot multiply allocation or pointer reads");
    trigger.cDataItems = 0; trigger.pTriggerSubtype = reinterpret_cast<GUID*>(bytes.data() + 161); store();
    require(state::detail::service_triggers(bytes)["validation_failure_count"] == "1", "unaligned GUID is refused before read");
    info.cTriggers = 0; info.pTriggers = reinterpret_cast<SERVICE_TRIGGER*>(bytes.data() + bytes.size()); store();
    require(state::detail::service_triggers(bytes)["value"]["triggers"]["value"].empty(), "unused zero-count pointer is not dereferenced");
    info.pReserved = reinterpret_cast<BYTE*>(bytes.data() + bytes.size()); store();
    require(state::detail::service_triggers(bytes)["validation_failure_count"] == "1", "reserved non-null pointer is reported without dereference");
    info.pReserved = nullptr;
    info.cTriggers = 1; info.pTriggers = reinterpret_cast<SERVICE_TRIGGER*>(bytes.data() + 65); store();
    require(state::detail::service_triggers(bytes)["validation_failure_count"] == "1", "unaligned trigger array is refused");
    info.cTriggers = 129; store();
    require(state::detail::service_triggers(bytes)["bound_exceeded"] == true, "trigger count limit preserves explicit unknown remainder");
    info.cTriggers = 33; info.pTriggers = reinterpret_cast<SERVICE_TRIGGER*>(bytes.data() + 64);
    trigger.pTriggerSubtype = nullptr; trigger.cDataItems = 1; item.dwDataType = SERVICE_TRIGGER_DATA_TYPE_BINARY;
    item.pData = reinterpret_cast<BYTE*>(bytes.data() + 4096); item.cbData = 1024; store();
    for (DWORD index = 0; index < 33; ++index) std::memcpy(bytes.data() + 64 + index * sizeof(trigger), &trigger, sizeof(trigger));
    result = state::detail::service_triggers(bytes);
    require(result["bound_exceeded"] == true && result.dump().size() < 256 * 1024,
        "overlapping payload references are charged repeatedly to a bounded aggregate output");
    info.cTriggers = 1; item.dwDataType = SERVICE_TRIGGER_DATA_TYPE_STRING; store();
    std::memset(bytes.data() + 4096, 0, 1024);
    result = state::detail::service_triggers(bytes);
    require(result["bound_exceeded"] == true && result.dump().size() < 256 * 1024,
        "zero UTF-16 segments cannot amplify a bounded buffer into unbounded JSON");
}
void optional_buffer_checks() {
    alignas(SERVICE_FAILURE_ACTIONSW) std::array<std::byte, 256> bytes{};
    DWORD scalar = 0xffffffffu; std::memcpy(bytes.data(), &scalar, sizeof(scalar));
    auto result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_LAUNCH_PROTECTED);
    require(result["state"] == "degraded" && result["value"]["reported_launch_protection"] == "4294967295"
        && result["value"]["sdk_symbol"].is_null(), "unknown protection preserves full DWORD without a guessed PPL level");
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_DELAYED_AUTO_START_INFO);
    require(result["value"]["delayed_auto_start"] == true && result["value"]["reported_delayed_auto_start"] == "4294967295",
        "BOOL interpretation retains original nonzero bits");
    scalar = 3; std::memcpy(bytes.data(), &scalar, sizeof(scalar));
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_SERVICE_SID_INFO);
    require(result["value"]["sdk_symbol"] == "SERVICE_SID_TYPE_RESTRICTED", "restricted SID setting is not confused with unrestricted");
    scalar = 2; std::memcpy(bytes.data(), &scalar, sizeof(scalar));
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_SERVICE_SID_INFO);
    require(result["state"] == "degraded" && result["value"]["sdk_symbol"].is_null(), "unknown SID setting has no invented interpretation");
    result = state::detail::service_optional_configuration(std::span<const std::byte>{bytes.data(), 3}, SERVICE_CONFIG_PRESHUTDOWN_INFO);
    require(result["value"].is_null() && result["error_domain"] == "validation", "short scalar structure cannot be read");
    std::fill(bytes.begin(), bytes.end(), std::byte{0});
    void* pointer = nullptr; std::memcpy(bytes.data(), &pointer, sizeof(pointer));
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO);
    require(result["state"] == "healthy" && result["value"].is_null(), "null configured privilege list is not invented empty effective privileges");
    const wchar_t names[] = L"SeChangeNotifyPrivilege\0SeDebugPrivilege\0\0";
    pointer = bytes.data() + 32; std::memcpy(bytes.data(), &pointer, sizeof(pointer));
    std::memcpy(bytes.data() + 32, names, sizeof(names));
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO);
    require(result["value"] == Json::array({"SeChangeNotifyPrivilege", "SeDebugPrivilege"}), "configured privilege names remain exact unresolved names");
    result = state::detail::service_optional_configuration(std::span<const std::byte>{bytes.data(), 32 + sizeof(names) - 4}, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO);
    require(result["value"].is_null(), "missing final MULTISZ terminator is refused");
    pointer = bytes.data() + bytes.size(); std::memcpy(bytes.data(), &pointer, sizeof(pointer));
    require(state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_DESCRIPTION)["value"].is_null(), "description outside native buffer is refused");
    std::fill(bytes.begin(), bytes.end(), std::byte{0});
    SERVICE_FAILURE_ACTIONSW failure{}; failure.dwResetPeriod = 0xffffffffu; failure.cActions = 2;
    failure.lpsaActions = reinterpret_cast<SC_ACTION*>(bytes.data() + 64);
    std::memcpy(bytes.data(), &failure, sizeof(failure));
    DWORD type = 0xffffffffu, delay = 0xffffffffu;
    std::memcpy(bytes.data() + 64 + offsetof(SC_ACTION, Type), &type, sizeof(type));
    std::memcpy(bytes.data() + 64 + offsetof(SC_ACTION, Delay), &delay, sizeof(delay));
    type = SC_ACTION_RUN_COMMAND;
    std::memcpy(bytes.data() + 64 + sizeof(SC_ACTION) + offsetof(SC_ACTION, Type), &type, sizeof(type));
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_FAILURE_ACTIONS);
    require(result["state"] == "degraded" && result["validation_failure_count"] == "0"
        && result["value"]["actions"]["value"][0]["reported_type"] == "4294967295"
        && result["value"]["actions"]["value"][0]["sdk_symbol"].is_null()
        && result["value"]["actions"]["value"][1]["sdk_symbol"] == "SC_ACTION_RUN_COMMAND",
        "unknown actions stay raw without invalid C++ enum reads; known commands are configuration only");
    failure.cActions = 0xffffffffu; std::memcpy(bytes.data(), &failure, sizeof(failure));
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_FAILURE_ACTIONS);
    require(result["validation_failure_count"] == "1" && result["value"]["reported_action_count"] == "4294967295"
        && result["value"]["actions"]["value"].is_null(), "oversized action count keeps scalar evidence and refuses array dereference");
    failure.lpsaActions = reinterpret_cast<SC_ACTION*>(bytes.data() + 65); failure.cActions = 1;
    std::memcpy(bytes.data(), &failure, sizeof(failure));
    require(state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_FAILURE_ACTIONS)["validation_failure_count"] == "1", "unaligned action arrays are refused");
    failure.lpsaActions = nullptr; std::memcpy(bytes.data(), &failure, sizeof(failure));
    result = state::detail::service_optional_configuration(bytes, SERVICE_CONFIG_FAILURE_ACTIONS);
    require(result["state"] == "healthy" && result["value"]["actions"]["value"].is_null()
        && result["value"]["reported_action_count"] == "1", "null actions pointer is retained without interpreting count as active policy");
}
int main(int argc, char** argv) {
    try {
        std::string error; const auto boot = core::query_native_boot_id(error);
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), boot, 1};
        Json records = Json::array(), ids = Json::array();
        const auto begin = factory.state("service_inventory_begin", {{"format", "paged_service_inventory_begin_v1"}});
        records.push_back(begin); std::size_t pages = 0, entries = 0, not_attempted = 0;
        std::map<std::string, std::array<std::uint64_t, 3>> optional_counts;
        state::ServiceInventoryLimits limits; limits.page_entries = 8; limits.enumeration_bytes = 4096;
        auto data = state::collect_service_inventory_pages([&](Json page) {
            require(page["page_index"] == std::to_string(pages++), "service pages are contiguous");
            require(page["entries"].size() <= 8 && page["entries"].dump().size() <= limits.encoded_bytes, "service page bounds apply");
            entries += page["entries"].size();
            for (const auto& row : page["entries"]) {
                require(row["process_reference"].is_null() && row["service_instance_reference"].is_null(), "SCM PID/name never becomes a verified instance");
                require(row["descriptor_configuration_relation"].is_string(), "descriptor/config name reuse remains explicit");
                const auto& config = row["later_configuration_query"];
                if (!config.contains("optional_configuration_queries")) { ++not_attempted; continue; }
                require(config["optional_configuration_queries"].size() == 9, "all selected config levels are independently queried");
                for (const auto& [name, fact] : config["optional_configuration_queries"].items()) {
                    auto& counts = optional_counts[name];
                    if (fact["native_query_succeeded"] == true) {
                        ++counts[0]; if (fact["state"] != "healthy") ++counts[2];
                    } else {
                        ++counts[1]; require(fact["value"].is_null() && fact["error_domain"] == "Win32", "optional query refusal retains native status and null value");
                    }
                    require(std::stoull(fact["query_completed_uptime_ms"].get<std::string>()) >= std::stoull(fact["query_started_uptime_ms"].get<std::string>()), "per-query windows are bounded by monotonic time");
                }
            }
            page["capture_id"] = begin.at("record_id"); const auto record = factory.state("service_inventory_page", std::move(page));
            ids.push_back(record.at("record_id")); records.push_back(record); return true;
        }, limits);
        require(data["inventory_complete"] == false, "SCM silent omissions prohibit a full census claim");
        if (data["state"] == "degraded") {
            require(data["entries_delivered"] == std::to_string(entries), "only accepted service pages count as delivered");
            require(data["scope"].get<std::string>().find("silently omit") != std::string::npos, "SCM access omission scope survives");
            if (data["enumeration_complete"] == true) require(data["native_enumeration_calls"] != "1", "small native buffer exercises actual SCM resume pagination");
            if (data["enumeration_complete"] == true) for (const auto& [name, counts] : optional_counts) {
                const auto& summary = data["optional_configuration_query_summary"][name];
                require(summary["successful_native_queries"] == std::to_string(counts[0])
                    && summary["failed_native_queries"] == std::to_string(counts[1])
                    && summary["uninterpreted_or_invalid_results"] == std::to_string(counts[2])
                    && summary["queries_not_attempted"] == std::to_string(not_attempted), "optional query accounting matches accepted complete caller-visible enumeration");
            }
        } else require(data["value"].is_null() && data["error_domain"] == "Win32", "SCM refusal preserves exact native error");
        data["capture_id"] = begin.at("record_id"); data["page_record_ids"] = ids;
        records.push_back(factory.state("service_inventory", data));
        if (argc == 2 && std::string{argv[1]} == "--emit-live") { std::cout << records.dump() << '\n'; return 0; }
        optional_buffer_checks();
        trigger_buffer_checks();
        security_buffer_checks();
        if (pages) {
            const auto refused = state::collect_service_inventory_pages([](Json) { return false; }, limits);
            require(refused["consumer_refused"] == true && refused["entries_delivered"] == "0" && refused["enumeration_complete"] == false,
                "consumer refusal cannot claim service enumeration or delivery");
            auto bounded_limits = limits; bounded_limits.total_entries = 1;
            const auto bounded = state::collect_service_inventory_pages([](Json) { return true; }, bounded_limits);
            require(bounded["bound_exceeded"] == true && bounded["entries_delivered"] == "1" && bounded["enumeration_complete"] == false,
                "total service limit retains accepted prefix and unknown remainder");
            bounded_limits = limits; bounded_limits.encoded_bytes = 2;
            const auto tiny = state::collect_service_inventory_pages([](Json) { throw std::runtime_error("empty/oversized page cannot be delivered"); return true; }, bounded_limits);
            require(tiny["entries_delivered"] == "0" && tiny["bound_exceeded"] == true, "oversized row stops explicitly");
            bounded_limits = limits; bounded_limits.pages = 1;
            const auto page_bound = state::collect_service_inventory_pages([](Json) { return true; }, bounded_limits);
            require(page_bound["pages_produced"] == "1" && page_bound["entries_delivered"] == "8"
                && page_bound["enumeration_complete"] == false && page_bound["bound_exceeded"] == true,
                "page ceiling retains only accepted pages and does not claim complete enumeration");
            const auto& attempted = page_bound["optional_configuration_query_summary"]["launch_protection"];
            require(std::stoull(attempted["successful_native_queries"].get<std::string>())
                + std::stoull(attempted["failed_native_queries"].get<std::string>())
                + std::stoull(attempted["queries_not_attempted"].get<std::string>()) > 8,
                "query summary explicitly includes already queried undelivered rows");
        }
        alignas(wchar_t) std::array<std::byte, 32> bytes{}; const wchar_t list[] = L"RPCSS\0+Group\0\0";
        std::memcpy(bytes.data(), list, sizeof(list));
        require(state::detail::service_dependencies(bytes, bytes.data())["value"] == Json::array({"RPCSS", "+Group"}), "dependency names and group marker remain raw/unresolved");
        const wchar_t malformed = static_cast<wchar_t>(0xd800); std::memcpy(bytes.data(), &malformed, sizeof(malformed));
        std::memset(bytes.data() + sizeof(malformed), 0, bytes.size() - sizeof(malformed));
        require(state::detail::service_text(bytes, bytes.data())["value"]["bytes"] == "00d8", "malformed UTF-16 is lossless");
        const auto outside = state::detail::service_text(bytes, bytes.data() + bytes.size());
        const auto unaligned = state::detail::service_text(bytes, bytes.data() + 1);
        require(outside["value"].is_null() && unaligned["value"].is_null(), "native string pointers are checked before dereference");
        const auto truncated = state::detail::service_text(std::span<const std::byte>{bytes.data(), 2}, bytes.data());
        require(truncated["state"] == "unavailable" && truncated["error_domain"] == "validation", "missing terminator remains unavailable");
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

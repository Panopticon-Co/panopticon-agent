#pragma once

#include "panopticon/officer/response/config.hpp"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace panopticon::officer::response {

// Describe the loaded runtime, not telemetry collection coverage or OS execution success.
inline std::string response_profile_json(const ResponseConfig& config, const std::string& host_id,
                                         const std::optional<std::string>& boot_id) {
    using nlohmann::json;
    const json implemented = {"KILL_PROCESS", "COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS",
                              "COLLECT_FILE", "QUARANTINE_FILE", "ISOLATE_HOST", "RELEASE_HOST_ISOLATION"};
    json allowed = json::array();
    if (config.enabled) {
        allowed = {"KILL_PROCESS", "COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS",
                   "RELEASE_HOST_ISOLATION"};
        if (!config.file_collection_root.empty()) allowed.push_back("COLLECT_FILE");
        if (!config.file_collection_root.empty() && !config.quarantine_root.empty())
            allowed.push_back("QUARANTINE_FILE");
        if (!config.manager_exception_host.empty() && config.manager_exception_port != 0)
            allowed.push_back("ISOLATE_HOST");
    }
    return json{{"schema_version", "2"}, {"platform", "windows"}, {"host_id", host_id},
                {"boot_id", boot_id ? json(*boot_id) : json(nullptr)},
                {"mode", config.enabled ? "enforce" : "off"},
                {"implemented_actions", implemented}, {"allowed_actions", allowed},
                {"require_boot_binding", true}, {"require_signature", false},
                {"require_collection_acceptance", true},
                {"artifact_protocol", "signed-json-v2-resume-v1"}}.dump();
}

}  // namespace panopticon::officer::response

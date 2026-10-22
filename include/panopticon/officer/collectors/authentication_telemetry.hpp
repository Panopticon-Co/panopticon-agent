#pragma once
#include <nlohmann/json.hpp>
#include <optional>
namespace panopticon::officer::collectors {
// Source-reported Security fields only. Retained log records do not establish
// the event's native boot, a process instance, or an exact logon-session entity.
[[nodiscard]] std::optional<nlohmann::json> decode_authentication(const nlohmann::json& event);
}

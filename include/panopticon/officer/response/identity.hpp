#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace panopticon::officer::response {

// An enrolled agent's durable credential, mirroring
// panopticon-linux-agent's enrolled_identity tuple exactly (agent_id,
// host_id, bearer_token). Persisted to a single-purpose local file that is
// never the same file as the telemetry-only delivery path uses -- opting
// into response does not change any existing telemetry behavior.
struct EnrolledIdentity {
    std::string agent_id;
    std::string host_id;
    std::string bearer_token;
};

// Same identifier grammar as the Manager/Linux-agent side: 1-128 characters,
// alnum plus '-', '_', '.'. Anything else is rejected before it can reach a
// URL path segment or a JSON field.
[[nodiscard]] bool is_valid_identifier(std::string_view value) noexcept;

// Loads a previously stored identity. Fails closed (nullopt) on a missing
// file, a malformed file, an identifier that fails validation, or (best
// effort on Windows, see identity.cpp) an ACL that grants access wider than
// the current user.
[[nodiscard]] std::optional<EnrolledIdentity> load_enrolled_identity(
    const std::filesystem::path& path, std::string& error_message);

// Atomically (write-temp, then rename) persists an identity and locks its
// ACL down to the current user only.
[[nodiscard]] bool store_enrolled_identity(
    const std::filesystem::path& path, const EnrolledIdentity& identity, std::string& error_message);

}  // namespace panopticon::officer::response

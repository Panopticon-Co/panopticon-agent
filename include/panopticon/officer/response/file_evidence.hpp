#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>

namespace panopticon::officer::response {

// Resolves requested_path against allowed_root and refuses to proceed
// unless the fully canonicalized result is still lexically under
// allowed_root -- rejects "..", absolute-path escapes, and (to the extent
// weakly_canonical resolves them) symlink/junction escapes. Returns
// std::nullopt (with error_message) on any escape, missing allowed_root
// configuration, or a target that is not a regular file.
[[nodiscard]] std::optional<std::filesystem::path> resolve_within_allowed_root(
    const std::filesystem::path& allowed_root, const std::filesystem::path& requested_path,
    std::string& error_message);

// Reads a bounded regular file strictly under allowed_root, hashes it with
// SHA-256 (panopticon::officer::core::sha256_hex, the same OS-shipped CNG
// implementation the telemetry pipeline already uses), and serializes
// path/size/hash as evidence -- never the raw content, which is discarded
// as soon as it is hashed and never appears in the returned string.
[[nodiscard]] std::optional<std::string> collect_file_evidence(const std::filesystem::path& allowed_root,
                                                                 const std::filesystem::path& requested_path,
                                                                 std::size_t maximum_bytes,
                                                                 std::string& error_message);

// Atomically moves (MoveFileExW, same-volume rename semantics; falls back
// to copy+delete across volumes) a regular file from allowed_root into
// quarantine_root, then applies a deny-everyone-execute/deny-everyone-write
// ACL to the quarantined copy so it cannot be re-run or altered in place --
// the Windows-specific hardening step beyond what the Linux agent's
// quarantine (a plain move under a root with restrictive Unix permissions)
// needs.
[[nodiscard]] std::optional<std::string> quarantine_file_and_serialize(
    const std::filesystem::path& allowed_root, const std::filesystem::path& requested_path,
    const std::filesystem::path& quarantine_root, std::size_t maximum_bytes, std::string& error_message);

}  // namespace panopticon::officer::response

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace panopticon::officer::response {

enum class QuarantineState : std::uint8_t { refused, failed, partial, completed };

// Typed facts are set even when the legacy optional JSON result is empty so
// the durable command worker can map post-mutation failures to indeterminate.
struct QuarantineOutcome {
    QuarantineState state = QuarantineState::refused;
    // True once the held source DACL was changed, even if the move later fails.
    bool source_security_changed = false;
    // True only after the source handle has been renamed out of its old path.
    bool source_removed = false;
    // True only after that rename placed the protected object in quarantine.
    bool destination_protected = false;
    // Metadata bytes were flushed and their final-name rename succeeded;
    // this does not claim directory-entry power-loss durability.
    bool metadata_durable = false;
    std::string stored_path;
    std::string metadata_path;
    std::string detail;
};

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

// Refuses cross-volume moves. For a same-volume move, holds and verifies the
// source and destination directory handles, protects the source with a
// restrictive DACL, and uses a handle-relative no-replace rename. The result
// may be partial if security was changed or the source moved but metadata
// promotion did not finish; callers must map that state to an indeterminate
// command result. This is best-effort user-mode protection and does not revoke
// pre-existing handles or provide kernel tamper protection.
[[nodiscard]] std::optional<std::string> quarantine_file_and_serialize(
    const std::filesystem::path& allowed_root, const std::filesystem::path& requested_path,
    const std::filesystem::path& quarantine_root, std::size_t maximum_bytes, std::string& error_message,
    QuarantineOutcome* outcome = nullptr);

}  // namespace panopticon::officer::response

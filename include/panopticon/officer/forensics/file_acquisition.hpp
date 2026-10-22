#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

namespace panopticon::officer::forensics {

// The store root and source collection root must both be explicitly configured
// by the host. The 256-bit key is supplied by the host and is never persisted by
// this component; provision it from an OS-protected secret store.
struct FileAcquisitionConfig {
    std::filesystem::path collection_root;
    std::filesystem::path encrypted_store_root;
    std::array<std::uint8_t, 32> encryption_key{};
    std::uint64_t maximum_capture_bytes = 256ull * 1024 * 1024;
    std::uint32_t chunk_bytes = 1024 * 1024;
};

struct FileAcquisitionRequest {
    // Stable caller idempotency key; restricted to [A-Za-z0-9_-], 1..96 chars.
    std::string capture_id;
    // Relative to collection_root. Absolute paths and traversal are refused.
    std::filesystem::path relative_path;
    // Requested bound, further capped by maximum_capture_bytes.
    std::uint64_t maximum_bytes = 0;
    // Durable originating command identity for restart reconciliation.
    std::string command_id;
    // Bound by the originating durable response command. An empty value is
    // permitted for standalone callers but cannot be restart-reconciled.
    std::string command_correlation_id;
    // Recovery mode never creates a new manifest; it only reconciles an
    // authenticated matching capture already present in the store.
    bool resume_existing_only = false;
};

struct FileAcquisitionResult {
    std::string capture_id;
    // complete, partial, truncated, refused, or failed. Partial captures are
    // retained and can be resumed only when source identity and metadata match.
    std::string state;
    std::string manifest_path;
    std::string error;
    std::uint64_t captured_bytes = 0;
    std::uint64_t next_sequence = 0;
    std::string sha256;
    bool existing_capture_verified = false;
};

// Loads or creates a random 256-bit key protected with the current Windows
// account's DPAPI. The protected key file is stored only under the explicitly
// configured acquisition store root; failures never rotate an unreadable key.
[[nodiscard]] bool load_or_create_dpapi_key(const std::filesystem::path& store_root,
    std::array<std::uint8_t, 32>& key, std::string& error_message, bool create_if_missing = true);

// Bounded, read-only Windows file acquisition. Each output chunk is AES-256-GCM
// authenticated before it is durably committed; no plaintext file is created.
// The class does not execute, quarantine, delete, or alter the source file.
class FileAcquisitionStore {
public:
    explicit FileAcquisitionStore(FileAcquisitionConfig config);
    ~FileAcquisitionStore();
    FileAcquisitionStore(const FileAcquisitionStore&) = delete;
    FileAcquisitionStore& operator=(const FileAcquisitionStore&) = delete;

    [[nodiscard]] FileAcquisitionResult acquire(const FileAcquisitionRequest& request);
    [[nodiscard]] FileAcquisitionResult inspect(const std::string& capture_id) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace panopticon::officer::forensics

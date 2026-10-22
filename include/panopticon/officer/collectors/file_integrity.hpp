#pragma once

#include "panopticon/officer/delivery/journal.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace panopticon::officer::collectors {

// Application-side bounds. A zero/empty root list disables FIM; this class
// never guesses a default directory or expands a root from machine policy.
struct FileIntegrityLimits {
    std::size_t maximum_roots = 8;
    std::size_t maximum_baseline_candidates = 10000;
    std::size_t maximum_directories = 2048;
    std::size_t maximum_depth = 16;
    std::size_t maximum_candidates_per_batch = 256;
    std::size_t maximum_relative_path_bytes = 2048;
    std::uint64_t maximum_file_hash_bytes = 16ull * 1024 * 1024;
    std::uint64_t maximum_total_hash_bytes = 256ull * 1024 * 1024;
    std::size_t native_buffer_bytes = 64 * 1024;
    // Recursive traversal and notifications are opt-out. Every root remains
    // explicitly configured; subtrees are bounded and reparse points skipped.
    bool recursive = true;
};

struct FileIntegrityCallbacks {
    std::function<std::optional<delivery::SourceCheckpoint>(const std::string&)> load;
    // Must return the immutable canonical record body. root is the configured
    // UTF-8 absolute root, body is source data, and gap marks a loss/unknown
    // interval. Commit it atomically with next_checkpoint when possible.
    std::function<std::string(const std::string& root, nlohmann::json body, bool gap)> make_record;
    std::function<bool(const std::string& record, const std::string& source,
        const std::string& next_checkpoint, std::uint64_t expected_revision)> commit;
    std::function<void()> changed;
};

// Monitors only explicitly configured absolute local paths. Empty roots create
// a disabled sensor. Recursive mode is bounded by depth, directory and entry
// limits; reparse points are never followed during root admission or baseline
// observation. Notifications are subtree-scoped only when recursive is true.
class FileIntegritySensor {
public:
    explicit FileIntegritySensor(std::vector<std::string> absolute_roots,
        FileIntegrityCallbacks callbacks, FileIntegrityLimits limits = {});
    ~FileIntegritySensor();
    FileIntegritySensor(const FileIntegritySensor&) = delete;
    FileIntegritySensor& operator=(const FileIntegritySensor&) = delete;
    FileIntegritySensor(FileIntegritySensor&&) = delete;
    FileIntegritySensor& operator=(FileIntegritySensor&&) = delete;
    void stop() noexcept;
    [[nodiscard]] nlohmann::json snapshot() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace panopticon::officer::collectors

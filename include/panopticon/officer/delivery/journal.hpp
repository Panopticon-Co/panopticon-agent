#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace panopticon::officer::delivery {

struct JournalConfig {
    std::filesystem::path directory;
    std::uint64_t retained_payload_limit = 16ull * 1024 * 1024 * 1024;
    std::size_t event_size_limit = 1024 * 1024;
    // Sampled preflight, not a disk reservation or a hard WAL ceiling.
    std::uint64_t physical_admission_limit = 32ull * 1024 * 1024 * 1024;
    std::uint64_t minimum_free_bytes = 128ull * 1024 * 1024;
};

struct JournalEntry {
    std::string key;
    std::string body;
};
struct JournalInspectionEntry {
    std::uint64_t local_sequence = 0;
    unsigned protocol = 1;
    JournalEntry original;
};

struct JournalBatch {
    std::string id;
    unsigned protocol = 1;
    std::vector<JournalEntry> entries;
    [[nodiscard]] std::string ndjson() const;
};

struct JournalStats {
    std::uint64_t pending_events = 0;
    std::uint64_t dead_letter_events = 0;
    std::uint64_t retained_bytes = 0;
    std::uint64_t disk_bytes = 0;
    std::uint64_t caller_available_bytes = 0;
    std::uint64_t physical_admission_limit = 0, minimum_free_bytes = 0;
    std::uint64_t storage_admission_refusals = 0; // Current object lifetime only.
    std::uint64_t acknowledged_events = 0;
    std::uint64_t legacy_gaps = 0;
    std::uint64_t commands_received = 0, commands_executing = 0, command_results_ready = 0;
    std::uint64_t commands_outboxed = 0, commands_unknown_state = 0;
};
struct JournalDeadLetter {
    JournalEntry original;
    std::string reason;
};
struct JournalCommand {
    std::string key, scope, body, state, result;
};

// One durable record per observation. COMMIT precedes success; no retry-count
// expiry or quota eviction. Rejections retain the encrypted original and reason.
// Exceptions mean acceptance/acknowledgment did not complete; callers must report
// degraded durability rather than presenting a successful enqueue.
class DurableJournal {
public:
    explicit DurableJournal(JournalConfig config);
    ~DurableJournal();
    DurableJournal(const DurableJournal&) = delete;
    DurableJournal& operator=(const DurableJournal&) = delete;

    void append(const std::string& line);
    [[nodiscard]] std::optional<JournalBatch> peek(std::size_t max_events, std::size_t max_bytes);
    // Bounded read-only diagnostic paging across protocols, never an ACK batch.
    // Cursor is local journal order, not canonical endpoint observation sequence.
    // Separate calls do not constitute an atomic snapshot of a live writer.
    [[nodiscard]] std::vector<JournalInspectionEntry> inspect_pending(
        std::uint64_t after_local_sequence, std::size_t max_events, std::size_t max_bytes) const;
    // The receipt must account for every submitted line and match this batch.
    // Invalid/partial receipts cause no changes, even on HTTP 200.
    void acknowledge(const JournalBatch& batch, const std::string& receipt);
    [[nodiscard]] JournalStats stats() const;
    [[nodiscard]] std::vector<JournalDeadLetter> dead_letters(std::size_t limit) const;
    [[nodiscard]] std::string persistent_identifier(const std::string& name);
    [[nodiscard]] std::uint64_t next_collector_generation();
    // Immutable received body; execution intent and outcome commit separately.
    // Retained final rows are replay tombstones, never automatic quota eviction.
    void receive_command(const std::string& scope, const std::string& key, const std::string& body);
    [[nodiscard]] std::vector<JournalCommand> pending_commands(const std::string& scope, std::size_t limit) const;
    [[nodiscard]] bool begin_command(const std::string& scope, const std::string& key);
    void finish_command(const std::string& scope, const std::string& key, const std::string& result);
    void mark_command_outboxed(const std::string& scope, const std::string& key);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace panopticon::officer::delivery

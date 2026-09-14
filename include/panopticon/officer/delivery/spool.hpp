#pragma once

// Phase 5: the durable telemetry spool. Closes the gap documented in
// docs/architecture/phase-6-delivery.md ("a failed batch ... is logged to
// stderr and dropped -- there is no disk spool yet") and anticipated by
// delivery/config.hpp ("durable spool config arrive in Phase 4/5").
//
// Design summary (see docs/architecture/phase-9-telemetry-durability.md for
// the full writeup):
//
//   - Append-only segment files under a spool directory. Every batch that
//     Uploader would otherwise POST is durably appended here FIRST, then an
//     immediate delivery attempt is made -- mirroring the eyedetect
//     AlertSpool/StreamingPipeline pattern (persist-before-deliver) that the
//     Linux agent and Detection Engine already use, applied to Windows.
//   - Single-writer, single-reader by contract: only Uploader's own
//     background thread touches an instance. The internal mutex is a
//     defensive guard, not a concurrency feature -- see "Concurrency" in the
//     design doc for why a second sender thread was deliberately rejected.
//   - Records are delivered strictly in order (head-of-line). A record that
//     keeps failing is retried with bounded exponential backoff; once
//     max_delivery_attempts is exhausted it is logged, counted, and skipped
//     -- never retried forever, never silently resurrected.
//   - Bounded disk: a hard max_total_bytes with an explicit, logged
//     drop-oldest-segment policy, never unbounded growth.
//   - Crash-safe: the durable read cursor is written to a sidecar file via
//     write-temp + atomic rename, so a crash at any point (before/during
//     append, before/after a delivery attempt, before/after the cursor is
//     advanced) resolves to safe at-least-once delivery, never data loss and
//     never partial/torn state. Replays are safe because the manager already
//     dedups by the agent-assigned deterministic event_id (ADR 002) --
//     this spool does not invent a second identity scheme.

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>

namespace panopticon::officer::delivery {

struct SpoolConfig {
    std::filesystem::path directory;

    // One segment file is capped near ADR 002's own 8 MiB batch ceiling --
    // a segment is many batches, but never allowed to grow unbounded.
    std::uint64_t max_segment_bytes = 8ull * 1024 * 1024;

    // Total on-disk spool size across all segments. Must be >= max_segment_bytes
    // (validated at construction) so the active segment can never itself be
    // an unsatisfiable quota violation.
    std::uint64_t max_total_bytes = 64ull * 1024 * 1024;

    // Bounded retries per record before it is logged, counted as dead, and
    // skipped. Never zero (that would mean "never even try once").
    unsigned max_delivery_attempts = 8;

    // Bounded exponential backoff between attempts of the same head record.
    unsigned base_backoff_ms = 1000;
    unsigned max_backoff_ms = 60000;
};

struct SpoolRecord {
    std::string batch_id;  // X-Panopticon-Batch-Id, stable across retries
    std::string body;      // NDJSON batch body, byte-for-byte what gets POSTed
};

struct SpoolStats {
    std::uint64_t total_bytes = 0;
    std::uint64_t segment_count = 0;
    std::uint64_t dropped_for_quota = 0;
    std::uint64_t dead_records = 0;
    std::uint64_t corrupt_records_skipped = 0;
};

class SegmentSpool {
public:
    // Throws std::invalid_argument for an unsafe configuration (zero limits,
    // max_total_bytes < max_segment_bytes, zero max_delivery_attempts) --
    // configuration is validated at startup, not silently clamped.
    explicit SegmentSpool(SpoolConfig config);

    SegmentSpool(const SegmentSpool&) = delete;
    SegmentSpool& operator=(const SegmentSpool&) = delete;

    // Durably appends one batch, evicting the oldest fully-consumed (or, if
    // none exists and quota is still exceeded, the oldest) segment first if
    // required to stay within max_total_bytes. Always call this before
    // attempting HTTP delivery of the same batch.
    void append(const std::string& batch_id, const std::string& body);

    // True if the oldest undelivered record's backoff window has elapsed
    // and it is ready to attempt again.
    [[nodiscard]] bool has_ready();

    // Returns (without consuming) the oldest undelivered ready record, or
    // nullopt if none is ready right now. Must be followed by exactly one
    // report_outcome() call before the next peek_ready().
    [[nodiscard]] std::optional<SpoolRecord> peek_ready();

    // Reports what happened to the record last returned by peek_ready().
    // delivered=true durably advances the cursor past it (never seen again).
    // delivered=false increments its attempt count; once
    // max_delivery_attempts is exhausted the record is counted as dead and
    // skipped (cursor still advances) rather than retried forever.
    void report_outcome(bool delivered);

    // Scans the spool directory, validates every record's framing and
    // checksum, quarantines (skips) any corrupt or partially-written record
    // without losing the healthy records around it, and resumes the durable
    // read cursor from the position persisted before the previous exit.
    // Safe to call multiple times; the first call is what a fresh process
    // start should do before consuming any live traffic.
    void recover();

    [[nodiscard]] SpoolStats stats() const;

private:
    struct HeadState {
        std::uint64_t read_segment_index = 0;
        std::uint64_t read_offset = 0;
        unsigned attempts = 0;
        std::uint64_t next_attempt_at_ms = 0;  // steady_clock-relative, 0 = ready now
        bool have_pending_read = false;
        SpoolRecord pending;
        // read_segment_index/read_offset are advanced the moment
        // read_next_record_locked() parses `pending` -- these snapshot the
        // position immediately BEFORE that parse, so a failed outcome can
        // roll the cursor back and re-serve the identical record on retry
        // instead of silently skipping past it.
        std::uint64_t pre_peek_segment_index = 0;
        std::uint64_t pre_peek_offset = 0;
    };

    std::filesystem::path segment_path(std::uint64_t index) const;
    std::filesystem::path cursor_path() const;
    void write_cursor_locked();
    void load_cursor_locked();
    std::uint64_t recompute_total_bytes_locked() const;
    void evict_for_quota_locked(std::uint64_t incoming_bytes);
    std::optional<SpoolRecord> read_next_record_locked();
    void advance_past_dead_or_delivered_locked();
    static std::uint32_t crc32(const void* data, std::size_t len);

    SpoolConfig config_;
    mutable std::mutex mutex_;

    std::uint64_t write_segment_index_ = 0;
    std::uint64_t write_segment_bytes_ = 0;

    HeadState head_;

    SpoolStats stats_;
};

}  // namespace panopticon::officer::delivery

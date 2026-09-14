#include "panopticon/officer/delivery/spool.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace panopticon::officer::delivery {

namespace {

using Clock = std::chrono::steady_clock;

std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
}

void write_u32(std::ostream& out, std::uint32_t v) {
    out.write(reinterpret_cast<const char*>(&v), sizeof(v));
}
bool read_u32(std::istream& in, std::uint32_t& v) {
    in.read(reinterpret_cast<char*>(&v), sizeof(v));
    return in.gcount() == static_cast<std::streamsize>(sizeof(v));
}

std::string segment_filename(std::uint64_t index) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "segment-%06llu.dat", static_cast<unsigned long long>(index));
    return std::string(buf);
}

// Parses "segment-000123.dat" -> 123, or nullopt if the name doesn't match.
std::optional<std::uint64_t> parse_segment_index(const std::string& filename) {
    const std::string prefix = "segment-";
    const std::string suffix = ".dat";
    if (filename.size() <= prefix.size() + suffix.size()) return std::nullopt;
    if (filename.compare(0, prefix.size(), prefix) != 0) return std::nullopt;
    if (filename.compare(filename.size() - suffix.size(), suffix.size(), suffix) != 0) return std::nullopt;
    const std::string digits = filename.substr(prefix.size(), filename.size() - prefix.size() - suffix.size());
    if (digits.empty()) return std::nullopt;
    for (char c : digits) {
        if (c < '0' || c > '9') return std::nullopt;
    }
    try {
        return static_cast<std::uint64_t>(std::stoull(digits));
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace

std::uint32_t SegmentSpool::crc32(const void* data, std::size_t len) {
    static const std::array<std::uint32_t, 256> table = [] {
        std::array<std::uint32_t, 256> t{};
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) {
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }();

    const auto* bytes = static_cast<const unsigned char*>(data);
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc = table[(crc ^ bytes[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

SegmentSpool::SegmentSpool(SpoolConfig config) : config_(std::move(config)) {
    if (config_.max_segment_bytes == 0 || config_.max_total_bytes == 0) {
        throw std::invalid_argument("spool byte limits must be non-zero");
    }
    if (config_.max_total_bytes < config_.max_segment_bytes) {
        throw std::invalid_argument("max_total_bytes must be >= max_segment_bytes");
    }
    if (config_.max_delivery_attempts == 0) {
        throw std::invalid_argument("max_delivery_attempts must be >= 1");
    }
    if (config_.base_backoff_ms == 0 || config_.max_backoff_ms < config_.base_backoff_ms) {
        throw std::invalid_argument("invalid backoff configuration");
    }
    std::error_code ec;
    std::filesystem::create_directories(config_.directory, ec);
}

std::filesystem::path SegmentSpool::segment_path(std::uint64_t index) const {
    return config_.directory / segment_filename(index);
}

std::filesystem::path SegmentSpool::cursor_path() const {
    return config_.directory / "spool.cursor";
}

void SegmentSpool::write_cursor_locked() {
    const auto tmp = config_.directory / "spool.cursor.tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        out << head_.read_segment_index << ' ' << head_.read_offset;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, cursor_path(), ec);
    if (ec) {
        // Atomic rename failed (e.g. cross-volume spool dir misconfiguration).
        // Not fatal -- the next recovery falls back to the oldest segment,
        // which is always safe (at-least-once replay), just less efficient.
        std::cerr << "[spool] cursor persist failed: " << ec.message() << '\n';
    }
}

void SegmentSpool::load_cursor_locked() {
    std::ifstream in(cursor_path(), std::ios::binary);
    std::uint64_t seg = 0, off = 0;
    if (in && (in >> seg >> off)) {
        head_.read_segment_index = seg;
        head_.read_offset = off;
    }
}

std::uint64_t SegmentSpool::recompute_total_bytes_locked() const {
    std::uint64_t total = 0;
    std::error_code ec;
    if (!std::filesystem::exists(config_.directory, ec)) return 0;
    for (const auto& entry : std::filesystem::directory_iterator(config_.directory, ec)) {
        if (!entry.is_regular_file()) continue;
        if (!parse_segment_index(entry.path().filename().string())) continue;
        std::error_code size_ec;
        const auto sz = std::filesystem::file_size(entry.path(), size_ec);
        if (!size_ec) total += sz;
    }
    return total;
}

void SegmentSpool::recover() {
    std::scoped_lock lock{mutex_};
    std::error_code ec;
    std::filesystem::create_directories(config_.directory, ec);

    std::optional<std::uint64_t> min_index, max_index;
    if (std::filesystem::exists(config_.directory, ec)) {
        for (const auto& entry : std::filesystem::directory_iterator(config_.directory, ec)) {
            if (!entry.is_regular_file()) continue;
            auto idx = parse_segment_index(entry.path().filename().string());
            if (!idx) continue;
            if (!min_index || *idx < *min_index) min_index = idx;
            if (!max_index || *idx > *max_index) max_index = idx;
        }
    }

    if (!max_index) {
        write_segment_index_ = 1;
        write_segment_bytes_ = 0;
        head_.read_segment_index = 1;
        head_.read_offset = 0;
    } else {
        write_segment_index_ = *max_index;
        std::error_code size_ec;
        write_segment_bytes_ = std::filesystem::file_size(segment_path(write_segment_index_), size_ec);
        if (size_ec) write_segment_bytes_ = 0;

        head_.read_segment_index = *min_index;
        head_.read_offset = 0;
        load_cursor_locked();
        // A stale/out-of-range cursor (deleted segment, corrupted sidecar)
        // falls back to the oldest surviving segment -- safe re-delivery of
        // everything still on disk, never an out-of-bounds read.
        if (head_.read_segment_index < *min_index || head_.read_segment_index > *max_index) {
            head_.read_segment_index = *min_index;
            head_.read_offset = 0;
        }
    }

    head_.attempts = 0;
    head_.next_attempt_at_ms = 0;
    head_.have_pending_read = false;

    stats_.total_bytes = recompute_total_bytes_locked();
    stats_.segment_count = 0;
    if (max_index) {
        for (auto idx = *min_index; idx <= *max_index; ++idx) {
            if (std::filesystem::exists(segment_path(idx))) ++stats_.segment_count;
        }
    }
}

std::optional<SpoolRecord> SegmentSpool::read_next_record_locked() {
    for (;;) {
        const auto path = segment_path(head_.read_segment_index);
        if (!std::filesystem::exists(path)) {
            if (head_.read_segment_index < write_segment_index_) {
                // Evicted or never-existed intermediate segment -- skip it.
                ++head_.read_segment_index;
                head_.read_offset = 0;
                continue;
            }
            return std::nullopt;  // nothing written yet
        }

        std::ifstream in(path, std::ios::binary);
        in.seekg(static_cast<std::streamoff>(head_.read_offset));

        std::uint32_t total_len = 0, crc_value = 0;
        const bool have_len = read_u32(in, total_len);
        const bool len_plausible =
            have_len && total_len >= 2 && total_len <= config_.max_segment_bytes;

        if (!have_len || !len_plausible) {
            // Either clean end-of-data, or a torn header from a crash
            // mid-write. Either way nothing after this point in THIS
            // segment can be trusted to have a valid boundary.
            if (head_.read_segment_index < write_segment_index_) {
                ++head_.read_segment_index;
                head_.read_offset = 0;
                continue;
            }
            return std::nullopt;
        }

        if (!read_u32(in, crc_value)) {
            if (head_.read_segment_index < write_segment_index_) {
                ++head_.read_segment_index;
                head_.read_offset = 0;
                continue;
            }
            return std::nullopt;
        }

        std::vector<char> payload(total_len);
        in.read(payload.data(), static_cast<std::streamsize>(total_len));
        if (in.gcount() != static_cast<std::streamsize>(total_len)) {
            // Torn payload -- the length field was written but the body
            // wasn't fully flushed before the crash.
            if (head_.read_segment_index < write_segment_index_) {
                ++head_.read_segment_index;
                head_.read_offset = 0;
                continue;
            }
            return std::nullopt;
        }

        const std::uint64_t record_on_disk_bytes = 4 + 4 + total_len;
        const std::uint32_t computed = crc32(payload.data(), payload.size());

        if (computed != crc_value) {
            std::cerr << "[spool] corrupt record at segment=" << head_.read_segment_index
                       << " offset=" << head_.read_offset << ", quarantined\n";
            ++stats_.corrupt_records_skipped;
            head_.read_offset += record_on_disk_bytes;
            continue;  // try the next record; framing (length) is still trusted
        }

        if (payload.size() < 2) {
            ++stats_.corrupt_records_skipped;
            head_.read_offset += record_on_disk_bytes;
            continue;
        }
        std::uint16_t batch_id_len = 0;
        std::memcpy(&batch_id_len, payload.data(), sizeof(batch_id_len));
        if (static_cast<std::size_t>(batch_id_len) + 2 > payload.size()) {
            ++stats_.corrupt_records_skipped;
            head_.read_offset += record_on_disk_bytes;
            continue;
        }

        SpoolRecord record;
        record.batch_id.assign(payload.data() + 2, batch_id_len);
        record.body.assign(payload.data() + 2 + batch_id_len, payload.size() - 2 - batch_id_len);

        head_.read_offset += record_on_disk_bytes;
        return record;
    }
}

bool SegmentSpool::has_ready() {
    std::scoped_lock lock{mutex_};
    if (head_.have_pending_read) return true;
    return now_ms() >= head_.next_attempt_at_ms;
}

std::optional<SpoolRecord> SegmentSpool::peek_ready() {
    std::scoped_lock lock{mutex_};
    if (head_.have_pending_read) return head_.pending;
    if (now_ms() < head_.next_attempt_at_ms) return std::nullopt;

    // read_next_record_locked mutates read_segment_index/read_offset as it
    // skips dead segments and quarantines corrupt records, but that state
    // is only made durable (written to the cursor file) in report_outcome,
    // so a crash between this peek and the outcome safely re-reads from the
    // last durable cursor -- at most a duplicate delivery, never a loss.
    head_.pre_peek_segment_index = head_.read_segment_index;
    head_.pre_peek_offset = head_.read_offset;

    auto record = read_next_record_locked();
    if (!record) return std::nullopt;
    head_.pending = std::move(*record);
    head_.have_pending_read = true;
    return head_.pending;
}

void SegmentSpool::report_outcome(bool delivered) {
    std::scoped_lock lock{mutex_};
    if (!head_.have_pending_read) return;

    bool commit = delivered;
    if (!delivered) {
        ++head_.attempts;
        if (head_.attempts >= config_.max_delivery_attempts) {
            std::cerr << "[spool] record permanently undeliverable after " << head_.attempts
                       << " attempts, dropping (batch_id=" << head_.pending.batch_id << ")\n";
            ++stats_.dead_records;
            commit = true;  // give up on this record; move past it
        }
    }

    if (commit) {
        head_.attempts = 0;
        head_.next_attempt_at_ms = 0;
        head_.have_pending_read = false;
        write_cursor_locked();

        // Best-effort reclaim: segments strictly behind the new read cursor
        // can never be read again, so free their disk space proactively
        // rather than waiting for quota pressure.
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(config_.directory, ec)) {
            if (!entry.is_regular_file()) continue;
            auto idx = parse_segment_index(entry.path().filename().string());
            if (idx && *idx < head_.read_segment_index) {
                std::filesystem::remove(entry.path(), ec);
            }
        }
        stats_.total_bytes = recompute_total_bytes_locked();
    } else {
        const unsigned exponent = head_.attempts > 0 ? head_.attempts - 1 : 0;
        std::uint64_t delay = config_.base_backoff_ms;
        for (unsigned i = 0; i < exponent && delay < config_.max_backoff_ms; ++i) {
            delay *= 2;
        }
        if (delay > config_.max_backoff_ms) delay = config_.max_backoff_ms;
        head_.next_attempt_at_ms = now_ms() + delay;
        head_.have_pending_read = false;
        // Roll the cursor back to before this record was parsed -- without
        // this, the next peek would resume reading PAST the failed record
        // (read_next_record_locked already advanced it), silently skipping
        // a record that was never actually delivered.
        head_.read_segment_index = head_.pre_peek_segment_index;
        head_.read_offset = head_.pre_peek_offset;
    }
}

void SegmentSpool::evict_for_quota_locked(std::uint64_t incoming_bytes) {
    while (recompute_total_bytes_locked() + incoming_bytes > config_.max_total_bytes) {
        std::optional<std::uint64_t> oldest;
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(config_.directory, ec)) {
            if (!entry.is_regular_file()) continue;
            auto idx = parse_segment_index(entry.path().filename().string());
            if (!idx || *idx == write_segment_index_) continue;  // never evict the active segment
            if (!oldest || *idx < *oldest) oldest = idx;
        }
        if (!oldest) break;  // only the active segment remains; allow the write through

        std::cerr << "[spool] quota exceeded, evicting segment " << *oldest
                   << (*oldest >= head_.read_segment_index ? " (undelivered telemetry lost)" : "") << '\n';
        std::filesystem::remove(segment_path(*oldest), ec);
        ++stats_.dropped_for_quota;

        if (*oldest == head_.read_segment_index) {
            head_.read_segment_index = *oldest + 1;
            head_.read_offset = 0;
            head_.have_pending_read = false;
            head_.attempts = 0;
            head_.next_attempt_at_ms = 0;
            write_cursor_locked();
        }
    }
}

void SegmentSpool::append(const std::string& batch_id, const std::string& body) {
    if (batch_id.size() > 0xFFFFu) {
        throw std::invalid_argument("batch_id too long to frame");
    }
    const std::uint32_t total_len = static_cast<std::uint32_t>(2 + batch_id.size() + body.size());
    const std::uint64_t record_bytes = 4 + 4 + total_len;
    if (record_bytes > config_.max_segment_bytes) {
        throw std::invalid_argument("record larger than max_segment_bytes");
    }

    std::scoped_lock lock{mutex_};
    std::error_code ec;
    std::filesystem::create_directories(config_.directory, ec);

    evict_for_quota_locked(record_bytes);

    if (write_segment_bytes_ > 0 && write_segment_bytes_ + record_bytes > config_.max_segment_bytes) {
        ++write_segment_index_;
        write_segment_bytes_ = 0;
    }

    std::ofstream out(segment_path(write_segment_index_), std::ios::binary | std::ios::app);
    write_u32(out, total_len);

    std::vector<char> payload(total_len);
    const std::uint16_t batch_id_len = static_cast<std::uint16_t>(batch_id.size());
    std::memcpy(payload.data(), &batch_id_len, sizeof(batch_id_len));
    std::memcpy(payload.data() + 2, batch_id.data(), batch_id.size());
    std::memcpy(payload.data() + 2 + batch_id.size(), body.data(), body.size());

    write_u32(out, crc32(payload.data(), payload.size()));
    out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    out.flush();

    write_segment_bytes_ += record_bytes;
    stats_.total_bytes = recompute_total_bytes_locked();
    const auto span = static_cast<std::int64_t>(write_segment_index_) -
                       static_cast<std::int64_t>(head_.read_segment_index) + 1;
    stats_.segment_count = static_cast<std::uint64_t>(std::max<std::int64_t>(1, span));
}

SpoolStats SegmentSpool::stats() const {
    std::scoped_lock lock{mutex_};
    return stats_;
}

}  // namespace panopticon::officer::delivery

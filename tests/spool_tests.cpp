#include "panopticon/officer/delivery/spool.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

namespace delivery = panopticon::officer::delivery;
namespace fs = std::filesystem;

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

// A fresh, uniquely-named scratch directory per test, cleaned up on
// destruction. This whole test file is platform-independent (std::filesystem
// only, no Windows API), so it can actually be compiled and run in a
// non-Windows/non-MSVC development environment, unlike the rest of Officer.
class ScratchDir {
public:
    ScratchDir() {
        static std::atomic<long long> counter{0};
        const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() /
                ("officer-spool-test-" + std::to_string(seed) + "-" + std::to_string(counter.fetch_add(1)));
        fs::create_directories(path_);
    }
    ~ScratchDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

delivery::SpoolConfig test_config(const fs::path& dir) {
    delivery::SpoolConfig config;
    config.directory = dir;
    config.max_segment_bytes = 4096;
    config.max_total_bytes = 16384;
    config.max_delivery_attempts = 3;
    config.base_backoff_ms = 10;
    config.max_backoff_ms = 40;
    return config;
}

void test_construction_validates_configuration() {
    fs::path dir = fs::temp_directory_path() / "officer-spool-validate";
    bool threw = false;
    try {
        delivery::SpoolConfig bad;
        bad.directory = dir;
        bad.max_segment_bytes = 0;
        delivery::SegmentSpool spool{bad};
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    expect(threw, "zero max_segment_bytes is rejected at construction");

    threw = false;
    try {
        delivery::SpoolConfig bad;
        bad.directory = dir;
        bad.max_segment_bytes = 100;
        bad.max_total_bytes = 50;  // less than max_segment_bytes
        delivery::SegmentSpool spool{bad};
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    expect(threw, "max_total_bytes < max_segment_bytes is rejected");

    threw = false;
    try {
        delivery::SpoolConfig bad;
        bad.directory = dir;
        bad.max_delivery_attempts = 0;
        delivery::SegmentSpool spool{bad};
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    expect(threw, "zero max_delivery_attempts is rejected");
}

void test_append_then_deliver_advances_past_the_record() {
    ScratchDir dir;
    delivery::SegmentSpool spool{test_config(dir.path())};
    spool.recover();

    expect(!spool.peek_ready().has_value(), "an empty spool has nothing ready");

    spool.append("batch-1", R"({"event_id":"evt_a"})");
    auto record = spool.peek_ready();
    expect(record.has_value(), "an appended record becomes ready");
    expect(record->batch_id == "batch-1", "the exact batch_id round-trips");
    expect(record->body == R"({"event_id":"evt_a"})", "the exact body bytes round-trip");

    spool.report_outcome(/*delivered=*/true);
    expect(!spool.peek_ready().has_value(), "delivered records are never served again");
}

void test_failed_delivery_retries_with_backoff_then_becomes_ready_again() {
    ScratchDir dir;
    delivery::SegmentSpool spool{test_config(dir.path())};
    spool.recover();

    spool.append("batch-1", "line-1");
    auto record = spool.peek_ready();
    expect(record.has_value(), "record is ready before any failure");
    spool.report_outcome(/*delivered=*/false);

    expect(!spool.peek_ready().has_value(), "immediately after a failure, backoff has not elapsed");
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    auto retried = spool.peek_ready();
    expect(retried.has_value(), "the same record becomes ready again once backoff elapses");
    expect(retried->body == "line-1", "retry re-serves the identical unmodified record");
    spool.report_outcome(/*delivered=*/true);
}

void test_permanently_failing_record_is_dropped_after_max_attempts_not_retried_forever() {
    ScratchDir dir;
    auto config = test_config(dir.path());
    config.max_delivery_attempts = 2;
    config.base_backoff_ms = 1;
    config.max_backoff_ms = 2;
    delivery::SegmentSpool spool{config};
    spool.recover();

    spool.append("batch-1", "poison");
    for (unsigned attempt = 0; attempt < config.max_delivery_attempts; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        auto record = spool.peek_ready();
        expect(record.has_value(), "record is retried up to max_delivery_attempts");
        spool.report_outcome(/*delivered=*/false);
    }

    expect(spool.stats().dead_records == 1, "exhausting attempts counts exactly one dead record");
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    expect(!spool.peek_ready().has_value(), "a dead record is never served again (bounded, not infinite retry)");
}

void test_second_record_is_not_starved_by_a_stuck_head_of_line_record() {
    ScratchDir dir;
    auto config = test_config(dir.path());
    config.max_delivery_attempts = 1;  // one failure and it's dead immediately
    config.base_backoff_ms = 1;
    config.max_backoff_ms = 2;
    delivery::SegmentSpool spool{config};
    spool.recover();

    spool.append("batch-1", "first");
    spool.append("batch-2", "second");

    auto first = spool.peek_ready();
    expect(first.has_value() && first->body == "first", "first record is head-of-line");
    spool.report_outcome(/*delivered=*/false);  // exhausts its single attempt -> dead, skipped

    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    auto second = spool.peek_ready();
    expect(second.has_value() && second->body == "second", "a dead head record does not block the record behind it");
    spool.report_outcome(/*delivered=*/true);
}

void test_recovery_after_restart_replays_undelivered_records() {
    ScratchDir dir;
    {
        delivery::SegmentSpool spool{test_config(dir.path())};
        spool.recover();
        spool.append("batch-1", "not-yet-delivered");
        // Process "crashes" here -- no report_outcome call, no clean shutdown.
    }
    {
        delivery::SegmentSpool spool{test_config(dir.path())};
        spool.recover();
        auto record = spool.peek_ready();
        expect(record.has_value(), "a fresh SegmentSpool instance recovers undelivered records from disk");
        expect(record->body == "not-yet-delivered", "recovered record content is byte-identical");
        spool.report_outcome(true);
    }
}

void test_delivered_records_are_not_replayed_after_restart() {
    ScratchDir dir;
    {
        delivery::SegmentSpool spool{test_config(dir.path())};
        spool.recover();
        spool.append("batch-1", "delivered-before-restart");
        auto record = spool.peek_ready();
        expect(record.has_value(), "record ready before restart");
        spool.report_outcome(true);  // durably committed to the cursor file
    }
    {
        delivery::SegmentSpool spool{test_config(dir.path())};
        spool.recover();
        expect(!spool.peek_ready().has_value(), "a durably-delivered record is never replayed after restart");
    }
}

void test_corrupt_record_is_quarantined_without_losing_the_record_after_it() {
    ScratchDir dir;
    {
        delivery::SegmentSpool spool{test_config(dir.path())};
        spool.recover();
        spool.append("batch-1", "will-be-corrupted");
        spool.append("batch-2", "healthy-record-after-corruption");
    }

    // Flip a byte inside the first record's payload region (well past the
    // 8-byte length+crc header) so its checksum fails but its length field
    // -- and therefore the position of the second record -- stays intact.
    fs::path segment = dir.path() / "segment-000001.dat";
    {
        std::fstream f(segment, std::ios::in | std::ios::out | std::ios::binary);
        f.seekg(20);
        char byte = 0;
        f.read(&byte, 1);
        byte = static_cast<char>(byte ^ 0xFF);
        f.seekp(20);
        f.write(&byte, 1);
    }

    delivery::SegmentSpool spool{test_config(dir.path())};
    spool.recover();
    auto record = spool.peek_ready();
    expect(record.has_value(), "recovery continues past a corrupt record instead of stopping");
    expect(record->body == "healthy-record-after-corruption",
           "the healthy record after the corrupted one is still recovered");
    expect(spool.stats().corrupt_records_skipped >= 1, "the corrupt record is counted, not silently ignored");
    spool.report_outcome(true);
}

void test_truncated_trailing_record_is_treated_as_a_clean_partial_write() {
    ScratchDir dir;
    {
        delivery::SegmentSpool spool{test_config(dir.path())};
        spool.recover();
        spool.append("batch-1", "complete-record");
        spool.append("batch-2", "this-one-gets-truncated");
    }

    // Simulate a crash mid-write: truncate the file partway into the second
    // record's payload (well after its complete header).
    fs::path segment = dir.path() / "segment-000001.dat";
    const auto full_size = fs::file_size(segment);
    fs::resize_file(segment, full_size - 5);

    delivery::SegmentSpool spool{test_config(dir.path())};
    spool.recover();
    auto first = spool.peek_ready();
    expect(first.has_value() && first->body == "complete-record",
           "the complete record before the torn tail recovers fine");
    spool.report_outcome(true);
    expect(!spool.peek_ready().has_value(), "a torn trailing record is not surfaced as data (safe partial-write handling)");
}

void test_quota_evicts_oldest_segment_and_bounds_total_disk_usage() {
    ScratchDir dir;
    auto config = test_config(dir.path());
    config.max_segment_bytes = 64;   // force rotation almost every append
    config.max_total_bytes = 128;    // force eviction quickly
    delivery::SegmentSpool spool{config};
    spool.recover();

    for (int i = 0; i < 20; ++i) {
        spool.append("batch-" + std::to_string(i), std::string(30, 'x'));
        expect(spool.stats().total_bytes <= config.max_total_bytes,
               "total spool bytes never exceeds max_total_bytes, even under sustained pressure");
    }
    expect(spool.stats().dropped_for_quota > 0, "sustained overflow actually triggers documented eviction");
}

void test_segment_rotation_creates_multiple_segment_files() {
    ScratchDir dir;
    auto config = test_config(dir.path());
    config.max_segment_bytes = 64;
    config.max_total_bytes = 1u << 20;  // large enough that nothing is evicted here
    delivery::SegmentSpool spool{config};
    spool.recover();

    for (int i = 0; i < 10; ++i) {
        spool.append("batch-" + std::to_string(i), std::string(30, 'y'));
    }

    int segment_files = 0;
    for (const auto& entry : fs::directory_iterator(dir.path())) {
        if (entry.path().filename().string().rfind("segment-", 0) == 0) ++segment_files;
    }
    expect(segment_files > 1, "exceeding max_segment_bytes rotates into a new segment file");
}

}  // namespace

int main() {
    test_construction_validates_configuration();
    test_append_then_deliver_advances_past_the_record();
    test_failed_delivery_retries_with_backoff_then_becomes_ready_again();
    test_permanently_failing_record_is_dropped_after_max_attempts_not_retried_forever();
    test_second_record_is_not_starved_by_a_stuck_head_of_line_record();
    test_recovery_after_restart_replays_undelivered_records();
    test_delivered_records_are_not_replayed_after_restart();
    test_corrupt_record_is_quarantined_without_losing_the_record_after_it();
    test_truncated_trailing_record_is_treated_as_a_clean_partial_write();
    test_quota_evicts_oldest_segment_and_bounds_total_disk_usage();
    test_segment_rotation_creates_multiple_segment_files();

    if (failures == 0) {
        std::cout << "All Officer spool tests passed.\n";
        return 0;
    }
    return 1;
}

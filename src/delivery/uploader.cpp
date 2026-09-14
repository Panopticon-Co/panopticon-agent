#include "panopticon/officer/delivery/uploader.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

namespace panopticon::officer::delivery {

namespace {

// A random (not time-based) UUIDv4, generated from BCryptGenRandom -- the
// same OS-shipped CNG source officer-core already uses for entity-id hashing
// (see docs/adr/003-process-entity-id.md) -- rather than adding Rpcrt4 as a
// new link dependency.
std::string generate_batch_id() {
    std::array<unsigned char, 16> bytes{};
    if (BCryptGenRandom(
            nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) !=
        0) {
        return "00000000-0000-4000-8000-000000000000";
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0F) | 0x40);  // version 4
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3F) | 0x80);  // variant 10xx

    std::array<char, 37> buffer{};
    std::snprintf(
        buffer.data(),
        buffer.size(),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string{buffer.data()};
}

}  // namespace

namespace {
SpoolConfig make_spool_config(const DeliveryConfig& config) {
    SpoolConfig spool_config;
    spool_config.directory = config.spool_directory;
    spool_config.max_segment_bytes = config.spool_max_segment_bytes;
    spool_config.max_total_bytes = config.spool_max_total_bytes;
    spool_config.max_delivery_attempts = config.spool_max_delivery_attempts;
    spool_config.base_backoff_ms = config.spool_base_backoff_ms;
    spool_config.max_backoff_ms = config.spool_max_backoff_ms;
    return spool_config;
}
}  // namespace

Uploader::Uploader(DeliveryConfig config, std::string agent_id)
    : config_(std::move(config)),
      agent_id_(std::move(agent_id)),
      http_client_(config_.verify_tls),
      spool_(make_spool_config(config_)) {
    worker_ = std::thread(&Uploader::run, this);
}

Uploader::~Uploader() { stop(); }

void Uploader::enqueue(std::string ndjson_line) {
    {
        std::scoped_lock lock{mutex_};
        pending_.push_back(std::move(ndjson_line));
    }
    if (pending_.size() >= config_.batch_max_events) {
        cv_.notify_one();
    }
}

void Uploader::stop() {
    if (stop_requested_.exchange(true)) {
        return;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void Uploader::run() {
    // Recovery happens once, before any live traffic is accepted onto this
    // thread, and before the constructor's caller can have enqueued
    // anything that would race with it.
    spool_.recover();

    while (!stop_requested_.load()) {
        std::vector<std::string> batch;
        {
            std::unique_lock lock{mutex_};
            cv_.wait_for(
                lock,
                std::chrono::milliseconds(config_.flush_interval_ms),
                [this] { return stop_requested_.load() || pending_.size() >= config_.batch_max_events; });
            batch.swap(pending_);
        }
        if (!batch.empty()) {
            persist_batch(std::move(batch));
        }
        // Every wake -- whether triggered by a full batch or by the plain
        // flush-interval timeout -- also drives any due retries, so a
        // backlog accumulated during a manager outage keeps draining even
        // when no fresh telemetry arrives.
        drain_spool(/*max_records=*/64);
    }

    // Final drain on shutdown: persist whatever is still buffered in memory
    // (never dropped -- it becomes durable spool state even if this last
    // attempt below doesn't get to send it), then make one bounded,
    // non-blocking attempt to clear the head of the spool. Whatever remains
    // stays on disk for the next process start; shutdown never blocks
    // waiting for the manager.
    std::vector<std::string> remaining;
    {
        std::scoped_lock lock{mutex_};
        remaining.swap(pending_);
    }
    if (!remaining.empty()) {
        persist_batch(std::move(remaining));
    }
    drain_spool(/*max_records=*/64);
}

void Uploader::persist_batch(std::vector<std::string>&& lines) {
    std::string body;
    for (const auto& line : lines) {
        body += line;
        body += '\n';
    }
    // Persist BEFORE any HTTP attempt is made (mirrors the eyedetect
    // AlertSpool/StreamingPipeline pattern): a crash between this line and
    // the send below never loses the batch, only leaves it to be replayed
    // on the next recover().
    spool_.append(generate_batch_id(), body);
}

void Uploader::drain_spool(std::size_t max_records) {
    for (std::size_t i = 0; i < max_records; ++i) {
        auto record = spool_.peek_ready();
        if (!record) return;

        const std::vector<HttpHeader> headers = {
            {"Content-Type", "application/x-ndjson"},
            {"X-Panopticon-Batch-Id", record->batch_id},
            {"X-Panopticon-Agent-Id", agent_id_},
            {"X-Panopticon-Protocol", "1"},
        };

        std::string error;
        const auto response =
            http_client_.post(config_.manager_url + "/api/v1/ingest", headers, record->body, error);

        bool delivered = false;
        if (!response) {
            std::cerr << "[delivery] batch_id=" << record->batch_id << " transport failure: " << error << '\n';
        } else if (response->status_code == 200) {
            delivered = true;
        } else {
            std::cerr << "[delivery] batch_id=" << record->batch_id << " manager returned "
                       << response->status_code << '\n';
        }

        spool_.report_outcome(delivered);
        if (!delivered) {
            // Don't hammer the same failing head-of-line record repeatedly
            // within one drain pass; wait for its backoff window (checked
            // again on the next wake) before trying it or anything behind
            // it again.
            return;
        }
    }
}

}  // namespace panopticon::officer::delivery

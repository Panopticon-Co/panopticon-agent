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

Uploader::Uploader(DeliveryConfig config, std::string agent_id)
    : config_(std::move(config)),
      agent_id_(std::move(agent_id)),
      http_client_(config_.verify_tls) {
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
            flush(std::move(batch));
        }
    }
    // Final drain on shutdown -- best-effort, still drop-on-failure at this phase.
    std::vector<std::string> remaining;
    {
        std::scoped_lock lock{mutex_};
        remaining.swap(pending_);
    }
    if (!remaining.empty()) {
        flush(std::move(remaining));
    }
}

void Uploader::flush(std::vector<std::string>&& lines) {
    std::string body;
    for (const auto& line : lines) {
        body += line;
        body += '\n';
    }

    const std::vector<HttpHeader> headers = {
        {"Content-Type", "application/x-ndjson"},
        {"X-Panopticon-Batch-Id", generate_batch_id()},
        {"X-Panopticon-Agent-Id", agent_id_},
        {"X-Panopticon-Protocol", "1"},
    };

    std::string error;
    const auto response = http_client_.post(config_.manager_url + "/api/v1/ingest", headers, body, error);
    if (!response) {
        std::cerr << "[delivery] batch of " << lines.size() << " events dropped: " << error << '\n';
        return;
    }
    if (response->status_code != 200) {
        std::cerr << "[delivery] batch of " << lines.size() << " events dropped: manager returned "
                   << response->status_code << '\n';
    }
}

}  // namespace panopticon::officer::delivery

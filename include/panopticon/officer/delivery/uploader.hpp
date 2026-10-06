#pragma once

#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/http_client.hpp"
#include "panopticon/officer/delivery/journal.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <nlohmann/json.hpp>

namespace panopticon::officer::delivery {

struct DeliveryHealth {
    std::uint64_t commit_failures = 0;
    std::uint64_t transport_failures = 0;
    std::uint64_t invalid_receipts = 0;
    std::uint64_t freshness_challenge_failures = 0;
    std::string capture_age_state = "unavailable";
    std::string durability_state = "healthy";
    std::string transport_state = "unavailable";
    std::string last_error;
};

// Durable per-observation acceptance with a separate network worker.
class Uploader {
public:
    Uploader(DeliveryConfig config, std::string agent_id);
    ~Uploader();

    Uploader(const Uploader&) = delete;
    Uploader& operator=(const Uploader&) = delete;

    // True only after FULL/WAL commit. Disk work is synchronous in this stage;
    // collector isolation and durable source-loss records remain roadmap work.
    // No network operation occurs on the caller's thread.
    [[nodiscard]] bool enqueue(const std::string& ndjson_line);

    void stop();

    [[nodiscard]] JournalStats journal_stats() const { return journal_.stats(); }
    [[nodiscard]] DeliveryHealth health() const;
    [[nodiscard]] std::string installation_id() { return journal_.persistent_identifier("installation"); }
    [[nodiscard]] std::uint64_t next_collector_generation() { return journal_.next_collector_generation(); }
    void set_bearer_token(const std::string& agent_id, std::string token);
    void set_capture_scope(nlohmann::json scope);

private:
    void run() noexcept;
    int deliver_one(); // 1 acknowledged, 0 empty, -1 retry

    DeliveryConfig config_;
    std::string agent_id_;
    HttpClient http_client_;
    DurableJournal journal_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    DeliveryHealth health_;
    nlohmann::json capture_scope_;
    bool wake_ = false;
    std::atomic<bool> stop_requested_{false};
    std::thread worker_;
};

}  // namespace panopticon::officer::delivery

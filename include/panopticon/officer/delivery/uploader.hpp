#pragma once

#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/http_client.hpp"
#include "panopticon/officer/delivery/spool.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace panopticon::officer::delivery {

// An in-memory batcher with its own background thread, so collector
// callback threads never make a network call directly -- see "Threading" in
// docs/architecture/phase-6-delivery.md. Every batch is durably persisted to
// a SegmentSpool BEFORE an HTTP attempt is made (Phase 5,
// docs/architecture/phase-9-telemetry-durability.md): a batch that fails to
// POST is retried from the spool with bounded backoff across restarts, not
// dropped. Only a record that exhausts spool_max_delivery_attempts is ever
// given up on.
class Uploader {
public:
    Uploader(DeliveryConfig config, std::string agent_id);
    ~Uploader();

    Uploader(const Uploader&) = delete;
    Uploader& operator=(const Uploader&) = delete;

    // Called from collector callback threads. Cheap: appends under a mutex
    // and returns; the network call happens later, on this class's own
    // background thread.
    void enqueue(std::string ndjson_line);

    void stop();

    [[nodiscard]] SpoolStats spool_stats() const { return spool_.stats(); }

private:
    void run();
    void persist_batch(std::vector<std::string>&& lines);
    void drain_spool(std::size_t max_records);

    DeliveryConfig config_;
    std::string agent_id_;
    HttpClient http_client_;
    SegmentSpool spool_;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::string> pending_;
    std::atomic<bool> stop_requested_{false};
    std::thread worker_;
};

}  // namespace panopticon::officer::delivery

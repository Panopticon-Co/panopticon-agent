#pragma once

#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/http_client.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace panopticon::officer::delivery {

// Phase 1 minimum: an in-memory batcher with its own background thread, so
// collector callback threads never make a network call directly -- see
// "Threading" in docs/architecture/phase-6-delivery.md. No disk spool yet
// (that's Phase 5's SegmentSpool): a batch that fails to POST is logged to
// stderr and dropped, not retried.
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

private:
    void run();
    void flush(std::vector<std::string>&& lines);

    DeliveryConfig config_;
    std::string agent_id_;
    HttpClient http_client_;

    std::mutex mutex_;
    std::condition_variable cv_;
    std::vector<std::string> pending_;
    std::atomic<bool> stop_requested_{false};
    std::thread worker_;
};

}  // namespace panopticon::officer::delivery

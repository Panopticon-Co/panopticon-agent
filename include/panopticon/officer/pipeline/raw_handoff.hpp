#pragma once
#include "panopticon/officer/telemetry/raw_process_event.hpp"
#include <atomic>
#include <condition_variable>
#include <vector>
#include <optional>
#include <functional>
#include <mutex>
#include <thread>

namespace panopticon::officer::pipeline {
// Charged owned string capacities plus the variant object, not total allocator RSS.
[[nodiscard]] std::size_t raw_event_charge(const telemetry::RawEvent& event);
struct HandoffStats {
    std::uint64_t admitted{}, completed{}, failed{}, refused{}, contention_refused{}, exception_refused{};
    std::size_t owned_events{}, charged_bytes{}, event_limit{}, byte_limit{};
    std::size_t fixed_ring_bytes{};
    bool accepting{};
};
// Admission means volatile ownership only. Handler return means durable success;
// exceptions are counted failures. Abrupt process exit can lose owned_events.
// try_submit waits only for the short preallocated-ring mutex section, never
// for capacity or handler I/O. This is not a hard callback latency guarantee.
class RawHandoff {
public:
    using Handler = std::function<void(telemetry::RawEvent)>;
    RawHandoff(std::size_t event_limit, std::size_t byte_limit, Handler handler);
    ~RawHandoff();
    RawHandoff(const RawHandoff&) = delete;
    RawHandoff& operator=(const RawHandoff&) = delete;
    [[nodiscard]] bool try_submit(telemetry::RawEvent event) noexcept;
    // Producer callbacks must be stopped before close. Drains accepted RAM work;
    // handler I/O deadlines and abrupt-exit durable loss accounting remain separate.
    void close();
    [[nodiscard]] HandoffStats stats() const;
private:
    struct Item { telemetry::RawEvent event; std::size_t charge; };
    void run();
    const std::size_t event_limit_, byte_limit_;
    Handler handler_;
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::vector<std::optional<Item>> queue_;
    std::size_t head_ = 0, tail_ = 0, queued_ = 0;
    HandoffStats status_;
    std::atomic_uint64_t exception_refused_{0};
    std::thread worker_;
};
}

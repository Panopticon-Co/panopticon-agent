#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace panopticon::officer::collectors {

struct NetworkStateChangeLimits {
    std::size_t callback_queue_capacity = 4096;
    std::size_t snapshot_row_limit = 4096;
};

// Windows IP Helper notifications for interface, unicast-address, and route
// changes. Callbacks only copy bounded native row bytes into a bounded queue;
// callers serialize/drain records from their own worker thread.
class NetworkStateChangeSource final {
public:
    explicit NetworkStateChangeSource(NetworkStateChangeLimits limits = {});
    ~NetworkStateChangeSource();
    NetworkStateChangeSource(const NetworkStateChangeSource&) = delete;
    NetworkStateChangeSource& operator=(const NetworkStateChangeSource&) = delete;
    NetworkStateChangeSource(NetworkStateChangeSource&&) = delete;
    NetworkStateChangeSource& operator=(NetworkStateChangeSource&&) = delete;

    // Registers all three notification families, then captures bounded,
    // non-atomic initial tables. Returns a Win32 error code (NO_ERROR on
    // success). A partial registration is rolled back and reported.
    [[nodiscard]] std::uint32_t start();
    // Cancels subscriptions and waits for in-flight callbacks. Buffered rows
    // remain available through drain(); callbacks refused during stop are
    // counted in status(). Safe to call more than once.
    [[nodiscard]] std::uint32_t stop() noexcept;

    [[nodiscard]] std::vector<nlohmann::json> drain(std::size_t maximum_records);
    [[nodiscard]] nlohmann::json status() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace panopticon::officer::collectors

#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace panopticon::officer::collectors {

struct ServiceStateChangeLimits {
    std::size_t callback_queue_capacity = 2048;
    std::size_t maximum_watched_services = 4096;
    std::size_t enumeration_buffer_bytes = 4 * 1024 * 1024;
    std::uint32_t reconciliation_interval_ms = 30000;
};

// Windows SCM per-service status notifications plus bounded periodic
// reconciliation for services created after the initial enumeration.
class ServiceStateChangeSource final {
public:
    explicit ServiceStateChangeSource(ServiceStateChangeLimits limits = {});
    ~ServiceStateChangeSource();
    ServiceStateChangeSource(const ServiceStateChangeSource&) = delete;
    ServiceStateChangeSource& operator=(const ServiceStateChangeSource&) = delete;
    ServiceStateChangeSource(ServiceStateChangeSource&&) = delete;
    ServiceStateChangeSource& operator=(ServiceStateChangeSource&&) = delete;

    // Dynamically resolves NotifyServiceStatusChangeW so older Windows builds
    // can report unsupported instead of failing module load. Returns Win32
    // status; ERROR_SUCCESS means the initial enumeration completed or was
    // explicitly marked partial and reconciliation started.
    [[nodiscard]] std::uint32_t start();
    // Stops reconciliation, closes SCM subscriptions, waits for callbacks,
    // and leaves already queued records available through drain().
    [[nodiscard]] std::uint32_t stop() noexcept;
    [[nodiscard]] std::vector<nlohmann::json> drain(std::size_t maximum_records);
    [[nodiscard]] nlohmann::json status() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace panopticon::officer::collectors

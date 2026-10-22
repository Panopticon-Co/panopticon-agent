#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace panopticon::officer::collectors {

struct RegistryChangeNotification {
    std::string root_id;
    std::string hive;
    std::string key_path;
    std::string local_sequence;
    std::string received_utc;
};

struct RegistryChangeRootStatus {
    std::string root_id;
    std::string hive;
    std::string key_path;
    std::string state;
    std::string error_code;
    std::string local_sequence;
    std::string queue_dropped_total;
    std::string first_dropped_sequence;
    std::string last_dropped_sequence;
};

struct RegistryChangeLossReport {
    std::string root_id;
    std::string hive;
    std::string key_path;
    std::uint64_t count = 0;
    std::uint64_t first_sequence = 0;
    std::uint64_t last_sequence = 0;
};

// Watches selected subtrees with read-only KEY_NOTIFY/READ_CONTROL rights. It
// does not read values or identify the changed descendant/value or actor.
class RegistryChangeWatch {
public:
    RegistryChangeWatch();
    ~RegistryChangeWatch();
    RegistryChangeWatch(const RegistryChangeWatch&) = delete;
    RegistryChangeWatch& operator=(const RegistryChangeWatch&) = delete;

    bool try_pop(RegistryChangeNotification& notification);
    std::size_t queued_count() const;
    std::vector<RegistryChangeRootStatus> snapshot() const;
    // Atomically moves the current bounded-queue overflow summary to the caller.
    // The caller must retain it until a durable loss record is accepted.
    std::vector<RegistryChangeLossReport> take_loss_reports();
    void stop() noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace panopticon::officer::collectors

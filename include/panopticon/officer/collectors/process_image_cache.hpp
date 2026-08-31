#pragma once

#include "panopticon/officer/telemetry/raw_process_event.hpp"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace panopticon::officer::collectors {

// Sysmon does not always resolve the process image for non-process telemetry
// (EID 3/7/11/12-14/23/26): under load, or once the process has exited, it
// writes Image="<unknown process>". Officer observes every EID 1 first, so it
// can keep a small PID -> identity table and backfill those events itself --
// which is what a real EDR agent's process table is for.
//
// Bounded with a two-generation scheme (no per-entry LRU bookkeeping): once the
// hot map fills, it becomes the cold map and a fresh hot map starts; lookups
// check both. A busy host churns PIDs fast enough that a modest cap never drops
// a still-relevant entry.
class ProcessImageCache {
public:
    static constexpr std::string_view kUnknownProcessSentinel = "<unknown process>";

    explicit ProcessImageCache(std::size_t generation_capacity = 4096);

    // Record identity from a decoded Sysmon EID 1 (ProcessCreate).
    void remember(const telemetry::RawProcessEvent& process_event);

    // If ``context.executable`` is absent, empty, or the Sysmon
    // "<unknown process>" sentinel, fill executable / user from a remembered
    // EID 1 for the same PID. Returns true if anything was filled.
    bool enrich(telemetry::RawProcessContext& context) const;

private:
    struct Identity {
        std::optional<std::string> executable;
        std::optional<std::string> user_name;
        std::optional<std::string> user_sid;
    };

    const Identity* find_locked(std::uint32_t pid) const;

    mutable std::mutex mutex_;
    std::size_t generation_capacity_;
    std::unordered_map<std::uint32_t, Identity> hot_;
    std::unordered_map<std::uint32_t, Identity> cold_;
};

}  // namespace panopticon::officer::collectors

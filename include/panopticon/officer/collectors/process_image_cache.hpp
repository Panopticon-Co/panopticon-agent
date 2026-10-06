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
// writes Image="<unknown process>". Backfill only when a retained ProcessGuid
// and PID both match. Event ordering is not guaranteed; a cache miss remains
// unresolved. PID alone must never transfer image/user facts between instances.
//
// Bounded with a two-generation scheme (no per-entry LRU bookkeeping): once the
// hot map fills, it becomes the cold map and a fresh hot map starts; lookups
// check both. Eviction can leave context unresolved and must not imply that
// full process state or tombstone retention is implemented.
class ProcessImageCache {
public:
    static constexpr std::string_view kUnknownProcessSentinel = "<unknown process>";

    explicit ProcessImageCache(std::size_t generation_capacity = 4096);

    // Record identity from a decoded Sysmon EID 1 (ProcessCreate).
    void remember(const telemetry::RawProcessEvent& process_event);

    // If ``context.executable`` is absent, empty, or the Sysmon
    // "<unknown process>" sentinel, attach a separate cached_context from a
    // matching EID 1. The current event's decoded fields remain unchanged.
    bool enrich(telemetry::RawProcessContext& context) const;

private:
    using Identity = telemetry::CachedProcessContext;

    const Identity* find_locked(const std::string& process_guid) const;

    mutable std::mutex mutex_;
    std::size_t generation_capacity_;
    std::unordered_map<std::string, Identity> hot_;
    std::unordered_map<std::string, Identity> cold_;
};

}  // namespace panopticon::officer::collectors

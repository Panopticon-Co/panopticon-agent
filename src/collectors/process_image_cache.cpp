#include "panopticon/officer/collectors/process_image_cache.hpp"

#include <algorithm>
#include <utility>

namespace panopticon::officer::collectors {

ProcessImageCache::ProcessImageCache(std::size_t generation_capacity)
    : generation_capacity_(std::max<std::size_t>(generation_capacity, 1)) {}

void ProcessImageCache::remember(const telemetry::RawProcessEvent& process_event) {
    if (!process_event.process_guid || process_event.process_guid->empty()) return;
    Identity identity{
        process_event.source,
        process_event.process_start_time,
        process_event.pid,
        *process_event.process_guid,
        process_event.executable,
        process_event.user_name,
        process_event.user_sid,
    };

    std::scoped_lock lock{mutex_};
    if (hot_.size() >= generation_capacity_ && hot_.find(*process_event.process_guid) == hot_.end()) {
        cold_ = std::move(hot_);
        hot_.clear();
    }
    hot_.insert_or_assign(*process_event.process_guid, std::move(identity));
}

const ProcessImageCache::Identity* ProcessImageCache::find_locked(const std::string& process_guid) const {
    if (const auto found = hot_.find(process_guid); found != hot_.end()) {
        return &found->second;
    }
    if (const auto found = cold_.find(process_guid); found != cold_.end()) {
        return &found->second;
    }
    return nullptr;
}

bool ProcessImageCache::enrich(telemetry::RawProcessContext& context) const {
    const bool image_resolved = context.executable && !context.executable->empty() &&
                                *context.executable != kUnknownProcessSentinel;
    if (image_resolved || !context.process_guid || context.process_guid->empty()) {
        return false;
    }

    std::scoped_lock lock{mutex_};
    const Identity* identity = find_locked(*context.process_guid);
    if (identity == nullptr || identity->pid != context.pid || !identity->executable ||
        identity->executable->empty() || *identity->executable == kUnknownProcessSentinel) {
        return false;
    }

    context.cached_context = *identity;
    return true;
}

}  // namespace panopticon::officer::collectors

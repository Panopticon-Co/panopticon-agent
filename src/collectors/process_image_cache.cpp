#include "panopticon/officer/collectors/process_image_cache.hpp"

#include <algorithm>
#include <utility>

namespace panopticon::officer::collectors {

ProcessImageCache::ProcessImageCache(std::size_t generation_capacity)
    : generation_capacity_(std::max<std::size_t>(generation_capacity, 1)) {}

void ProcessImageCache::remember(const telemetry::RawProcessEvent& process_event) {
    Identity identity{
        process_event.executable,
        process_event.user_name,
        process_event.user_sid,
    };

    std::scoped_lock lock{mutex_};
    if (hot_.size() >= generation_capacity_ && hot_.find(process_event.pid) == hot_.end()) {
        cold_ = std::move(hot_);
        hot_.clear();
    }
    hot_.insert_or_assign(process_event.pid, std::move(identity));
}

const ProcessImageCache::Identity* ProcessImageCache::find_locked(std::uint32_t pid) const {
    if (const auto found = hot_.find(pid); found != hot_.end()) {
        return &found->second;
    }
    if (const auto found = cold_.find(pid); found != cold_.end()) {
        return &found->second;
    }
    return nullptr;
}

bool ProcessImageCache::enrich(telemetry::RawProcessContext& context) const {
    const bool image_resolved = context.executable && !context.executable->empty() &&
                                *context.executable != kUnknownProcessSentinel;
    if (image_resolved) {
        return false;
    }

    std::scoped_lock lock{mutex_};
    const Identity* identity = find_locked(context.pid);
    if (identity == nullptr || !identity->executable) {
        return false;
    }

    context.executable = identity->executable;
    if (!context.user_name) {
        context.user_name = identity->user_name;
    }
    if (!context.user_sid) {
        context.user_sid = identity->user_sid;
    }
    return true;
}

}  // namespace panopticon::officer::collectors

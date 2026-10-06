#include "panopticon/officer/pipeline/raw_handoff.hpp"
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace panopticon::officer::pipeline {
std::size_t raw_event_charge(const telemetry::RawEvent& event) {
    std::size_t bytes = sizeof(event);
    const auto add = [&](const std::string& value) {
        if (value.capacity() >= std::numeric_limits<std::size_t>::max() - bytes)
            throw std::length_error("raw event charge overflow");
        bytes += value.capacity() + 1;
    };
    const auto optional = [&](const std::optional<std::string>& value) { if (value) add(*value); };
    const auto source = [&](const telemetry::SourceProvenance& value) { add(value.provider); optional(value.channel); };
    std::visit([&](const auto& raw) {
        using T = std::decay_t<decltype(raw)>;
        source(raw.source);
        if constexpr (std::is_same_v<T, telemetry::RawProcessEvent>) {
            optional(raw.process_guid); optional(raw.parent_process_guid); optional(raw.parent_executable);
            optional(raw.executable); optional(raw.command_line); optional(raw.user_sid); optional(raw.user_name); optional(raw.sha256);
        } else {
            const auto& process = raw.process;
            optional(process.executable); optional(process.process_name); optional(process.user_name);
            optional(process.user_sid); optional(process.process_guid);
            if (process.cached_context) {
                const auto& cached = *process.cached_context;
                source(cached.source); add(cached.process_guid); optional(cached.executable);
                optional(cached.user_name); optional(cached.user_sid);
            }
            if constexpr (std::is_same_v<T, telemetry::RawNetworkEvent>) {
                optional(raw.source_ip); optional(raw.destination_ip); optional(raw.destination_hostname);
            } else if constexpr (std::is_same_v<T, telemetry::RawFileEvent>) {
                optional(raw.path); optional(raw.target_path); optional(raw.previous_path); optional(raw.sha256);
            } else if constexpr (std::is_same_v<T, telemetry::RawRegistryEvent>) {
                optional(raw.key_path); optional(raw.value_name); optional(raw.value_type); optional(raw.value_data);
            } else if constexpr (std::is_same_v<T, telemetry::RawImageLoadEvent>) {
                optional(raw.path); optional(raw.signature_status); optional(raw.sha256);
            }
        }
    }, event);
    return bytes;
}
RawHandoff::RawHandoff(std::size_t events, std::size_t bytes, Handler handler)
    : event_limit_(events), byte_limit_(bytes), handler_(std::move(handler)) {
    if (!events || events > 65536 || !bytes || !handler_) throw std::invalid_argument("invalid raw handoff configuration");
    static_assert(std::is_nothrow_move_constructible_v<telemetry::RawEvent>);
    queue_.resize(events);
    status_.accepting = true; status_.event_limit = events; status_.byte_limit = bytes;
    status_.fixed_ring_bytes = queue_.size() * sizeof(std::optional<Item>);
    worker_ = std::thread([this] { run(); });
}
RawHandoff::~RawHandoff() { close(); }
bool RawHandoff::try_submit(telemetry::RawEvent event) noexcept {
    try {
        const auto charge = raw_event_charge(event);
        std::unique_lock lock{mutex_};
        if (!status_.accepting || status_.owned_events >= event_limit_ || charge > byte_limit_ - status_.charged_bytes) {
            ++status_.refused; return false;
        }
        queue_[tail_].emplace(Item{std::move(event), charge});
        tail_ = (tail_ + 1) % event_limit_; ++queued_;
        ++status_.admitted; ++status_.owned_events; status_.charged_bytes += charge;
        changed_.notify_one(); return true;
    } catch (...) { ++exception_refused_; return false; }
}
void RawHandoff::run() {
    for (;;) {
        std::unique_lock lock{mutex_};
        changed_.wait(lock, [&] { return queued_ != 0 || !status_.accepting; });
        if (queued_ == 0) return;
        auto item = std::move(*queue_[head_]); queue_[head_].reset();
        head_ = (head_ + 1) % event_limit_; --queued_;
        lock.unlock();
        bool completed = false;
        try { handler_(std::move(item.event)); completed = true; } catch (...) {}
        lock.lock();
        if (completed) ++status_.completed; else ++status_.failed;
        --status_.owned_events; status_.charged_bytes -= item.charge;
    }
}
void RawHandoff::close() {
    { std::scoped_lock lock{mutex_}; status_.accepting = false; changed_.notify_all(); }
    if (worker_.joinable()) worker_.join();
}
HandoffStats RawHandoff::stats() const {
    std::scoped_lock lock{mutex_}; auto result = status_;
    result.exception_refused = exception_refused_.load();
    result.refused += result.exception_refused; return result;
}
}

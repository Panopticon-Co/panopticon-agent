#include "panopticon/officer/pipeline/diagnostic_output.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
namespace panopticon::officer::pipeline {
struct DiagnosticOutput::State {
    struct Item { std::string line; std::size_t charge; };
    HANDLE output = nullptr;
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<std::optional<Item>> queue;
    std::size_t head = 0, tail = 0, queued = 0, owned = 0, bytes = 0;
    std::size_t event_limit, byte_limit, line_limit;
    std::uint64_t admitted = 0, completed = 0, failed = 0, abandoned = 0, refused = 0;
    std::uint64_t written_bytes = 0, partial_records = 0, write_started = 0;
    DWORD last_native_error = 0, last_cancel_error = 0, reported_failure_bytes = 0;
    int worker_start_error = 0;
    const char* worker_start_error_category = "";
    const char* last_failure_kind = "";
    bool available = false, accepting = false, closing = false, abort = false, done = false, writing = false, deadline_exceeded = false;
    std::atomic_uint64_t exception_refused{0};
    State(std::size_t events, std::size_t limit, std::size_t line) : event_limit(events), byte_limit(limit), line_limit(line) { queue.resize(events); }
    ~State() { if (output) CloseHandle(output); }
    void abandon_queued() {
        while (queued) { const auto charge = queue[head]->charge; queue[head].reset();
            head = (head + 1) % event_limit; --queued; --owned; bytes -= charge; ++abandoned; }
    }
    void run() {
        for (;;) {
            std::optional<Item> item;
            { std::unique_lock lock{mutex}; changed.wait(lock, [&] { return queued || closing || !available; });
              if (abort || !available || (!queued && closing)) { abandon_queued(); done = true; changed.notify_all(); return; }
              item = std::move(queue[head]); queue[head].reset(); head = (head + 1) % event_limit; --queued;
              writing = true; write_started = GetTickCount64(); }
            std::size_t offset = 0; DWORD error = 0, failure_bytes = 0; const char* failure_kind = "";
            while (offset < item->line.size()) {
                { std::scoped_lock lock{mutex}; if (abort) { failure_kind = "shutdown_abandonment"; break; } }
                DWORD written = 0; const auto remaining = static_cast<DWORD>(item->line.size() - offset);
                if (!WriteFile(output, item->line.data() + offset, remaining, &written, nullptr)) {
                    error = GetLastError(); failure_bytes = written; failure_kind = "Win32"; break;
                }
                if (!written || written > remaining) { failure_bytes = written; failure_kind = "validation_native_write_progress"; break; }
                offset += written;
            }
            { std::scoped_lock lock{mutex}; written_bytes += offset;
              if (!*failure_kind) ++completed;
              else { ++failed; if (offset) ++partial_records; available = false; accepting = false;
                  last_native_error = error; reported_failure_bytes = failure_bytes; last_failure_kind = failure_kind; }
              const auto charge = item->charge; item.reset(); --owned; bytes -= charge; writing = false; changed.notify_all(); }
        }
    }
};
DiagnosticOutput::DiagnosticOutput(void* borrowed_handle, std::size_t events, std::size_t bytes, std::size_t line_limit) {
    if (!events || events > 8192 || !bytes || bytes > 64 * 1024 * 1024 || !line_limit || line_limit > 1024 * 1024)
        throw std::invalid_argument("diagnostic output limits invalid");
    state_ = std::make_shared<State>(events, bytes, line_limit);
    if (!borrowed_handle || borrowed_handle == INVALID_HANDLE_VALUE) { state_->last_native_error = ERROR_INVALID_HANDLE; state_->last_failure_kind = "initialization_invalid_handle"; state_->done = true; return; }
    if (!DuplicateHandle(GetCurrentProcess(), borrowed_handle, GetCurrentProcess(), &state_->output, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        state_->last_native_error = GetLastError(); state_->last_failure_kind = "Win32_duplicate_handle"; state_->done = true; return;
    }
    state_->available = state_->accepting = true;
    try { worker_ = std::thread([state = state_] { state->run(); }); }
    catch (const std::system_error& error) { state_->available = state_->accepting = false; state_->done = true;
        state_->last_failure_kind = "worker_start_failure";
        state_->worker_start_error = error.code().value();
        state_->worker_start_error_category = error.code().category().name(); }
}
DiagnosticOutput::~DiagnosticOutput() { close(); }
bool DiagnosticOutput::try_submit(std::string_view line) noexcept {
    try {
        if (line.size() > state_->line_limit) { std::scoped_lock lock{state_->mutex}; ++state_->refused; return false; }
        std::string owned{line}; owned.push_back('\n'); const auto charge = sizeof(State::Item) + owned.capacity();
        std::scoped_lock lock{state_->mutex};
        if (!state_->accepting || state_->owned >= state_->event_limit || charge > state_->byte_limit - state_->bytes) { ++state_->refused; return false; }
        state_->queue[state_->tail].emplace(State::Item{std::move(owned), charge});
        state_->tail = (state_->tail + 1) % state_->event_limit; ++state_->queued; ++state_->owned; state_->bytes += charge; ++state_->admitted;
        state_->changed.notify_one(); return true;
    } catch (...) { ++state_->exception_refused; return false; }
}
nlohmann::json DiagnosticOutput::snapshot() const {
    std::scoped_lock lock{state_->mutex};
    return {{"state", !state_->available ? "unavailable" : state_->closing && state_->done ? "disabled" : "degraded"},
        {"scope", "volatile best-effort diagnostic display; no durable acceptance, reader receipt or telemetry loss claim; counters reset on restart"},
        {"admitted_volatile", std::to_string(state_->admitted)}, {"completed_native_writes", std::to_string(state_->completed)},
        {"failed_native_writes", std::to_string(state_->failed)}, {"abandoned_unattempted", std::to_string(state_->abandoned)},
        {"refused", std::to_string(state_->refused)}, {"exception_refused", std::to_string(state_->exception_refused.load())},
        {"owned_lines", std::to_string(state_->owned)}, {"charged_bytes", std::to_string(state_->bytes)},
        {"event_limit", std::to_string(state_->event_limit)}, {"byte_limit", std::to_string(state_->byte_limit)},
        {"line_limit", std::to_string(state_->line_limit)}, {"fixed_ring_bytes", std::to_string(state_->queue.capacity() * sizeof(std::optional<State::Item>))},
        {"byte_scope", "owned item objects/string capacities including in-flight write; allocator/thread/temporary admission RSS excluded"},
        {"completed_write_bytes", std::to_string(state_->written_bytes)}, {"partially_written_records", std::to_string(state_->partial_records)},
        {"reported_bytes_on_failure", std::to_string(state_->reported_failure_bytes)}, {"failure_kind", state_->last_failure_kind},
        {"native_error_code", std::to_string(state_->last_native_error)}, {"cancel_error_code", std::to_string(state_->last_cancel_error)},
        {"worker_start_error_code", std::to_string(state_->worker_start_error)},
        {"worker_start_error_category", state_->worker_start_error_category},
        {"write_in_progress", state_->writing}, {"write_started_uptime_ms", std::to_string(state_->write_started)},
        {"accepting", state_->accepting}, {"worker_finished", state_->done}, {"shutdown_deadline_exceeded", state_->deadline_exceeded}};
}
void DiagnosticOutput::close() {
    if (!worker_.joinable()) return;
    { std::unique_lock lock{state_->mutex}; state_->accepting = false; state_->closing = true; state_->changed.notify_all();
      if (!state_->changed.wait_for(lock, std::chrono::milliseconds(100), [&] { return state_->done; })) {
          state_->abort = true; state_->abandon_queued(); state_->changed.notify_all(); } }
    const auto deadline = GetTickCount64() + 1000;
    for (;;) {
        { std::unique_lock lock{state_->mutex}; if (state_->done) break;
          if (GetTickCount64() >= deadline) { state_->deadline_exceeded = true; state_->available = false; break; } }
        const auto cancel = CancelSynchronousIo(worker_.native_handle()); const auto error = cancel ? 0 : GetLastError();
        std::unique_lock lock{state_->mutex}; state_->last_cancel_error = error;
        state_->changed.wait_for(lock, std::chrono::milliseconds(10), [&] { return state_->done; });
    }
    bool done; { std::scoped_lock lock{state_->mutex}; done = state_->done; }
    if (done) worker_.join(); else worker_.detach();
}
}

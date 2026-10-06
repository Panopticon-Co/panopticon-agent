#pragma once
#include <nlohmann/json.hpp>
#include <memory>
#include <string_view>
#include <thread>
namespace panopticon::officer::pipeline {
// Best-effort display only. Submission must follow durable telemetry acceptance.
// The borrowed native handle is duplicated; the caller's handle is never closed.
class DiagnosticOutput {
public:
    DiagnosticOutput(void* borrowed_handle, std::size_t event_limit, std::size_t byte_limit,
        std::size_t line_limit = 1024 * 1024);
    ~DiagnosticOutput();
    DiagnosticOutput(const DiagnosticOutput&) = delete;
    DiagnosticOutput& operator=(const DiagnosticOutput&) = delete;
    [[nodiscard]] bool try_submit(std::string_view line) noexcept;
    [[nodiscard]] nlohmann::json snapshot() const;
    // Briefly drain, then cancel owned synchronous I/O. Unsupported/late native
    // cancellation leaves only a self-owned diagnostic thread, never dangling
    // data or a blocking join; expose deadline failure rather than terminate it.
    void close();
private:
    struct State;
    std::shared_ptr<State> state_;
    std::thread worker_;
};
}

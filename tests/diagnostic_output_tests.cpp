#include "panopticon/officer/pipeline/diagnostic_output.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
using panopticon::officer::pipeline::DiagnosticOutput;
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value) CloseHandle(value); }
};
std::uint64_t number(const nlohmann::json& value, const char* key) {
    return std::stoull(value.at(key).get<std::string>());
}
void accounting(const nlohmann::json& value) {
    require(number(value, "admitted_volatile") == number(value, "completed_native_writes") +
        number(value, "failed_native_writes") + number(value, "abandoned_unattempted") + number(value, "owned_lines"),
        "accepted diagnostics must have one accounted disposition");
    require(number(value, "charged_bytes") <= number(value, "byte_limit"), "owned bytes exceeded bound");
}
void blocked_pipe() {
    Handle reader, writer;
    require(CreatePipe(&reader.value, &writer.value, nullptr, 4096), "create owned pipe");
    DiagnosticOutput output{writer.value, 2, 128 * 1024};
    require(output.try_submit(std::string(32768, 'a')), "first admission");
    const auto deadline = GetTickCount64() + 2000;
    while (!output.snapshot().at("write_in_progress").get<bool>() && GetTickCount64() < deadline)
        std::this_thread::yield();
    require(output.snapshot().at("write_in_progress").get<bool>(), "owned unread pipe write did not start");
    require(output.try_submit(std::string(32768, 'b')), "second admission including in-flight ownership");
    const auto before = GetTickCount64();
    require(!output.try_submit("refused"), "in-flight line must count toward bound");
    require(GetTickCount64() - before < 500, "admission waited for native blocked write");
    accounting(output.snapshot());
    const auto close_start = GetTickCount64();
    output.close();
    require(GetTickCount64() - close_start < 2000, "diagnostic shutdown exceeded bounded window");
    const auto status = output.snapshot();
    require(status.at("worker_finished").get<bool>(), "owned anonymous pipe cancellation did not finish");
    require(!status.at("shutdown_deadline_exceeded").get<bool>(), "owned pipe required orphan fallback");
    require(number(status, "owned_lines") == 0 && number(status, "abandoned_unattempted") == 1, "queued line not abandoned/accounted");
    require(number(status, "failed_native_writes") == 1, "blocked in-flight line not failed/accounted");
    require(number(status, "native_error_code") == ERROR_OPERATION_ABORTED, "retain native cancellation error");
    accounting(status);
    require(!output.try_submit("after close"), "closed writer accepted diagnostic");
}
void exact_display_and_handle_ownership() {
    Handle reader, writer;
    require(CreatePipe(&reader.value, &writer.value, nullptr, 4096), "create owned pipe");
    DiagnosticOutput output{writer.value, 4, 4096};
    const std::string line{"embedded\0byte", 13};
    require(output.try_submit(line), "binary diagnostic admission");
    output.close();
    auto status = output.snapshot();
    require(number(status, "completed_native_writes") == 1, "native completion missing");
    char bytes[64]{}; DWORD count = 0;
    require(ReadFile(reader.value, bytes, 64, &count, nullptr) && std::string(bytes, count) == line + '\n', "display altered bytes/framing");
    DWORD written = 0;
    require(WriteFile(writer.value, "x", 1, &written, nullptr) && written == 1, "borrowed handle was closed");
    accounting(status);
}
void broken_and_invalid_handles() {
    DiagnosticOutput invalid{INVALID_HANDLE_VALUE, 1, 4096};
    require(!invalid.try_submit("no output"), "invalid handle accepted");
    require(number(invalid.snapshot(), "native_error_code") == ERROR_INVALID_HANDLE, "invalid handle provenance");
    Handle reader, writer;
    require(CreatePipe(&reader.value, &writer.value, nullptr, 4096), "create pipe");
    CloseHandle(reader.value); reader.value = nullptr;
    DWORD probe_written = 0;
    require(!WriteFile(writer.value, "probe", 5, &probe_written, nullptr), "owned closed-reader probe unexpectedly succeeded");
    const auto expected_error = GetLastError();
    DiagnosticOutput broken{writer.value, 1, 4096};
    require(broken.try_submit("diagnostic"), "broken pipe should be detected at native write");
    broken.close();
    const auto status = broken.snapshot();
    require(number(status, "native_error_code") == expected_error, "exact closed-reader native error lost");
    require(number(status, "completed_native_writes") == 0 && number(status, "failed_native_writes") == 1, "failed write credited successful");
    accounting(status);
}
void independent_byte_and_line_limits() {
    Handle reader, writer;
    require(CreatePipe(&reader.value, &writer.value, nullptr, 4096), "create bounded pipe");
    DiagnosticOutput output{writer.value, 4, 16, 16};
    require(!output.try_submit(std::string(17, 'a')), "input line bound ignored");
    require(!output.try_submit("short"), "item object/string capacity byte bound ignored");
    const auto status = output.snapshot();
    require(number(status, "admitted_volatile") == 0 && number(status, "refused") == 2,
        "independent line/byte refusals not counted");
    accounting(status);
    output.close();
}
int main() {
    try { blocked_pipe(); exact_display_and_handle_ownership(); broken_and_invalid_handles(); independent_byte_and_line_limits();
        std::cout << "Owned unread pipe, cancellation, framing, handle ownership and failure accounting passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

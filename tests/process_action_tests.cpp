#include "panopticon/officer/response/process_actions.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
namespace response = panopticon::officer::response;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::uint64_t creation_ticks(HANDLE handle) {
    FILETIME creation{}, exit{}, kernel{}, user{};
    require(GetProcessTimes(handle, &creation, &exit, &kernel, &user) != 0, "owned test process creation query");
    return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}
struct OwnedChild {
    HANDLE process = nullptr;
    DWORD pid = 0;
    OwnedChild() {
        std::vector<wchar_t> executable(32768);
        require(GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size())) != 0, "test executable path");
        std::wstring command = L"\"" + std::wstring{executable.data()} + L"\" --owned-child";
        STARTUPINFOW startup{}; startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESHOWWINDOW; startup.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION info{};
        require(CreateProcessW(executable.data(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &info) != 0, "create only owned inert test child");
        process = info.hProcess; pid = info.dwProcessId; CloseHandle(info.hThread);
    }
    ~OwnedChild() {
        if (process) {
            if (WaitForSingleObject(process, 0) == WAIT_TIMEOUT) { TerminateProcess(process, 1); WaitForSingleObject(process, 5000); }
            CloseHandle(process);
        }
    }
};
int main(int argc, char** argv) {
    if (argc == 2 && std::string{argv[1]} == "--owned-child") { Sleep(60000); return 0; }
    if (argc == 2 && std::string{argv[1]} == "--emit-execution-fixtures") {
        nlohmann::json records = nlohmann::json::array();
        unsigned sequence = 0;
        for (const DWORD status : std::vector<DWORD>{WAIT_OBJECT_0, WAIT_TIMEOUT, WAIT_FAILED}) {
            const auto receipt = response::termination_receipt(
                response::detail::termination_completion(status, ERROR_INVALID_HANDLE),
                "cmd-native-execution-" + std::to_string(sequence++), "corr-native-execution");
            std::string error;
            const auto wire = response::serialize_command_result(receipt, 4096, error);
            if (!wire) { std::cerr << error; return 1; }
            records.push_back(nlohmann::json::parse(*wire));
        }
        std::cout << records.dump() << '\n';
        return 0;
    }
    if (argc != 1) return 2;
    try {
        std::string error;
        response::ProcessTarget self{"test-host", GetCurrentProcessId(), creation_ticks(GetCurrentProcess())};
        const auto self_result = response::terminate_process(self);
        require(self_result.state == response::ProcessTerminationState::refused && !self_result.action_initiated &&
            self_result.stage == response::ProcessTerminationStage::preflight, "self termination must fail closed before action");
        require(response::is_protected_process(99, "WINLOGON.EXE"), "winlogon is protected by image guard");
        OwnedChild child;
        const auto ticks = creation_ticks(child.process);
        const auto boot = panopticon::officer::core::query_native_boot_id(error);
        require(boot.has_value(), "native boot identity required for owned response qualification on this host");
        response::ProcessTarget legacy{"test-host", child.pid, ticks};
        require(response::terminate_process(legacy).state == response::ProcessTerminationState::refused,
            "unscoped legacy process termination must be refused");
        require(!response::reobserve_process(legacy, error), "unscoped legacy process observation must be refused");
        response::ProcessTarget prior_boot{"test-host", child.pid, ticks, "boot_other"};
        require(response::terminate_process(prior_boot).state == response::ProcessTerminationState::refused,
            "wrong boot cannot terminate owned instance");
        require(!response::reobserve_process(prior_boot, error), "wrong boot cannot acquire process evidence");
        response::ProcessTarget wrong{"test-host", child.pid, ticks + 1};
        wrong.boot_id = boot;
        const auto wrong_result = response::terminate_process(wrong);
        require(wrong_result.state == response::ProcessTerminationState::refused && !wrong_result.action_initiated &&
            wrong_result.stage == response::ProcessTerminationStage::identity, "wrong instance token cannot terminate owned child");
        require(WaitForSingleObject(child.process, 0) == WAIT_TIMEOUT, "wrong target must remain alive");
        response::ProcessTarget exact{"test-host", child.pid, ticks};
        exact.boot_id = boot;
        const auto observation = response::reobserve_process(exact, error);
        require(observation && observation->executable_path, "owned instance can be re-observed without termination");
        require(response::to_raw_process_event(*observation).start_time_ticks == ticks, "response evidence must retain exact native creation ticks");
        const auto outcome = response::terminate_process(exact);
        require(outcome.state == response::ProcessTerminationState::succeeded && outcome.action_initiated &&
            outcome.completion_observed && !outcome.native_error, "verified owned child termination must observe completion");
        require(WaitForSingleObject(child.process, 0) == WAIT_OBJECT_0, "success means process object signaled");
        for (const DWORD status : std::vector<DWORD>{WAIT_TIMEOUT, WAIT_FAILED, WAIT_ABANDONED}) {
            auto uncertain = response::detail::termination_completion(status, ERROR_INVALID_HANDLE);
            require(uncertain.state == response::ProcessTerminationState::indeterminate && uncertain.action_initiated &&
                !uncertain.completion_observed, "unobserved completion cannot become definite failure or success");
            require(uncertain.native_error.has_value() == (status == WAIT_FAILED),
                "native errors belong only to failed waits, never stale timeout error state");
            uncertain.summary = "different diagnostic text with no classification keyword";
            const auto receipt = response::termination_receipt(uncertain, "cmd-wait", "corr-wait");
            require(receipt.code == response::ReceiptCode::indeterminate, "receipt outcome is independent of diagnostic wording");
            const auto wire = response::serialize_command_result(receipt, 4096, error);
            require(wire && wire->find("\"outcome\":\"indeterminate\"") != std::string::npos,
                "typed uncertain completion survives wire serialization");
            const auto evidence = nlohmann::json::parse(*wire).at("execution");
            require(evidence.at("representation") == "windows_process_termination_v1" &&
                evidence.at("stage") == "completion" && evidence.at("action_initiated") == true &&
                evidence.at("completion_observed") == false, "structured execution facts survive serialization");
            require(status == WAIT_FAILED ? evidence.at("native_error") == ERROR_INVALID_HANDLE
                : evidence.at("native_error").is_null(), "native error is exact integer or explicit null");
        }
        const auto refused_receipt = response::termination_receipt(wrong_result, "cmd-wrong", "corr-wrong");
        const auto refused_wire = response::serialize_command_result(refused_receipt, 4096, error);
        require(refused_wire && refused_wire->find("\"outcome\":\"rejected\"") != std::string::npos,
            "verified target mismatch is a refusal rather than an attempted action failure");
        auto conflicting = response::detail::termination_completion(WAIT_TIMEOUT);
        conflicting.state = response::ProcessTerminationState::failed;
        require(response::termination_receipt(conflicting, "cmd-conflicting", "corr-conflicting").code ==
            response::ReceiptCode::indeterminate, "initiated action with unknown completion cannot claim definite failure");
        conflicting.state = response::ProcessTerminationState::succeeded;
        require(response::termination_receipt(conflicting, "cmd-conflicting", "corr-conflicting").code ==
            response::ReceiptCode::indeterminate, "success requires consistent observed completion evidence");
        require(!response::termination_receipt(conflicting, "cmd-conflicting", "corr-conflicting").execution,
            "contradictory native state cannot emit conclusive structured facts");
        auto invalid_evidence = refused_receipt;
        invalid_evidence.execution->action_initiated = true;
        require(!response::serialize_command_result(invalid_evidence, 4096, error),
            "serializer rejects contradictory execution facts instead of emitting invalid evidence");
        std::cout << "held-handle process action tests passed; only owned inert child terminated\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

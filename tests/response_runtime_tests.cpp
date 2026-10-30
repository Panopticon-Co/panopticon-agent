// Exercise the production response worker without starting collectors or network
// polling. Expired and interrupted commands must never invoke their OS actions.
#define main officer_agent_entry_not_called
#include "../src/main.cpp"
#undef main
#include <fstream>
#include <stdexcept>

void require_runtime(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
std::string runtime_command(const std::string& id, bool expired) {
    return nlohmann::json{{"command_id", id}, {"agent_id", "agent-runtime"}, {"host_id", "host-runtime"},
        {"schema_version", "2"}, {"action", "KILL_PROCESS"}, {"correlation_id", "corr-runtime"},
        {"created_at", "2019-01-01T00:00:00Z"}, {"expires_at", expired ? "2020-01-01T00:00:00Z" : "2999-01-01T00:00:00Z"},
        {"target", {{"pid", 4242}, {"start_time_ticks", "123"}, {"boot_id", "boot_" + std::string(64, 'a')}}}}.dump();
}
int verify_untrusted_https(const char* manager_url, const char* directory, const char* token_file) {
    std::ifstream token_input(token_file);
    std::string token; std::getline(token_input, token);
    require_runtime(!token.empty(), "owned test token required");
    const std::filesystem::path root(directory);
    response::EnrolledIdentity identity{"agent-1", "host-1", token};
    pipeline::NormalizationContext context{};
    response::ResponseConfig config{};
    std::string original_result;
    {
        response::ReplayLedger ledger{root / "legacy-ledger", 4096};
        std::string error; require_runtime(ledger.load(error), "owned legacy guard loads");
        ResponseRuntime runtime{identity, std::move(ledger), config, manager_url, context,
            [](const std::string&) { throw std::runtime_error("unexpected OS action"); }, root / "scope", root / "missing-artifact-signing-key"};
        auto command = nlohmann::json::parse(runtime_command("tls-interrupted", false));
        command["agent_id"] = identity.agent_id; command["host_id"] = identity.host_id;
        runtime.inbox.receive_command(runtime.inbox_scope, "tls-interrupted", command.dump());
        require_runtime(runtime.inbox.begin_command(runtime.inbox_scope, "tls-interrupted"), "owned intent commits");
        process_durable_commands(runtime);
        runtime.outcomes.flush([&](const std::string& payload) {
            original_result = payload;
            return runtime.client.submit_command_result(runtime.manager_url, runtime.identity, payload);
        });
        require_runtime(!original_result.empty() && runtime.outcomes.pending() == 1,
            "untrusted TLS cannot acknowledge or delete the durable outcome");
        std::string poll_error;
        require_runtime(!runtime.client.poll_commands(runtime.manager_url, runtime.identity, poll_error) &&
            poll_error.find("Windows error 12175") != std::string::npos,
            "native HTTPS refuses the fixture certificate with ERROR_WINHTTP_SECURE_FAILURE");
        run_response_cycle(runtime);
        require_runtime(runtime.poll_failures.load() == 1 && runtime.poll_state.load() == 2,
            "untrusted TLS poll fails visibly");
        require_runtime(runtime.outcomes.pending() == 1, "failed TLS retry preserves pending outcome");
    }
    {
        response::ReplayLedger ledger{root / "legacy-ledger", 4096};
        std::string error; require_runtime(ledger.load(error), "owned legacy guard reopens");
        ResponseRuntime runtime{identity, std::move(ledger), config, manager_url, context,
            [](const std::string&) { throw std::runtime_error("unexpected repeated OS action"); }, root / "scope", root / "missing-artifact-signing-key"};
        process_durable_commands(runtime);
        bool exact = false;
        runtime.outcomes.flush([&](const std::string& payload) {
            exact = payload == original_result;
            return runtime.client.submit_command_result(runtime.manager_url, runtime.identity, payload);
        });
        require_runtime(exact && runtime.outcomes.pending() == 1,
            "exact outcome survives reopen and repeated TLS refusal");
        require_runtime(runtime.inbox.pending_commands(runtime.inbox_scope, 10).empty(),
            "completed inbox handoff is not repeated");
    }
    std::cout << "{\"pending_results\":1,\"exact_result_recovered\":true,\"untrusted_tls_refused\":true,\"poll_failure_visible\":true}\n";
    return 0;
}
int main(int argc, char* argv[]) {
    if (argc == 5 && std::string_view(argv[1]) == "--verify-untrusted-https") {
        try { return verify_untrusted_https(argv[2], argv[3], argv[4]); }
        catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    }
    if (argc != 1) return 2;
    const auto root = std::filesystem::temp_directory_path() / ("officer-runtime-inbox-" +
        std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    try {
        response::EnrolledIdentity identity{"agent-runtime", "host-runtime", "owned-unused-test-token"};
        pipeline::NormalizationContext context{};
        response::ResponseConfig config{};
        unsigned collection_case = 0;
        for (const auto* action : {"COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS", "COLLECT_FILE"}) {
            for (const auto status : {response::TransportOutcome::rejected, response::TransportOutcome::retryable,
                                      response::TransportOutcome::authentication_failed}) {
                const auto scope = root / ("collection-gate-" + std::to_string(collection_case++));
                response::ReplayLedger ledger{scope / "legacy", 4096};
                std::string ledger_error;
                require_runtime(ledger.load(ledger_error), "owned collection replay ledger loads");
                auto enabled = config; enabled.enabled = true;
                unsigned emitted = 0, accepts = 0;
                ResponseRuntime runtime{identity, std::move(ledger), enabled, "https://unused.invalid", context,
                    [&](const std::string&) { ++emitted; }, scope / "scope", scope / "missing-key"};
                const auto initial_artifact_failures = runtime.artifact_failures.load();
                runtime.acceptance_transport = [&](const std::string&) { ++accepts; return status; };
                auto value = nlohmann::json::parse(runtime_command("collect-refused", false));
                value["action"] = action;
                if (std::string_view{action} == "COLLECT_NETWORK_CONNECTIONS") {
                    value["schema_version"] = "1"; value["target"] = nlohmann::json::object();
                } else if (std::string_view{action} == "COLLECT_FILE") {
                    value["schema_version"] = "1"; value["target"] = {{"path", "C:\\PanopticonLab\\sample.txt"}};
                }
                runtime.inbox.receive_command(runtime.inbox_scope, "collect-refused", value.dump());
                process_durable_commands(runtime);
                bool refused_before_execution = false;
                std::string observed_result;
                runtime.outcomes.flush([&](const std::string& payload) {
                    observed_result = payload;
                    const auto result = nlohmann::json::parse(payload);
                    refused_before_execution = result["outcome"] == "failed" &&
                        result["detail"].get<std::string>().find("Manager acceptance") != std::string::npos;
                    return response::TransportOutcome::acknowledged;
                });
                if (!refused_before_execution || accepts != 1 || emitted != 0 ||
                    runtime.artifact_failures != initial_artifact_failures)
                    std::cerr << "collection gate case " << action << " accepts=" << accepts << " emitted=" << emitted
                        << " artifact_failures=" << runtime.artifact_failures.load() << " result=" << observed_result << '\n';
                require_runtime(refused_before_execution && accepts == 1 && emitted == 0 &&
                    runtime.artifact_failures == initial_artifact_failures && runtime.pending_artifacts == 0,
                    "Manager refusal/timeout prevents every collection before collector/evidence execution");
                runtime.inbox.receive_command(runtime.inbox_scope, "collect-refused", value.dump());
                process_durable_commands(runtime);
                require_runtime(accepts == 1 && emitted == 0 && runtime.outcomes.pending() == 0,
                    "a refused collection cannot execute or re-authorize on replay");
            }
        }
        {
            response::ReplayLedger ledger{root / "legacy-ledger", 4096};
            std::string error;
            require_runtime(ledger.load(error), "empty legacy ledger loads");
            ResponseRuntime runtime{identity, std::move(ledger), config, "https://unused.invalid", context,
                [](const std::string&) { throw std::runtime_error("unexpected OS action evidence"); }, root / "scope", root / "missing-artifact-signing-key"};
            const auto expired_dispatch = response::parse_command_json(runtime_command("dispatch-expiry", true), error);
            require_runtime(expired_dispatch.has_value(), "dispatch expiry fixture decodes");
            auto evidence_receipt = response::CommandReceipt{"missing-key", "corr-runtime",
                response::ReceiptCode::succeeded, "collection fixture"};
            require_runtime(!retain_collection_artifact(runtime, *expired_dispatch, "process_snapshot",
                "{}", evidence_receipt) && evidence_receipt.code == response::ReceiptCode::indeterminate,
                "missing enrolled key refuses signed evidence commit");
            require_runtime(!std::filesystem::exists(root / "missing-artifact-signing-key"),
                "missing enrolled key is never silently regenerated");
            const auto expired_receipt = execute_command(runtime, *expired_dispatch,
                {"dispatch-expiry", "corr-runtime", response::ReceiptCode::succeeded, "previous gate accepted"});
            require_runtime(expired_receipt.code == response::ReceiptCode::expired,
                "prior acceptance cannot authorize an OS action after command expiry");
            runtime.inbox.receive_command(runtime.inbox_scope, "expired", runtime_command("expired", true));
            runtime.inbox.receive_command(runtime.inbox_scope, "interrupted", runtime_command("interrupted", false));
            require_runtime(runtime.inbox.begin_command(runtime.inbox_scope, "interrupted"), "interrupt fixture commits intent");
        }
        {
            response::ReplayLedger ledger{root / "legacy-ledger", 4096};
            std::string error; require_runtime(ledger.load(error), "legacy ledger reopens");
            ResponseRuntime runtime{identity, std::move(ledger), config, "https://unused.invalid", context,
                [](const std::string&) { throw std::runtime_error("unexpected repeated OS action"); }, root / "scope", root / "missing-artifact-signing-key"};
            bool refused = false;
            try {
                response::ReplayLedger other{root / "other-legacy", 4096};
                ResponseRuntime duplicate{identity, std::move(other), config, "https://unused.invalid", context,
                    [](const std::string&) {}, root / "scope", root / "missing-artifact-signing-key"};
            } catch (const std::exception&) { refused = true; }
            require_runtime(refused, "live response scope owner prevents a second worker");
            process_durable_commands(runtime);
            require_runtime(runtime.inbox.pending_commands(runtime.inbox_scope, 10).empty(), "production worker hands off both durable outcomes");
            require_runtime(runtime.outcomes.pending() == 2, "both outcomes survive in encrypted outbox");
            bool expired = false, interrupted = false;
            runtime.outcomes.flush([&](const std::string& payload) {
                const auto value = nlohmann::json::parse(payload);
                expired |= value["command_id"] == "expired" && value["outcome"] == "rejected";
                interrupted |= value["command_id"] == "interrupted" && value["outcome"] == "indeterminate";
                return response::TransportOutcome::acknowledged;
            });
            require_runtime(expired && interrupted, "queued expiry differs from interrupted execution and no action repeats");
            runtime.inbox.receive_command(runtime.inbox_scope, "interrupted", runtime_command("interrupted", false));
            process_durable_commands(runtime);
            require_runtime(runtime.outcomes.pending() == 0, "duplicate delivery cannot recreate a terminal outcome or action");
        }
        if (std::filesystem::equivalent(root.parent_path(), std::filesystem::temp_directory_path()) &&
            root.filename().string().starts_with("officer-runtime-inbox-")) std::filesystem::remove_all(root);
        std::cout << "production inbox recovery, expiry, owner lock and duplicate suppression passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

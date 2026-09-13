#include "panopticon/officer/response/command.hpp"
#include "panopticon/officer/response/file_evidence.hpp"
#include "panopticon/officer/response/isolation.hpp"
#include "panopticon/officer/response/replay_ledger.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

namespace {

namespace response = panopticon::officer::response;

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

std::string valid_command_json(const std::string& command_id, const std::string& action,
                                const std::string& target_json, const std::string& expires_at = "2999-01-01T00:00:00Z") {
    return "{"
           "\"command_id\":\"" + command_id + "\","
           "\"agent_id\":\"agent-1\","
           "\"host_id\":\"host-1\","
           "\"schema_version\":\"1\","
           "\"action\":\"" + action + "\","
           "\"expires_at\":\"" + expires_at + "\","
           "\"created_at\":\"2020-01-01T00:00:00Z\","
           "\"correlation_id\":\"corr-1\","
           "\"target\":" + target_json +
           "}";
}

void test_parse_kill_process_command_round_trip() {
    std::string error;
    const auto command =
        response::parse_command_json(valid_command_json("cmd-1", "KILL_PROCESS", R"({"pid":4242,"start_time_ticks":123456789})"), error);
    expect(command.has_value(), "a well-formed KILL_PROCESS command parses");
    if (!command) return;
    expect(command->action == response::ActionType::kill_process, "action decodes to kill_process");
    expect(command->process_target.pid == 4242, "pid decodes correctly");
    expect(command->process_target.start_time_ticks == 123456789ULL, "start_time_ticks decodes correctly");
    expect(command->process_target.host_id == "host-1", "process target inherits host_id");
}

void test_parse_collect_file_command_round_trip() {
    std::string error;
    const auto command =
        response::parse_command_json(valid_command_json("cmd-2", "COLLECT_FILE", R"({"path":"evidence/sample.bin"})"), error);
    expect(command.has_value(), "a well-formed COLLECT_FILE command parses");
    if (command) expect(command->file_target_path == "evidence/sample.bin", "file target path decodes correctly");
}

void test_rejects_unknown_action() {
    std::string error;
    const auto command = response::parse_command_json(valid_command_json("cmd-3", "DELETE_EVERYTHING", "{}"), error);
    expect(!command.has_value(), "an unknown action is rejected, not silently ignored");
}

void test_rejects_unexpected_top_level_field() {
    std::string error;
    std::string payload = valid_command_json("cmd-4", "ISOLATE_HOST", "{}");
    payload.insert(payload.size() - 1, R"(,"shell":"rm -rf /")");
    const auto command = response::parse_command_json(payload, error);
    expect(!command.has_value(), "an unexpected top-level field (e.g. a smuggled shell command) is rejected");
}

void test_rejects_process_target_missing_start_time() {
    std::string error;
    const auto command =
        response::parse_command_json(valid_command_json("cmd-5", "KILL_PROCESS", R"({"pid":4242})"), error);
    expect(!command.has_value(), "a process target missing start_time_ticks is rejected");
}

void test_rejects_wrong_target_shape_for_action() {
    std::string error;
    // ISOLATE_HOST must carry no target at all.
    const auto command =
        response::parse_command_json(valid_command_json("cmd-6", "ISOLATE_HOST", R"({"pid":1,"start_time_ticks":1})"), error);
    expect(!command.has_value(), "a target on an action that accepts none is rejected");
}

void test_rejects_non_utc_timestamp() {
    std::string error;
    const auto command = response::parse_command_json(
        valid_command_json("cmd-7", "ISOLATE_HOST", "{}", "2999-01-01T00:00:00+05:00"), error);
    expect(!command.has_value(), "a non-UTC offset timestamp is rejected");
}

void test_rejects_malformed_json() {
    std::string error;
    const auto command = response::parse_command_json("{not json", error);
    expect(!command.has_value(), "malformed JSON is rejected");
    const auto empty = response::parse_command_json("", error);
    expect(!empty.has_value(), "empty payload is rejected");
}

void test_rejects_oversized_payload() {
    std::string error;
    std::string huge = valid_command_json("cmd-8", "ISOLATE_HOST", "{}");
    huge.insert(huge.size() - 1, std::string(9000, ' '));
    const auto command = response::parse_command_json(huge, error);
    expect(!command.has_value(), "an oversized payload is rejected");
}

void test_serialize_command_result_round_trip() {
    std::string error;
    response::CommandReceipt receipt{"cmd-1", "corr-1", response::ReceiptCode::succeeded, "ok"};
    const auto serialized = response::serialize_command_result(receipt, 4096, error);
    expect(serialized.has_value(), "a valid receipt serializes");
    if (serialized) {
        expect(serialized->find("\"outcome\":\"succeeded\"") != std::string::npos, "outcome field is present");
        expect(serialized->find("\"command_id\":\"cmd-1\"") != std::string::npos, "command_id field is present");
    }
}

response::Command make_command(const std::string& id, response::ActionType action, std::int64_t expires_at) {
    response::Command command;
    command.command_id = id;
    command.agent_id = "agent-1";
    command.host_id = "host-1";
    command.schema_version = "1";
    command.correlation_id = "corr-" + id;
    command.action = action;
    command.expires_at_epoch_seconds = expires_at;
    command.process_target = {"host-1", 4242, 123456789ULL};
    return command;
}

void test_gate_accepts_once_then_replay_detected() {
    response::CommandGate gate{"agent-1", "host-1", [] { return 1000; }};
    const auto command = make_command("dup-1", response::ActionType::collect_network_connections, 2000);
    const auto first = gate.validate_and_mark(command);
    expect(first.code == response::ReceiptCode::succeeded, "first submission of a fresh command_id succeeds");
    const auto second = gate.validate_and_mark(command);
    expect(second.code == response::ReceiptCode::replay_detected, "a second submission of the same command_id is replay-detected");
}

void test_gate_rejects_expired_command() {
    response::CommandGate gate{"agent-1", "host-1", [] { return 5000; }};
    const auto command = make_command("expired-1", response::ActionType::collect_network_connections, 4000);
    const auto receipt = gate.validate_and_mark(command);
    expect(receipt.code == response::ReceiptCode::expired, "a command whose expiry is in the past is rejected as expired");
}

void test_gate_rejects_kill_process_targeting_protected_pid() {
    response::CommandGate gate{"agent-1", "host-1", [] { return 1000; }};
    auto command = make_command("kill-protected", response::ActionType::kill_process, 2000);
    command.process_target.pid = 4;  // System process.
    const auto receipt = gate.validate_and_mark(command);
    expect(receipt.code == response::ReceiptCode::target_protected, "KILL_PROCESS targeting PID 4 (System) is refused by the gate");
}

void test_gate_rejects_wrong_agent_or_host() {
    response::CommandGate gate{"agent-1", "host-1", [] { return 1000; }};
    auto command = make_command("wrong-agent", response::ActionType::collect_network_connections, 2000);
    command.agent_id = "some-other-agent";
    const auto receipt = gate.validate_and_mark(command);
    expect(receipt.code == response::ReceiptCode::invalid_command, "a command addressed to a different agent_id is rejected");
}

void test_gate_with_durable_ledger_survives_restart() {
    const auto ledger_path = std::filesystem::temp_directory_path() / "officer-response-tests-ledger.txt";
    std::filesystem::remove(ledger_path);
    {
        response::ReplayLedger ledger{ledger_path, 16};
        std::string ledger_error;
        expect(ledger.load(ledger_error), "a fresh (nonexistent) ledger loads cleanly");
        response::CommandGate gate{"agent-1", "host-1", [] { return 1000; }, &ledger};
        const auto command = make_command("durable-1", response::ActionType::collect_network_connections, 2000);
        const auto receipt = gate.validate_and_mark(command);
        expect(receipt.code == response::ReceiptCode::succeeded, "first acceptance with a durable ledger succeeds");
    }
    {
        // Simulate a process restart: a brand-new in-memory CommandGate, but
        // the same durable ledger file on disk.
        response::ReplayLedger ledger{ledger_path, 16};
        std::string ledger_error;
        (void)ledger.load(ledger_error);
        response::CommandGate gate{"agent-1", "host-1", [] { return 1000; }, &ledger};
        const auto command = make_command("durable-1", response::ActionType::collect_network_connections, 2000);
        const auto receipt = gate.validate_and_mark(command);
        expect(receipt.code == response::ReceiptCode::replay_detected,
               "after a simulated restart, the durable ledger still remembers a previously accepted command_id");
    }
    std::filesystem::remove(ledger_path);
}

void test_is_protected_process() {
    expect(response::is_protected_process(0, ""), "PID 0 is protected");
    expect(response::is_protected_process(4, ""), "PID 4 (System) is protected");
    expect(response::is_protected_process(9999, "lsass.exe"), "lsass.exe is protected regardless of PID");
    expect(response::is_protected_process(9999, R"(C:\Windows\System32\csrss.exe)"),
           "csrss.exe is protected when named by full path");
    expect(!response::is_protected_process(9999, "notepad.exe"), "an ordinary process is not protected");
}

void test_isolation_plan_is_deterministic_and_pure() {
    response::IsolationExceptionEndpoint endpoint{"10.0.0.5", 8443};
    const auto plan_a = response::build_isolation_plan(endpoint);
    const auto plan_b = response::build_isolation_plan(endpoint);
    expect(plan_a.sublayer_name == plan_b.sublayer_name, "isolation plan sublayer naming is deterministic");
    expect(plan_a.block_outbound_filter_name == plan_b.block_outbound_filter_name,
           "isolation plan filter naming is deterministic");
    expect(plan_a.manager_exception.manager_host == "10.0.0.5", "the manager exception endpoint is carried through unchanged");
    expect(plan_a.manager_exception.manager_port == 8443, "the manager exception port is carried through unchanged");
}

void test_file_evidence_rejects_path_traversal() {
    const auto root = std::filesystem::temp_directory_path() / "officer-response-tests-root";
    std::filesystem::create_directories(root);
    std::string error;
    const auto escaped = response::resolve_within_allowed_root(root, "..\\..\\Windows\\System32\\config\\SAM", error);
    expect(!escaped.has_value(), "a '..'-based traversal attempt is rejected");
    const auto absolute = response::resolve_within_allowed_root(root, "C:\\Windows\\System32\\drivers\\etc\\hosts", error);
    expect(!absolute.has_value(), "an absolute path target is rejected outright");
}

// Proves this agent's parse_command_json is compatible with
// Panopticon-Co/panopticon-contracts' golden fixtures, checked out as a
// workspace sibling in CI (see .github/workflows/ci.yml) -- the same
// convention panopticon-manager already uses for its own cross-repo schema
// contract test. Unlike response_engine.contract.Command (Python), this
// parser decodes the FULL wire envelope including host_id/schema_version/
// created_at, so fixtures are passed through unmodified rather than
// stripped. Skips gracefully (does not fail) if the sibling checkout is
// absent, e.g. a local dev build without panopticon-contracts cloned.
void test_parses_every_valid_canonical_fixture_and_rejects_the_intended_invalid_ones() {
#ifdef PANOPTICON_CONTRACTS_DIR
    const std::filesystem::path contracts_dir{PANOPTICON_CONTRACTS_DIR};
    const auto valid_path = contracts_dir / "fixtures" / "commands" / "valid.json";
    const auto invalid_path = contracts_dir / "fixtures" / "commands" / "invalid.json";
    if (!std::filesystem::exists(valid_path) || !std::filesystem::exists(invalid_path)) {
        std::cout << "SKIP: panopticon-contracts sibling checkout not found at " << contracts_dir << '\n';
        return;
    }

    std::ifstream valid_stream{valid_path};
    nlohmann::json valid_fixtures;
    valid_stream >> valid_fixtures;
    for (const auto& [action, entry] : valid_fixtures.items()) {
        if (action.starts_with('$')) continue;
        std::string error;
        const auto command = response::parse_command_json(entry.at("command").dump(), error);
        expect(command.has_value(), ("valid fixture for " + action + " must parse: " + error).c_str());
    }

    // These invalid.json entries are genuine parse/decode-level rejections.
    // expired_command is intentionally excluded: parse_command_json only
    // checks created_at < expires_at ordering, not wall-clock "now" -- that
    // is CommandGate::validate_and_mark's job, already covered by
    // test_gate_rejects_expired_command above. replay_detected_scenario,
    // cross_agent_mismatch, and correlation_mismatch describe multi-step or
    // transport-level scenarios a single parse call cannot exercise.
    static constexpr std::array<std::string_view, 8> parse_level_invalid_fixtures{
        "malformed_command",     "missing_required_field", "unknown_action",
        "invalid_target_types",  "wrong_target_shape",     "smuggled_shell_field",
        "oversized_correlation_id", "non_utc_timestamp"};

    std::ifstream invalid_stream{invalid_path};
    nlohmann::json invalid_fixtures;
    invalid_stream >> invalid_fixtures;
    for (const auto& name : parse_level_invalid_fixtures) {
        const auto& entry = invalid_fixtures.at(std::string{name});
        const std::string payload = entry.contains("raw") ? entry.at("raw").get<std::string>()
                                                            : entry.at("command").dump();
        std::string error;
        const auto command = response::parse_command_json(payload, error);
        expect(!command.has_value(), ("invalid fixture " + std::string{name} + " must be rejected").c_str());
    }
#else
    std::cout << "SKIP: PANOPTICON_CONTRACTS_DIR not defined by the build\n";
#endif
}

void test_file_evidence_collects_hash_for_allowed_file() {
    const auto root = std::filesystem::temp_directory_path() / "officer-response-tests-root";
    std::filesystem::create_directories(root);
    const auto sample = root / "sample.txt";
    {
        std::ofstream output{sample, std::ios::trunc};
        output << "panopticon-response-test-fixture";
    }
    std::string error;
    const auto evidence = response::collect_file_evidence(root, "sample.txt", 65536, error);
    expect(evidence.has_value(), "a file within the allow-listed root is collected");
    if (evidence) {
        expect(evidence->find("\"sha256\":\"") != std::string::npos, "collected evidence includes a sha256 field");
        expect(evidence->find("panopticon-response-test-fixture") == std::string::npos,
               "collected evidence never includes the raw file content");
    }
    std::filesystem::remove(sample);
}

}  // namespace

int main() {
    test_parse_kill_process_command_round_trip();
    test_parse_collect_file_command_round_trip();
    test_rejects_unknown_action();
    test_rejects_unexpected_top_level_field();
    test_rejects_process_target_missing_start_time();
    test_rejects_wrong_target_shape_for_action();
    test_rejects_non_utc_timestamp();
    test_rejects_malformed_json();
    test_rejects_oversized_payload();
    test_serialize_command_result_round_trip();
    test_gate_accepts_once_then_replay_detected();
    test_gate_rejects_expired_command();
    test_gate_rejects_kill_process_targeting_protected_pid();
    test_gate_rejects_wrong_agent_or_host();
    test_gate_with_durable_ledger_survives_restart();
    test_is_protected_process();
    test_isolation_plan_is_deterministic_and_pure();
    test_file_evidence_rejects_path_traversal();
    test_file_evidence_collects_hash_for_allowed_file();
    test_parses_every_valid_canonical_fixture_and_rejects_the_intended_invalid_ones();

    if (failures == 0) {
        std::cout << "All Officer response tests passed.\n";
        return 0;
    }
    std::cerr << failures << " Officer response test(s) failed.\n";
    return 1;
}

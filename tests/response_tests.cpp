#include "panopticon/officer/response/artifact_outbox.hpp"
#include <chrono>
#include "panopticon/officer/response/profile.hpp"
#include "panopticon/officer/response/command.hpp"
#include "panopticon/officer/response/file_evidence.hpp"
#include "panopticon/officer/response/isolation.hpp"
#include "panopticon/officer/response/replay_ledger.hpp"
#include "panopticon/officer/response/result_outbox.hpp"

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

void test_current_response_profile() {
    response::ResponseConfig config;
    auto profile = nlohmann::json::parse(response::response_profile_json(config, "host-1", std::nullopt));
    expect(profile["schema_version"] == "2", "artifact capability uses versioned profile");
    expect(profile["artifact_protocol"] == "signed-json-v2-resume-v1", "signed durable artifact delivery is explicit");
    expect(profile["require_collection_acceptance"] == true, "collection requires current Manager acceptance");
    expect(response::response_profile_json(config, "host-1", std::nullopt) ==
        response::response_profile_json(config, "host-1", std::nullopt), "unchanged reports are repeatable");
    expect(profile["mode"] == "off" && profile["allowed_actions"].empty(), "disabled policy reports no allowed actions");
    expect(profile["boot_id"].is_null(), "unavailable boot is explicit");
    config.enabled = true;
    profile = nlohmann::json::parse(response::response_profile_json(config, "host-1", "boot_" + std::string(64, 'a')));
    expect(profile["mode"] == "enforce", "Windows loaded runtime enforces policy");
    expect(profile["implemented_actions"].size() == 7U, "closed native implementation vocabulary");
    expect(profile["allowed_actions"].size() == 4U, "unconfigured file and isolation actions are excluded");
    expect(profile["require_signature"] == false, "Windows does not claim signature verification");
    expect(profile["require_boot_binding"] == true, "Windows process actions require native boot binding");
    config.file_collection_root = "C:/lab";
    config.quarantine_root = "C:/quarantine";
    config.manager_exception_host = "127.0.0.1";
    config.manager_exception_port = 443;
    profile = nlohmann::json::parse(response::response_profile_json(config, "host-1", std::nullopt));
    expect(profile["allowed_actions"].size() == 7U, "configured native policy reports all seven actions");
    expect(profile["artifact_protocol"] == "signed-json-v2-resume-v1", "capability reporting is stable across policy modes");
}

void test_collection_acceptance_ack() {
    expect(response::valid_collection_accept_ack("c1", R"({"command_id":"c1","accepted":true})"), "exact acceptance permits collection");
    for (const auto* body : {"{}", R"({"command_id":"wrong","accepted":true})",
         R"({"command_id":"c1","accepted":1})", R"({"command_id":"c1","accepted":false})",
         R"({"command_id":"c1","accepted":true,"extra":1})",
         R"({"command_id":"c1","accepted":false,"accepted":true})"})
        expect(!response::valid_collection_accept_ack("c1", body), "wrong, ambiguous or malformed acceptance refuses collection");
    expect(!response::valid_collection_accept_ack("c1", std::string(4097, 'x')), "acceptance body is bounded");
}

void test_artifact_outbox_and_exact_receipts() {
    const std::string data = "{ \"pid\": 42 }\n";
    const auto payload = response::make_artifact_payload("command-1", "correlation-1", "host-1", "process_snapshot", data);
    const auto value = nlohmann::json::parse(payload);
    expect(value["content_bytes"] == data.size() && value["media_type"] == "application/json", "artifact preserves exact content byte count");
    expect(response::make_artifact_payload("command-1", "correlation-1", "host-1", "process_snapshot", data) == payload,
        "artifact identity and bytes stay stable on retry");
    const auto ack = nlohmann::json{{"artifact_id", value["artifact_id"]}, {"sha256", value["sha256"]}, {"retained", true}}.dump();
    expect(response::valid_artifact_ack(payload, ack), "exact identity/digest receipt accepted");
    expect(!response::valid_artifact_ack(payload, "{}"), "HTTP200 alone does not retire artifacts");
    auto wrong = nlohmann::json::parse(ack); wrong["sha256"] = std::string(64, '0');
    expect(!response::valid_artifact_ack(payload, wrong.dump()), "wrong digest rejected");
    wrong = nlohmann::json::parse(ack); wrong["artifact_id"] = "another";
    expect(!response::valid_artifact_ack(payload, wrong.dump()), "wrong artifact rejected");
    wrong = nlohmann::json::parse(ack); wrong["retained"] = 1;
    expect(!response::valid_artifact_ack(payload, wrong.dump()), "boolean receipt stays strict");
    expect(!response::valid_artifact_ack(payload, ack.substr(0, ack.size() - 1) + ",\"retained\":true}"), "duplicate receipt keys rejected");
    const auto temp = std::filesystem::temp_directory_path();
    const auto path = temp / ("officer-artifacts-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    expect(std::filesystem::create_directory(path), "unique owned artifact fixture");
    {
        response::ArtifactOutbox outbox{path, "agent-1", "host-1"};
        outbox.save(payload);
        const auto retired = outbox.flush([](const std::string&) -> std::optional<std::string> { return "{}"; });
        expect(!retired && outbox.pending() == 1, "wrong acknowledgement retains encrypted evidence");
    }
    {
        response::ArtifactOutbox wrong_scope{path, "other-agent", "host-1"};
        bool refused = false;
        try { (void)wrong_scope.flush([&](const std::string&) -> std::optional<std::string> { return ack; }); }
        catch (const std::exception&) { refused = true; }
        expect(refused && wrong_scope.pending() == 1, "identity change cannot deliver original evidence");
    }
    {
        response::ArtifactOutbox reopened{path, "agent-1", "host-1"};
        expect(reopened.pending() == 1, "artifact survives restart");
        const auto retired = reopened.flush([&](const std::string& replay) -> std::optional<std::string> {
            expect(replay == payload, "restart uploads identical artifact envelope"); return ack;
        });
        expect(retired == 1 && reopened.pending() == 0, "exact retained receipt retires one artifact");
    }
    const bool owned = std::filesystem::equivalent(path.parent_path(), temp) && path.filename().string().starts_with("officer-artifacts-");
    expect(owned, "artifact cleanup stays in owned temporary directory");
    if (owned) std::filesystem::remove_all(path);
}

void test_signed_artifact_manifest() {
    std::string error;
    const auto key = response::generate_ec_p256_keypair(error);
    expect(key.has_value(), "artifact signing uses endpoint P-256 key");
    if (!key) return;
    const auto unsigned_payload = response::make_artifact_payload("command-1", "correlation-1", "host-1",
        "process_snapshot", "{\"pid\":42}");
    const auto payload = response::sign_artifact_payload(unsigned_payload, "agent-1", *key, 1793232000U);
    const auto value = nlohmann::json::parse(payload);
    const auto manifest = value.at("manifest");
    expect(manifest.at("schema_version") == "2" && manifest.at("agent_id") == "agent-1", "signed identity version");
    expect(manifest.at("authorization").at("signature").get<std::string>().size() == 88, "raw P-256 signature encoding");
    const auto input = response::artifact_manifest_signing_input(manifest.dump());
    expect(input.starts_with("panopticon-response-artifact-auth/2\n"), "artifact domain separated from commands");
    auto changed = manifest;
    changed["host_id"] = "another-host";
    expect(response::artifact_manifest_signing_input(changed.dump()) != input, "endpoint binding is signed");
    const auto ack = nlohmann::json{{"artifact_id", manifest.at("artifact_id")},
        {"sha256", manifest.at("sha256")}, {"retained", true}}.dump();
    expect(response::valid_artifact_ack(payload, ack), "signed envelope exact receipt");
    const auto temp = std::filesystem::temp_directory_path();
    const auto path = temp / ("officer-signed-artifacts-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    { response::ArtifactOutbox box{path, "agent-1", "host-1"}; box.save(payload); }
    { response::ArtifactOutbox box{path, "agent-1", "host-1"};
      expect(box.flush([&](const std::string& retry) -> std::optional<std::string> {
          expect(retry == payload, "restart retains exact signature/time/content without re-signing"); return ack;
      }) == 1, "signed evidence retired only after exact receipt"); }
    if (std::filesystem::equivalent(path.parent_path(), temp) && path.filename().string().starts_with("officer-signed-artifacts-"))
        std::filesystem::remove_all(path);
}

void test_resumable_artifact_outbox() {
    std::string error;
    const auto key = response::generate_ec_p256_keypair(error);
    expect(key.has_value(), "resumable artifact key"); if (!key) return;
    const auto data = std::string{"{\"evidence\":\""} + std::string(400000, 'x') + "\"}";
    const auto payload = response::sign_artifact_payload(response::make_artifact_payload(
        "command-1", "correlation-1", "host-1", "process_snapshot", data), "agent-1", *key, 1793232000U);
    const auto manifest = nlohmann::json::parse(payload).at("manifest");
    const auto id = manifest.at("artifact_id").get<std::string>(), sha = manifest.at("sha256").get<std::string>();
    const std::string manifest_sha(64, 'b');
    std::string received;
    bool lose_chunk = true, lose_final = true, retained = false;
    unsigned requests = 0, uploads = 0, completions = 0;
    const auto progress = [&] {
        return nlohmann::json{{"schema_version", "1"}, {"artifact_id", id}, {"sha256", sha},
            {"manifest_sha256", manifest_sha}, {"received_bytes", received.size()}, {"chunk_bytes", 65536U},
            {"complete", retained}, {"expires_at", retained ? nlohmann::json(nullptr) : nlohmann::json("2026-10-30T00:00:00Z")}}.dump();
    };
    const response::ArtifactExchange server = [&](const std::string& method, const std::string& suffix,
            const std::string& type, const std::string& body, const std::string& digest) -> std::optional<std::string> {
        ++requests;
        if (suffix.empty()) {
            expect(method == "POST" && type == "application/json", "manifest admission framing");
            expect(nlohmann::json::parse(body).at("manifest") == manifest, "resume never resigns or recollects manifest");
            return progress();
        }
        if (method == "PUT") {
            ++uploads;
            const auto offset = std::stoull(suffix.substr(suffix.find_last_of('/') + 1));
            expect(offset == received.size() && body == data.substr(received.size(), 65536), "resume sends only next exact original chunk");
            expect(type == "application/octet-stream" && digest.size() == 64, "chunk framing has explicit digest");
            received += body;
            if (lose_chunk) { lose_chunk = false; return std::nullopt; }
            return progress();
        }
        ++completions;
        expect(received == data, "retention requires complete original bytes");
        expect(nlohmann::json::parse(body).at("manifest_sha256") == manifest_sha, "completion bound to admitted manifest");
        retained = true;
        if (lose_final) { lose_final = false; return std::nullopt; }
        return nlohmann::json{{"artifact_id", id}, {"sha256", sha}, {"retained", true}}.dump();
    };
    const auto temp = std::filesystem::temp_directory_path();
    const auto path = temp / ("officer-resumable-artifacts-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    {
        response::ArtifactOutbox box{path, "agent-1", "host-1"}; box.save(payload);
        expect(box.flush([&](const std::string& original) { return response::resume_artifact_upload(original, server); }) == 0,
            "lost chunk ACK cannot retire artifact");
        expect(box.pending() == 1 && received.size() == 65536, "durable original survives interrupted upload");
    }
    {
        response::ArtifactOutbox box{path, "agent-1", "host-1"};
        for (unsigned attempt = 0; attempt < 5 && box.pending(); ++attempt) {
            requests = 0; bool made_progress = false;
            box.flush([&](const std::string& original) {
                expect(original == payload, "restart retains exact signed outbox original");
                return response::resume_artifact_upload(original, server, &made_progress);
            });
            expect(requests <= 6, "one transfer step bounds network work");
        }
        expect(box.pending() == 0 && completions == 2 && uploads == 7, "lost final receipt retries without duplicate data or early retirement");
    }
    const auto invalid = nlohmann::json{{"schema_version", "1"}, {"artifact_id", id}, {"sha256", sha},
        {"manifest_sha256", manifest_sha}, {"received_bytes", true}, {"chunk_bytes", 65536U},
        {"complete", false}, {"expires_at", "2026-10-30T00:00:00Z"}}.dump();
    expect(!response::resume_artifact_upload(payload, [&](const auto&, const auto&, const auto&, const auto&, const auto&)
        -> std::optional<std::string> { return invalid; }), "ambiguous progress integer refuses transfer");
    if (std::filesystem::equivalent(path.parent_path(), temp) && path.filename().string().starts_with("officer-resumable-artifacts-"))
        std::filesystem::remove_all(path);
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

void test_boot_bound_process_command_v2() {
    std::string error;
    auto payload = nlohmann::json::parse(valid_command_json("cmd-v2", "KILL_PROCESS", "{}"));
    payload["schema_version"] = "2";
    const std::string boot = "boot_" + std::string(64, 'a');
    payload["target"] = {{"pid", 4242}, {"start_time_ticks", "18446744073709551615"}, {"boot_id", boot}};
    auto command = response::parse_command_json(payload.dump(), error);
    expect(command && command->schema_version == "2" && command->process_target.boot_id == boot &&
           command->process_target.start_time_ticks == UINT64_MAX, "schema-2 preserves exact full uint64 token and boot scope");
    payload["created_at"] = "2999-01-01T00:00:00.000001+00:00";
    payload["expires_at"] = "2999-01-01T00:00:00.000002Z";
    expect(response::parse_command_json(payload.dump(), error).has_value(), "fractional UTC order is exact within one second");
    payload["created_at"] = "2999-01-01T00:00:00.000003Z";
    expect(!response::parse_command_json(payload.dump(), error), "reverse fractional ordering is rejected");
    for (const auto* invalid : {"2999-01-01T00:00:00.Z", "2999-01-01T00:00:00.1234567890Z", "2999-01-01T00:00:00.xZ"}) {
        payload["created_at"] = invalid;
        expect(!response::parse_command_json(payload.dump(), error), "invalid or excessive UTC fractions are rejected");
    }
    payload["created_at"] = "2020-01-01T00:00:00.123456+00:00";
    response::CommandGate gate{"agent-1", "host-1", [] { return 0; }};
    if (command) expect(gate.validate_and_mark(*command).code == response::ReceiptCode::succeeded, "schema-2 retains authenticated host/agent gate");
    for (const auto* invalid : {"0", "01", "+1", "-1", "1.0", "18446744073709551616", " 1"}) {
        payload["target"]["start_time_ticks"] = invalid;
        expect(!response::parse_command_json(payload.dump(), error), "schema-2 rejects noncanonical or overflowing uint64");
    }
    payload["target"]["start_time_ticks"] = 123;
    expect(!response::parse_command_json(payload.dump(), error), "schema-2 rejects numeric creation tokens");
    payload["target"]["start_time_ticks"] = "123";
    payload["target"].erase("boot_id");
    expect(!response::parse_command_json(payload.dump(), error), "schema-2 requires explicit boot scope");
    payload["target"]["boot_id"] = "boot_other";
    expect(!response::parse_command_json(payload.dump(), error), "schema-2 requires canonical Windows boot digest");
}

void test_rejects_ambiguous_command_and_poll_json() {
    std::string error;
    auto command = valid_command_json("cmd-duplicate", "KILL_PROCESS", R"({"pid":4242,"start_time_ticks":123456789})");
    auto duplicate_action = command;
    duplicate_action.insert(duplicate_action.size() - 1, R"(,"action":"ISOLATE_HOST")");
    expect(!response::parse_command_json(duplicate_action, error), "duplicate action is rejected before DOM replacement");
    auto duplicate_target = valid_command_json("cmd-duplicate", "KILL_PROCESS", R"({"pid":4242,"\u0070id":9999,"start_time_ticks":123456789})");
    expect(!response::parse_command_json(duplicate_target, error), "escaped duplicate target key is rejected");
    expect(!response::parse_command_poll_response("{\"commands\":[" + duplicate_target + "]}", 10, error),
           "poll parsing preserves duplicate-key rejection within command entries");
    expect(!response::parse_command_poll_response(R"({"commands":[],"commands":[]})", 10, error),
           "duplicate poll commands field is rejected");
    expect(!response::parse_command_poll_response(R"({"commands":[],"ignored":true})", 10, error),
           "unknown poll envelope field is rejected");
    const auto valid_poll = response::parse_command_poll_response("{\"commands\":[" + command + "," + command + "]}", 10, error);
    expect(valid_poll && valid_poll->size() == 2, "same key names in separate command objects are allowed (replay gate remains separate)");
    const std::string deep = "{\"commands\":" + std::string(40, '[') + "0" + std::string(40, ']') + "}";
    expect(!response::parse_command_poll_response(deep, 10, error), "excessive JSON nesting is bounded before semantic validation");
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

void test_durable_result_outbox_and_ack_contract() {
    const auto path = std::filesystem::temp_directory_path() / ("officer-outcomes-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::string error;
    const auto result = response::serialize_command_result({"cmd-outbox", "corr-1", response::ReceiptCode::indeterminate, "completion unknown"}, 4096, error);
    expect(result.has_value(), "indeterminate result serializes with version 2");
    if (!result) return;
    const auto id = nlohmann::json::parse(*result).at("result_id");
    expect(!response::valid_result_ack(*result, "{}"), "HTTP 200 without retention acknowledgment cannot drop result");
    expect(!response::valid_result_ack(*result, "{\"result_id\":" + id.dump() + ",\"accepted\":true,\"retained\":false,\"retained\":true}"), "ambiguous receipt cannot dispose durable result");
    expect(!response::valid_result_ack(*result, nlohmann::json{{"result_id", id}, {"accepted", true}}.dump()), "legacy acknowledgment lacks immutable retention proof");
    expect(response::valid_result_ack(*result, nlohmann::json{{"result_id", id}, {"accepted", true}, {"retained", true}}.dump()), "matching retained result acknowledgment validates");
    {
        response::ResultOutbox box{{path}, "agent-1", "host-1"};
        box.save(*result);
        box.flush([](const std::string&) { return response::TransportOutcome::retryable; });
        expect(box.pending() == 1, "transport failure retains encrypted committed result");
    }
    {
        response::ResultOutbox box{{path}, "agent-1", "host-1"};
        box.flush([&](const std::string& received) {
            expect(received == *result, "restart replays exact committed result bytes");
            return response::TransportOutcome::acknowledged;
        });
        expect(box.pending() == 0, "only validated sender acknowledgment disposes result");
    }
    const bool owned = std::filesystem::equivalent(path.parent_path(), std::filesystem::temp_directory_path()) && path.filename().string().starts_with("officer-outcomes-");
    expect(owned, "cleanup remains within owned temporary outbox");
    if (owned)
        std::filesystem::remove_all(path);
}

// Locks this agent's ReceiptCode -> wire outcome collapse against the same
// three-value vocabulary panopticon-linux-agent uses (see
// panopticon-contracts/docs/CONTRACT.md section 3's collapse table,
// independently verified against this file's own serialize_command_result
// by direct source read during the cross-implementation audit that added
// this test).
void test_receipt_code_collapses_to_the_canonical_three_wire_outcomes() {
    const auto outcome_of = [](response::ReceiptCode code) {
        std::string error;
        const response::CommandReceipt receipt{"cmd-1", "corr-1", code, "x"};
        const auto serialized = response::serialize_command_result(receipt, 4096, error);
        expect(serialized.has_value(), "every ReceiptCode must still serialize to a bounded receipt");
        if (!serialized) return std::string{"unknown"};
        if (serialized->find("\"outcome\":\"succeeded\"") != std::string::npos) return std::string{"succeeded"};
        if (serialized->find("\"outcome\":\"failed\"") != std::string::npos) return std::string{"failed"};
        if (serialized->find("\"outcome\":\"rejected\"") != std::string::npos) return std::string{"rejected"};
        return std::string{"unknown"};
    };
    expect(outcome_of(response::ReceiptCode::succeeded) == "succeeded", "succeeded must stay succeeded");
    expect(outcome_of(response::ReceiptCode::execution_failed) == "failed",
           "execution_failed is the only code that collapses to failed");
    expect(outcome_of(response::ReceiptCode::invalid_command) == "rejected", "invalid_command must collapse to rejected");
    expect(outcome_of(response::ReceiptCode::expired) == "rejected", "expired must collapse to rejected");
    expect(outcome_of(response::ReceiptCode::replay_detected) == "rejected", "replay_detected must collapse to rejected");
    expect(outcome_of(response::ReceiptCode::target_mismatch) == "rejected", "target_mismatch must collapse to rejected");
    expect(outcome_of(response::ReceiptCode::target_protected) == "rejected", "target_protected must collapse to rejected");
    expect(outcome_of(response::ReceiptCode::unsupported_action) == "rejected", "unsupported_action must collapse to rejected");
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

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "--emit-response-profile-fixture") {
        response::ResponseConfig config;
        config.enabled = true;
        config.file_collection_root = "C:/PanopticonLab";
        std::cout << response::response_profile_json(config, "host-1", "boot_" + std::string(64, 'a')) << '\n';
        return 0;
    }
    if (argc == 2 && std::string_view{argv[1]} == "--emit-signed-artifact-fixture") {
        std::string error;
        const auto key = response::generate_ec_p256_keypair(error);
        if (!key) return 2;
        const auto payload = response::make_artifact_payload("fixture-command", "fixture-correlation", "host-1", "process_snapshot",
            "{\"pid\":42,\"start_time_ticks\":\"18446744073709551615\"}\n");
        auto value = nlohmann::json::parse(response::sign_artifact_payload(payload, "agent-1", *key, 1793232000U));
        static constexpr char digits[] = "0123456789abcdef";
        std::string point;
        for (const auto byte : key->public_point) { point += digits[byte >> 4]; point += digits[byte & 15]; }
        value["test_public_point_hex"] = point;
        std::cout << value.dump() << '\n';
        return 0;
    }
    if (argc == 2 && std::string_view{argv[1]} == "--emit-artifact-fixture") {
        std::cout << response::make_artifact_payload("fixture-command", "fixture-correlation", "host-1", "process_snapshot",
            "{\"pid\":42,\"start_time_ticks\":\"18446744073709551615\"}\n") << '\n';
        return 0;
    }
    if (argc == 2 && std::string_view{argv[1]} == "--decode-command-stdin") {
        std::array<char, 8193> buffer{};
        std::cin.read(buffer.data(), buffer.size());
        std::string error;
        const auto command = response::parse_command_json(std::string_view{buffer.data(), static_cast<std::size_t>(std::cin.gcount())}, error);
        if (!command) { std::cerr << error << '\n'; return 2; }
        std::cout << nlohmann::json{{"schema_version", command->schema_version}, {"pid", command->process_target.pid},
            {"start_time_ticks", std::to_string(command->process_target.start_time_ticks)},
            {"boot_id", command->process_target.boot_id.value_or("")}}.dump() << '\n';
        return 0;
    }
    test_artifact_outbox_and_exact_receipts();
    test_signed_artifact_manifest();
    test_resumable_artifact_outbox();
    test_current_response_profile();
    test_collection_acceptance_ack();
    test_parse_kill_process_command_round_trip();
    test_parse_collect_file_command_round_trip();
    test_boot_bound_process_command_v2();
    test_rejects_unknown_action();
    test_rejects_unexpected_top_level_field();
    test_rejects_process_target_missing_start_time();
    test_rejects_wrong_target_shape_for_action();
    test_rejects_non_utc_timestamp();
    test_rejects_malformed_json();
    test_rejects_ambiguous_command_and_poll_json();
    test_rejects_oversized_payload();
    test_serialize_command_result_round_trip();
    test_durable_result_outbox_and_ack_contract();
    test_receipt_code_collapses_to_the_canonical_three_wire_outcomes();
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

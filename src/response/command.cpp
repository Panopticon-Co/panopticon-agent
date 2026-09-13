#include "panopticon/officer/response/command.hpp"
#include "panopticon/officer/response/identity.hpp"
#include "panopticon/officer/response/replay_ledger.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <optional>
#include <sstream>
#include <utility>

namespace panopticon::officer::response {

namespace {

using nlohmann::json;

// Strict RFC 3339 UTC-only parser: rejects anything that is not exactly
// YYYY-MM-DDTHH:MM:SS(Z|+00:00) with valid calendar fields. Deliberately
// rejects fractional seconds and any non-UTC offset, matching
// panopticon-linux-agent's utc_timestamp() so both agents reject the same
// malformed/ambiguous timestamps the Manager could never have produced.
std::optional<std::int64_t> parse_utc_timestamp(const std::string& value) {
    if (value.size() < 20U || (value.back() != 'Z' && (value.size() < 6U || value.substr(value.size() - 6U) != "+00:00"))) {
        return std::nullopt;
    }
    const auto digits = [&](std::size_t offset, std::size_t count) -> std::optional<int> {
        int number = 0;
        for (std::size_t index = 0; index < count; ++index) {
            const char character = value[offset + index];
            if (character < '0' || character > '9') return std::nullopt;
            number = number * 10 + (character - '0');
        }
        return number;
    };
    if (value.size() < 19U || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' ||
        value[16] != ':') {
        return std::nullopt;
    }
    const auto year = digits(0, 4);
    const auto month = digits(5, 2);
    const auto day = digits(8, 2);
    const auto hour = digits(11, 2);
    const auto minute = digits(14, 2);
    const auto second = digits(17, 2);
    if (!year || !month || !day || !hour || !minute || !second) return std::nullopt;
    if (*month < 1 || *month > 12 || *day < 1 || *day > 31 || *hour > 23 || *minute > 59 || *second > 59) {
        return std::nullopt;
    }
    // Exact trailing content: after the 19 fixed characters, only "Z" or
    // "+00:00" may remain -- anything else (fractional seconds, junk) is
    // rejected rather than silently ignored.
    const auto tail = value.substr(19U);
    if (tail != "Z" && tail != "+00:00") return std::nullopt;

    static constexpr std::array<int, 12> days_in_month{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (*year % 4 == 0 && *year % 100 != 0) || *year % 400 == 0;
    const int max_day = (*month == 2 && leap) ? 29 : days_in_month[static_cast<std::size_t>(*month - 1)];
    if (*day > max_day) return std::nullopt;

    // Days since epoch via a civil-from-days style calculation (Howard
    // Hinnant's algorithm), avoiding any dependency on <chrono>'s
    // year_month_day (kept identical in spirit to the Linux agent, portable
    // to any C++20 standard library).
    std::int64_t y = *year;
    const std::int64_t m = *month;
    y -= (m <= 2) ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const std::int64_t yoe = y - era * 400;
    const std::int64_t doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + *day - 1;
    const std::int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days_since_epoch = era * 146097 + doe - 719468;

    return days_since_epoch * 86400LL + static_cast<std::int64_t>(*hour) * 3600LL +
           static_cast<std::int64_t>(*minute) * 60LL + static_cast<std::int64_t>(*second);
}

bool is_bounded_string(const json& value, std::size_t max_length) {
    return value.is_string() && !value.get_ref<const std::string&>().empty() &&
           value.get_ref<const std::string&>().size() <= max_length;
}

bool is_positive_integer(const json& value) {
    return value.is_number_integer() && !value.is_boolean() && value.get<std::int64_t>() > 0;
}

}  // namespace

std::optional<Command> parse_command_json(const std::string_view payload, std::string& error_message) {
    if (payload.empty() || payload.size() > 8192U) {
        error_message = "command JSON exceeds bounds";
        return std::nullopt;
    }
    json document;
    try {
        document = json::parse(payload, /*callback*/ nullptr, /*allow_exceptions*/ true);
    } catch (const json::exception&) {
        error_message = "command JSON is not well-formed";
        return std::nullopt;
    }
    if (!document.is_object()) {
        error_message = "command JSON must be an object";
        return std::nullopt;
    }

    static const std::array<std::string_view, 9> allowed_keys{
        "command_id", "agent_id", "host_id", "schema_version", "action",
        "expires_at", "created_at", "correlation_id", "target"};
    for (const auto& [key, value] : document.items()) {
        (void)value;
        if (std::find(allowed_keys.begin(), allowed_keys.end(), key) == allowed_keys.end()) {
            error_message = "command JSON contains an unexpected field";
            return std::nullopt;
        }
    }
    static const std::array<std::string_view, 8> required_keys{
        "command_id", "agent_id", "host_id", "schema_version", "action",
        "expires_at", "created_at", "correlation_id"};
    for (const auto& key : required_keys) {
        if (!document.contains(key)) {
            error_message = "command JSON is missing a required field";
            return std::nullopt;
        }
    }

    if (!is_bounded_string(document["command_id"], 128) || !is_bounded_string(document["agent_id"], 128) ||
        !is_bounded_string(document["host_id"], 128) || !is_bounded_string(document["correlation_id"], 128)) {
        error_message = "command identity fields are invalid";
        return std::nullopt;
    }
    const auto command_id = document["command_id"].get<std::string>();
    const auto agent_id = document["agent_id"].get<std::string>();
    const auto host_id = document["host_id"].get<std::string>();
    const auto correlation_id = document["correlation_id"].get<std::string>();
    if (!is_valid_identifier(command_id) || !is_valid_identifier(agent_id) || !is_valid_identifier(host_id) ||
        !is_valid_identifier(correlation_id)) {
        error_message = "command identity fields fail identifier validation";
        return std::nullopt;
    }
    if (!document["schema_version"].is_string() || document["schema_version"].get<std::string>() != "1") {
        error_message = "unsupported command schema version";
        return std::nullopt;
    }
    if (!document["expires_at"].is_string() || !document["created_at"].is_string()) {
        error_message = "command timestamps must be strings";
        return std::nullopt;
    }
    const auto created_at = parse_utc_timestamp(document["created_at"].get<std::string>());
    const auto expires_at = parse_utc_timestamp(document["expires_at"].get<std::string>());
    if (!created_at || !expires_at || *created_at >= *expires_at) {
        error_message = "command timestamps are invalid, non-UTC, or out of order";
        return std::nullopt;
    }
    if (!document["action"].is_string()) {
        error_message = "command action must be a string";
        return std::nullopt;
    }
    const auto action_name = document["action"].get<std::string>();
    ActionType action{};
    if (action_name == "KILL_PROCESS") action = ActionType::kill_process;
    else if (action_name == "COLLECT_PROCESS_INFO") action = ActionType::collect_process_info;
    else if (action_name == "COLLECT_NETWORK_CONNECTIONS") action = ActionType::collect_network_connections;
    else if (action_name == "COLLECT_FILE") action = ActionType::collect_file;
    else if (action_name == "QUARANTINE_FILE") action = ActionType::quarantine_file;
    else if (action_name == "ISOLATE_HOST") action = ActionType::isolate_host;
    else if (action_name == "RELEASE_HOST_ISOLATION") action = ActionType::release_host_isolation;
    else {
        error_message = "command action is not supported by this agent build";
        return std::nullopt;
    }

    const bool is_process_action = action == ActionType::kill_process || action == ActionType::collect_process_info;
    const bool is_file_action = action == ActionType::collect_file || action == ActionType::quarantine_file;
    const json target = document.contains("target") && !document["target"].is_null() ? document["target"] : json::object();
    if (!target.is_object()) {
        error_message = "command target must be an object";
        return std::nullopt;
    }

    ProcessTarget process_target{host_id, 0, 0};
    std::string file_path;
    if (is_process_action) {
        if (target.size() != 2U || !target.contains("pid") || !target.contains("start_time_ticks") ||
            !is_positive_integer(target["pid"]) || !is_positive_integer(target["start_time_ticks"])) {
            error_message = "process command target is invalid";
            return std::nullopt;
        }
        const auto pid = target["pid"].get<std::int64_t>();
        const auto start = target["start_time_ticks"].get<std::int64_t>();
        if (pid > std::numeric_limits<std::uint32_t>::max()) {
            error_message = "process command target pid is out of range";
            return std::nullopt;
        }
        process_target.pid = static_cast<std::uint32_t>(pid);
        process_target.start_time_ticks = static_cast<std::uint64_t>(start);
    } else if (is_file_action) {
        if (target.size() != 1U || !target.contains("path") || !is_bounded_string(target["path"], 4096)) {
            error_message = "file command target is invalid";
            return std::nullopt;
        }
        file_path = target["path"].get<std::string>();
    } else if (!target.empty()) {
        error_message = "this action does not accept a target";
        return std::nullopt;
    }

    return Command{command_id,       agent_id,      host_id, "1", correlation_id, action,
                   *expires_at,      process_target, file_path};
}

std::optional<std::vector<Command>> parse_command_poll_response(const std::string_view payload,
                                                                  const std::size_t maximum_commands,
                                                                  std::string& error_message) {
    if (maximum_commands == 0U || payload.empty() || payload.size() > 1U * 1024U * 1024U) {
        error_message = "command poll response is invalid";
        return std::nullopt;
    }
    json document;
    try {
        document = json::parse(payload, nullptr, true);
    } catch (const json::exception&) {
        error_message = "command poll response is not well-formed JSON";
        return std::nullopt;
    }
    if (!document.is_object() || !document.contains("commands") || !document["commands"].is_array()) {
        error_message = "command poll response must be {\"commands\": [...]}";
        return std::nullopt;
    }
    const auto& array = document["commands"];
    if (array.size() > maximum_commands) {
        error_message = "command poll response exceeds bounds";
        return std::nullopt;
    }
    std::vector<Command> commands;
    commands.reserve(array.size());
    for (const auto& entry : array) {
        const auto serialized = entry.dump();
        auto parsed = parse_command_json(serialized, error_message);
        if (!parsed) return std::nullopt;
        commands.push_back(std::move(*parsed));
    }
    return commands;
}

std::optional<std::string> serialize_command_result(const CommandReceipt& receipt, const std::size_t maximum_bytes,
                                                      std::string& error_message) {
    if (!is_valid_identifier(receipt.command_id) || !is_valid_identifier(receipt.correlation_id) ||
        maximum_bytes == 0U) {
        error_message = "receipt is invalid";
        return std::nullopt;
    }
    const auto outcome = receipt.code == ReceiptCode::succeeded    ? "succeeded"
                          : receipt.code == ReceiptCode::execution_failed ? "failed"
                                                                           : "rejected";
    json document = {
        {"result_id", "result-" + receipt.command_id},
        {"command_id", receipt.command_id},
        {"outcome", outcome},
        {"detail", std::string{outcome} + ":" + std::to_string(static_cast<unsigned int>(receipt.code)) +
                       (receipt.summary.empty() ? std::string{} : (" " + receipt.summary))},
        {"correlation_id", receipt.correlation_id},
    };
    // Manager's CommandResult.detail is capped at 512 bytes -- truncate
    // rather than reject, since the receipt itself is still valid and must
    // still be reported.
    auto detail = document["detail"].get<std::string>();
    if (detail.size() > 512U) {
        detail.resize(512U);
        document["detail"] = detail;
    }
    auto serialized = document.dump();
    if (serialized.size() > maximum_bytes) {
        error_message = "command result exceeds limit";
        return std::nullopt;
    }
    return serialized;
}

CommandGate::CommandGate(std::string agent_id, std::string host_id,
                          std::function<std::int64_t()> clock_epoch_seconds, ReplayLedger* durable_ledger)
    : agent_id_{std::move(agent_id)},
      host_id_{std::move(host_id)},
      clock_epoch_seconds_{std::move(clock_epoch_seconds)},
      durable_ledger_{durable_ledger} {}

CommandReceipt CommandGate::validate_and_mark(const Command& received) {
    std::lock_guard lock{mutex_};
    if (!is_valid_identifier(received.command_id) || !is_valid_identifier(received.correlation_id) ||
        received.schema_version != "1" || received.agent_id != agent_id_ || received.host_id != host_id_ ||
        received.process_target.host_id != host_id_) {
        return {received.command_id, received.correlation_id, ReceiptCode::invalid_command,
                "command identity, target, or schema is invalid"};
    }
    if (received.expires_at_epoch_seconds <= clock_epoch_seconds_()) {
        return {received.command_id, received.correlation_id, ReceiptCode::expired, "command has expired"};
    }
    if (seen_.contains(received.command_id)) {
        return {received.command_id, received.correlation_id, ReceiptCode::replay_detected,
                "command was already accepted"};
    }
    if (received.action != ActionType::kill_process && received.action != ActionType::collect_process_info &&
        received.action != ActionType::collect_network_connections && received.action != ActionType::collect_file &&
        received.action != ActionType::quarantine_file && received.action != ActionType::isolate_host &&
        received.action != ActionType::release_host_isolation) {
        return {received.command_id, received.correlation_id, ReceiptCode::unsupported_action,
                "action is not implemented"};
    }
    if (received.action == ActionType::kill_process && is_protected_process(received.process_target.pid, "")) {
        return {received.command_id, received.correlation_id, ReceiptCode::target_protected,
                "target is a protected process"};
    }
    if (durable_ledger_ != nullptr) {
        std::string ledger_error;
        const auto recorded = durable_ledger_->mark_if_new(received.command_id, ledger_error);
        if (!recorded.has_value()) {
            return {received.command_id, received.correlation_id, ReceiptCode::execution_failed,
                    "cannot persist command replay state"};
        }
        if (!*recorded) {
            return {received.command_id, received.correlation_id, ReceiptCode::replay_detected,
                    "command was accepted before restart"};
        }
    }
    seen_.insert(received.command_id);
    return {received.command_id, received.correlation_id, ReceiptCode::succeeded,
            "command accepted for a closed action handler"};
}

bool is_protected_process(const std::uint32_t pid, const std::string_view image_name) noexcept {
    if (pid == 0U || pid == 4U) return true;
    static constexpr std::array<std::string_view, 5> protected_images{
        "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "smss.exe"};
    std::string lowered{image_name};
    std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    // Only compare the file name component, in case a full path was passed.
    const auto separator = lowered.find_last_of("\\/");
    const std::string_view base = separator == std::string::npos ? lowered : std::string_view{lowered}.substr(separator + 1);
    return std::any_of(protected_images.begin(), protected_images.end(),
                        [&](std::string_view candidate) { return base == candidate; });
}

}  // namespace panopticon::officer::response

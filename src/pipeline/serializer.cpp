#include "panopticon/officer/pipeline/serializer.hpp"

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>

namespace panopticon::officer::pipeline {
namespace {

using Json = nlohmann::json;

Json nullable_string(const std::optional<std::string>& value) {
    return value ? Json(*value) : Json(nullptr);
}

void require_exact_keys(
    const Json& object,
    std::initializer_list<std::string_view> expected,
    std::string_view path) {
    if (!object.is_object()) {
        throw std::runtime_error(std::string{path} + " must be a JSON object.");
    }
    if (object.size() != expected.size()) {
        throw std::runtime_error(std::string{path} + " has missing or unknown fields.");
    }
    for (const std::string_view key : expected) {
        if (!object.contains(key)) {
            throw std::runtime_error(
                std::string{path} + " is missing required field '" + std::string{key} + "'.");
        }
    }
}

std::string required_string(
    const Json& object,
    std::string_view key,
    std::string_view path) {
    const Json& value = object.at(key);
    if (!value.is_string()) {
        throw std::runtime_error(
            std::string{path} + "." + std::string{key} + " must be a string.");
    }
    std::string result = value.get<std::string>();
    if (result.empty()) {
        throw std::runtime_error(
            std::string{path} + "." + std::string{key} + " cannot be empty.");
    }
    return result;
}

std::optional<std::string> optional_string(
    const Json& object,
    std::string_view key,
    std::string_view path) {
    const Json& value = object.at(key);
    if (value.is_null()) {
        return std::nullopt;
    }
    if (!value.is_string()) {
        throw std::runtime_error(
            std::string{path} + "." + std::string{key} + " must be a string or null.");
    }
    std::string result = value.get<std::string>();
    if (result.empty()) {
        throw std::runtime_error(
            std::string{path} + "." + std::string{key} + " cannot be empty when present.");
    }
    return result;
}

std::uint32_t required_pid(const Json& value, std::string_view path) {
    if (!value.is_number_integer() && !value.is_number_unsigned()) {
        throw std::runtime_error(std::string{path} + " must be an unsigned integer.");
    }
    if (value.is_number_integer() && value.get<std::int64_t>() < 0) {
        throw std::runtime_error(std::string{path} + " cannot be negative.");
    }
    const std::uint64_t pid = value.get<std::uint64_t>();
    if (pid > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error(std::string{path} + " exceeds the Windows PID range.");
    }
    return static_cast<std::uint32_t>(pid);
}

std::optional<std::uint32_t> optional_pid(const Json& value, std::string_view path) {
    return value.is_null() ? std::nullopt : std::optional<std::uint32_t>{required_pid(value, path)};
}

void require_pattern(
    std::string_view value,
    const std::regex& pattern,
    std::string_view field_name) {
    if (!std::regex_match(value.begin(), value.end(), pattern)) {
        throw std::runtime_error(std::string{field_name} + " has an invalid format.");
    }
}

}  // namespace

nlohmann::json event_to_json(const telemetry::PanopticonEvent& event) {
    return Json{
        {"schema_version", event.schema_version},
        {"event",
         {
             {"id", event.event.id},
             {"category", event.event.category},
             {"type", event.event.type},
             {"timestamp", event.event.timestamp},
         }},
        {"source",
         {
             {"kind", event.source.kind},
             {"provider", event.source.provider},
             {"channel", nullable_string(event.source.channel)},
             {"record_id",
              event.source.record_id ? Json(*event.source.record_id) : Json(nullptr)},
         }},
        {"agent", {{"id", event.agent.id}, {"version", event.agent.version}}},
        {"host",
         {
             {"id", event.host.id},
             {"hostname", event.host.hostname},
             {"os", {{"name", event.host.os.name}, {"build", event.host.os.build}}},
         }},
        {"user",
         {
             {"name", nullable_string(event.user.name)},
             {"domain", nullable_string(event.user.domain)},
             {"sid", nullable_string(event.user.sid)},
         }},
        {"process",
         {
             {"entity_id", event.process.entity_id},
             {"pid", event.process.pid},
             {"name", nullable_string(event.process.name)},
             {"executable", nullable_string(event.process.executable)},
             {"command_line", nullable_string(event.process.command_line)},
             {"parent",
              {
                  {"entity_id", nullable_string(event.process.parent.entity_id)},
                  {"pid",
                   event.process.parent.pid ? Json(*event.process.parent.pid) : Json(nullptr)},
                  {"name", nullable_string(event.process.parent.name)},
              }},
             {"hash", {{"sha256", nullable_string(event.process.hash.sha256)}}},
         }},
    };
}

std::string serialize_event(const telemetry::PanopticonEvent& event) {
    return event_to_json(event).dump();
}

std::optional<telemetry::PanopticonEvent> deserialize_event(
    std::string_view json_text,
    std::string& error_message) {
    error_message.clear();
    try {
        const Json root = Json::parse(json_text.begin(), json_text.end());
        require_exact_keys(
            root,
            {"schema_version", "event", "source", "agent", "host", "user", "process"},
            "$");

        telemetry::PanopticonEvent result;
        result.schema_version = required_string(root, "schema_version", "$" );
        if (result.schema_version != telemetry::kSchemaVersion) {
            throw std::runtime_error("$.schema_version is not supported by this agent.");
        }

        const Json& event = root.at("event");
        require_exact_keys(event, {"id", "category", "type", "timestamp"}, "$.event");
        result.event = {
            required_string(event, "id", "$.event"),
            required_string(event, "category", "$.event"),
            required_string(event, "type", "$.event"),
            required_string(event, "timestamp", "$.event"),
        };
        if (result.event.category != "process" || result.event.type != "start") {
            throw std::runtime_error("Schema 0.2 accepts only process/start events.");
        }

        const Json& source = root.at("source");
        require_exact_keys(source, {"kind", "provider", "channel", "record_id"}, "$.source");
        result.source = {
            required_string(source, "kind", "$.source"),
            required_string(source, "provider", "$.source"),
            optional_string(source, "channel", "$.source"),
            source.at("record_id").is_null()
                ? std::nullopt
                : std::optional<std::uint64_t>{
                      source.at("record_id").is_number_unsigned()
                          ? source.at("record_id").get<std::uint64_t>()
                          : throw std::runtime_error(
                                "$.source.record_id must be an unsigned integer or null.")},
        };
        if (result.source.kind != "etw" && result.source.kind != "sysmon" &&
            result.source.kind != "windows_event_log") {
            throw std::runtime_error("$.source.kind is not a supported telemetry source.");
        }

        const Json& agent = root.at("agent");
        require_exact_keys(agent, {"id", "version"}, "$.agent");
        result.agent = {
            required_string(agent, "id", "$.agent"),
            required_string(agent, "version", "$.agent"),
        };

        const Json& host = root.at("host");
        require_exact_keys(host, {"id", "hostname", "os"}, "$.host");
        const Json& os = host.at("os");
        require_exact_keys(os, {"name", "build"}, "$.host.os");
        result.host = {
            required_string(host, "id", "$.host"),
            required_string(host, "hostname", "$.host"),
            {
                required_string(os, "name", "$.host.os"),
                required_string(os, "build", "$.host.os"),
            },
        };

        const Json& user = root.at("user");
        require_exact_keys(user, {"name", "domain", "sid"}, "$.user");
        result.user = {
            optional_string(user, "name", "$.user"),
            optional_string(user, "domain", "$.user"),
            optional_string(user, "sid", "$.user"),
        };

        const Json& process = root.at("process");
        require_exact_keys(
            process,
            {"entity_id", "pid", "name", "executable", "command_line", "parent", "hash"},
            "$.process");
        const Json& parent = process.at("parent");
        require_exact_keys(parent, {"entity_id", "pid", "name"}, "$.process.parent");
        const Json& hash = process.at("hash");
        require_exact_keys(hash, {"sha256"}, "$.process.hash");
        result.process = {
            required_string(process, "entity_id", "$.process"),
            required_pid(process.at("pid"), "$.process.pid"),
            optional_string(process, "name", "$.process"),
            optional_string(process, "executable", "$.process"),
            optional_string(process, "command_line", "$.process"),
            {
                optional_string(parent, "entity_id", "$.process.parent"),
                optional_pid(parent.at("pid"), "$.process.parent.pid"),
                optional_string(parent, "name", "$.process.parent"),
            },
            {optional_string(hash, "sha256", "$.process.hash")},
        };

        static const std::regex event_id_pattern{R"(^evt_[0-9a-f]{64}$)"};
        static const std::regex entity_id_pattern{R"(^proc_[0-9a-f]{64}$)"};
        static const std::regex timestamp_pattern{
            R"(^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$)"};
        static const std::regex sha256_pattern{R"(^[0-9a-f]{64}$)"};
        require_pattern(result.event.id, event_id_pattern, "$.event.id");
        require_pattern(result.event.timestamp, timestamp_pattern, "$.event.timestamp");
        require_pattern(result.process.entity_id, entity_id_pattern, "$.process.entity_id");
        if (result.process.parent.entity_id) {
            require_pattern(
                *result.process.parent.entity_id,
                entity_id_pattern,
                "$.process.parent.entity_id");
        }
        if (result.process.hash.sha256) {
            require_pattern(*result.process.hash.sha256, sha256_pattern, "$.process.hash.sha256");
        }
        return result;
    } catch (const std::exception& exception) {
        error_message = exception.what();
        return std::nullopt;
    }
}

}  // namespace panopticon::officer::pipeline

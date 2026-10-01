#include "panopticon/officer/pipeline/serializer.hpp"

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::officer::pipeline {
namespace {

using Json = nlohmann::json;

Json nullable_string(const std::optional<std::string>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json nullable_uint(const std::optional<std::uint16_t>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json nullable_uint64(const std::optional<std::uint64_t>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json nullable_bool(const std::optional<bool>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json hash_object(const telemetry::ProcessHashMetadata& hash) {
    return Json{{"sha256", nullable_string(hash.sha256)}};
}

Json nullable_uint32(const std::optional<std::uint32_t>& value) {
    return value ? Json(*value) : Json(nullptr);
}

Json target_object(const telemetry::TargetProcessMetadata& target) {
    return Json{
        {"entity_id", nullable_string(target.entity_id)},
        {"pid", nullable_uint32(target.pid)},
        {"executable", nullable_string(target.executable)},
        {"user", nullable_string(target.user)},
    };
}

void require_only_keys(
    const Json& object,
    std::initializer_list<std::string_view> required,
    std::initializer_list<std::string_view> optional,
    std::string_view path) {
    if (!object.is_object()) {
        throw std::runtime_error(std::string{path} + " must be a JSON object.");
    }
    for (const std::string_view key : required) {
        if (!object.contains(key)) {
            throw std::runtime_error(
                std::string{path} + " is missing required field '" + std::string{key} + "'.");
        }
    }
    for (const auto& item : object.items()) {
        bool known = false;
        for (const std::string_view key : required) {
            if (item.key() == key) { known = true; break; }
        }
        for (const std::string_view key : optional) {
            if (item.key() == key) { known = true; break; }
        }
        if (!known) {
            throw std::runtime_error(
                std::string{path} + " has an unknown field '" + item.key() + "'.");
        }
    }
}

void require_exact_keys(
    const Json& object,
    std::initializer_list<std::string_view> expected,
    std::string_view path) {
    require_only_keys(object, expected, {}, path);
    if (object.size() != expected.size()) {
        throw std::runtime_error(std::string{path} + " has missing or unknown fields.");
    }
}

std::string required_string(const Json& object, std::string_view key, std::string_view path) {
    const Json& value = object.at(key);
    if (!value.is_string()) {
        throw std::runtime_error(std::string{path} + "." + std::string{key} + " must be a string.");
    }
    std::string result = value.get<std::string>();
    if (result.empty()) {
        throw std::runtime_error(std::string{path} + "." + std::string{key} + " cannot be empty.");
    }
    return result;
}

std::optional<std::string> optional_string(const Json& object, std::string_view key, std::string_view path) {
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

std::optional<std::uint16_t> optional_port(const Json& value, std::string_view path) {
    if (value.is_null()) {
        return std::nullopt;
    }
    if (!value.is_number_integer() && !value.is_number_unsigned()) {
        throw std::runtime_error(std::string{path} + " must be an integer or null.");
    }
    if (value.is_number_integer() && value.get<std::int64_t>() < 0) {
        throw std::runtime_error(std::string{path} + " cannot be negative.");
    }
    const std::uint64_t port = value.get<std::uint64_t>();
    if (port > 65535) {
        throw std::runtime_error(std::string{path} + " exceeds the TCP/UDP port range.");
    }
    return static_cast<std::uint16_t>(port);
}

std::optional<std::uint64_t> optional_uint64(const Json& value, std::string_view path) {
    if (value.is_null()) {
        return std::nullopt;
    }
    if (!value.is_number_integer() && !value.is_number_unsigned()) {
        throw std::runtime_error(std::string{path} + " must be an integer or null.");
    }
    if (value.is_number_integer() && value.get<std::int64_t>() < 0) {
        throw std::runtime_error(std::string{path} + " cannot be negative.");
    }
    return value.get<std::uint64_t>();
}

std::optional<bool> optional_bool(const Json& value, std::string_view path) {
    if (value.is_null()) {
        return std::nullopt;
    }
    if (!value.is_boolean()) {
        throw std::runtime_error(std::string{path} + " must be a boolean or null.");
    }
    return value.get<bool>();
}

telemetry::ProcessHashMetadata parse_hash(const Json& parent, std::string_view path) {
    const Json& hash = parent.at("hash");
    require_exact_keys(hash, {"sha256"}, path);
    return {optional_string(hash, "sha256", path)};
}

void require_pattern(std::string_view value, const std::regex& pattern, std::string_view field_name) {
    if (!std::regex_match(value.begin(), value.end(), pattern)) {
        throw std::runtime_error(std::string{field_name} + " has an invalid format.");
    }
}

// -- family type vocabularies -------------------------------------------
bool is_network_type(const std::string& t) { return t == "connect"; }
bool is_file_type(const std::string& t) { return t == "create" || t == "delete" || t == "rename"; }
bool is_registry_type(const std::string& t) {
    return t == "add_key" || t == "delete_key" || t == "set_value" || t == "rename_key";
}
bool is_image_load_type(const std::string& t) { return t == "load"; }

std::optional<std::uint32_t> optional_uint32(const Json& value, std::string_view path) {
    if (value.is_null()) {
        return std::nullopt;
    }
    if (!value.is_number_integer() && !value.is_number_unsigned()) {
        throw std::runtime_error(std::string{path} + " must be an integer or null.");
    }
    if (value.is_number_integer() && value.get<std::int64_t>() < 0) {
        throw std::runtime_error(std::string{path} + " cannot be negative.");
    }
    const std::uint64_t number = value.get<std::uint64_t>();
    if (number > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error(std::string{path} + " exceeds the 32-bit range.");
    }
    return static_cast<std::uint32_t>(number);
}

telemetry::TargetProcessMetadata parse_target(const Json& parent, std::string_view path) {
    const Json& target = parent.at("target");
    require_exact_keys(target, {"entity_id", "pid", "executable", "user"}, path);
    return {
        optional_string(target, "entity_id", path),
        optional_pid(target.at("pid"), std::string{path} + ".pid"),
        optional_string(target, "executable", path),
        optional_string(target, "user", path),
    };
}

}  // namespace

nlohmann::json event_to_json(const telemetry::PanopticonEvent& event) {
    Json out{
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
             {"hash", hash_object(event.process.hash)},
             {"start_time_ticks", nullable_uint64(event.process.start_time_ticks)},
         }},
    };

    if (event.network) {
        out["network"] = {
            {"direction", event.network->direction},
            {"protocol", nullable_string(event.network->protocol)},
            {"source_ip", nullable_string(event.network->source_ip)},
            {"source_port", nullable_uint(event.network->source_port)},
            {"destination_ip", nullable_string(event.network->destination_ip)},
            {"destination_port", nullable_uint(event.network->destination_port)},
            {"destination_hostname", nullable_string(event.network->destination_hostname)},
        };
    }
    if (event.file) {
        out["file"] = {
            {"operation", event.file->operation},
            {"path", nullable_string(event.file->path)},
            {"target_path", nullable_string(event.file->target_path)},
            {"previous_path", nullable_string(event.file->previous_path)},
            {"hash", hash_object(event.file->hash)},
        };
    }
    if (event.registry) {
        out["registry"] = {
            {"operation", event.registry->operation},
            {"key_path", nullable_string(event.registry->key_path)},
            {"value_name", nullable_string(event.registry->value_name)},
            {"value_type", nullable_string(event.registry->value_type)},
            {"value_data", nullable_string(event.registry->value_data)},
        };
    }
    if (event.image_load) {
        out["image_load"] = {
            {"path", nullable_string(event.image_load->path)},
            {"is_signed", nullable_bool(event.image_load->is_signed)},
            {"signature_status", nullable_string(event.image_load->signature_status)},
            {"hash", hash_object(event.image_load->hash)},
        };
    }
    if (event.dns) {
        out["dns"] = {
            {"query_name", nullable_string(event.dns->query_name)},
            {"query_status", nullable_uint32(event.dns->query_status)},
            {"query_results", nullable_string(event.dns->query_results)},
        };
    }
    if (event.process_access) {
        out["process_access"] = {
            {"target", target_object(event.process_access->target)},
            {"granted_access", nullable_string(event.process_access->granted_access)},
            {"call_trace", nullable_string(event.process_access->call_trace)},
        };
    }
    if (event.remote_thread) {
        out["remote_thread"] = {
            {"target", target_object(event.remote_thread->target)},
            {"new_thread_id", nullable_uint32(event.remote_thread->new_thread_id)},
            {"start_address", nullable_string(event.remote_thread->start_address)},
            {"start_module", nullable_string(event.remote_thread->start_module)},
            {"start_function", nullable_string(event.remote_thread->start_function)},
        };
    }
    if (event.script_block) {
        out["script_block"] = {
            {"script_block_id", nullable_string(event.script_block->script_block_id)},
            {"message_number", nullable_uint32(event.script_block->message_number)},
            {"message_total", nullable_uint32(event.script_block->message_total)},
            {"path", nullable_string(event.script_block->path)},
            {"text", nullable_string(event.script_block->text)},
            {"text_length", event.script_block->text_length},
            {"text_truncated", event.script_block->text_truncated},
            {"text_sha256", nullable_string(event.script_block->text_sha256)},
        };
    }
    return out;
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
        require_only_keys(
            root,
            {"schema_version", "event", "source", "agent", "host", "user", "process"},
            {"network", "file", "registry", "image_load", "dns", "process_access",
             "remote_thread", "script_block"},
            "$");

        telemetry::PanopticonEvent result;
        result.schema_version = required_string(root, "schema_version", "$");
        if (result.schema_version != "0.2" && result.schema_version != "0.3" &&
            result.schema_version != "0.4" && result.schema_version != "0.5") {
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

        const std::string& category = result.event.category;
        const std::string& type = result.event.type;
        const bool has_network = root.contains("network");
        const bool has_file = root.contains("file");
        const bool has_registry = root.contains("registry");
        const bool has_image_load = root.contains("image_load");
        const bool has_dns = root.contains("dns");
        const bool has_process_access = root.contains("process_access");
        const bool has_remote_thread = root.contains("remote_thread");
        const bool has_script_block = root.contains("script_block");
        const int family_blocks = static_cast<int>(has_network) + static_cast<int>(has_file) +
                                  static_cast<int>(has_registry) + static_cast<int>(has_image_load) +
                                  static_cast<int>(has_dns) + static_cast<int>(has_process_access) +
                                  static_cast<int>(has_remote_thread) +
                                  static_cast<int>(has_script_block);

        if (category == "process") {
            // Schema 0.5 added process 'stop'; 'start' remains the 0.2 shape.
            if (type != "start" && type != "stop") {
                throw std::runtime_error("A process event must be of type 'start' or 'stop'.");
            }
            if (family_blocks != 0) {
                throw std::runtime_error("A process event must not carry a telemetry-family block.");
            }
        } else if (category == "network") {
            if (!is_network_type(type)) throw std::runtime_error("Unsupported network event type.");
            if (!has_network || family_blocks != 1) {
                throw std::runtime_error("A network event must carry exactly the network block.");
            }
        } else if (category == "file") {
            if (!is_file_type(type)) throw std::runtime_error("Unsupported file event type.");
            if (!has_file || family_blocks != 1) {
                throw std::runtime_error("A file event must carry exactly the file block.");
            }
        } else if (category == "registry") {
            if (!is_registry_type(type)) throw std::runtime_error("Unsupported registry event type.");
            if (!has_registry || family_blocks != 1) {
                throw std::runtime_error("A registry event must carry exactly the registry block.");
            }
        } else if (category == "image_load") {
            if (!is_image_load_type(type)) throw std::runtime_error("Unsupported image_load event type.");
            if (!has_image_load || family_blocks != 1) {
                throw std::runtime_error("An image_load event must carry exactly the image_load block.");
            }
        } else if (category == "dns") {
            if (type != "query") throw std::runtime_error("Unsupported dns event type.");
            if (!has_dns || family_blocks != 1) {
                throw std::runtime_error("A dns event must carry exactly the dns block.");
            }
        } else if (category == "process_access") {
            if (type != "access") throw std::runtime_error("Unsupported process_access event type.");
            if (!has_process_access || family_blocks != 1) {
                throw std::runtime_error("A process_access event must carry exactly the process_access block.");
            }
        } else if (category == "remote_thread") {
            if (type != "create") throw std::runtime_error("Unsupported remote_thread event type.");
            if (!has_remote_thread || family_blocks != 1) {
                throw std::runtime_error("A remote_thread event must carry exactly the remote_thread block.");
            }
        } else if (category == "script_block") {
            if (type != "execute") throw std::runtime_error("Unsupported script_block event type.");
            if (!has_script_block || family_blocks != 1) {
                throw std::runtime_error("A script_block event must carry exactly the script_block block.");
            }
        } else {
            throw std::runtime_error("$.event.category is not a supported telemetry category.");
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
            {"entity_id", "pid", "name", "executable", "command_line", "parent", "hash",
             "start_time_ticks"},
            "$.process");
        const Json& parent = process.at("parent");
        require_exact_keys(parent, {"entity_id", "pid", "name"}, "$.process.parent");
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
            parse_hash(process, "$.process.hash"),
            optional_uint64(process.at("start_time_ticks"), "$.process.start_time_ticks"),
        };

        if (has_network) {
            const Json& n = root.at("network");
            require_exact_keys(
                n,
                {"direction", "protocol", "source_ip", "source_port", "destination_ip",
                 "destination_port", "destination_hostname"},
                "$.network");
            const std::string direction = required_string(n, "direction", "$.network");
            if (direction != "inbound" && direction != "outbound") {
                throw std::runtime_error("$.network.direction must be 'inbound' or 'outbound'.");
            }
            std::optional<std::string> protocol = optional_string(n, "protocol", "$.network");
            if (protocol && *protocol != "tcp" && *protocol != "udp") {
                throw std::runtime_error("$.network.protocol must be 'tcp', 'udp' or null.");
            }
            result.network = telemetry::NetworkMetadata{
                direction,
                protocol,
                optional_string(n, "source_ip", "$.network"),
                optional_port(n.at("source_port"), "$.network.source_port"),
                optional_string(n, "destination_ip", "$.network"),
                optional_port(n.at("destination_port"), "$.network.destination_port"),
                optional_string(n, "destination_hostname", "$.network"),
            };
        }
        if (has_file) {
            const Json& f = root.at("file");
            require_exact_keys(
                f, {"operation", "path", "target_path", "previous_path", "hash"}, "$.file");
            const std::string operation = required_string(f, "operation", "$.file");
            if (!is_file_type(operation)) {
                throw std::runtime_error("$.file.operation is not a supported file operation.");
            }
            result.file = telemetry::FileMetadata{
                operation,
                optional_string(f, "path", "$.file"),
                optional_string(f, "target_path", "$.file"),
                optional_string(f, "previous_path", "$.file"),
                parse_hash(f, "$.file.hash"),
            };
        }
        if (has_registry) {
            const Json& r = root.at("registry");
            require_exact_keys(
                r, {"operation", "key_path", "value_name", "value_type", "value_data"}, "$.registry");
            const std::string operation = required_string(r, "operation", "$.registry");
            if (!is_registry_type(operation)) {
                throw std::runtime_error("$.registry.operation is not a supported registry operation.");
            }
            result.registry = telemetry::RegistryMetadata{
                operation,
                optional_string(r, "key_path", "$.registry"),
                optional_string(r, "value_name", "$.registry"),
                optional_string(r, "value_type", "$.registry"),
                optional_string(r, "value_data", "$.registry"),
            };
        }
        if (has_image_load) {
            const Json& im = root.at("image_load");
            require_exact_keys(
                im, {"path", "is_signed", "signature_status", "hash"}, "$.image_load");
            result.image_load = telemetry::ImageLoadMetadata{
                optional_string(im, "path", "$.image_load"),
                optional_bool(im.at("is_signed"), "$.image_load.is_signed"),
                optional_string(im, "signature_status", "$.image_load"),
                parse_hash(im, "$.image_load.hash"),
            };
        }
        if (has_dns) {
            const Json& d = root.at("dns");
            require_exact_keys(d, {"query_name", "query_status", "query_results"}, "$.dns");
            result.dns = telemetry::DnsMetadata{
                optional_string(d, "query_name", "$.dns"),
                optional_uint32(d.at("query_status"), "$.dns.query_status"),
                optional_string(d, "query_results", "$.dns"),
            };
        }
        if (has_process_access) {
            const Json& pa = root.at("process_access");
            require_exact_keys(pa, {"target", "granted_access", "call_trace"}, "$.process_access");
            result.process_access = telemetry::ProcessAccessMetadata{
                parse_target(pa, "$.process_access.target"),
                optional_string(pa, "granted_access", "$.process_access"),
                optional_string(pa, "call_trace", "$.process_access"),
            };
        }
        if (has_remote_thread) {
            const Json& rt = root.at("remote_thread");
            require_exact_keys(
                rt,
                {"target", "new_thread_id", "start_address", "start_module", "start_function"},
                "$.remote_thread");
            result.remote_thread = telemetry::RemoteThreadMetadata{
                parse_target(rt, "$.remote_thread.target"),
                optional_uint32(rt.at("new_thread_id"), "$.remote_thread.new_thread_id"),
                optional_string(rt, "start_address", "$.remote_thread"),
                optional_string(rt, "start_module", "$.remote_thread"),
                optional_string(rt, "start_function", "$.remote_thread"),
            };
        }
        if (has_script_block) {
            const Json& sb = root.at("script_block");
            require_exact_keys(
                sb,
                {"script_block_id", "message_number", "message_total", "path", "text",
                 "text_length", "text_truncated", "text_sha256"},
                "$.script_block");
            const Json& length = sb.at("text_length");
            if (!length.is_number_unsigned() &&
                !(length.is_number_integer() && length.get<std::int64_t>() >= 0)) {
                throw std::runtime_error("$.script_block.text_length must be a non-negative integer.");
            }
            const Json& truncated = sb.at("text_truncated");
            if (!truncated.is_boolean()) {
                throw std::runtime_error("$.script_block.text_truncated must be a boolean.");
            }
            telemetry::ScriptBlockMetadata block;
            block.script_block_id = optional_string(sb, "script_block_id", "$.script_block");
            block.message_number = optional_uint32(sb.at("message_number"), "$.script_block.message_number");
            block.message_total = optional_uint32(sb.at("message_total"), "$.script_block.message_total");
            block.path = optional_string(sb, "path", "$.script_block");
            block.text = optional_string(sb, "text", "$.script_block");
            block.text_length = length.get<std::uint64_t>();
            block.text_truncated = truncated.get<bool>();
            block.text_sha256 = optional_string(sb, "text_sha256", "$.script_block");
            result.script_block = std::move(block);
        }

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
                *result.process.parent.entity_id, entity_id_pattern, "$.process.parent.entity_id");
        }
        if (result.process.hash.sha256) {
            require_pattern(*result.process.hash.sha256, sha256_pattern, "$.process.hash.sha256");
        }
        if (result.file && result.file->hash.sha256) {
            require_pattern(*result.file->hash.sha256, sha256_pattern, "$.file.hash.sha256");
        }
        if (result.image_load && result.image_load->hash.sha256) {
            require_pattern(*result.image_load->hash.sha256, sha256_pattern, "$.image_load.hash.sha256");
        }
        if (result.script_block && result.script_block->text_sha256) {
            require_pattern(
                *result.script_block->text_sha256, sha256_pattern, "$.script_block.text_sha256");
        }
        if (result.process_access && result.process_access->target.entity_id) {
            require_pattern(
                *result.process_access->target.entity_id, entity_id_pattern,
                "$.process_access.target.entity_id");
        }
        if (result.remote_thread && result.remote_thread->target.entity_id) {
            require_pattern(
                *result.remote_thread->target.entity_id, entity_id_pattern,
                "$.remote_thread.target.entity_id");
        }
        return result;
    } catch (const std::exception& exception) {
        error_message = exception.what();
        return std::nullopt;
    }
}

}  // namespace panopticon::officer::pipeline

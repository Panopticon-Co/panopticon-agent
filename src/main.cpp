#include "eyetrace/event_log_reader.hpp"
#include "eyetrace/sysmon_parser.hpp"

#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr std::size_t kDefaultLimit = 20;
constexpr std::size_t kMaximumLimit = 1'000;

enum class ExitCode { success = 0, invalid_arguments = 2, acquisition_failure = 3, parsing_failure = 4, output_failure = 5 };
enum class OutputFormat { json, xml };

struct CommandLineOptions {
    std::size_t limit{kDefaultLimit};
    std::uint32_t event_id{1};
    OutputFormat format{OutputFormat::json};
    std::optional<std::string> output_path;
};

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name
              << " [--limit N] [--event-id N] [--format json|xml] [--output FILE]\n"
              << "  --limit N     Read 1 to " << kMaximumLimit << " newest records (default: " << kDefaultLimit << ").\n"
              << "  --event-id N  Sysmon ID: 1, 3, 11, 12, 13, or 14 (default: 1).\n"
              << "  --format      Output json (default) or raw xml.\n"
              << "  --output      Also write the same output to FILE.\n";
}

template <typename Integer>
std::optional<Integer> parse_number(std::string_view text) {
    Integer value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc{} && end == text.data() + text.size() ? std::optional<Integer>(value)
                                                                     : std::nullopt;
}

bool is_supported_event_id(std::uint32_t event_id) {
    return event_id == 1 || event_id == 3 || event_id == 11 || event_id == 12 || event_id == 13 || event_id == 14;
}

std::optional<CommandLineOptions> parse_command_line(int argc, char* argv[]) {
    CommandLineOptions options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument = argv[index];
        if (index + 1 == argc) {
            std::cerr << "Missing value for " << argument << '\n';
            return std::nullopt;
        }
        const std::string_view value = argv[++index];
        if (argument == "--limit") {
            const auto limit = parse_number<std::size_t>(value);
            if (!limit || *limit == 0 || *limit > kMaximumLimit) {
                std::cerr << "Invalid --limit value: " << value << '\n';
                return std::nullopt;
            }
            options.limit = *limit;
        } else if (argument == "--event-id") {
            const auto event_id = parse_number<std::uint32_t>(value);
            if (!event_id || !is_supported_event_id(*event_id)) {
                std::cerr << "Unsupported --event-id value: " << value << '\n';
                return std::nullopt;
            }
            options.event_id = *event_id;
        } else if (argument == "--format") {
            if (value == "json") options.format = OutputFormat::json;
            else if (value == "xml") options.format = OutputFormat::xml;
            else {
                std::cerr << "Invalid --format value: " << value << " (use json or xml).\n";
                return std::nullopt;
            }
        } else if (argument == "--output") {
            options.output_path = std::string(value);
        } else {
            std::cerr << "Unknown option: " << argument << '\n';
            return std::nullopt;
        }
    }
    return options;
}

template <typename T>
nlohmann::json json_value(const std::optional<T>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

template <typename T, typename Serializer>
nlohmann::json json_object(const std::optional<T>& value, Serializer serializer) {
    return value ? serializer(*value) : nlohmann::json(nullptr);
}

nlohmann::json to_json(const eyetrace::TelemetryEvent& event) {
    return {
        {"schema_version", event.schema_version}, {"timestamp", json_value(event.timestamp)},
        {"source", {{"provider", json_value(event.source.provider)}, {"channel", json_value(event.source.channel)},
                    {"event_id", json_value(event.source.event_id)}, {"record_id", json_value(event.source.record_id)}}},
        {"host", {{"name", json_value(event.host_name)}}},
        {"event", {{"category", event.category}, {"type", event.type}}},
        {"process", {{"guid", json_value(event.process.guid)}, {"pid", json_value(event.process.pid)},
                     {"image", json_value(event.process.image)}, {"command_line", json_value(event.process.command_line)},
                     {"current_directory", json_value(event.process.current_directory)}, {"user", json_value(event.process.user)},
                     {"integrity_level", json_value(event.process.integrity_level)}, {"hashes", json_value(event.process.hashes)}}},
        {"parent", {{"guid", json_value(event.parent.guid)}, {"pid", json_value(event.parent.pid)},
                    {"image", json_value(event.parent.image)}, {"command_line", json_value(event.parent.command_line)}}},
        {"network", json_object(event.network, [](const eyetrace::NetworkDetails& network) {
            return nlohmann::json{{"protocol", json_value(network.protocol)}, {"initiated", json_value(network.initiated)},
                                  {"source_ip", json_value(network.source_ip)}, {"source_port", json_value(network.source_port)},
                                  {"destination_ip", json_value(network.destination_ip)}, {"destination_port", json_value(network.destination_port)},
                                  {"destination_hostname", json_value(network.destination_hostname)}};
        })},
        {"file", json_object(event.file, [](const eyetrace::FileDetails& file) {
            return nlohmann::json{{"path", json_value(file.path)}, {"creation_utc", json_value(file.creation_utc)}};
        })},
        {"registry", json_object(event.registry, [](const eyetrace::RegistryDetails& registry) {
            return nlohmann::json{{"operation", json_value(registry.operation)}, {"target_object", json_value(registry.target_object)},
                                  {"details", json_value(registry.details)}, {"new_name", json_value(registry.new_name)}};
        })},
    };
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        print_usage(argv[0]);
        return static_cast<int>(ExitCode::success);
    }
    const auto options = parse_command_line(argc, argv);
    if (!options) {
        print_usage(argv[0]);
        return static_cast<int>(ExitCode::invalid_arguments);
    }

    std::string error_message;
    const auto xml_events = eyetrace::EventLogReader::read_newest_event_xmls(options->event_id, options->limit, error_message);
    if (!xml_events) {
        std::cerr << "EyeTrace Query acquisition failed: " << error_message << '\n';
        return static_cast<int>(ExitCode::acquisition_failure);
    }

    std::vector<std::string> output_lines;
    output_lines.reserve(xml_events->size());
    for (const std::string& xml : *xml_events) {
        if (options->format == OutputFormat::xml) {
            output_lines.push_back(xml);
            continue;
        }
        const auto parsed_event = eyetrace::SysmonParser::parse_xml(xml, error_message);
        if (!parsed_event) {
            std::cerr << "EyeTrace Query parsing failed: " << error_message << '\n';
            return static_cast<int>(ExitCode::parsing_failure);
        }
        output_lines.push_back(to_json(*parsed_event).dump());
    }

    std::ofstream output_file;
    if (options->output_path) {
        output_file.open(*options->output_path, std::ios::out | std::ios::trunc);
        if (!output_file) {
            std::cerr << "EyeTrace Query could not open output file: " << *options->output_path << '\n';
            return static_cast<int>(ExitCode::output_failure);
        }
    }
    for (const std::string& line : output_lines) {
        std::cout << line << '\n';
        if (options->output_path) {
            output_file << line << '\n';
            if (!output_file) {
                std::cerr << "EyeTrace Query could not write the complete output file.\n";
                return static_cast<int>(ExitCode::output_failure);
            }
        }
    }
    return static_cast<int>(ExitCode::success);
}

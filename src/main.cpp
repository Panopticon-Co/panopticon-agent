#include "eyetrace/event_log_reader.hpp"
#include "eyetrace/sysmon_parser.hpp"

#include <charconv>
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

enum class OutputFormat { json, xml };

struct CommandLineOptions {
    std::size_t limit{kDefaultLimit};
    OutputFormat format{OutputFormat::json};
    std::optional<std::string> output_path;
};

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [--limit N] [--format json|xml] [--output FILE]\n"
              << "  --limit N  Read 1 to " << kMaximumLimit
              << " newest Sysmon Event ID 1 records (default: " << kDefaultLimit << ").\n"
              << "  --format   Output json (default) or raw xml.\n"
              << "  --output   Also write the same output to FILE.\n";
}

std::optional<std::size_t> parse_limit(std::string_view text);

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
            const auto parsed_limit = parse_limit(value);
            if (!parsed_limit.has_value()) {
                std::cerr << "Invalid --limit value: " << value << '\n';
                return std::nullopt;
            }
            options.limit = *parsed_limit;
        } else if (argument == "--format") {
            if (value == "json") {
                options.format = OutputFormat::json;
            } else if (value == "xml") {
                options.format = OutputFormat::xml;
            } else {
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
    return value.has_value() ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

nlohmann::json to_json(const eyetrace::TelemetryEvent& event) {
    return {
        {"schema_version", event.schema_version},
        {"timestamp", json_value(event.timestamp)},
        {"source",
         {{"provider", json_value(event.source.provider)},
          {"channel", json_value(event.source.channel)},
          {"event_id", json_value(event.source.event_id)},
          {"record_id", json_value(event.source.record_id)}}},
        {"host", {{"name", json_value(event.host_name)}}},
        {"event", {{"category", "process_create"}}},
        {"process",
         {{"guid", json_value(event.process.guid)},
          {"pid", json_value(event.process.pid)},
          {"image", json_value(event.process.image)},
          {"command_line", json_value(event.process.command_line)},
          {"current_directory", json_value(event.process.current_directory)},
          {"user", json_value(event.process.user)},
          {"integrity_level", json_value(event.process.integrity_level)},
          {"hashes", json_value(event.process.hashes)}}},
        {"parent",
         {{"guid", json_value(event.parent.guid)},
          {"pid", json_value(event.parent.pid)},
          {"image", json_value(event.parent.image)},
          {"command_line", json_value(event.parent.command_line)}}},
    };
}

std::optional<std::size_t> parse_limit(std::string_view text) {
    unsigned long long value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0 ||
        value > kMaximumLimit) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(value);
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string_view(argv[1]) == "--help") {
        print_usage(argv[0]);
        return EXIT_SUCCESS;
    }

    const auto options = parse_command_line(argc, argv);
    if (!options.has_value()) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::string error_message;
    const auto xml_events =
        eyetrace::EventLogReader::read_newest_process_creation_xmls(options->limit, error_message);
    if (!xml_events.has_value()) {
        std::cerr << "EyeTrace Query failed: " << error_message << '\n';
        return EXIT_FAILURE;
    }

    std::vector<std::string> output_lines;
    output_lines.reserve(xml_events->size());
    for (const std::string& xml : *xml_events) {
        if (options->format == OutputFormat::xml) {
            output_lines.push_back(xml);
            continue;
        }

        const auto parsed_event = eyetrace::SysmonParser::parse_process_create_xml(xml, error_message);
        if (!parsed_event.has_value()) {
            std::cerr << "EyeTrace Query failed to parse Sysmon XML: " << error_message << '\n';
            return EXIT_FAILURE;
        }
        output_lines.push_back(to_json(*parsed_event).dump());
    }

    std::ofstream output_file;
    if (options->output_path.has_value()) {
        output_file.open(*options->output_path, std::ios::out | std::ios::trunc);
        if (!output_file) {
            std::cerr << "EyeTrace Query could not open output file: " << *options->output_path << '\n';
            return EXIT_FAILURE;
        }
    }

    for (const std::string& line : output_lines) {
        std::cout << line << '\n';
        if (options->output_path.has_value()) {
            output_file << line << '\n';
            if (!output_file) {
                std::cerr << "EyeTrace Query could not write the complete output file.\n";
                return EXIT_FAILURE;
            }
        }
    }
    return 0;
}

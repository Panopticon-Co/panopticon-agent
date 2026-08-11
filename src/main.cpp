#include "eyetrace/event_log_reader.hpp"

#include <cerrno>
#include <charconv>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr std::size_t kDefaultLimit = 20;
constexpr std::size_t kMaximumLimit = 1'000;

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [--limit N]\n"
              << "  --limit N  Read 1 to " << kMaximumLimit
              << " newest Sysmon Event ID 1 records (default: " << kDefaultLimit << ").\n";
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
    std::size_t limit = kDefaultLimit;
    if (argc != 1) {
        if (argc != 3 || std::string_view(argv[1]) != "--limit") {
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }

        const auto parsed_limit = parse_limit(argv[2]);
        if (!parsed_limit.has_value()) {
            std::cerr << "Invalid --limit value: " << argv[2] << '\n';
            print_usage(argv[0]);
            return EXIT_FAILURE;
        }
        limit = *parsed_limit;
    }

    std::string error_message;
    const auto xml_events =
        eyetrace::EventLogReader::read_newest_process_creation_xmls(limit, error_message);
    if (!xml_events.has_value()) {
        std::cerr << "EyeTrace Query failed: " << error_message << '\n';
        return EXIT_FAILURE;
    }

    for (const std::string& xml : *xml_events) {
        std::cout << xml << '\n';
    }
    return 0;
}

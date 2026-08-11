#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace eyetrace {

struct EventSource {
    std::optional<std::string> provider;
    std::optional<std::string> channel;
    std::optional<std::uint32_t> event_id;
    std::optional<std::uint64_t> record_id;
};

struct ProcessDetails {
    std::optional<std::string> guid;
    std::optional<std::uint32_t> pid;
    std::optional<std::string> image;
    std::optional<std::string> command_line;
    std::optional<std::string> current_directory;
    std::optional<std::string> user;
    std::optional<std::string> integrity_level;
    std::optional<std::string> hashes;
};

struct ParentProcessDetails {
    std::optional<std::string> guid;
    std::optional<std::uint32_t> pid;
    std::optional<std::string> image;
    std::optional<std::string> command_line;
};

// This is the stable, Windows-API-independent representation used by output
// and future collectors.
struct TelemetryEvent {
    std::string schema_version{"0.1"};
    std::optional<std::string> timestamp;
    EventSource source;
    std::optional<std::string> host_name;
    ProcessDetails process;
    ParentProcessDetails parent;
};

}  // namespace eyetrace

#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::query {

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

struct NetworkDetails {
    std::optional<std::string> protocol;
    std::optional<std::string> initiated;
    std::optional<std::string> source_ip;
    std::optional<std::uint32_t> source_port;
    std::optional<std::string> destination_ip;
    std::optional<std::uint32_t> destination_port;
    std::optional<std::string> destination_hostname;
};

struct FileDetails {
    std::optional<std::string> path;
    std::optional<std::string> creation_utc;
};

struct RegistryDetails {
    std::optional<std::string> operation;
    std::optional<std::string> target_object;
    std::optional<std::string> details;
    std::optional<std::string> new_name;
};

// This is the stable, Windows-API-independent representation used by output
// and future collectors.
struct TelemetryEvent {
    std::string schema_version{"0.1"};
    std::optional<std::string> timestamp;
    EventSource source;
    std::optional<std::string> host_name;
    std::string category;
    std::string type;
    ProcessDetails process;
    ParentProcessDetails parent;
    std::optional<NetworkDetails> network;
    std::optional<FileDetails> file;
    std::optional<RegistryDetails> registry;
};

}  // namespace panopticon::officer::query

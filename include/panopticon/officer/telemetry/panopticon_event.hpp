#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::telemetry {

inline constexpr char kSchemaVersion[] = "0.1";
inline constexpr char kAgentVersion[] = "0.1.0";

struct EventMetadata {
    std::string id;
    std::string category;
    std::string type;
    std::string timestamp;
    bool operator==(const EventMetadata&) const = default;
};

struct AgentMetadata {
    std::string id;
    std::string version;
    bool operator==(const AgentMetadata&) const = default;
};

struct OperatingSystemMetadata {
    std::string name;
    std::string build;
    bool operator==(const OperatingSystemMetadata&) const = default;
};

struct HostMetadata {
    std::string id;
    std::string hostname;
    OperatingSystemMetadata os;
    bool operator==(const HostMetadata&) const = default;
};

struct UserMetadata {
    std::optional<std::string> name;
    std::optional<std::string> domain;
    std::optional<std::string> sid;
    bool operator==(const UserMetadata&) const = default;
};

struct ParentProcessMetadata {
    std::optional<std::string> entity_id;
    std::optional<std::uint32_t> pid;
    std::optional<std::string> name;
    bool operator==(const ParentProcessMetadata&) const = default;
};

struct ProcessHashMetadata {
    std::optional<std::string> sha256;
    bool operator==(const ProcessHashMetadata&) const = default;
};

struct ProcessMetadata {
    std::string entity_id;
    std::uint32_t pid{};
    std::optional<std::string> name;
    std::optional<std::string> executable;
    std::optional<std::string> command_line;
    ParentProcessMetadata parent;
    ProcessHashMetadata hash;
    bool operator==(const ProcessMetadata&) const = default;
};

struct PanopticonEvent {
    std::string schema_version{kSchemaVersion};
    EventMetadata event;
    AgentMetadata agent;
    HostMetadata host;
    UserMetadata user;
    ProcessMetadata process;
    bool operator==(const PanopticonEvent&) const = default;
};

}  // namespace panopticon::officer::telemetry

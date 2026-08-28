#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace panopticon::officer::telemetry {

inline constexpr char kSchemaVersion[] = "0.3";
inline constexpr char kAgentVersion[] = "0.3.0";

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

struct SourceMetadata {
    std::string kind;
    std::string provider;
    std::optional<std::string> channel;
    std::optional<std::uint64_t> record_id;
    bool operator==(const SourceMetadata&) const = default;
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

// -- V3 optional telemetry-family blocks --------------------------------
// Present only on events of the matching category. Field names match the
// Schema 0.3 contract and the detection-engine rule vocabulary.

struct NetworkMetadata {
    std::string direction;  // "inbound" | "outbound"
    std::optional<std::string> protocol;  // "tcp" | "udp" | null
    std::optional<std::string> source_ip;
    std::optional<std::uint16_t> source_port;
    std::optional<std::string> destination_ip;
    std::optional<std::uint16_t> destination_port;
    std::optional<std::string> destination_hostname;
    bool operator==(const NetworkMetadata&) const = default;
};

struct FileMetadata {
    std::string operation;  // "create" | "delete" | "rename"
    std::optional<std::string> path;
    std::optional<std::string> target_path;
    std::optional<std::string> previous_path;
    ProcessHashMetadata hash;
    bool operator==(const FileMetadata&) const = default;
};

struct RegistryMetadata {
    std::string operation;  // "add_key" | "delete_key" | "set_value" | "rename_key"
    std::optional<std::string> key_path;
    std::optional<std::string> value_name;
    std::optional<std::string> value_type;
    std::optional<std::string> value_data;  // metadata-only; usually null
    bool operator==(const RegistryMetadata&) const = default;
};

struct ImageLoadMetadata {
    std::optional<std::string> path;
    std::optional<bool> is_signed;
    std::optional<std::string> signature_status;
    ProcessHashMetadata hash;
    bool operator==(const ImageLoadMetadata&) const = default;
};

struct PanopticonEvent {
    std::string schema_version{kSchemaVersion};
    EventMetadata event;
    SourceMetadata source;
    AgentMetadata agent;
    HostMetadata host;
    UserMetadata user;
    ProcessMetadata process;
    // Exactly one of these is set, matching event.category; all unset for a
    // plain process event (Schema 0.2 shape).
    std::optional<NetworkMetadata> network;
    std::optional<FileMetadata> file;
    std::optional<RegistryMetadata> registry;
    std::optional<ImageLoadMetadata> image_load;
    bool operator==(const PanopticonEvent&) const = default;
};

}  // namespace panopticon::officer::telemetry

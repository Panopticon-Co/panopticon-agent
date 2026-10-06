#include "panopticon/officer/core/process_instance.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "panopticon/officer/pipeline/normalizer.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstring>
#include <stdexcept>

namespace panopticon::officer::core {
namespace {
std::string field(const std::string& value) { return std::to_string(value.size()) + ":" + value; }
std::string identity(const std::string& value) {
    std::string error;
    const auto hash = sha256_hex(value, error);
    if (!hash) throw std::runtime_error(error);
    return "proc_" + *hash;
}
}
nlohmann::json ProcessReference::json() const {
    // Decimal strings preserve opaque 64-bit tokens in JavaScript consumers.
    return {{"observed_pid", observed_pid}, {"entity_id", entity_id ? nlohmann::json(*entity_id) : nlohmann::json(nullptr)},
        {"resolution", resolution}, {"native_creation_ticks", native_creation_ticks ? nlohmann::json(std::to_string(*native_creation_ticks)) : nlohmann::json(nullptr)},
        {"source_guid", source_guid ? nlohmann::json(*source_guid) : nlohmann::json(nullptr)},
        {"boot_id", boot_id ? nlohmann::json(*boot_id) : nlohmann::json(nullptr)}, {"source_namespace", source_namespace}};
}
ProcessInstanceStore::ProcessInstanceStore(std::string host_id, std::optional<std::string> boot_id, std::size_t resident_limit)
    : host_id_(std::move(host_id)), boot_id_(std::move(boot_id)), resident_limit_(resident_limit) {
    if (host_id_.empty() || !resident_limit_ || (boot_id_ && boot_id_->empty())) throw std::invalid_argument("invalid process identity scope");
}
ProcessReference ProcessInstanceStore::observe(std::uint32_t pid, std::optional<std::uint64_t> ticks,
    std::optional<std::string> guid, std::string source_namespace) {
    if (source_namespace.empty() || source_namespace.size() > 1024 || (guid && (guid->empty() || guid->size() > 256)))
        throw std::invalid_argument("invalid process source alias");
    ProcessReference reference{pid, std::nullopt, "unresolved", ticks, guid, boot_id_, source_namespace};
    if (ticks && *ticks != 0 && boot_id_) {
        reference.entity_id = identity(field("native-process-instance-v1") + field(host_id_) + field(*boot_id_) + field(std::to_string(pid)) + field(std::to_string(*ticks)));
        reference.resolution = "native_exact";
    } else if (guid) {
        reference.entity_id = identity(field("source-process-instance-v1") + field(host_id_) + field(boot_id_.value_or("unknown")) + field(source_namespace) + field(std::to_string(pid)) + field(*guid));
        reference.resolution = "source_scoped";
    } else if (ticks && *ticks != 0) {
        reference.resolution = "native_unscoped";
    }
    if (reference.entity_id) {
        std::scoped_lock lock{mutex_};
        if (!instances_.contains(*reference.entity_id) && instances_.size() >= resident_limit_) ++admission_failures_;
        else instances_.try_emplace(*reference.entity_id, Instance{reference, std::nullopt});
    }
    return reference;
}
void ProcessInstanceStore::terminate(const ProcessReference& reference, telemetry::UtcTimestamp time) {
    if (!reference.entity_id) return;
    std::scoped_lock lock{mutex_};
    const auto found = instances_.find(*reference.entity_id);
    if (found != instances_.end()) found->second.terminated_at = time;
}
nlohmann::json ProcessInstanceStore::snapshot() const {
    std::scoped_lock lock{mutex_};
    auto result = nlohmann::json::array();
    for (const auto& [id, instance] : instances_) {
        auto entry = instance.reference.json();
        entry["terminated_at"] = instance.terminated_at ? nlohmann::json(pipeline::format_utc_timestamp(*instance.terminated_at)) : nlohmann::json(nullptr);
        result.push_back(std::move(entry));
    }
    return result;
}
std::uint64_t ProcessInstanceStore::admission_failures() const {
    std::scoped_lock lock{mutex_};
    return admission_failures_;
}
std::optional<std::string> query_native_boot_id(std::string& error) {
    error.clear();
    // SystemBootEnvironmentInformation (0x5a), an internal NT information
    // class. Its layout and availability require the compatibility matrix;
    // absence is a coverage degradation, never an invented identifier.
    struct BootEnvironment { GUID identifier; ULONG firmware; ULONG padding; ULONGLONG flags; };
    static_assert(sizeof(BootEnvironment) == 32);
    using Query = LONG(NTAPI*)(ULONG, void*, ULONG, ULONG*);
    const auto module = GetModuleHandleW(L"ntdll.dll");
    const auto query = module ? reinterpret_cast<Query>(GetProcAddress(module, "NtQuerySystemInformation")) : nullptr;
    if (!query) { error = "native boot identity query unavailable"; return std::nullopt; }
    BootEnvironment environment{};
    ULONG length = 0;
    const auto status = query(0x5a, &environment, sizeof(environment), &length);
    const GUID zero{};
    if (status < 0 || length < 24 || length > sizeof(environment) || std::memcmp(&environment.identifier, &zero, sizeof(GUID)) == 0) {
        error = "native boot identity query failed or returned an unsupported layout";
        return std::nullopt;
    }
    std::string hash_error;
    const auto hash = sha256_hex(std::string_view(reinterpret_cast<const char*>(&environment.identifier), sizeof(GUID)), hash_error);
    if (!hash) { error = hash_error; return std::nullopt; }
    return "boot_" + *hash;
}
}  // namespace panopticon::officer::core

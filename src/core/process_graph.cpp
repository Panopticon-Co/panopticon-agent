#include "panopticon/officer/core/process_graph.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#include "panopticon/officer/pipeline/source_facts.hpp"
#include <charconv>
#include <limits>
#include <stdexcept>

namespace panopticon::officer::core {
namespace {
using Json = nlohmann::json;
bool identifier(const std::string& value, const std::string& prefix) {
    return value.size() == prefix.size() + 64 && value.starts_with(prefix) &&
        value.find_first_not_of("0123456789abcdef", prefix.size()) == std::string::npos;
}
std::optional<std::string> text(const Json& value, std::size_t limit) {
    if (value.is_null()) return std::nullopt;
    const auto result = value.get<std::string>();
    if (result.empty() || result.size() > limit || !pipeline::valid_utf8(result))
        throw std::invalid_argument("invalid graph identity text");
    return result;
}
std::optional<std::uint64_t> ticks(const Json& value) {
    if (value.is_null()) return std::nullopt;
    const auto string = value.get<std::string>();
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(string.data(), string.data() + string.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != string.data() + string.size() || std::to_string(result) != string)
        throw std::invalid_argument("noncanonical graph creation token");
    return result;
}
std::uint32_t pid(const Json& value) {
    if (!value.is_number_unsigned() || value.get<std::uint64_t>() > UINT32_MAX)
        throw std::invalid_argument("invalid graph PID");
    return value.get<std::uint32_t>();
}
}
ProcessGraphFact process_graph_fact(const nlohmann::json& record) {
    ProcessGraphFact result;
    try {
        if (record.at("schema_version") != "1.0" || record.at("kind") != "observation")
            throw std::invalid_argument("not a canonical observation");
        result.record_id = record.at("record_id").get<std::string>();
        if (!identifier(result.record_id, "rec_")) throw std::invalid_argument("invalid record identity");
        const auto& endpoint = record.at("endpoint");
        const auto host = text(endpoint.at("host_id"), 128);
        if (!host) throw std::invalid_argument("missing host scope");
        const auto boot = text(endpoint.at("boot_id"), 69);
        if (boot && !identifier(*boot, "boot_")) throw std::invalid_argument("invalid boot scope");
        const auto& provenance = record.at("provenance");
        const auto kind = provenance.at("kind").get<std::string>();
        if (kind != "etw" && kind != "sysmon" && kind != "windows_event_log")
            throw std::invalid_argument("not an observed process source");
        const auto provider = text(provenance.at("provider"), 512);
        const auto channel = provenance.at("channel").is_null() ? std::optional<std::string>{} :
            std::optional<std::string>{provenance.at("channel").get<std::string>()};
        if (channel && (channel->size() > 512 || !pipeline::valid_utf8(*channel)))
            throw std::invalid_argument("invalid channel");
        if (!provider) throw std::invalid_argument("missing source provider");
        const auto scope = kind + ":" + *provider + ":" + channel.value_or("");
        const auto& data = record.at("data");
        const auto& facts = data.at("source_facts");
        if (facts.at("representation") != "decoded_source_facts_v1" || facts.at("family") != "process" ||
            facts.at("source").at("kind") != kind || facts.at("source").at("provider") != *provider ||
            facts.at("source").at("channel") != provenance.at("channel"))
            throw std::invalid_argument("inconsistent source scope");
        result.stop = record.at("category") == "process_stop";
        if ((!result.stop && (record.at("category") != "process" || data.at("event").at("type") != "start")) ||
            facts.at("operation") != (result.stop ? "stop" : "start"))
            throw std::invalid_argument("inconsistent lifecycle operation");
        const auto& process = facts.at("process");
        ProcessInstanceStore derive{*host, boot, 1};
        const auto reference = derive.observe(pid(process.at("pid")), ticks(process.at("start_time_ticks")),
            text(process.at("process_guid"), 256), scope);
        if (reference.json() != record.at("subject") ||
            data.at("process").at("entity_id") != reference.json().at("entity_id") ||
            data.at("process").at("pid") != process.at("pid") ||
            data.at("process").at("start_time_ticks") != reference.json().at("native_creation_ticks"))
            throw std::invalid_argument("inconsistent process reference");
        if (result.stop && data.at("lifecycle").at("identity") != reference.json())
            throw std::invalid_argument("inconsistent stop reference");
        result.entity_id = reference.entity_id;
        result.identity = reference.json();
        // Stops do not supply parentage. For births, only an exact decoded
        // parent GUID plus observed PID can generate a source-scoped edge.
        if (!result.stop && !process.at("parent_pid").is_null()) {
            const auto parent = derive.observe(pid(process.at("parent_pid")), std::nullopt,
                text(process.at("parent_process_guid"), 256), scope);
            if (data.at("process").at("parent").at("identity") != parent.json() ||
                data.at("process").at("parent").at("entity_id") != parent.json().at("entity_id"))
                throw std::invalid_argument("inconsistent parent reference");
            result.parent_identity = parent.json();
            result.parent_entity_id = parent.entity_id;
        }
        result.interpretable = true;
        result.reason = result.entity_id ? "exact_reference_rederived" : "identity_unresolved";
    } catch (const Json::exception&) {
        result = {}; result.reason = "canonical_shape_refused";
    } catch (const std::invalid_argument&) {
        result = {}; result.reason = "canonical_identity_or_scope_refused";
    }
    return result;
}
} // namespace panopticon::officer::core

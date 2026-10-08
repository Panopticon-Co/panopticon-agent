#pragma once
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace panopticon::officer::core {
struct ProcessGraphFact {
    bool interpretable = false;
    bool stop = false;
    std::string record_id, reason;
    std::optional<std::string> entity_id, parent_entity_id;
    nlohmann::json identity = nullptr, parent_identity = nullptr;
};

// Re-derive references from the immutable decoded native/source facts. Never
// join a PID, rounded timestamp, live process query or a different source alias.
[[nodiscard]] ProcessGraphFact process_graph_fact(const nlohmann::json& record);
} // namespace panopticon::officer::core

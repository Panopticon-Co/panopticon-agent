#pragma once
#include "panopticon/officer/delivery/journal.hpp"
#include "panopticon/officer/response/transport.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace panopticon::officer::response {
// Dedicated identity-scoped encrypted journal. No telemetry uploader reads it.
class ResultOutbox {
public:
    explicit ResultOutbox(delivery::JournalConfig config, std::string agent, std::string host)
        : journal_(std::move(config)), agent_(std::move(agent)), host_(std::move(host)) {}
    void save(const std::string& result) {
        const auto value = nlohmann::json::parse(result);
        if (value.at("schema_version") != "2") throw std::invalid_argument("outbox requires result version 2");
        journal_.append(nlohmann::json{{"agent_id", agent_}, {"host_id", host_}, {"result", result}}.dump());
    }
    template<class Sender> void flush(Sender&& sender, std::size_t limit = 32) {
        for (std::size_t index = 0; index < limit; ++index) {
            auto batch = journal_.peek(1, 1024 * 1024);
            if (!batch) return;
            const auto wrapper = nlohmann::json::parse(batch->entries.front().body);
            if (wrapper.at("agent_id") != agent_ || wrapper.at("host_id") != host_)
                throw std::runtime_error("response outbox identity scope mismatch; evidence retained");
            if (sender(wrapper.at("result").get<std::string>()) != TransportOutcome::acknowledged) return;
            journal_.acknowledge(*batch, nlohmann::json{{"batch_id", batch->id}, {"received", 1u},
                {"accepted", 1u}, {"duplicates", 0u}, {"rejected", nlohmann::json::array()}}.dump());
        }
    }
    [[nodiscard]] std::uint64_t pending() const { return journal_.stats().pending_events; }
private:
    delivery::DurableJournal journal_;
    std::string agent_, host_;
};
}

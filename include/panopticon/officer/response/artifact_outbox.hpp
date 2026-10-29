#pragma once

#include "panopticon/officer/delivery/journal.hpp"
#include "panopticon/officer/response/transport.hpp"
#include <nlohmann/json.hpp>
#include <functional>
#include <stdexcept>
#include <utility>

namespace panopticon::officer::response {

[[nodiscard]] std::string make_artifact_payload(const std::string& command_id,
    const std::string& correlation_id, const std::string& host_id,
    const std::string& kind, const std::string& content);
[[nodiscard]] bool valid_artifact_ack(const std::string& payload, const std::string& receipt);
[[nodiscard]] std::string artifact_manifest_signing_input(const std::string& manifest);
[[nodiscard]] std::string sign_artifact_payload(const std::string& payload, const std::string& agent_id,
    const EcKeyPair& keypair, std::uint64_t produced_at_unix);
using ArtifactExchange = std::function<std::optional<std::string>(const std::string& method,
    const std::string& suffix, const std::string& content_type, const std::string& body,
    const std::string& chunk_sha256)>;
// At most four chunks per step; a progress reply never retires the durable original.
[[nodiscard]] std::optional<std::string> resume_artifact_upload(const std::string& payload,
    const ArtifactExchange& exchange, bool* made_progress = nullptr);

// Separate encrypted identity-scoped journal. Collection commits before success;
// upload retirement requires an exact artifact/digest receipt, never HTTP200 alone.
class ArtifactOutbox {
public:
    ArtifactOutbox(const std::filesystem::path& directory, std::string agent, std::string host)
        : journal_(bounded_config(directory)), agent_(std::move(agent)), host_(std::move(host)) {}
    void save(const std::string& payload) {
        const auto value = nlohmann::json::parse(payload);
        const auto& manifest = value.contains("manifest") ? value.at("manifest") : value;
        if ((manifest.at("schema_version") != "1" && manifest.at("schema_version") != "2") ||
            manifest.at("host_id") != host_ ||
            (value.contains("manifest") && manifest.at("agent_id") != agent_))
            throw std::invalid_argument("artifact outbox identity/schema disagreement");
        journal_.append(nlohmann::json{{"agent_id", agent_}, {"host_id", host_},
                                      {"artifact", payload}}.dump());
    }
    template<class Sender> std::size_t flush(Sender&& sender, std::size_t limit = 8) {
        std::size_t retired = 0;
        for (std::size_t i = 0; i < limit; ++i) {
            auto batch = journal_.peek(1, 2 * 1024 * 1024);
            if (!batch) return retired;
            const auto wrapper = nlohmann::json::parse(batch->entries.front().body);
            if (wrapper.at("agent_id") != agent_ || wrapper.at("host_id") != host_)
                throw std::runtime_error("artifact outbox scope mismatch; original retained");
            const auto payload = wrapper.at("artifact").get<std::string>();
            const auto receipt = sender(payload);
            if (!receipt || !valid_artifact_ack(payload, *receipt)) return retired;
            journal_.acknowledge(*batch, nlohmann::json{{"batch_id", batch->id}, {"received", 1u},
                {"accepted", 1u}, {"duplicates", 0u}, {"rejected", nlohmann::json::array()}}.dump());
            ++retired;
        }
        return retired;
    }
    [[nodiscard]] std::uint64_t pending() const { return journal_.stats().pending_events; }
private:
    static delivery::JournalConfig bounded_config(const std::filesystem::path& directory) {
        delivery::JournalConfig config{directory};
        config.retained_payload_limit = 64ull * 1024 * 1024;
        config.physical_admission_limit = 128ull * 1024 * 1024;
        config.event_size_limit = 1500 * 1024;
        return config;
    }
    delivery::DurableJournal journal_;
    std::string agent_, host_;
};

}  // namespace panopticon::officer::response

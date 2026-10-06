#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>
#include <deque>
#include <optional>
namespace panopticon::officer::health {
// Annotates a copied health snapshot; does not mutate committed query evidence.
void apply_state_capture_freshness(nlohmann::json& health, std::uint64_t now_uptime_ms);
// Single health-emitter owner. Front is immutable until durable acceptance.
class StateCaptureGapBuffer {
public:
    StateCaptureGapBuffer(std::size_t report_limit = 128, std::size_t byte_limit = 256 * 1024);
    void observe(const nlohmann::json& health, std::uint64_t uptime_ms);
    [[nodiscard]] bool empty() const { return reports_.empty(); }
    [[nodiscard]] bool pending() const { return !reports_.empty() || omitted_pending_ != 0; }
    [[nodiscard]] const nlohmann::json& front() const { return reports_.front().data; }
    void acknowledge_front();
    [[nodiscard]] nlohmann::json snapshot() const;
private:
    struct Report { nlohmann::json data; std::size_t bytes; };
    bool append(nlohmann::json data);
    void flush_omissions();
    nlohmann::json observed_ = nlohmann::json::object();
    nlohmann::json observed_samples_ = nlohmann::json::object();
    std::optional<std::uint64_t> last_sample_;
    std::deque<Report> reports_;
    std::size_t report_limit_, byte_limit_, bytes_ = 0;
    std::uint64_t acknowledged_ = 0, omitted_total_ = 0, omitted_pending_ = 0;
    std::uint64_t first_omitted_ = 0, last_omitted_ = 0;
};
}

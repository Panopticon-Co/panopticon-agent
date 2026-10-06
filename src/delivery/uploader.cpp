#include "panopticon/officer/delivery/uploader.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <utility>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace panopticon::officer::delivery {
namespace {
DeliveryConfig validate(DeliveryConfig config) {
    if (config.manager_url.empty() || config.batch_max_events == 0 || config.batch_max_events > 1000 ||
        config.flush_interval_ms == 0 || config.spool_base_backoff_ms == 0 ||
        config.spool_max_backoff_ms < config.spool_base_backoff_ms || config.request_timeout_ms == 0)
        throw std::invalid_argument("invalid delivery configuration");
    return config;
}
}

Uploader::Uploader(DeliveryConfig config, std::string agent_id)
    : config_(validate(std::move(config))), agent_id_(std::move(agent_id)),
      http_client_(config_.verify_tls, config_.request_timeout_ms),
      journal_({config_.spool_directory, config_.spool_max_total_bytes}) {
    if (agent_id_.empty()) throw std::invalid_argument("delivery requires an agent identity");
    worker_ = std::thread(&Uploader::run, this);
}
Uploader::~Uploader() { stop(); }

bool Uploader::enqueue(const std::string& line) {
    std::scoped_lock lock{mutex_};
    if (stop_requested_.load()) return false;
    try {
        journal_.append(line);
        health_.durability_state = "healthy";
        wake_ = true;
        cv_.notify_one();
        return true;
    } catch (const std::exception& error) {
        ++health_.commit_failures;
        health_.durability_state = "degraded";
        health_.last_error = error.what();
        std::cerr << "[delivery] observation commit failed: " << error.what() << '\n';
        return false;
    }
}
DeliveryHealth Uploader::health() const {
    std::scoped_lock lock{mutex_};
    return health_;
}
void Uploader::set_bearer_token(const std::string& agent_id, std::string token) {
    std::scoped_lock lock{mutex_};
    if (agent_id != agent_id_ || token.empty() || token.size() > 512) throw std::invalid_argument("delivery credential identity mismatch");
    config_.bearer_token = std::move(token);
    wake_ = true;
    cv_.notify_one();
}
void Uploader::set_capture_scope(nlohmann::json scope) {
    if (!scope.is_object() || scope.size() != 4 || !scope.contains("installation_id") ||
        !scope.contains("boot_id") || !scope.contains("collector_generation") || !scope.contains("collector_epoch"))
        throw std::invalid_argument("invalid factory capture scope");
    std::scoped_lock lock{mutex_};
    if (!capture_scope_.is_null()) throw std::logic_error("capture scope is immutable during a collector generation");
    capture_scope_ = std::move(scope);
}
void Uploader::stop() {
    {
        std::scoped_lock lock{mutex_};
        stop_requested_.store(true);
    }
    cv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

void Uploader::run() noexcept {
    unsigned backoff = config_.spool_base_backoff_ms;
    auto retry_at = std::chrono::steady_clock::time_point::min();
    while (!stop_requested_.load()) {
        {
            std::unique_lock lock{mutex_};
            cv_.wait_for(lock, std::chrono::milliseconds(config_.flush_interval_ms),
                         [this] { return stop_requested_.load() || wake_; });
            wake_ = false;
        }
        if (stop_requested_.load()) break;
        if (std::chrono::steady_clock::now() < retry_at) continue;
        try {
            for (unsigned count = 0; count < 64 && !stop_requested_.load(); ++count) {
                const auto outcome = deliver_one();
                if (outcome == 0) break; // empty journal does not increase retry backoff
                if (outcome < 0) {
                    retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(backoff);
                    backoff = static_cast<unsigned>(std::min<std::uint64_t>(
                        config_.spool_max_backoff_ms, static_cast<std::uint64_t>(backoff) * 2));
                    break;
                }
                backoff = config_.spool_base_backoff_ms;
            }
        } catch (const std::exception& error) {
            std::scoped_lock lock{mutex_};
            health_.durability_state = "degraded";
            health_.last_error = error.what();
            retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(config_.spool_max_backoff_ms);
            std::cerr << "[delivery] journal processing failed; evidence retained: " << error.what() << '\n';
        } catch (...) {
            std::scoped_lock lock{mutex_};
            health_.durability_state = "degraded";
            health_.last_error = "unexpected delivery worker exception";
            retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(config_.spool_max_backoff_ms);
        }
    }
}

int Uploader::deliver_one() {
    const auto batch = journal_.peek(config_.batch_max_events, 8u * 1024 * 1024);
    if (!batch) return 0;
    std::vector<HttpHeader> headers{{"Content-Type", "application/x-ndjson"},
        {"X-Panopticon-Batch-Id", batch->id}, {"X-Panopticon-Agent-Id", agent_id_}, {"X-Panopticon-Protocol", std::to_string(batch->protocol)}};
    nlohmann::json scope;
    {
        std::scoped_lock lock{mutex_};
        if (!config_.bearer_token.empty()) headers.push_back({"Authorization", "Bearer " + config_.bearer_token});
        scope = capture_scope_;
    }
    // Optional proof failure never prevents durable evidence delivery. A fresh
    // one-use challenge prevents replayed request context blessing old capture.
    if (batch->protocol == 2 && scope.is_object()) {
        bool challenge_valid = false;
        auto challenge_headers = headers;
        challenge_headers[0].value = "application/json";
        std::string challenge_error;
        const auto challenge = http_client_.post(config_.manager_url + "/api/v2/endpoint/freshness-challenge", challenge_headers, "{}", challenge_error);
        if (challenge && challenge->status_code == 200) {
            const auto proof = nlohmann::json::parse(challenge->body, nullptr, false);
            if (proof.is_object() && proof.contains("nonce") && proof["nonce"].is_string()) {
                const auto nonce = proof["nonce"].get<std::string>();
                if (nonce.size() == 64 && std::all_of(nonce.begin(), nonce.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })) {
                    scope["send_uptime_ms"] = std::to_string(GetTickCount64());
                    headers.push_back({"X-Panopticon-Freshness-Nonce", nonce});
                    headers.push_back({"X-Panopticon-Capture-Context", scope.dump()});
                    challenge_valid = true;
                }
            }
        }
        if (!challenge_valid) {
            std::scoped_lock lock{mutex_};
            ++health_.freshness_challenge_failures;
            health_.capture_age_state = "unavailable";
        }
    }
    std::string error;
    const auto response = http_client_.post(config_.manager_url + (batch->protocol == 2 ? "/api/v2/endpoint/records" : "/api/v1/ingest"), headers, batch->ndjson(), error);
    if (!response || response->status_code != 200) {
        std::scoped_lock lock{mutex_};
        ++health_.transport_failures;
        health_.transport_state = "degraded";
        health_.last_error = response ? "manager status " + std::to_string(response->status_code) : error;
        return -1;
    }
    try {
        journal_.acknowledge(*batch, response->body);
    } catch (const std::exception& receipt_error) {
        std::scoped_lock lock{mutex_};
        ++health_.invalid_receipts;
        health_.transport_state = "degraded";
        health_.last_error = receipt_error.what();
        return -1;
    }
    std::scoped_lock lock{mutex_};
    health_.transport_state = "healthy";
    if (batch->protocol == 2) {
        const auto receipt = nlohmann::json::parse(response->body, nullptr, false);
        health_.capture_age_state = receipt.is_object() && receipt.contains("capture_age_records") &&
            receipt["capture_age_records"].is_number_unsigned() && receipt["capture_age_records"].get<std::uint64_t>() > 0 &&
            receipt["capture_age_records"].get<std::uint64_t>() <= batch->entries.size() ? "healthy" : "unavailable";
    }
    return 1;
}
}  // namespace panopticon::officer::delivery

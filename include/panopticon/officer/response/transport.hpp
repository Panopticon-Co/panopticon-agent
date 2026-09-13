#pragma once

#include "panopticon/officer/response/identity.hpp"

#include <cstddef>
#include <optional>
#include <string>

namespace panopticon::officer::response {

enum class TransportOutcome { acknowledged, retryable, authentication_failed, rejected };

// WinHTTP-based counterpart to panopticon-linux-agent's curl_https_client,
// covering exactly the four response-path operations: enroll, poll_commands,
// accept_command (best-effort), submit_command_result. Built on the same
// panopticon::officer::delivery::HttpClient the existing telemetry Uploader
// already uses (see delivery/http_client.hpp's new request() verb entry
// point) rather than a second parallel HTTP stack. Always verifies the TLS
// certificate chain -- unlike the telemetry HttpClient, this class has no
// insecure-TLS constructor parameter at all, so a response-path caller can
// never accidentally disable certificate validation.
class ResponseTransportClient {
public:
    explicit ResponseTransportClient(unsigned timeout_ms = 15000, std::size_t maximum_response_bytes = 65536);

    // Bootstrap is a separate operation, same as the Linux agent: the
    // bootstrap secret is sent only once, over verified TLS, and is never
    // itself persisted as the ongoing credential.
    [[nodiscard]] std::optional<EnrolledIdentity> enroll(const std::string& manager_url, const std::string& agent_id,
                                                          const std::string& host_id,
                                                          const std::string& bootstrap_token,
                                                          std::string& error_message) const;
    [[nodiscard]] std::optional<std::string> poll_commands(const std::string& manager_url,
                                                             const EnrolledIdentity& identity,
                                                             std::string& error_message) const;
    // Best-effort DISPATCHED -> ACCEPTED acknowledgement; the outcome is
    // intentionally not distinguished beyond acknowledged/not, mirroring
    // the Linux agent's "ignore and proceed to execute regardless" contract.
    [[nodiscard]] TransportOutcome accept_command(const std::string& manager_url, const EnrolledIdentity& identity,
                                                   const std::string& command_id) const;
    [[nodiscard]] TransportOutcome submit_command_result(const std::string& manager_url,
                                                          const EnrolledIdentity& identity,
                                                          const std::string& payload) const;

private:
    unsigned timeout_ms_;
    std::size_t maximum_response_bytes_;
};

}  // namespace panopticon::officer::response

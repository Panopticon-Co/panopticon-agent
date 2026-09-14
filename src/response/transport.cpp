#include "panopticon/officer/response/transport.hpp"
#include "panopticon/officer/delivery/http_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>

#include <nlohmann/json.hpp>

#pragma comment(lib, "crypt32.lib")

namespace panopticon::officer::response {

namespace {

using nlohmann::json;
namespace delivery = panopticon::officer::delivery;

std::string without_trailing_slash(const std::string& url) {
    return (!url.empty() && url.back() == '/') ? url.substr(0, url.size() - 1) : url;
}

bool looks_like_https(const std::string& url) { return url.rfind("https://", 0) == 0; }

// Thin wrappers over CryptBinaryToStringA/CryptStringToBinaryA (crypt32,
// OS-shipped) -- no new base64 implementation to review or get wrong.
std::string base64_encode(const std::uint8_t* data, std::size_t size) {
    DWORD out_len = 0;
    CryptBinaryToStringA(data, static_cast<DWORD>(size), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr,
                          &out_len);
    std::string out(out_len, '\0');
    CryptBinaryToStringA(data, static_cast<DWORD>(size), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, out.data(),
                          &out_len);
    // CryptBinaryToStringA's reported length includes a trailing NUL.
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::optional<std::vector<std::uint8_t>> base64_decode(const std::string& text) {
    DWORD out_len = 0;
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, nullptr,
                               &out_len, nullptr, nullptr)) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> out(out_len);
    if (!CryptStringToBinaryA(text.c_str(), static_cast<DWORD>(text.size()), CRYPT_STRING_BASE64, out.data(),
                               &out_len, nullptr, nullptr)) {
        return std::nullopt;
    }
    out.resize(out_len);
    return out;
}

}  // namespace

ResponseTransportClient::ResponseTransportClient(const unsigned timeout_ms, const std::size_t maximum_response_bytes)
    : timeout_ms_{timeout_ms}, maximum_response_bytes_{maximum_response_bytes} {}

std::optional<std::string> ResponseTransportClient::request_enrollment_challenge(const std::string& manager_url,
                                                                                   std::string& error_message) const {
    if (!looks_like_https(manager_url)) {
        error_message = "enrollment challenge input is invalid";
        return std::nullopt;
    }
    const delivery::HttpClient client{/*verify_tls=*/true, timeout_ms_};
    std::string transport_error;
    const auto response = client.post(without_trailing_slash(manager_url) + "/api/v1/agents/enrollment-challenge",
                                       {}, "", transport_error);
    if (!response) {
        error_message = "enrollment challenge transport failure: " + transport_error;
        return std::nullopt;
    }
    if (response->status_code != 200) {
        error_message = "enrollment challenge service rejected request";
        return std::nullopt;
    }
    try {
        const auto parsed = json::parse(response->body);
        const auto nonce = parsed.value("nonce", std::string{});
        if (nonce.empty() || nonce.size() > 64U) {
            error_message = "enrollment challenge response is malformed";
            return std::nullopt;
        }
        return nonce;
    } catch (const json::exception&) {
        error_message = "enrollment challenge response is not valid JSON";
        return std::nullopt;
    }
}

std::optional<EnrolledIdentity> ResponseTransportClient::enroll(const std::string& manager_url,
                                                                 const std::string& agent_id,
                                                                 const std::string& host_id,
                                                                 const std::string& bootstrap_token,
                                                                 const EcKeyPair& keypair,
                                                                 const std::string& nonce_b64,
                                                                 std::string& error_message) const {
    if (!looks_like_https(manager_url) || !is_valid_identifier(agent_id) || !is_valid_identifier(host_id) ||
        bootstrap_token.empty() || bootstrap_token.size() > 512U || nonce_b64.empty()) {
        error_message = "enrollment input is invalid";
        return std::nullopt;
    }
    const auto nonce_raw = base64_decode(nonce_b64);
    if (!nonce_raw) {
        error_message = "enrollment challenge nonce is not valid base64";
        return std::nullopt;
    }
    const auto signature = sign_raw(keypair, *nonce_raw, error_message);
    if (!signature) {
        return std::nullopt;
    }

    // TLS verification is never optional on this path -- see the class
    // comment in transport.hpp.
    const delivery::HttpClient client{/*verify_tls=*/true, timeout_ms_};
    const json body = {
        {"agent_id", agent_id},
        {"host_id", host_id},
        {"public_key", base64_encode(keypair.public_point.data(), keypair.public_point.size())},
        {"nonce", nonce_b64},
        {"signature", base64_encode(signature->data(), signature->size())},
    };
    const std::vector<delivery::HttpHeader> headers = {
        {"Content-Type", "application/json"},
        {"X-Panopticon-Enrollment-Token", bootstrap_token},
    };
    std::string transport_error;
    const auto response = client.post(without_trailing_slash(manager_url) + "/api/v1/agents/enroll", headers,
                                       body.dump(), transport_error);
    if (!response) {
        error_message = "enrollment transport failure: " + transport_error;
        return std::nullopt;
    }
    if (response->status_code == 401 || response->status_code == 403) {
        error_message = "enrollment credential rejected";
        return std::nullopt;
    }
    if (response->status_code != 200) {
        error_message = "enrollment service rejected request";
        return std::nullopt;
    }
    try {
        const auto parsed = json::parse(response->body);
        const auto returned_agent = parsed.value("agent_id", std::string{});
        const auto access_token = parsed.value("access_token", std::string{});
        if (returned_agent != agent_id || access_token.empty() || access_token.size() > 512U) {
            error_message = "enrollment response is malformed";
            return std::nullopt;
        }
        return EnrolledIdentity{agent_id, host_id, access_token};
    } catch (const json::exception&) {
        error_message = "enrollment response is not valid JSON";
        return std::nullopt;
    }
}

std::optional<std::string> ResponseTransportClient::poll_commands(const std::string& manager_url,
                                                                    const EnrolledIdentity& identity,
                                                                    std::string& error_message) const {
    if (!looks_like_https(manager_url) || !is_valid_identifier(identity.agent_id) || identity.bearer_token.empty() ||
        identity.bearer_token.size() > 512U) {
        error_message = "command polling input is invalid";
        return std::nullopt;
    }
    const delivery::HttpClient client{/*verify_tls=*/true, timeout_ms_};
    const std::vector<delivery::HttpHeader> headers = {{"Authorization", "Bearer " + identity.bearer_token}};
    const auto endpoint =
        without_trailing_slash(manager_url) + "/api/v1/agents/" + identity.agent_id + "/commands";
    std::string transport_error;
    const auto response = client.request("GET", endpoint, headers, "", transport_error);
    if (!response) {
        error_message = "command poll transport failure: " + transport_error;
        return std::nullopt;
    }
    if (response->status_code != 200) {
        error_message = "manager rejected command poll (status " + std::to_string(response->status_code) + ")";
        return std::nullopt;
    }
    if (response->body.size() > maximum_response_bytes_) {
        error_message = "command poll response exceeds bounds";
        return std::nullopt;
    }
    return response->body;
}

TransportOutcome ResponseTransportClient::accept_command(const std::string& manager_url,
                                                          const EnrolledIdentity& identity,
                                                          const std::string& command_id) const {
    if (!looks_like_https(manager_url) || !is_valid_identifier(identity.agent_id) ||
        !is_valid_identifier(command_id) || identity.bearer_token.empty()) {
        return TransportOutcome::rejected;
    }
    const delivery::HttpClient client{/*verify_tls=*/true, timeout_ms_};
    const std::vector<delivery::HttpHeader> headers = {{"Authorization", "Bearer " + identity.bearer_token}};
    const auto endpoint = without_trailing_slash(manager_url) + "/api/v1/agents/" + identity.agent_id +
                          "/commands/" + command_id + "/accept";
    std::string transport_error;
    const auto response = client.post(endpoint, headers, "", transport_error);
    if (!response) return TransportOutcome::retryable;
    if (response->status_code == 401 || response->status_code == 403) return TransportOutcome::authentication_failed;
    if (response->status_code != 200) return TransportOutcome::rejected;
    return TransportOutcome::acknowledged;
}

TransportOutcome ResponseTransportClient::submit_command_result(const std::string& manager_url,
                                                                 const EnrolledIdentity& identity,
                                                                 const std::string& payload) const {
    if (!looks_like_https(manager_url) || !is_valid_identifier(identity.agent_id) || identity.bearer_token.empty() ||
        payload.empty() || payload.size() > maximum_response_bytes_) {
        return TransportOutcome::rejected;
    }
    const delivery::HttpClient client{/*verify_tls=*/true, timeout_ms_};
    const std::vector<delivery::HttpHeader> headers = {
        {"Content-Type", "application/json"},
        {"Authorization", "Bearer " + identity.bearer_token},
    };
    const auto endpoint =
        without_trailing_slash(manager_url) + "/api/v1/agents/" + identity.agent_id + "/command-results";
    std::string transport_error;
    const auto response = client.post(endpoint, headers, payload, transport_error);
    if (!response) return TransportOutcome::retryable;
    if (response->status_code == 401 || response->status_code == 403) return TransportOutcome::authentication_failed;
    if (response->status_code != 200) return TransportOutcome::rejected;
    return TransportOutcome::acknowledged;
}

}  // namespace panopticon::officer::response

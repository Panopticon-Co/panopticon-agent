#include "panopticon/officer/response/artifact_outbox.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "panopticon/officer/response/transport.hpp"
#include "panopticon/officer/delivery/http_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>

#include <nlohmann/json.hpp>
#include <set>
#include <algorithm>

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
                                                                    std::string& error_message,
                                                                    const std::string& response_profile) const {
    if (!looks_like_https(manager_url) || !is_valid_identifier(identity.agent_id) || identity.bearer_token.empty() ||
        identity.bearer_token.size() > 512U) {
        error_message = "command polling input is invalid";
        return std::nullopt;
    }
    const delivery::HttpClient client{/*verify_tls=*/true, timeout_ms_};
    std::vector<delivery::HttpHeader> headers = {{"Authorization", "Bearer " + identity.bearer_token}};
    if (!response_profile.empty()) {
        const auto encoded = base64_encode(reinterpret_cast<const std::uint8_t*>(response_profile.data()), response_profile.size());
        if (encoded.size() > 4096U) { error_message = "response profile exceeds header bound"; return std::nullopt; }
        headers.push_back({"X-Panopticon-Response-Profile", encoded});
    }
    const auto endpoint =
        without_trailing_slash(manager_url) + "/api/v1/agents/" + identity.agent_id + "/commands?delivery_mode=durable";
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
    return valid_collection_accept_ack(command_id, response->body)
        ? TransportOutcome::acknowledged : TransportOutcome::rejected;
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
    return valid_result_ack(payload, response->body) ? TransportOutcome::acknowledged : TransportOutcome::retryable;
}

std::string make_artifact_payload(const std::string& command_id, const std::string& correlation_id,
                                 const std::string& host_id, const std::string& kind,
                                 const std::string& content) {
    if (content.empty() || content.size() > 1024U * 1024U)
        throw std::invalid_argument("structured artifact exceeds content bound");
    const auto document = json::parse(content);
    if (!document.is_object() && !document.is_array())
        throw std::invalid_argument("structured artifact requires JSON object/array");
    std::string error;
    const auto digest = core::sha256_hex(content, error);
    if (!digest) throw std::runtime_error("artifact SHA-256 failed: " + error);
    std::string material = "response-artifact-v1\n";
    for (const auto& field : {command_id, correlation_id, kind, *digest})
        material += std::to_string(field.size()) + ":" + field;
    const auto identity = core::sha256_hex(material, error);
    if (!identity) throw std::runtime_error("artifact identity hash failed: " + error);
    return json{{"schema_version", "1"}, {"artifact_id", "art_" + *identity},
        {"command_id", command_id}, {"correlation_id", correlation_id}, {"host_id", host_id},
        {"kind", kind}, {"media_type", "application/json"}, {"content_bytes", content.size()},
        {"sha256", *digest}, {"content_base64", base64_encode(
            reinterpret_cast<const std::uint8_t*>(content.data()), content.size())}}.dump();
}

std::string artifact_manifest_signing_input(const std::string& manifest_json) {
    const auto manifest = json::parse(manifest_json);
    if (manifest.size() != 12 || manifest.at("schema_version") != "2" ||
        manifest.at("authorization").size() != 3 || manifest.at("authorization").at("algorithm") != "ES256")
        throw std::invalid_argument("invalid closed signed artifact manifest");
    std::string input = "panopticon-response-artifact-auth/2\n";
    for (const auto* name : {"schema_version", "artifact_id", "agent_id", "host_id", "command_id",
            "correlation_id", "kind", "media_type", "content_bytes", "sha256", "produced_at_unix",
            "algorithm", "key_id"}) {
        const auto& field = (std::string_view{name} == "algorithm" || std::string_view{name} == "key_id")
            ? manifest.at("authorization").at(name) : manifest.at(name);
        const bool numeric = std::string_view{name} == "content_bytes" || std::string_view{name} == "produced_at_unix";
        if (numeric && !field.is_number_unsigned()) throw std::invalid_argument("invalid artifact integer");
        const auto value = numeric ? std::to_string(field.get<std::uint64_t>()) : field.get<std::string>();
        input += std::string{name} + ":" + std::to_string(value.size()) + ":" + value + "\n";
    }
    return input;
}

std::string sign_artifact_payload(const std::string& payload, const std::string& agent_id,
    const EcKeyPair& keypair, const std::uint64_t produced_at_unix) {
    auto manifest = json::parse(payload);
    const auto content = manifest.at("content_base64");
    manifest.erase("content_base64");
    manifest["schema_version"] = "2";
    manifest["agent_id"] = agent_id;
    manifest["produced_at_unix"] = produced_at_unix;
    std::string error;
    const auto key_digest = core::sha256_hex(std::string{
        reinterpret_cast<const char*>(keypair.public_point.data()), keypair.public_point.size()}, error);
    if (!key_digest) throw std::runtime_error("artifact key identity failed: " + error);
    manifest["authorization"] = json{{"algorithm", "ES256"}, {"key_id", key_digest->substr(0,16)},
        {"signature", base64_encode(std::vector<std::uint8_t>(64).data(), 64)}};
    const auto input = artifact_manifest_signing_input(manifest.dump());
    const auto signed_bytes = sign_raw(keypair, std::vector<std::uint8_t>(input.begin(), input.end()), error);
    if (!signed_bytes) throw std::runtime_error("artifact signature failed: " + error);
    manifest["authorization"]["signature"] = base64_encode(signed_bytes->data(), signed_bytes->size());
    return json{{"manifest", manifest}, {"content_base64", content}}.dump();
}

bool valid_artifact_ack(const std::string& payload, const std::string& receipt) {
    if (receipt.size() > 4096U) return false;
    try {
        const auto sent = json::parse(payload);
        const auto& manifest = sent.contains("manifest") ? sent.at("manifest") : sent;
        std::set<std::string> keys;
        bool ambiguous = false;
        const auto ack = json::parse(receipt, [&](int depth, json::parse_event_t event, json& value) {
            if (depth > 1) ambiguous = true;
            if (event == json::parse_event_t::key && !keys.insert(value.get<std::string>()).second) ambiguous = true;
            return true;
        });
        return !ambiguous && ack.is_object() && ack.size() == 3 && ack.contains("retained") &&
            ack["retained"].is_boolean() && ack["retained"] == true &&
            ack.contains("artifact_id") && ack["artifact_id"].is_string() &&
            ack["artifact_id"] == manifest.at("artifact_id") && ack.contains("sha256") &&
            ack["sha256"].is_string() && ack["sha256"] == manifest.at("sha256");
    } catch (const json::exception&) { return false; }
}

std::optional<std::string> resume_artifact_upload(const std::string& payload,
    const ArtifactExchange& exchange, bool* made_progress) {
    if (made_progress) *made_progress = false;
    if (payload.size() > 1500U * 1024U) return std::nullopt;
    try {
        const auto envelope = json::parse(payload);
        if (!envelope.is_object() || envelope.size() != 2) return std::nullopt;
        const auto manifest = envelope.at("manifest");
        (void)artifact_manifest_signing_input(manifest.dump());
        const auto id = manifest.at("artifact_id").get<std::string>();
        const auto sha = manifest.at("sha256").get<std::string>();
        const auto hexadecimal = [](const std::string& value) {
            return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
        };
        if (!id.starts_with("art_") || !hexadecimal(id.substr(4)) || !hexadecimal(sha)) return std::nullopt;
        const auto encoded = envelope.at("content_base64").get<std::string>();
        const auto decoded = base64_decode(encoded);
        if (!decoded || decoded->empty() || decoded->size() > 1024U * 1024U ||
            decoded->size() != manifest.at("content_bytes").get<std::uint64_t>() ||
            base64_encode(decoded->data(), decoded->size()) != encoded) return std::nullopt;
        const std::string content(reinterpret_cast<const char*>(decoded->data()), decoded->size());
        std::string error;
        const auto actual_sha = core::sha256_hex(content, error);
        if (!actual_sha || *actual_sha != sha) return std::nullopt;
        std::string manifest_sha;
        const auto read_progress = [&](const std::string& body) -> std::optional<std::size_t> {
            if (body.size() > 4096U) return std::nullopt;
            std::set<std::string> keys; bool ambiguous = false;
            const auto value = json::parse(body, [&](int depth, json::parse_event_t event, json& item) {
                if (depth > 1) ambiguous = true;
                if (event == json::parse_event_t::key && !keys.insert(item.get<std::string>()).second)
                    ambiguous = true;
                return true;
            });
            if (ambiguous || !value.is_object() || value.size() != 8 || value.at("schema_version") != "1" ||
                value.at("artifact_id") != id || value.at("sha256") != sha ||
                !value.at("manifest_sha256").is_string() || !value.at("received_bytes").is_number_unsigned() ||
                !value.at("chunk_bytes").is_number_unsigned() || value.at("chunk_bytes") != 65536U ||
                !value.at("complete").is_boolean()) return std::nullopt;
            const auto digest = value.at("manifest_sha256").get<std::string>();
            if (!hexadecimal(digest) || (!manifest_sha.empty() && digest != manifest_sha)) return std::nullopt;
            const auto received = value.at("received_bytes").get<std::uint64_t>();
            const bool complete = value.at("complete").get<bool>();
            if (received > content.size() || (received != content.size() && received % 65536U != 0) ||
                (complete && (received != content.size() || !value.at("expires_at").is_null())) ||
                (!complete && (!value.at("expires_at").is_string() || value.at("expires_at").get<std::string>().empty())))
                return std::nullopt;
            manifest_sha = digest;
            return static_cast<std::size_t>(received);
        };
        const auto admitted = exchange("POST", "", "application/json",
            json{{"schema_version", "1"}, {"manifest", manifest}}.dump(), "");
        if (!admitted) return std::nullopt;
        auto received = read_progress(*admitted);
        if (!received) return std::nullopt;
        for (unsigned step = 0; step < 4 && *received < content.size(); ++step) {
            const auto part = content.substr(*received, 65536U);
            const auto digest = core::sha256_hex(part, error);
            if (!digest) return std::nullopt;
            const auto reply = exchange("PUT", "/" + id + "/chunks/" + std::to_string(*received),
                "application/octet-stream", part, *digest);
            if (!reply) return std::nullopt;
            const auto next = read_progress(*reply);
            if (!next || *next != *received + part.size()) return std::nullopt;
            received = next;
            if (made_progress) *made_progress = true;
        }
        if (*received != content.size()) return std::nullopt;
        const auto receipt = exchange("POST", "/" + id + "/complete", "application/json",
            json{{"schema_version", "1"}, {"manifest_sha256", manifest_sha}}.dump(), "");
        return receipt && valid_artifact_ack(payload, *receipt) ? receipt : std::nullopt;
    } catch (const std::exception&) { return std::nullopt; }
}

std::optional<std::string> ResponseTransportClient::submit_artifact(const std::string& manager_url,
    const EnrolledIdentity& identity, const std::string& payload, bool* made_progress) const {
    if (!looks_like_https(manager_url) || !is_valid_identifier(identity.agent_id) ||
        identity.bearer_token.empty() || payload.size() > 1500U * 1024U) return std::nullopt;
    try {
        const auto value = json::parse(payload);
        const auto command_id = value.at("manifest").at("command_id").get<std::string>();
        if (!is_valid_identifier(command_id)) return std::nullopt;
        const delivery::HttpClient client{/*verify_tls=*/true, std::min(timeout_ms_, 5000u)};
        const auto base = without_trailing_slash(manager_url) + "/api/v1/agents/" +
            identity.agent_id + "/commands/" + command_id + "/artifact-transfers";
        return resume_artifact_upload(payload, [&](const std::string& method, const std::string& suffix,
                const std::string& type, const std::string& body, const std::string& digest) -> std::optional<std::string> {
            std::vector<delivery::HttpHeader> headers = {{"Content-Type", type},
                {"Authorization", "Bearer " + identity.bearer_token}};
            if (!digest.empty()) headers.push_back({"X-Panopticon-Chunk-SHA256", digest});
            std::string error;
            const auto reply = client.request(method, base + suffix, headers, body, error);
            if (!reply || reply->status_code != 200 || reply->body.size() > 4096U) return std::nullopt;
            return reply->body;
        }, made_progress);
    } catch (const json::exception&) { return std::nullopt; }
}

bool valid_collection_accept_ack(const std::string& command_id, const std::string& receipt) {
    if (receipt.size() > 4096U) return false;
    try {
        std::set<std::string> keys;
        bool ambiguous = false;
        const auto value = json::parse(receipt, [&](int depth, json::parse_event_t event, json& item) {
            if (depth > 1) ambiguous = true;
            if (event == json::parse_event_t::key && !keys.insert(item.get<std::string>()).second)
                ambiguous = true;
            return true;
        });
        return !ambiguous && value.is_object() && value.size() == 2 &&
            value.contains("command_id") && value["command_id"].is_string() && value["command_id"] == command_id &&
            value.contains("accepted") && value["accepted"].is_boolean() && value["accepted"] == true;
    } catch (const json::exception&) { return false; }
}

bool valid_result_ack(const std::string& payload, const std::string& receipt) {
    try {
        const auto sent = json::parse(payload);
        std::set<std::string> keys;
        bool ambiguous = false;
        const auto ack = json::parse(receipt, [&](int depth, json::parse_event_t event, json& value) {
            if (depth > 1) ambiguous = true;
            if (event == json::parse_event_t::key && !keys.insert(value.get<std::string>()).second) ambiguous = true;
            return true;
        });
        return !ambiguous && ack.is_object() && ack.size() == 3 &&
            ack.contains("accepted") && ack["accepted"].is_boolean() && ack["accepted"] == true &&
            ack.contains("retained") && ack["retained"].is_boolean() && ack["retained"] == true && ack.contains("result_id") &&
            ack["result_id"].is_string() && ack["result_id"] == sent.at("result_id");
    } catch (const json::exception&) { return false; }
}

}  // namespace panopticon::officer::response

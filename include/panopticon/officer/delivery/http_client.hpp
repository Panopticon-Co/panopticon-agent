#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace panopticon::officer::delivery {

struct HttpHeader {
    std::string name;
    std::string value;
};

struct HttpResponse {
    std::uint32_t status_code = 0;
    std::string body;
};

// Minimal synchronous HTTPS POST client over WinHTTP (OS-shipped, no vcpkg
// dependency). One call = one connect + request + response; no connection
// pooling or keep-alive reuse. Adequate at this project's scale -- ADR 002
// keeps at most one batch in flight per agent -- and simple enough to test
// without mocking WinHTTP.
class HttpClient {
public:
    explicit HttpClient(bool verify_tls = true, unsigned timeout_ms = 30000);

    // Returns nullopt only on a transport-level failure (DNS, connect, TLS
    // handshake, timeout) and sets error_message. A non-2xx HTTP status is
    // NOT a transport failure -- it comes back as a normal HttpResponse for
    // the caller to inspect via status_code.
    [[nodiscard]] std::optional<HttpResponse> post(
        const std::string& url,
        const std::vector<HttpHeader>& headers,
        const std::string& body,
        std::string& error_message) const;

private:
    bool verify_tls_;
    unsigned timeout_ms_;
};

}  // namespace panopticon::officer::delivery

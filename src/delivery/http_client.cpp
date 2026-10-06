#include "panopticon/officer/delivery/http_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>

#include <array>
#include <cstddef>
#include <limits>

#pragma comment(lib, "winhttp.lib")

namespace panopticon::officer::delivery {

namespace {

std::wstring utf8_to_utf16(const std::string& text) {
    if (text.empty()) {
        return std::wstring{};
    }
    const int required =
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (required == 0) return {};
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), required);
    return result;
}

class UniqueInternet {
public:
    explicit UniqueInternet(HINTERNET handle = nullptr) noexcept : handle_(handle) {}
    ~UniqueInternet() {
        if (handle_ != nullptr) {
            WinHttpCloseHandle(handle_);
        }
    }
    UniqueInternet(const UniqueInternet&) = delete;
    UniqueInternet& operator=(const UniqueInternet&) = delete;
    [[nodiscard]] HINTERNET get() const noexcept { return handle_; }

private:
    HINTERNET handle_;
};

}  // namespace

HttpClient::HttpClient(bool verify_tls, unsigned timeout_ms)
    : verify_tls_(verify_tls), timeout_ms_(timeout_ms) {}

std::optional<HttpResponse> HttpClient::post(
    const std::string& url,
    const std::vector<HttpHeader>& headers,
    const std::string& body,
    std::string& error_message) const {
    error_message.clear();
    return request("POST", url, headers, body, error_message);
}

std::optional<HttpResponse> HttpClient::request(
    const std::string& method,
    const std::string& url,
    const std::vector<HttpHeader>& headers,
    const std::string& body,
    std::string& error_message) const {
    if (method != "GET" && method != "POST") {
        error_message = "unsupported HTTP method";
        return std::nullopt;
    }
    if (body.size() > 8u * 1024 * 1024 || url.size() > 8192 || timeout_ms_ == 0 || timeout_ms_ > static_cast<unsigned>(std::numeric_limits<int>::max())) {
        error_message = "HTTP request exceeds configured bounds";
        return std::nullopt;
    }
    const std::wstring wide_method = utf8_to_utf16(method);
    const std::wstring wide_url = utf8_to_utf16(url);
    if (wide_url.empty()) {
        error_message = "manager URL is empty or invalid UTF-8";
        return std::nullopt;
    }

    std::array<wchar_t, 256> host_buffer{};
    std::array<wchar_t, 2048> path_buffer{};
    std::array<wchar_t, 4096> extra_buffer{};
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host_buffer.data();
    components.dwHostNameLength = static_cast<DWORD>(host_buffer.size());
    components.lpszUrlPath = path_buffer.data();
    components.dwUrlPathLength = static_cast<DWORD>(path_buffer.size());
    components.lpszExtraInfo = extra_buffer.data();
    components.dwExtraInfoLength = static_cast<DWORD>(extra_buffer.size());
    if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &components)) {
        error_message = "Could not parse manager URL.";
        return std::nullopt;
    }
    const bool use_tls = components.nScheme == INTERNET_SCHEME_HTTPS;
    if (!use_tls || components.dwUserNameLength || components.dwPasswordLength) {
        error_message = "manager transport requires HTTPS without URL credentials";
        return std::nullopt;
    }
    std::wstring request_path(components.lpszUrlPath, components.dwUrlPathLength);
    const std::wstring extra(components.lpszExtraInfo, components.dwExtraInfoLength);
    if (extra.find(L'#') != std::wstring::npos) {
        error_message = "manager URL cannot contain a fragment";
        return std::nullopt;
    }
    request_path += extra;

    UniqueInternet session{WinHttpOpen(
        L"officer-agent/officer-delivery",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0)};
    if (session.get() == nullptr) {
        error_message = "WinHttpOpen failed.";
        return std::nullopt;
    }
    if (!WinHttpSetTimeouts(
        session.get(),
        static_cast<int>(timeout_ms_),
        static_cast<int>(timeout_ms_),
        static_cast<int>(timeout_ms_),
        static_cast<int>(timeout_ms_))) {
        error_message = "WinHttpSetTimeouts failed";
        return std::nullopt;
    }

    UniqueInternet connection{
        WinHttpConnect(session.get(), components.lpszHostName, components.nPort, 0)};
    if (connection.get() == nullptr) {
        error_message = "WinHttpConnect failed.";
        return std::nullopt;
    }

    const DWORD request_flags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    UniqueInternet request{WinHttpOpenRequest(
        connection.get(),
        wide_method.c_str(),
        request_path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        request_flags)};
    if (request.get() == nullptr) {
        error_message = "WinHttpOpenRequest failed.";
        return std::nullopt;
    }
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY, &redirect_policy, sizeof(redirect_policy))) {
        error_message = "could not disable HTTP redirects";
        return std::nullopt;
    }

    if (use_tls && !verify_tls_) {
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                                SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        if (!WinHttpSetOption(
            request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags))) {
            error_message = "could not set explicit TLS development options";
            return std::nullopt;
        }
    }

    std::wstring header_block;
    for (const auto& header : headers) {
        if (header.name.empty() || header.name.size() > 256 || header.value.size() > 16384 ||
            header.name.find_first_of("\r\n:") != std::string::npos || header.value.find_first_of("\r\n") != std::string::npos ||
            header.name.find('\0') != std::string::npos || header.value.find('\0') != std::string::npos) {
            error_message = "invalid HTTP header";
            return std::nullopt;
        }
        header_block += utf8_to_utf16(header.name);
        header_block += L": ";
        header_block += utf8_to_utf16(header.value);
        header_block += L"\r\n";
    }

    const BOOL sent = WinHttpSendRequest(
        request.get(),
        header_block.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : header_block.c_str(),
        header_block.empty() ? 0 : static_cast<DWORD>(header_block.size()),
        body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(body.data()),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);
    if (!sent) {
        const DWORD native_error = GetLastError();
        error_message = "WinHttpSendRequest failed (Windows error " + std::to_string(native_error) + ").";
        return std::nullopt;
    }

    if (!WinHttpReceiveResponse(request.get(), nullptr)) {
        const DWORD native_error = GetLastError();
        error_message = "WinHttpReceiveResponse failed (Windows error " + std::to_string(native_error) + ").";
        return std::nullopt;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    if (!WinHttpQueryHeaders(
        request.get(),
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code,
        &status_size,
        WINHTTP_NO_HEADER_INDEX)) {
        error_message = "could not read HTTP status";
        return std::nullopt;
    }

    std::string response_body;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available)) {
            error_message = "HTTP response availability query failed";
            return std::nullopt;
        }
        if (available == 0) break;
        if (available > 1024u * 1024 - response_body.size()) {
            error_message = "HTTP response exceeds 1 MiB limit";
            return std::nullopt;
        }
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), chunk.data(), available, &read)) {
            error_message = "WinHttpReadData failed.";
            return std::nullopt;
        }
        chunk.resize(read);
        response_body += chunk;
        if (read == 0) {
            error_message = "HTTP response ended before advertised bytes were read";
            return std::nullopt;
        }
    }

    return HttpResponse{static_cast<std::uint32_t>(status_code), std::move(response_body)};
}

}  // namespace panopticon::officer::delivery

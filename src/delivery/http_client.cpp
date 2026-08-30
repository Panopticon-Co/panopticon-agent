#include "panopticon/officer/delivery/http_client.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>

#include <array>
#include <cstddef>

#pragma comment(lib, "winhttp.lib")

namespace panopticon::officer::delivery {

namespace {

std::wstring utf8_to_utf16(const std::string& text) {
    if (text.empty()) {
        return std::wstring{};
    }
    const int required =
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), required);
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
    const std::wstring wide_url = utf8_to_utf16(url);

    std::array<wchar_t, 256> host_buffer{};
    std::array<wchar_t, 2048> path_buffer{};
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host_buffer.data();
    components.dwHostNameLength = static_cast<DWORD>(host_buffer.size());
    components.lpszUrlPath = path_buffer.data();
    components.dwUrlPathLength = static_cast<DWORD>(path_buffer.size());
    if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &components)) {
        error_message = "Could not parse manager URL.";
        return std::nullopt;
    }
    const bool use_tls = components.nScheme == INTERNET_SCHEME_HTTPS;

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
    WinHttpSetTimeouts(
        session.get(),
        static_cast<int>(timeout_ms_),
        static_cast<int>(timeout_ms_),
        static_cast<int>(timeout_ms_),
        static_cast<int>(timeout_ms_));

    UniqueInternet connection{
        WinHttpConnect(session.get(), components.lpszHostName, components.nPort, 0)};
    if (connection.get() == nullptr) {
        error_message = "WinHttpConnect failed.";
        return std::nullopt;
    }

    const DWORD request_flags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    UniqueInternet request{WinHttpOpenRequest(
        connection.get(),
        L"POST",
        components.lpszUrlPath,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        request_flags)};
    if (request.get() == nullptr) {
        error_message = "WinHttpOpenRequest failed.";
        return std::nullopt;
    }

    if (use_tls && !verify_tls_) {
        DWORD security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                                SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(
            request.get(), WINHTTP_OPTION_SECURITY_FLAGS, &security_flags, sizeof(security_flags));
    }

    std::wstring header_block;
    for (const auto& header : headers) {
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
        error_message = "WinHttpSendRequest failed.";
        return std::nullopt;
    }

    if (!WinHttpReceiveResponse(request.get(), nullptr)) {
        error_message = "WinHttpReceiveResponse failed.";
        return std::nullopt;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(
        request.get(),
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code,
        &status_size,
        WINHTTP_NO_HEADER_INDEX);

    std::string response_body;
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.get(), &available) || available == 0) {
            break;
        }
        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request.get(), chunk.data(), available, &read)) {
            error_message = "WinHttpReadData failed.";
            return std::nullopt;
        }
        chunk.resize(read);
        response_body += chunk;
    }

    return HttpResponse{static_cast<std::uint32_t>(status_code), std::move(response_body)};
}

}  // namespace panopticon::officer::delivery

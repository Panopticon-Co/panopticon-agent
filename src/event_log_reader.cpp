#include "eyetrace/event_log_reader.hpp"

#include <windows.h>
#include <winevt.h>

#include <string>
#include <vector>

namespace eyetrace {
namespace {

constexpr wchar_t kSysmonChannel[] = L"Microsoft-Windows-Sysmon/Operational";
constexpr wchar_t kProcessCreateQuery[] = L"*[System[(EventID=1)]]";

std::string wide_to_utf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                         nullptr, 0, nullptr, nullptr);
    if (size == 0) {
        return "";
    }

    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), size,
                        nullptr, nullptr);
    return result;
}

std::string win32_error_message(DWORD error) {
    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);

    std::string message = "Win32 error " + std::to_string(error);
    if (length != 0 && buffer != nullptr) {
        message += ": " + wide_to_utf8(std::wstring(buffer, length));
        LocalFree(buffer);
    }
    return message;
}

}  // namespace

std::optional<std::vector<std::string>> EventLogReader::read_newest_process_creation_xmls(
    std::size_t limit, std::string& error_message) {
    EVT_HANDLE query = EvtQuery(nullptr, kSysmonChannel, kProcessCreateQuery,
                                EvtQueryChannelPath | EvtQueryReverseDirection);
    if (query == nullptr) {
        error_message = "Could not open the Sysmon Event ID 1 query: " +
                        win32_error_message(GetLastError());
        return std::nullopt;
    }

    std::vector<std::string> xml_events;
    xml_events.reserve(limit);

    for (std::size_t index = 0; index < limit; ++index) {
        EVT_HANDLE event = nullptr;
        DWORD returned = 0;
        if (!EvtNext(query, 1, &event, INFINITE, 0, &returned)) {
            const DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                break;
            }

            EvtClose(query);
            error_message = "Could not retrieve a Sysmon event: " + win32_error_message(error);
            return std::nullopt;
        }

        DWORD characters_needed = 0;
        DWORD property_count = 0;
        if (EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &characters_needed,
                      &property_count) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            const DWORD error = GetLastError();
            EvtClose(event);
            EvtClose(query);
            error_message = "Could not determine the XML buffer size: " + win32_error_message(error);
            return std::nullopt;
        }

        std::vector<wchar_t> xml_buffer(characters_needed);
        if (!EvtRender(nullptr, event, EvtRenderEventXml,
                       static_cast<DWORD>(xml_buffer.size() * sizeof(wchar_t)), xml_buffer.data(),
                       &characters_needed, &property_count)) {
            const DWORD error = GetLastError();
            EvtClose(event);
            EvtClose(query);
            error_message = "Could not render the Sysmon event as XML: " + win32_error_message(error);
            return std::nullopt;
        }

        EvtClose(event);
        xml_events.push_back(wide_to_utf8(std::wstring(xml_buffer.data())));
    }

    EvtClose(query);
    if (xml_events.empty()) {
        error_message = "The Sysmon channel contains no Event ID 1 records.";
        return std::nullopt;
    }

    return xml_events;
}

}  // namespace eyetrace

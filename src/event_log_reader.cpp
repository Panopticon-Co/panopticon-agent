#include "eyetrace/event_log_reader.hpp"
#include "eyetrace/win_event_handle.hpp"

#include <windows.h>
#include <winevt.h>

#include <string>
#include <vector>

namespace eyetrace {
namespace {

constexpr wchar_t kSysmonChannel[] = L"Microsoft-Windows-Sysmon/Operational";
std::wstring event_id_query(std::uint32_t event_id) {
    return L"*[System[(EventID=" + std::to_wstring(event_id) + L")]]";
}

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

std::string query_error_message(DWORD error) {
    if (error == ERROR_EVT_CHANNEL_NOT_FOUND) {
        return "Sysmon channel not found. Install Sysmon and verify Microsoft-Windows-Sysmon/Operational exists.";
    }
    if (error == ERROR_ACCESS_DENIED) {
        return "Access denied reading the Sysmon channel. Run from an elevated session or grant Event Log Readers access.";
    }
    if (error == ERROR_EVT_INVALID_QUERY) {
        return "The Event Log XPath query was rejected. Check the requested event ID and query syntax.";
    }
    return win32_error_message(error);
}

}  // namespace

std::optional<std::vector<std::string>> EventLogReader::read_newest_event_xmls(
    std::uint32_t event_id, std::size_t limit, std::string& error_message) {
    WinEventHandle query(EvtQuery(nullptr, kSysmonChannel, event_id_query(event_id).c_str(),
                                  EvtQueryChannelPath | EvtQueryReverseDirection));
    if (!query) {
        error_message = "Could not open the Sysmon event query: " + query_error_message(GetLastError());
        return std::nullopt;
    }

    std::vector<std::string> xml_events;
    xml_events.reserve(limit);

    for (std::size_t index = 0; index < limit; ++index) {
        EVT_HANDLE raw_event = nullptr;
        DWORD returned = 0;
        if (!EvtNext(query.get(), 1, &raw_event, INFINITE, 0, &returned)) {
            const DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                break;
            }

            error_message = "Could not retrieve a Sysmon event: " + win32_error_message(error);
            return std::nullopt;
        }
        WinEventHandle event(raw_event);

        DWORD characters_needed = 0;
        DWORD property_count = 0;
        if (EvtRender(nullptr, event.get(), EvtRenderEventXml, 0, nullptr, &characters_needed,
                      &property_count) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            const DWORD error = GetLastError();
            error_message = "Could not determine the XML buffer size: " + win32_error_message(error);
            return std::nullopt;
        }

        std::vector<wchar_t> xml_buffer(characters_needed);
        if (!EvtRender(nullptr, event.get(), EvtRenderEventXml,
                       static_cast<DWORD>(xml_buffer.size() * sizeof(wchar_t)), xml_buffer.data(),
                       &characters_needed, &property_count)) {
            const DWORD error = GetLastError();
            error_message = "Could not render the Sysmon event as XML: " + win32_error_message(error);
            return std::nullopt;
        }

        xml_events.push_back(wide_to_utf8(std::wstring(xml_buffer.data())));
    }

    if (xml_events.empty()) {
        error_message = "The Sysmon channel contains no Event ID 1 records.";
        return std::nullopt;
    }

    return xml_events;
}

}  // namespace eyetrace

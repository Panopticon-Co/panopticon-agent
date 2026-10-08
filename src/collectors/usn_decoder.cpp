#include "panopticon/officer/collectors/usn_journal.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <charconv>
#include <cstring>
#include <stdexcept>
#include <limits>
namespace panopticon::officer::collectors {
namespace {
using Json = nlohmann::json;
template<class T> T at(std::span<const std::byte> buffer, std::size_t offset) {
    if (offset > buffer.size() || sizeof(T) > buffer.size() - offset) throw std::invalid_argument("short USN field");
    T value{}; std::memcpy(&value, buffer.data() + offset, sizeof(value)); return value;
}
std::string hex(std::span<const std::byte> buffer) {
    constexpr char digits[] = "0123456789abcdef"; std::string value; value.reserve(buffer.size() * 2);
    for (const auto byte : buffer) { auto v = std::to_integer<unsigned>(byte); value += digits[v >> 4]; value += digits[v & 15]; }
    return value;
}
std::uint64_t number(const Json& value, std::uint64_t maximum) {
    if (!value.is_string()) throw std::invalid_argument("USN cursor scalar is not a string");
    const auto& s = value.get_ref<const std::string&>(); std::uint64_t result = 0;
    const auto parsed = std::from_chars(s.data(), s.data() + s.size(), result);
    if (s.empty() || (s.size() > 1 && s[0] == '0') || parsed.ec != std::errc{} || parsed.ptr != s.data() + s.size() || result > maximum)
        throw std::invalid_argument("invalid canonical USN cursor scalar");
    return result;
}
}
std::string encode_usn_cursor(UsnCursor cursor) {
    if (cursor.next_usn < 0) throw std::invalid_argument("negative USN cursor");
    return Json{{"format", "windows_usn_cursor_v1"}, {"journal_id", std::to_string(cursor.journal_id)},
        {"next_usn", std::to_string(cursor.next_usn)}}.dump();
}
UsnCursor decode_usn_cursor(const std::string& value) {
    if (value.size() > 512) throw std::invalid_argument("USN cursor copy bound");
    const auto data = Json::parse(value);
    if (!data.is_object() || data.size() != 3 || data.value("format", "") != "windows_usn_cursor_v1")
        throw std::invalid_argument("unsupported USN cursor shape/version");
    return {number(data.at("journal_id"), UINT64_MAX), static_cast<std::int64_t>(number(data.at("next_usn"), INT64_MAX))};
}
Json decode_usn_buffer(std::span<const std::byte> buffer, std::int64_t start) {
    if (start < 0 || buffer.size() < 8 || buffer.size() > 16384) throw std::invalid_argument("USN native buffer bound");
    const auto next = at<std::int64_t>(buffer, 0);
    if (next < start) throw std::invalid_argument("USN native cursor regressed");
    Json rows = Json::array(); std::int64_t last = start; std::size_t unknown = 0;
    for (std::size_t offset = 8; offset < buffer.size();) {
        const auto remaining = buffer.subspan(offset);
        const auto length = at<std::uint32_t>(remaining, 0);
        if (length < 8 || length % 8 || length > remaining.size()) throw std::invalid_argument("invalid USN record length/alignment");
        const auto record = remaining.first(length);
        const auto major = at<std::uint16_t>(record, 4), minor = at<std::uint16_t>(record, 6);
        Json row{{"major_version", major}, {"minor_version", minor}, {"record_length", length}};
        if (major != 2 && major != 3) {
            row["state"] = "unsupported"; row["reason"] = "uninterpreted_native_record_version";
            row["raw_record_hex"] = hex(record); ++unknown;
        } else {
            const std::size_t extra = major == 3 ? 16 : 0;
            if (length < 60 + extra) throw std::invalid_argument("short USN versioned record");
            const auto usn = at<std::int64_t>(record, 24 + extra);
            if (usn < last || usn >= next) throw std::invalid_argument("USN record outside requested/returned cursor interval");
            last = usn;
            const auto name_length = at<std::uint16_t>(record, 56 + extra), name_offset = at<std::uint16_t>(record, 58 + extra);
            if (name_offset < 60 + extra || name_offset % 2 || name_length % 2 || name_offset > length || name_length > length - name_offset)
                throw std::invalid_argument("invalid USN UTF-16 filename span");
            const auto name_bytes = record.subspan(name_offset, name_length);
            std::wstring native_name(name_length / 2, L'\0');
            if (name_length) std::memcpy(native_name.data(), name_bytes.data(), name_length);
            const int size = name_length ? WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, native_name.data(),
                static_cast<int>(native_name.size()), nullptr, 0, nullptr, nullptr) : 0;
            Json name = nullptr;
            if (size > 0) {
                std::string s(size, '\0');
                if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, native_name.data(), static_cast<int>(native_name.size()),
                    s.data(), size, nullptr, nullptr) != size) throw std::invalid_argument("USN filename conversion changed");
                name = std::move(s);
            } else if (!name_length) name = "";
            row["state"] = name.is_null() ? "degraded" : "healthy";
            row["usn"] = std::to_string(usn);
            row["file_id_native_bytes_hex"] = hex(record.subspan(8, major == 3 ? 16 : 8));
            row["parent_file_id_native_bytes_hex"] = hex(record.subspan(major == 3 ? 24 : 16, major == 3 ? 16 : 8));
            row["file_id_width_bits"] = major == 3 ? 128 : 64;
            row["native_timestamp_filetime_signed"] = std::to_string(at<std::int64_t>(record, 32 + extra));
            row["reason_mask"] = std::to_string(at<std::uint32_t>(record, 40 + extra));
            row["source_info_mask"] = std::to_string(at<std::uint32_t>(record, 44 + extra));
            row["security_id"] = std::to_string(at<std::uint32_t>(record, 48 + extra));
            row["file_attributes"] = std::to_string(at<std::uint32_t>(record, 52 + extra));
            row["filename"] = std::move(name); row["filename_utf16le_hex"] = hex(name_bytes);
            row["path"] = nullptr; row["process_reference"] = nullptr; row["rename_pair_verified"] = false;
        }
        rows.push_back(std::move(row)); offset += length;
    }
    return {{"format", "windows_usn_batch_v1"}, {"state", "degraded"}, {"requested_start_usn", std::to_string(start)},
        {"next_usn", std::to_string(next)}, {"entries", std::move(rows)}, {"uninterpreted_version_records", std::to_string(unknown)},
        {"native_buffer_bytes", buffer.size()}, {"raw_native_buffer_hex", hex(buffer)}, {"full_native_buffer_retained", true},
        {"process_attribution_verified", false}, {"full_file_coverage_verified", false}, {"event_boot_id", nullptr},
        {"timestamp_semantics", "per-record raw signed native FILETIME; envelope clock is capture time"}};
}
}

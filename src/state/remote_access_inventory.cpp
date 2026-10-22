#include "panopticon/officer/state/remote_access_inventory.hpp"
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include "persistence_native.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <lm.h>

#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace panopticon::officer::state {
using namespace native_persistence;

namespace {
struct NetBuffer {
    LPBYTE value = nullptr;
    ~NetBuffer() { if (value) NetApiBufferFree(value); }
    NetBuffer(const NetBuffer&) = delete;
    NetBuffer& operator=(const NetBuffer&) = delete;
    NetBuffer() = default;
};

bool within(const std::byte* base, std::size_t bytes, const void* pointer, std::size_t need) {
    if (!pointer || !base || need > bytes) return false;
    const auto p = reinterpret_cast<std::uintptr_t>(pointer);
    const auto b = reinterpret_cast<std::uintptr_t>(base);
    return p >= b && p - b <= bytes - need;
}

Json bounded_text(Pager& pager, const std::byte* base, std::size_t bytes, const wchar_t* value) {
    if (!value) return nullptr;
    if (!within(base, bytes, value, sizeof(wchar_t))) {
        pager.field({{"state", "unavailable"}, {"source", "NetAPI buffer validation"}, {"reason", "string_pointer_outside_buffer"}});
        return {{"state", "unavailable"}, {"value", nullptr}, {"reason", "string_pointer_outside_buffer"}};
    }
    const auto offset = reinterpret_cast<const std::byte*>(value) - base;
    const auto remaining_units = (bytes - static_cast<std::size_t>(offset)) / sizeof(wchar_t);
    const auto max_units = std::min(remaining_units, pager.limits.field_bytes / sizeof(wchar_t));
    std::size_t units = 0;
    while (units < max_units && value[units] != L'\0') ++units;
    if (units == max_units) {
        pager.field({{"state", "degraded"}, {"source", "NetAPI buffer validation"}, {"bound_exceeded", true}});
        return {{"state", "degraded"}, {"value", nullptr}, {"bound_exceeded", true}, {"reason", "unterminated_or_oversized_string"}};
    }
    return text(value, units);
}

bool append_sessions(Pager& pager, bool& complete) {
    DWORD resume = 0;
    for (;;) {
        if (!pager.active()) { complete = false; return false; }
        NetBuffer buffer;
        DWORD read = 0, total = 0;
        const NET_API_STATUS status = NetSessionEnum(nullptr, nullptr, nullptr, 10,
            &buffer.value, 64 * 1024, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            auto query = failure("NetSessionEnum", status, "NetAPI"); pager.field(query);
            pager.add({{"entry_kind", "smb_session_query"}, {"query", std::move(query)}, {"scope", "local_server"}});
            pager.partitions.push_back({{"partition", "smb_sessions"}, {"enumeration_complete", false}, {"reported_total", std::to_string(total)}});
            complete = false; return false;
        }
        DWORD native_bytes = 0;
        if (buffer.value) {
            if (NetApiBufferSize(buffer.value, &native_bytes) != NERR_Success ||
                static_cast<std::size_t>(native_bytes) > pager.limits.encoded_bytes * 4) {
                pager.field({{"state", "degraded"}, {"source", "NetSessionEnum buffer"}, {"bound_exceeded", true}});
                pager.add({{"entry_kind", "smb_session_query"}, {"state", "degraded"}, {"reason", "native_buffer_size_unavailable_or_excessive"}});
                complete = false; return false;
            }
        }
        const auto bytes = static_cast<std::size_t>(native_bytes);
        auto* rows = reinterpret_cast<SESSION_INFO_10*>(buffer.value);
        if (static_cast<std::uint64_t>(read) * sizeof(SESSION_INFO_10) > bytes) {
            pager.field({{"state", "unavailable"}, {"source", "NetSessionEnum buffer"}});
            pager.add({{"entry_kind", "smb_session_query"}, {"state", "unavailable"}, {"reason", "row_array_outside_buffer"}});
            complete = false; return false;
        }
        for (DWORD i = 0; i < read && pager.active(); ++i) {
            const auto* base = reinterpret_cast<const std::byte*>(buffer.value);
            Json row{{"entry_kind", "smb_server_session"}, {"scope", "local_server"},
                {"client_name", bounded_text(pager, base, bytes, rows[i].sesi10_cname)},
                {"username", bounded_text(pager, base, bytes, rows[i].sesi10_username)},
                {"session_seconds", std::to_string(rows[i].sesi10_time)},
                {"idle_seconds", std::to_string(rows[i].sesi10_idle_time)},
                {"process_entity_id", nullptr}, {"actor_identity_verified", false}};
            if (!pager.add(std::move(row))) { complete = false; return false; }
        }
        if (status == NERR_Success) break;
        if (read == 0) { complete = false; pager.partitions.push_back({{"partition", "smb_sessions"}, {"enumeration_complete", false}, {"reason", "no_progress"}}); return false; }
    }
    pager.partitions.push_back({{"partition", "smb_sessions"}, {"enumeration_complete", true}});
    return true;
}

bool append_open_files(Pager& pager, bool& complete) {
    DWORD_PTR resume = 0;
    for (;;) {
        if (!pager.active()) { complete = false; return false; }
        NetBuffer buffer;
        DWORD read = 0, total = 0;
        const NET_API_STATUS status = NetFileEnum(nullptr, nullptr, nullptr, 3,
            &buffer.value, 64 * 1024, &read, &total, &resume);
        if (status != NERR_Success && status != ERROR_MORE_DATA) {
            auto query = failure("NetFileEnum", status, "NetAPI"); pager.field(query);
            pager.add({{"entry_kind", "smb_open_file_query"}, {"query", std::move(query)}, {"scope", "local_server"}});
            pager.partitions.push_back({{"partition", "smb_open_files"}, {"enumeration_complete", false}, {"reported_total", std::to_string(total)}});
            complete = false; return false;
        }
        DWORD native_bytes = 0;
        if (buffer.value && (NetApiBufferSize(buffer.value, &native_bytes) != NERR_Success ||
            static_cast<std::size_t>(native_bytes) > pager.limits.encoded_bytes * 4)) {
            pager.field({{"state", "degraded"}, {"source", "NetFileEnum buffer"}, {"bound_exceeded", true}});
            pager.add({{"entry_kind", "smb_open_file_query"}, {"state", "degraded"}, {"reason", "native_buffer_size_unavailable_or_excessive"}});
            complete = false; return false;
        }
        const auto bytes = static_cast<std::size_t>(native_bytes);
        auto* rows = reinterpret_cast<FILE_INFO_3*>(buffer.value);
        if (static_cast<std::uint64_t>(read) * sizeof(FILE_INFO_3) > bytes) {
            pager.field({{"state", "unavailable"}, {"source", "NetFileEnum buffer"}});
            pager.add({{"entry_kind", "smb_open_file_query"}, {"state", "unavailable"}, {"reason", "row_array_outside_buffer"}});
            complete = false; return false;
        }
        for (DWORD i = 0; i < read && pager.active(); ++i) {
            const auto* base = reinterpret_cast<const std::byte*>(buffer.value);
            Json row{{"entry_kind", "smb_server_open_file"}, {"scope", "local_server"},
                {"file_id", std::to_string(rows[i].fi3_id)},
                {"permissions_mask", std::to_string(rows[i].fi3_permissions)},
                {"lock_count", std::to_string(rows[i].fi3_num_locks)},
                {"path", bounded_text(pager, base, bytes, rows[i].fi3_pathname)},
                {"username", bounded_text(pager, base, bytes, rows[i].fi3_username)},
                {"process_entity_id", nullptr}, {"file_identity_verified", false}};
            if (!pager.add(std::move(row))) { complete = false; return false; }
        }
        if (status == NERR_Success) break;
        if (read == 0) { complete = false; pager.partitions.push_back({{"partition", "smb_open_files"}, {"enumeration_complete", false}, {"reason", "no_progress"}}); return false; }
    }
    pager.partitions.push_back({{"partition", "smb_open_files"}, {"enumeration_complete", true}});
    return true;
}
}

nlohmann::json collect_remote_access_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer, NativeInventoryLimits limits,
    const std::function<bool()>& cancelled) {
    Pager pager(limits, "remote_access_inventory", consumer, cancelled, "remote_access_state_version");
    bool complete = true;
    append_sessions(pager, complete);
    if (complete && pager.active()) append_open_files(pager, complete);
    return pager.finish("local SMB server sessions and open-file records visible to this caller; no outbound client, RDP/WinRM, actor process attribution or atomic cross-query snapshot", complete);
}
}

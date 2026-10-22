#include "panopticon/officer/collectors/registry_change_watch.hpp"

#include <array>
#include <cstdio>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>

namespace panopticon::officer::collectors {
namespace {
constexpr std::size_t queue_limit = 256;
constexpr DWORD notify_filter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET |
    REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_SECURITY;
struct RootDefinition { HKEY hive; const wchar_t* path; const char* id; const char* hive_name; };
constexpr std::size_t root_count = 5;
const std::array<RootDefinition, root_count> root_definitions{{
    {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion", "hklm_current_version", "HKEY_LOCAL_MACHINE"},
    {HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion", "hkcu_current_version", "HKEY_CURRENT_USER/caller"},
    {HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", "hklm_nt_current_version", "HKEY_LOCAL_MACHINE"},
    {HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Services", "hklm_services", "HKEY_LOCAL_MACHINE"},
    {HKEY_LOCAL_MACHINE, L"System\\CurrentControlSet\\Control\\Lsa", "hklm_lsa", "HKEY_LOCAL_MACHINE"}
}};

std::string received_time_utc() {
    FILETIME file_time{};
    SYSTEMTIME time{};
    GetSystemTimeAsFileTime(&file_time);
    if (!FileTimeToSystemTime(&file_time, &time)) return "unavailable";
    char text[32]{};
    std::snprintf(text, sizeof(text), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        static_cast<unsigned>(time.wYear), static_cast<unsigned>(time.wMonth), static_cast<unsigned>(time.wDay),
        static_cast<unsigned>(time.wHour), static_cast<unsigned>(time.wMinute), static_cast<unsigned>(time.wSecond),
        static_cast<unsigned>(time.wMilliseconds));
    return text;
}

struct KeyHandle {
    HKEY value = nullptr;
    ~KeyHandle() { if (value) RegCloseKey(value); }
    KeyHandle() = default;
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
};
}

struct RegistryChangeWatch::Impl {
    struct Root {
        HKEY hive = nullptr;
        const wchar_t* path = nullptr;
        const char* id = nullptr;
        const char* hive_name = nullptr;
        std::string path_utf8;
        KeyHandle key;
        HANDLE event = nullptr;
        std::string state = "starting";
        LSTATUS error = ERROR_SUCCESS;
        std::uint64_t sequence = 0;
        std::uint64_t queue_dropped = 0;
        std::uint64_t loss_count = 0;
        std::uint64_t pending_first_loss = 0;
        std::uint64_t pending_last_loss = 0;
        std::uint64_t first_loss = 0;
        std::uint64_t last_loss = 0;
    };

    mutable std::mutex mutex;
    std::deque<RegistryChangeNotification> queue;
    std::array<Root, root_count> roots;
    HANDLE stop_event = nullptr;
    std::jthread thread;

    Impl() {
        stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const auto stop_event_error = stop_event ? ERROR_SUCCESS : GetLastError();
        for (std::size_t i = 0; i < roots.size(); ++i) {
            auto& root = roots[i];
            root.hive = root_definitions[i].hive; root.path = root_definitions[i].path;
            root.id = root_definitions[i].id; root.hive_name = root_definitions[i].hive_name;
            const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root.path, -1, nullptr, 0, nullptr, nullptr);
            if (required > 1 && required <= 512) {
                std::string path(static_cast<std::size_t>(required), '\0');
                if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, root.path, -1, path.data(), required, nullptr, nullptr) == required) {
                    path.resize(static_cast<std::size_t>(required - 1));
                    root.path_utf8 = std::move(path);
                }
            }
            root.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!root.event) { root.state = "unavailable"; root.error = GetLastError(); }
        }
        if (!stop_event) {
            for (auto& root : roots) { root.state = "unavailable"; root.error = stop_event_error; }
            return;
        }
        thread = std::jthread([this](std::stop_token stop) { run(stop); });
    }

    ~Impl() {
        stop();
        for (auto& root : roots) if (root.event) CloseHandle(root.event);
        if (stop_event) CloseHandle(stop_event);
    }

    void try_arm(Root& root) {
        if (!root.event) return;
        if (!root.key.value) {
            const auto open = RegOpenKeyExW(root.hive, root.path, 0, KEY_NOTIFY | READ_CONTROL | KEY_WOW64_64KEY, &root.key.value);
            if (open != ERROR_SUCCESS) {
                root.error = open;
                root.state = "unavailable";
                return;
            }
        }
        ResetEvent(root.event);
        const auto status = RegNotifyChangeKeyValue(root.key.value, TRUE, notify_filter, root.event, TRUE);
        if (status != ERROR_SUCCESS) {
            root.error = status;
            root.state = "blind";
            RegCloseKey(root.key.value);
            root.key.value = nullptr;
            return;
        }
        root.error = ERROR_SUCCESS;
        root.state = "active";
    }

    void run(std::stop_token stop) {
        { std::scoped_lock lock{mutex}; for (auto& root : roots) try_arm(root); }
        std::array<HANDLE, root_count + 1> handles{};
        std::array<std::size_t, root_count> handle_to_root{};
        DWORD handle_count = 1;
        handles[0] = stop_event;
        for (std::size_t i = 0; i < roots.size(); ++i) {
            if (!roots[i].event) continue;
            handles[handle_count] = roots[i].event;
            handle_to_root[handle_count - 1] = i;
            ++handle_count;
        }
        std::uint64_t next_retry = GetTickCount64() + 30000;
        while (!stop.stop_requested()) {
            const auto wait = WaitForMultipleObjects(handle_count, handles.data(), FALSE, 1000);
            if (wait == WAIT_OBJECT_0) break;
            if (wait == WAIT_FAILED) {
                const auto error = GetLastError();
                { std::scoped_lock lock{mutex};
                  for (auto& root : roots) if (root.state == "active") { root.state = "blind"; root.error = error; } }
                (void)WaitForSingleObject(stop_event, 250);
                continue;
            }
            if (wait >= WAIT_OBJECT_0 + 1 && wait < WAIT_OBJECT_0 + handle_count) {
                const auto index = handle_to_root[static_cast<std::size_t>(wait - WAIT_OBJECT_0 - 1)];
                auto& root = roots[index];
                // Re-arm immediately. Registry notifications are coalescing signals,
                // not a count of underlying writes; a race during re-arm is possible.
                { std::scoped_lock lock{mutex}; try_arm(root); }
                RegistryChangeNotification notification;
                {
                    std::scoped_lock lock{mutex};
                    notification.root_id = root.id;
                    notification.hive = root.hive_name;
                    notification.key_path = root.path_utf8.empty() ? "bounded_path_conversion_failed" : root.path_utf8;
                    notification.local_sequence = std::to_string(++root.sequence);
                    notification.received_utc = received_time_utc();
                    if (queue.size() < queue_limit) queue.push_back(std::move(notification));
                    else {
                        ++root.queue_dropped;
                        if (root.queue_dropped == 1) root.first_loss = root.sequence;
                        root.last_loss = root.sequence;
                        if (root.loss_count == 0) root.pending_first_loss = root.sequence;
                        root.pending_last_loss = root.sequence;
                        ++root.loss_count;
                    }
                }
            }
            if (GetTickCount64() >= next_retry) {
                { std::scoped_lock lock{mutex}; for (auto& root : roots) if (!root.key.value) try_arm(root); }
                next_retry = GetTickCount64() + 30000;
            }
        }
        std::scoped_lock lock{mutex};
        for (auto& root : roots) {
            root.state = "stopped";
            if (root.key.value) { RegCloseKey(root.key.value); root.key.value = nullptr; }
        }
    }

    void stop() noexcept {
        if (stop_event) SetEvent(stop_event);
        if (thread.joinable()) { thread.request_stop(); thread.join(); }
    }
};

RegistryChangeWatch::RegistryChangeWatch() : impl_(std::make_unique<Impl>()) {}
RegistryChangeWatch::~RegistryChangeWatch() = default;
bool RegistryChangeWatch::try_pop(RegistryChangeNotification& notification) {
    std::scoped_lock lock{impl_->mutex};
    if (impl_->queue.empty()) return false;
    notification = std::move(impl_->queue.front());
    impl_->queue.pop_front();
    return true;
}
std::size_t RegistryChangeWatch::queued_count() const {
    std::scoped_lock lock{impl_->mutex};
    return impl_->queue.size();
}
std::vector<RegistryChangeRootStatus> RegistryChangeWatch::snapshot() const {
    std::scoped_lock lock{impl_->mutex};
    std::vector<RegistryChangeRootStatus> result;
    result.reserve(impl_->roots.size());
    for (const auto& root : impl_->roots) {
        result.push_back({root.id ? root.id : "unknown", root.hive_name ? root.hive_name : "unknown",
            root.path_utf8.empty() ? "bounded_path_conversion_failed" : root.path_utf8, root.state, std::to_string(root.error), std::to_string(root.sequence),
            std::to_string(root.queue_dropped), std::to_string(root.first_loss), std::to_string(root.last_loss)});
    }
    return result;
}
std::vector<RegistryChangeLossReport> RegistryChangeWatch::take_loss_reports() {
    std::scoped_lock lock{impl_->mutex};
    std::vector<RegistryChangeLossReport> result;
    for (auto& root : impl_->roots) {
        if (root.loss_count == 0) continue;
        result.push_back({root.id, root.hive_name, root.path_utf8, root.loss_count, root.pending_first_loss, root.pending_last_loss});
        root.loss_count = 0;
        root.pending_first_loss = root.pending_last_loss = 0;
    }
    return result;
}
void RegistryChangeWatch::stop() noexcept { if (impl_) impl_->stop(); }

} // namespace panopticon::officer::collectors

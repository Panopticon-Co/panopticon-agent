#pragma once
#include "panopticon/officer/delivery/journal.hpp"
#include "panopticon/officer/telemetry/raw_event_common.hpp"
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>
namespace panopticon::officer::collectors {
struct DecodedWindowsEvent {
    nlohmann::json data;
    std::optional<telemetry::UtcTimestamp> event_time;
};
[[nodiscard]] DecodedWindowsEvent decode_windows_event_xml(const std::string& xml, const std::string& requested_channel);
struct WindowsLogCallbacks {
    std::function<std::optional<delivery::SourceCheckpoint>(const std::string&)> load;
    std::function<std::string(const std::string&, const DecodedWindowsEvent&, bool)> make_record;
    // Empty checkpoint means ordinary gap record; never advances a source cursor.
    std::function<bool(const std::string&, const std::string&, const std::string&, std::uint64_t)> commit;
    std::function<void()> changed;
};
class WindowsEventLog {
public:
    explicit WindowsEventLog(WindowsLogCallbacks callbacks, std::vector<std::string> channels = default_channels());
    ~WindowsEventLog();
    WindowsEventLog(const WindowsEventLog&) = delete;
    WindowsEventLog& operator=(const WindowsEventLog&) = delete;
    void stop();
    [[nodiscard]] nlohmann::json snapshot() const;
    [[nodiscard]] static std::vector<std::string> default_channels();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}

#pragma once
#include "panopticon/officer/delivery/journal.hpp"
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>
namespace panopticon::officer::collectors {
struct UsnCursor { std::uint64_t journal_id = 0; std::int64_t next_usn = 0; };
[[nodiscard]] std::string encode_usn_cursor(UsnCursor cursor);
[[nodiscard]] UsnCursor decode_usn_cursor(const std::string& value);
// Native output begins with the next signed USN; record layouts are selected by
// version and checked before any offset/length access. No native pointer casts.
[[nodiscard]] nlohmann::json decode_usn_buffer(std::span<const std::byte> buffer, std::int64_t start_usn);
struct UsnCallbacks {
    std::function<std::optional<delivery::SourceCheckpoint>(const std::string&)> load;
    std::function<std::string(const std::string&, nlohmann::json, bool)> make_record;
    std::function<bool(const std::string&, const std::string&, const std::string&, std::uint64_t)> commit;
    std::function<void()> changed;
};
class UsnJournal {
public:
    // Empty list rediscovers at most 16 GUIDs every 30 seconds. Discovery
    // transitions/checkpoints commit before worker changes; incomplete scans
    // retain the prior workers and report an unknown interval. Removal joins
    // the worker and preserves its journal cursor for later reappearance.
    // Explicit volumes must use the native volume GUID path, never a drive letter.
    // Explicit mode does not discover hotplug. stop() joins discovery before
    // workers; snapshot() and changed callbacks may run concurrently.
    explicit UsnJournal(UsnCallbacks callbacks, std::vector<std::string> volumes = {});
    ~UsnJournal();
    UsnJournal(const UsnJournal&) = delete;
    void stop();
    [[nodiscard]] nlohmann::json snapshot() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}

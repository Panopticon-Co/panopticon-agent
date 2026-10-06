#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <set>
#include <string>

namespace panopticon::officer::response {

// Legacy file-backed set of command_ids this agent has already accepted,
// so a restart cannot re-accept a command a crash interrupted mid-execution.
// Same semantics as panopticon-linux-agent's replay_ledger: an append-only
// newline-delimited file, loaded once at startup, appended to (and flushed)
// synchronously on every newly-seen id. Stream flush is not full crash/power-loss
// qualification. The live Windows worker reads this only as a migration guard;
// new command durability uses the SQLite inbox.
class ReplayLedger {
public:
    ReplayLedger(std::filesystem::path path, std::size_t maximum_entries);

    // Returns false (and sets error_message) only on a corrupt or
    // over-capacity ledger file; a missing file is not an error (empty
    // ledger).
    [[nodiscard]] bool load(std::string& error_message);
    // Migration guard only: prior acceptance cannot prove prior completion.
    [[nodiscard]] bool contains(const std::string& command_id) const { return entries_.contains(command_id); }

    // Returns true iff command_id had not been seen before (and is now
    // durably recorded); false if it was already present. Returns
    // std::nullopt (with error_message set) on an invalid id, a full
    // ledger, or an I/O failure -- callers must treat that the same as
    // "reject the command", never as "allow it".
    [[nodiscard]] std::optional<bool> mark_if_new(const std::string& command_id, std::string& error_message);

private:
    std::filesystem::path path_;
    std::size_t maximum_entries_;
    std::set<std::string> entries_;
};

}  // namespace panopticon::officer::response

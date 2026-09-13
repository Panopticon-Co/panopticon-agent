#include "panopticon/officer/response/replay_ledger.hpp"
#include "panopticon/officer/response/identity.hpp"

#include <fstream>

namespace panopticon::officer::response {

ReplayLedger::ReplayLedger(std::filesystem::path path, const std::size_t maximum_entries)
    : path_{std::move(path)}, maximum_entries_{maximum_entries} {}

bool ReplayLedger::load(std::string& error_message) {
    std::ifstream input{path_};
    if (!input) {
        if (std::filesystem::exists(path_)) {
            error_message = "cannot read replay ledger";
            return false;
        }
        return true;
    }
    for (std::string id; std::getline(input, id);) {
        if (!is_valid_identifier(id) || entries_.size() == maximum_entries_) {
            error_message = "replay ledger is malformed or exceeds limit";
            return false;
        }
        entries_.insert(std::move(id));
    }
    return true;
}

std::optional<bool> ReplayLedger::mark_if_new(const std::string& command_id, std::string& error_message) {
    if (!is_valid_identifier(command_id) || maximum_entries_ == 0U) {
        error_message = "command id or replay ledger limit is invalid";
        return std::nullopt;
    }
    if (entries_.contains(command_id)) {
        return false;
    }
    if (entries_.size() == maximum_entries_) {
        error_message = "replay ledger capacity exhausted";
        return std::nullopt;
    }
    std::error_code filesystem_error;
    std::filesystem::create_directories(path_.parent_path(), filesystem_error);
    if (filesystem_error) {
        error_message = "cannot create replay ledger directory";
        return std::nullopt;
    }
    std::ofstream output{path_, std::ios::app};
    if (!output) {
        error_message = "cannot persist replay entry";
        return std::nullopt;
    }
    output << command_id << '\n';
    output.flush();
    if (!output) {
        error_message = "cannot flush replay entry";
        return std::nullopt;
    }
    entries_.insert(command_id);
    return true;
}

}  // namespace panopticon::officer::response

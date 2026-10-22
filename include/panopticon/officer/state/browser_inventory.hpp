#pragma once

#include "panopticon/officer/state/native_inventory_limits.hpp"
#include <nlohmann/json.hpp>
#include <functional>
#include <string>
#include <vector>

namespace panopticon::officer::state {

struct BrowserInventoryFixtureRoot {
    // Explicit fixture namespace. Accepted names: Chrome, Edge, Chromium, Firefox.
    // Callers must point only at an owned inert fixture tree.
    std::string browser;
    std::wstring root_path;
    bool caller_owned_inert_fixture = false;
};

struct BrowserInventoryLimits {
    NativeInventoryLimits pages;
    std::size_t profiles = 256;
    std::size_t user_profile_candidates = 64;
    std::size_t directories = 4096;
    std::size_t manifests = 4096;
    std::size_t directory_depth = 5;
    std::size_t file_bytes = 256 * 1024;
    std::size_t parse_depth = 32;
    std::size_t metadata_string_bytes = 4096;
    std::vector<BrowserInventoryFixtureRoot> owned_inert_fixture_roots;
};

// Reads only extension manifest/metadata files for current-caller and bounded
// conventional profile-directory candidates. Candidate directories are not
// mapped to verified accounts. Production rows omit raw profile paths and use
// per-capture salted profile scope tokens. Pages are delivered synchronously.
[[nodiscard]] nlohmann::json collect_browser_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer,
    BrowserInventoryLimits limits = {}, const std::function<bool()>& cancelled = {});

} // namespace panopticon::officer::state

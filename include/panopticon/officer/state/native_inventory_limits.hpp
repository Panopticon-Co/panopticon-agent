#pragma once
#include <cstddef>
#include <cstdint>
namespace panopticon::officer::state {
// Application-copy/page bounds for local Windows-native state collectors.
// These do not impose a hard deadline or allocation cap on native APIs.
struct NativeInventoryLimits {
    std::size_t page_entries = 64, encoded_bytes = 512 * 1024;
    std::size_t total_entries = 16384, pages = 1024, field_bytes = 128 * 1024;
    std::uint64_t soft_budget_ms = 60000;
};
}

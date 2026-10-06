#pragma once
#include <nlohmann/json.hpp>
#include <cstddef>
#include <cstdint>
#include <span>
namespace panopticon::officer::state {
struct ProcessTokenQuery {
    nlohmann::json fact;
    bool opened = false;
    std::uint64_t successful_fields = 0, failed_fields = 0, uninterpreted_fields = 0;
};
// Caller retains this process handle. Opens one primary token with TOKEN_QUERY;
// never reopens a PID, resolves account names or changes token/privilege state.
[[nodiscard]] ProcessTokenQuery query_primary_process_token(void* held_process);
namespace detail {
[[nodiscard]] nlohmann::json bounded_token_sid(std::span<const std::byte> buffer, const void* sid);
[[nodiscard]] nlohmann::json integrity_level_name(std::uint32_t rid);
[[nodiscard]] nlohmann::json token_elevation_type_result(std::uint32_t raw);
}
}

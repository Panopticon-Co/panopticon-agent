#pragma once
#include <nlohmann/json.hpp>
#include <functional>
#include <span>
#include <cstdint>
namespace panopticon::officer::state {
[[nodiscard]] nlohmann::json collect_loaded_driver_pages(const std::function<bool(nlohmann::json)>& consumer);
namespace detail {
[[nodiscard]] nlohmann::json driver_address_visibility(std::span<const std::uintptr_t> addresses);
}
}

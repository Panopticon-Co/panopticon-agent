#pragma once
#include <nlohmann/json.hpp>
#include <cstddef>
#include <functional>
#include <span>
#include <cstdint>
namespace panopticon::officer::state {
struct ServiceInventoryLimits {
    std::size_t page_entries = 256, encoded_bytes = 512 * 1024;
    std::size_t total_entries = 65536, pages = 4096, enumeration_bytes = 256 * 1024;
};
// Caller-visible SCM enumeration is non-atomic and can silently omit inaccessible
// services. Consumer acceptance does not establish full service/driver coverage.
[[nodiscard]] nlohmann::json collect_service_inventory_pages(
    const std::function<bool(nlohmann::json)>& consumer, ServiceInventoryLimits limits = {});
// A separately opened READ_CONTROL object; relation to another name lookup is
// unverified. Does not request SACL access or alter caller privileges.
[[nodiscard]] nlohmann::json query_service_security(void* manager_handle, const wchar_t* service_name);
namespace detail {
[[nodiscard]] nlohmann::json service_security_descriptor(std::span<const std::byte> buffer);
[[nodiscard]] nlohmann::json service_triggers(std::span<const std::byte> buffer);
[[nodiscard]] nlohmann::json service_text(std::span<const std::byte> buffer,
    const void* pointer, std::size_t character_limit = 4096);
[[nodiscard]] nlohmann::json service_dependencies(std::span<const std::byte> buffer, const void* pointer);
// Decode only bounded successful native buffers; no configured text is executed
// or resolved into a process, privilege, signer, or service instance.
[[nodiscard]] nlohmann::json service_optional_configuration(
    std::span<const std::byte> buffer, std::uint32_t information_level);
}
}

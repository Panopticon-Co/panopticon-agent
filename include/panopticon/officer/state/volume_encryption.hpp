#pragma once

#include <nlohmann/json.hpp>

namespace panopticon::officer::state {

// Read-only local Win32_EncryptableVolume status. No state-changing method is called.
[[nodiscard]] nlohmann::json collect_volume_encryption_state();

}

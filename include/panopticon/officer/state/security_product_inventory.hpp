#pragma once
#include <nlohmann/json.hpp>

namespace panopticon::officer::state {
// Caller-visible WSC product registrations only. A reported product state is
// not proof of effective protection or product integrity.
[[nodiscard]] nlohmann::json collect_security_product_inventory();
}

#include "panopticon/officer/telemetry/panopticon_event.hpp"

#include <iostream>

int main() {
    std::cout << "Officer agent "
              << panopticon::officer::telemetry::kAgentVersion << '\n';
    std::cout << "Panopticon event contract "
              << panopticon::officer::telemetry::kSchemaVersion << '\n';
    std::cout << "Phase 1 contracts are ready; no live collectors are started.\n";
    return 0;
}

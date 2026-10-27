// Live remote-access inventory on this machine: every partition is reported
// (SMB, service state, RDP and WinRM configuration), absent keys are explicit,
// and nothing claims a listener or effective policy was verified.
#include "panopticon/officer/state/remote_access_inventory.hpp"

#include <iostream>
#include <set>
#include <stdexcept>
#include <string>

using Json = nlohmann::json;
void require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }

int main(int argc, char** argv) {
    try {
        Json pages = Json::array();
        const auto summary = panopticon::officer::state::collect_remote_access_inventory_pages(
            [&](Json page) { pages.push_back(std::move(page)); return true; });
        if (argc == 2 && std::string{argv[1]} == "--emit") {
            std::cout << Json{{"summary", summary}, {"pages", pages}}.dump() << '\n';
            return 0;
        }
        std::set<std::string> partitions;
        for (const auto& partition : summary.at("partitions")) partitions.insert(partition.at("partition").get<std::string>());
        for (const auto* expected : {"remote_access_services", "rdp_configuration", "winrm_configuration"})
            require(partitions.count(expected) == 1, "every remote-access partition is reported independently");
        require(summary.at("inventory_complete") == false, "inventory never claims completeness");

        std::set<std::string> services, mechanisms;
        for (const auto& page : pages)
            for (const auto& row : page.at("entries")) {
                if (row.value("entry_kind", "") == "remote_access_service") {
                    services.insert(row.at("service_name").get<std::string>());
                    require(row.at("listener_accepting_verified") == false, "service state is not listener proof");
                    const auto state = row.at("state").get<std::string>();
                    require(state == "healthy" || state == "not_present" || state == "unavailable", "service state is explicit");
                    if (state == "healthy") require(row.at("running").is_boolean(), "healthy service reports a boolean running state");
                }
                if (row.contains("mechanism")) mechanisms.insert(row.at("mechanism").get<std::string>());
            }
        require(services == std::set<std::string>{"TermService", "WinRM"}, "both remote-access services are queried");
        require(mechanisms.count("rdp_configuration") == 1, "RDP configuration rows are emitted (present or explicitly absent)");
        require(mechanisms.count("rdp_policy") == 1, "RDP policy key is reported even when absent");
        require(mechanisms.count("winrm_configuration") == 1, "WinRM service configuration is reported");
        std::cout << "remote access inventory tests passed; services=" << services.size()
                  << " mechanisms=" << mechanisms.size() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

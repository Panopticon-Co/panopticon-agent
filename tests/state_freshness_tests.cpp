#include "panopticon/officer/health/state_freshness.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <filesystem>
#include <chrono>
#include <vector>
#include <iostream>
#include <stdexcept>
using Json = nlohmann::json;
namespace health = panopticon::officer::health;
void require(bool ok, const char* text) { if (!ok) throw std::runtime_error(text); }
Json sample() {
    Json result{{"capabilities", Json::array()}};
    for (const auto* key : {"host_inventory", "process_inventory", "thread_inventory", "memory_region_inventory", "service_inventory", "loaded_driver_inventory",
        "socket_inventory", "route_inventory", "ip_interface_inventory", "firewall_profile_state", "firewall_rule_inventory", "security_center_state", "defender_status",
        "scheduled_task_inventory", "wmi_subscription_inventory", "startup_inventory",
        "account_inventory", "local_group_inventory", "logon_session_inventory", "terminal_session_inventory",
        "msi_product_inventory", "uninstall_registry_inventory"})
        result[key] = {{"state", "degraded"}, {"last_committed_record_id", "record-1"},
            {"last_committed_capture_started_uptime_ms", "100"}, {"last_committed_uptime_ms", "200"},
            {"collection_started_uptime_ms", "360100"}, {"collection_in_progress", true},
            {"last_committed_query_status", {{"state", "healthy"}, {"native_error_code", "0"}}}};
    for (const auto* id : {"A.host", "state.process_inventory", "state.thread_inventory", "state.memory_region_inventory", "C.thread_handle", "state.service_security_descriptor",
        "state.loaded_driver_inventory", "state.socket_table.tcp4", "state.route_table.ipv4",
        "state.ip_interface_table.ipv6", "state.firewall_profiles", "state.firewall_rule_inventory", "state.security_center.antivirus", "state.defender_status",
        "state.scheduled_task_inventory", "state.wmi_subscription_inventory", "state.startup_inventory",
        "state.account_inventory", "state.local_group_inventory", "state.logon_session_inventory", "state.terminal_session_inventory",
        "state.msi_product_inventory", "state.uninstall_registry_inventory", "B.process"})
        result["capabilities"].push_back({{"id", id}, {"state", "healthy"}, {"reason", "native query"}});
    return result;
}
Json history_cases(const Json& fresh, const Json& stale, const Json& recovered) {
    health::StateCaptureGapBuffer history;
    auto one = Json{{"host_inventory", fresh["host_inventory"]}};
    history.observe(one, 360100);
    const auto retained = history.front().dump();
    one["host_inventory"]["capture_freshness"]["record_id"] = "record-2";
    history.observe(one, 360100);
    require(history.snapshot()["queued_reports"] == "1", "unchanged eligibility duplicated transition");
    history.observe(Json::object(), 360101);
    history.observe({{"host_inventory", stale["host_inventory"]}}, 360102);
    history.observe({{"host_inventory", recovered["host_inventory"]}}, 360103);
    require(history.front().dump() == retained && history.snapshot()["queued_reports"] == "3",
        "pending front overwritten by outage or recovery");
    Json reports = Json::array();
    while (!history.empty()) { reports.push_back(history.front()); history.acknowledge_front(); }
    require(reports[1]["previous_freshness"]["record_id"] == "record-2" &&
        reports[1]["current_freshness"]["state"] == "blind" &&
        reports[2]["previous_freshness"]["state"] == "blind" &&
        reports[2]["current_freshness"]["state"] == "healthy", "transition baseline/order changed");
    require(reports[1]["previous_sample_uptime_ms"] == "360100", "absent source advanced its baseline time");
    require(reports[1]["lost_native_events"].is_null(), "coverage gap fabricated native loss count");
    health::StateCaptureGapBuffer bounded{1, 2048};
    bounded.observe(one, 360100);
    bounded.observe({{"host_inventory", stale["host_inventory"]}}, 360101);
    bounded.observe({{"host_inventory", recovered["host_inventory"]}}, 360103);
    require(bounded.snapshot()["omitted_reports_total"] == "2" && bounded.pending(), "history bound omissions lost");
    bounded.acknowledge_front();
    const auto summary = bounded.front();
    require(summary["omitted_transition_reports"] == "2" && summary["lost_native_events"].is_null(),
        "omitted transitions became native loss");
    reports.push_back(summary); bounded.acknowledge_front();
    bounded.observe({{"host_inventory", recovered["host_inventory"]}}, 360104);
    require(!bounded.pending(), "omitted history did not advance observed baseline");
    health::StateCaptureGapBuffer byte_bounded{128, 2048};
    byte_bounded.observe(one, 360100);
    byte_bounded.observe({{"host_inventory", stale["host_inventory"]}}, 360101);
    byte_bounded.observe({{"host_inventory", recovered["host_inventory"]}}, 360103);
    require(byte_bounded.snapshot()["omitted_reports_total"] != "0" &&
        std::stoull(byte_bounded.snapshot()["encoded_gap_bytes"].get<std::string>()) <= 2048,
        "encoded byte history limit ignored in favor of report count");
    return reports;
}
Json journal_retry_cases(const Json& fresh, const Json& stale, const Json& recovered) {
    using namespace panopticon::officer;
    const auto root = std::filesystem::weakly_canonical(std::filesystem::temp_directory_path());
    const auto path = root / ("officer-state-history-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Cleanup {
        std::filesystem::path path, root;
        ~Cleanup() {
            std::error_code error;
            const auto resolved = std::filesystem::weakly_canonical(path, error);
            if (!error && resolved.parent_path() == root &&
                resolved.filename().string().starts_with("officer-state-history-"))
                std::filesystem::remove_all(resolved, error);
        }
    } cleanup{path, root};
    pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
    pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
    health::StateCaptureGapBuffer history;
    history.observe({{"host_inventory", fresh["host_inventory"]}}, 360100);
    const auto pending = factory.gap("state.capture_freshness", history.front()).dump();
    const auto front = history.front();
    {
        delivery::DurableJournal limited{{path, pending.size() - 1}};
        bool refused = false;
        try { limited.append(pending); } catch (const std::exception& error) {
            refused = std::string{error.what()}.starts_with("journal retention quota exhausted");
        }
        require(refused && limited.stats().pending_events == 0, "actual quota did not refuse pending gap");
        history.observe({{"host_inventory", stale["host_inventory"]}}, 360101);
        history.observe({{"host_inventory", recovered["host_inventory"]}}, 360103);
        require(history.front() == front && history.snapshot()["queued_reports"] == "3",
            "actual journal refusal replaced pending gap or lost outage/recovery");
    }
    std::vector<std::string> accepted;
    {
        delivery::DurableJournal reopened{{path}};
        reopened.append(pending); accepted.push_back(pending); history.acknowledge_front();
        while (!history.empty()) {
            const auto line = factory.gap("state.capture_freshness", history.front()).dump();
            reopened.append(line); accepted.push_back(line); history.acknowledge_front();
        }
    }
    delivery::DurableJournal retained{{path}};
    const auto stored = retained.inspect_pending(0, 10, 1024 * 1024);
    require(stored.size() == 3 && !history.pending(), "accepted retry history not retained");
    Json result = Json::array();
    for (std::size_t i = 0; i < stored.size(); ++i) {
        require(stored[i].original.body == accepted[i], "retry bytes changed on journal reopen");
        result.push_back(Json::parse(stored[i].original.body));
    }
    require(result[1]["data"]["current_freshness"]["state"] == "blind" &&
        result[2]["data"]["previous_freshness"]["state"] == "blind" &&
        result[2]["data"]["current_freshness"]["state"] == "healthy", "reopened history erased outage");
    return result;
}
int main(int argc, char** argv) {
    try {
        auto software = sample();
        software["capabilities"].push_back({{"id", "Z.software"}, {"state", "unavailable"}});
        software["msi_product_inventory"]["state"] = "unavailable";
        health::apply_state_capture_freshness(software, 360100);
        require(software["capabilities"].back()["state"] == "degraded", "MSI refusal erased registry evidence");
        software = sample();
        software["capabilities"].push_back({{"id", "Z.software"}, {"state", "degraded"}});
        health::apply_state_capture_freshness(software, 360101);
        require(software["capabilities"].back()["state"] == "blind", "stale software census remained current");
        auto identity = sample();
        for (const auto* id : {"D.user_session", "U.remote_access"})
            identity["capabilities"].push_back({{"id", id}, {"state", "unavailable"}});
        identity["logon_session_inventory"]["state"] = "unavailable";
        health::apply_state_capture_freshness(identity, 360100);
        require(identity["capabilities"].back()["state"] == "degraded" &&
            identity["capabilities"][identity["capabilities"].size()-2]["state"] == "degraded",
            "LSA refusal erased independent account/group/WTS evidence");
        identity = sample();
        for (const auto* id : {"D.user_session", "U.remote_access"})
            identity["capabilities"].push_back({{"id", id}, {"state", "degraded"}});
        health::apply_state_capture_freshness(identity, 360101);
        require(identity["capabilities"].back()["state"] == "blind" &&
            identity["capabilities"][identity["capabilities"].size()-2]["state"] == "blind",
            "stale identity captures remained current user or remote-session coverage");
        identity = sample();
        for (const auto* id : {"D.user_session", "U.remote_access"})
            identity["capabilities"].push_back({{"id", id}, {"state", "unavailable"}});
        identity["logon_session_inventory"]["state"] = "unavailable";
        identity["terminal_session_inventory"]["state"] = "unavailable";
        health::apply_state_capture_freshness(identity, 360100);
        require(identity["capabilities"].back()["state"] == "unavailable" &&
            identity["capabilities"][identity["capabilities"].size()-2]["state"] == "degraded",
            "local account evidence invented remote-session coverage");
        auto persistence = sample();
        for (const auto* id : {"J.persistence", "L.scheduled_task", "M.wmi"})
            persistence["capabilities"].push_back({{"id", id}, {"state", "unavailable"}});
        persistence["scheduled_task_inventory"]["state"] = "unavailable";
        health::apply_state_capture_freshness(persistence, 360100);
        require(persistence["capabilities"].back()["state"] == "degraded" &&
            persistence["capabilities"][persistence["capabilities"].size()-2]["state"] == "unavailable" &&
            persistence["capabilities"][persistence["capabilities"].size()-3]["state"] == "degraded",
            "independent source failure erased persistence evidence or invented task coverage");
        persistence = sample();
        persistence["capabilities"].push_back({{"id", "L.scheduled_task"}, {"state", "degraded"}});
        health::apply_state_capture_freshness(persistence, 360101);
        require(persistence["capabilities"].back()["state"] == "blind", "stale task inventory kept domain eligible");
        persistence = sample();
        persistence["capabilities"].push_back({{"id", "L.scheduled_task"}, {"state", "degraded"}});
        persistence["windows_event_log"] = {{"channels", Json::array({{{"channel", "Microsoft-Windows-TaskScheduler/Operational"}, {"state", "degraded"}}})}};
        health::apply_state_capture_freshness(persistence, 360101);
        require(persistence["capabilities"].back()["state"] == "degraded" && persistence["scheduled_task_inventory"]["state"] == "blind",
            "active native task log did not preserve scoped partial coverage alongside stale inventory");
        auto posture = sample();
        posture["capabilities"].push_back({{"id", "Q.security_product"}, {"state", "unavailable"}});
        posture["security_center_state"]["state"] = "unsupported";
        health::apply_state_capture_freshness(posture, 360100);
        require(posture["capabilities"].back()["state"] == "degraded", "Server WSC erased fresh Defender evidence");
        posture = sample();
        posture["capabilities"].push_back({{"id", "Q.security_product"}, {"state", "degraded"}});
        posture["defender_status"]["state"] = "unavailable";
        health::apply_state_capture_freshness(posture, 360100);
        require(posture["capabilities"].back()["state"] == "degraded", "Defender refusal erased fresh WSC evidence");
        posture = sample();
        posture["capabilities"].push_back({{"id", "Q.security_product"}, {"state", "degraded"}});
        health::apply_state_capture_freshness(posture, 360101);
        require(posture["capabilities"].back()["state"] == "blind", "all stale security sources stayed eligible");
        const auto original = sample(); auto fresh = original;
        health::apply_state_capture_freshness(fresh, 360100);
        require(fresh["host_inventory"]["capture_freshness"]["state"] == "healthy", "age boundary off by one");
        auto stale = original; health::apply_state_capture_freshness(stale, 360101);
        for (auto it = original.begin(); it != original.end(); ++it) {
            if (it.key() == "capabilities") continue;
            require(stale[it.key()]["state"] == "blind", "overdue capture did not become blind");
            require(stale[it.key()]["last_committed_query_status"] == it.value()["last_committed_query_status"],
                "freshness rewrote committed native evidence");
        }
        for (const auto& capability : stale["capabilities"])
            require(capability["state"] == (capability["id"] == "B.process" ? "healthy" : "blind"),
                "wrong freshness capability scope");
        auto delayed = original;
        delayed["host_inventory"]["last_committed_uptime_ms"] = "360101";
        health::apply_state_capture_freshness(delayed, 360101);
        require(delayed["host_inventory"]["capture_freshness"]["commit_age_ms"] == "0" &&
            delayed["host_inventory"]["state"] == "blind", "late commit refreshed old collection");
        auto missing = original; missing["host_inventory"].erase("last_committed_capture_started_uptime_ms");
        missing["socket_inventory"]["last_committed_uptime_ms"] = "18446744073709551616";
        missing["route_inventory"]["last_committed_uptime_ms"] = "0200";
        missing["firewall_rule_inventory"]["last_committed_record_id"] = nullptr;
        health::apply_state_capture_freshness(missing, 300);
        for (const auto* key : {"host_inventory", "socket_inventory", "route_inventory", "firewall_rule_inventory"})
            require(missing[key]["state"] == "unavailable" && missing[key]["capture_freshness"]["capture_age_ms"].is_null(),
                "missing/invalid time or record evidence interpreted");
        auto future = original; health::apply_state_capture_freshness(future, 199);
        require(future["host_inventory"]["state"] == "unavailable", "clock rollback underflow");
        auto inverted = original; inverted["host_inventory"]["last_committed_uptime_ms"] = "99";
        health::apply_state_capture_freshness(inverted, 300);
        require(inverted["host_inventory"]["capture_freshness"]["reason"] == "capture_clock_order_invalid", "clock order ignored");
        auto disabled = original; disabled["host_inventory"]["state"] = "disabled";
        disabled["capabilities"][0]["state"] = "unsupported";
        health::apply_state_capture_freshness(disabled, 360101);
        require(disabled["host_inventory"]["state"] == "disabled" && disabled["capabilities"][0]["state"] == "unsupported",
            "freshness replaced disabled/unsupported state");
        auto recovered = original;
        recovered["host_inventory"]["last_committed_capture_started_uptime_ms"] = "360101";
        recovered["host_inventory"]["last_committed_uptime_ms"] = "360102";
        health::apply_state_capture_freshness(recovered, 360103);
        require(recovered["host_inventory"]["state"] == "degraded", "new committed capture failed to recover");
        const auto history = history_cases(fresh, stale, recovered);
        const auto retried = journal_retry_cases(fresh, stale, recovered);
        if (argc == 2 && std::string{argv[1]} == "--emit-retry") {
            std::cout << retried.dump() << '\n'; return 0;
        }
        if (argc == 2 && (std::string{argv[1]} == "--emit-fixtures" || std::string{argv[1]} == "--emit-history")) {
            using namespace panopticon::officer;
            pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
            pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
            Json records = Json::array();
            if (std::string{argv[1]} == "--emit-history")
                for (const auto& value : history) records.push_back(factory.gap("state.capture_freshness", value));
            else for (const auto& value : {fresh, stale, delayed, missing, future, disabled, recovered}) records.push_back(factory.health(value));
            std::cout << records.dump() << '\n'; return 0;
        }
        std::cout << "State capture age, stalled new collection, late commit, clock refusal and recovery passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

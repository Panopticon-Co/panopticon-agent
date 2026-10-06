#include "panopticon/officer/health/source_supervisor.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/collectors/etw_process_collector.hpp"
#include "panopticon/officer/collectors/sysmon_event_collector.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <filesystem>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <atomic>
#include <thread>
#include <chrono>
using namespace panopticon::officer;
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
void journal_retry_history(pipeline::EndpointRecordFactory& factory) {
    const auto path = std::filesystem::temp_directory_path() /
        ("officer-source-history-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    struct Cleanup {
        std::filesystem::path path;
        ~Cleanup() {
            std::error_code error;
            if (std::filesystem::equivalent(path.parent_path(), std::filesystem::temp_directory_path(), error) &&
                !error && path.filename().string().starts_with("officer-source-history-"))
                std::filesystem::remove_all(path, error);
        }
    } cleanup{path};
    collectors::CollectorStatus first;
    first.running = true; first.statistics_available = true;
    first.events_lost = first.realtime_buffers_lost = first.log_buffers_lost = 0;
    health::SourceGapBuffer history;
    history.observe(first, 10);
    const auto pending = factory.gap("etw", history.front()).dump();
    {
        delivery::DurableJournal bounded{{path, pending.size() - 1}};
        bool refused = false;
        try { bounded.append(pending); } catch (const std::exception&) { refused = true; }
        require(refused && bounded.stats().pending_events == 0, "owned journal did not refuse quota acceptance");
        auto outage = first; outage.statistics_available = false;
        outage.events_lost.reset(); outage.realtime_buffers_lost.reset(); outage.log_buffers_lost.reset();
        history.observe(outage, 20);
        auto restored = first; restored.events_lost = 7;
        history.observe(restored, 30);
        require(history.front()["sample_uptime_ms"] == "10", "quota failure advanced retry front");
    }
    std::vector<std::string> accepted;
    {
        delivery::DurableJournal reopened{{path}};
        reopened.append(pending); accepted.push_back(pending); history.acknowledge_front();
        while (!history.empty()) {
            const auto line = factory.gap("etw", history.front()).dump();
            reopened.append(line); accepted.push_back(line); history.acknowledge_front();
        }
    }
    delivery::DurableJournal retained{{path}};
    const auto original = retained.inspect_pending(0, 10, 1024 * 1024);
    require(original.size() == 3, "accepted retry history not durable");
    for (std::size_t index = 0; index < original.size(); ++index)
        require(original[index].original.body == accepted[index], "accepted retry bytes changed on journal reopen");
    const auto restored = nlohmann::json::parse(original[2].original.body);
    require(restored["data"]["previous_sample_uptime_ms"] == "20" &&
        restored["data"]["changes"][1]["delta"].is_null(), "journal retry fabricated delta across outage");
}
int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string{argv[1]} == "--probe-source") {
            std::unique_ptr<collectors::TelemetryCollector> collector;
            const std::string source = argv[2];
            if (source == "etw") collector = std::make_unique<collectors::EtwProcessCollector>();
            else if (source == "sysmon") collector = std::make_unique<collectors::SysmonEventCollector>();
            else throw std::runtime_error("unknown probe source");
            std::atomic_uint64_t delivered{0};
            std::string error;
            if (!collector->start([&](telemetry::RawEvent) { ++delivered; },
                [](std::string_view name, std::string message) { std::cerr << name << ": " << message << '\n'; }, error)) {
                std::cerr << "source unavailable: " << error << '\n';
                return 2;
            }
            std::this_thread::sleep_for(std::chrono::seconds{2});
            const auto status = collector->status();
            auto output = health::source_status_json(status);
            output["delivered"] = std::to_string(delivered.load());
            std::cout << output.dump() << '\n';
            collector->stop();
            require(!collector->running(), "owned collector must stop");
            require(status.running, "consumer must remain running during probe");
            if (source == "etw") require(status.statistics_available, "owned ETW statistics query must succeed");
            return 0;
        }
        collectors::CollectorStatus first;
        first.running = true;
        first.statistics_available = true;
        first.events_lost = 0;
        first.realtime_buffers_lost = 0;
        first.log_buffers_lost = 0;
        require(health::source_gap_since(std::nullopt, first).has_value(), "startup history must remain unknown");
        require(!health::source_gap_since(first, first), "unchanged samples must not duplicate gaps");
        auto lost = first;
        lost.events_lost = 7;
        lost.realtime_buffers_lost = 2;
        auto gap = health::source_gap_since(first, lost);
        require(gap && (*gap)["changes"].size() == 2, "events and buffers must stay separate");
        require((*gap)["changes"][0]["delta"] == "7" && (*gap)["changes"][1]["unit"] == "buffers", "exact loss delta");
        require(health::source_gap_since(first, lost) == gap, "failed durable commit must leave previous baseline intact");
        require(!health::source_gap_since(lost, lost), "committed gaps must not repeat");
        auto reset = lost;
        reset.events_lost = 1;
        gap = health::source_gap_since(lost, reset);
        require((*gap)["changes"][0]["delta"].is_null(), "decreasing counter cannot invent wrap count");
        auto unavailable = lost;
        unavailable.events_lost.reset();
        unavailable.realtime_buffers_lost.reset();
        unavailable.log_buffers_lost.reset();
        unavailable.statistics_available = false;
        require(health::source_status_json(unavailable)["events_lost"].is_null(), "unknown loss is not zero");
        gap = health::source_gap_since(unavailable, lost);
        require((*gap)["changes"][1]["delta"].is_null(), "query outage breaks measured interval");
        auto stopped = first;
        stopped.running = false;
        gap = health::source_gap_since(first, stopped);
        require((*gap)["changes"][0]["reason"] == "consumer_stopped", "consumer stop must be visible");
        auto sysmon = first;
        sysmon.subscription_errors = 1;
        sysmon.continuity_fault = true;
        require(health::source_gap_since(first, sysmon).has_value(), "subscription error must produce a gap");
        require(health::source_status_json(sysmon)["continuity"] == "unverified", "active subscription cannot prove continuity");
        auto rejected = first;
        rejected.decode_failures = 2;
        rejected.sink_failures = 3;
        gap = health::source_gap_since(first, rejected);
        require((*gap)["changes"].size() == 2 && (*gap)["changes"][0]["counter"] == "decode_failures" &&
            (*gap)["changes"][1]["delta"] == "3", "decode failures and sink exceptions have separate stage accounting");
        // Refuse journal acceptance of the first report while newer measured
        // outages/transitions arrive. The retry front must remain byte-identical.
        health::SourceGapBuffer history;
        history.observe(first, 100);
        const auto pending_bytes = history.front().dump();
        history.observe(unavailable, 200);
        history.observe(lost, 300);
        history.observe(stopped, 400);
        history.observe(first, 500);
        require(history.front().dump() == pending_bytes, "new samples changed pending retry evidence");
        history.acknowledge_front();
        require(history.front()["sample_uptime_ms"] == "200" &&
            history.front()["changes"][0]["reason"] == "source_statistics_unavailable",
            "statistics outage during retry disappeared");
        history.acknowledge_front();
        require(history.front()["previous_sample_uptime_ms"] == "200" &&
            history.front()["changes"][1]["delta"].is_null(),
            "durable retry stitched loss delta across observed statistics outage");
        history.acknowledge_front();
        require(history.front()["changes"][0]["reason"] == "consumer_stopped", "transient stop omitted");
        history.acknowledge_front();
        require(history.front()["changes"][0]["reason"] == "consumer_resumed_continuity_unverified",
            "transient resume falsely restored continuity");
        history.acknowledge_front();
        require(history.empty() && history.snapshot()["acknowledged_reports"] == "5", "history disposition mismatch");
        health::SourceGapBuffer bounded{2, 4096};
        bounded.observe(first, 10); bounded.observe(lost, 20);
        const auto bounded_front = bounded.front().dump();
        bounded.observe(unavailable, 30); bounded.observe(stopped, 40);
        require(bounded.front().dump() == bounded_front && bounded.snapshot()["queued_reports"] == "2" &&
            bounded.snapshot()["omitted_reports_total"] == "2", "bounded history erased front or omitted report accounting");
        bounded.acknowledge_front(); bounded.acknowledge_front();
        require(bounded.front()["changes"][0]["reason"] == "supervisor_history_bound" &&
            bounded.front()["changes"][0]["omitted_gap_reports"] == "2" &&
            bounded.front()["changes"][0]["count"].is_null() && bounded.front()["source_status"].is_null(),
            "history omission invented native loss count or source state");
        bounded.acknowledge_front();
        require(!bounded.pending(), "accepted history omission summary remained pending");
        health::SourceGapBuffer byte_bound{4, 2048};
        auto oversized = first; oversized.statistics_error = std::string(8192, 'x');
        byte_bound.observe(oversized, 1);
        require(byte_bound.empty() && byte_bound.pending() && byte_bound.snapshot()["omitted_reports_total"] == "1",
            "oversized source report escaped byte bound or hid pending omission");
        byte_bound.observe(oversized, 2);
        require(byte_bound.front()["changes"][0]["reason"] == "supervisor_history_bound", "oversized history summary missing");
        auto one_unknown = first; one_unknown.events_lost.reset();
        gap = health::source_gap_since(first, one_unknown);
        require(gap && (*gap)["changes"][0]["reason"] == "counter_sample_unavailable", "individual counter outage hidden");
        gap = health::source_gap_since(one_unknown, first);
        require(gap && (*gap)["changes"][0]["total"] == "0" && (*gap)["changes"][0]["delta"].is_null(),
            "restored zero counter became known zero-loss interval");
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
        journal_retry_history(factory);
        if (argc == 2 && std::string{argv[1]} == "--emit-gap-history") {
            health::SourceGapBuffer fixture{2, 4096};
            fixture.observe(first, 10); fixture.observe(unavailable, 20);
            fixture.observe(lost, 30); fixture.observe(stopped, 40);
            auto records = nlohmann::json::array();
            while (!fixture.empty()) {
                records.push_back(factory.gap("etw", fixture.front())); fixture.acknowledge_front();
            }
            std::cout << records.dump() << '\n'; return 0;
        }
        const auto record = factory.gap("etw", *health::source_gap_since(first, lost));
        if (argc == 2 && std::string{argv[1]} == "--emit-gap") {
            std::cout << record.dump() << '\n';
            return 0;
        }
        require(record["kind"] == "gap" && record["category"] == "source_loss" && record["subject"].is_null(), "source loss must be first-class canonical evidence");
        require(record["provenance"]["channel"] == "etw" && record["provenance"]["continuity"] == "unverified", "loss record cannot claim restored coverage");
        std::cout << "source supervision tests passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

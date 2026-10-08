#include "panopticon/officer/core/process_graph.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsqlite/winsqlite3.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace {
using Json = nlohmann::json;
namespace delivery = panopticon::officer::delivery;
namespace pipeline = panopticon::officer::pipeline;
namespace telemetry = panopticon::officer::telemetry;
void require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
template<class Action> void refusal(Action action, const char* reason) {
    bool failed = false; try { action(); } catch (const std::exception&) { failed = true; }
    require(failed, reason);
}
struct Scratch {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
        ("officer-graph-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    ~Scratch() {
        std::error_code error;
        if (path.parent_path() == std::filesystem::temp_directory_path() && path.filename().string().starts_with("officer-graph-"))
            std::filesystem::remove_all(path, error);
    }
};
pipeline::NormalizationContext context() { return {{"agent-1", "dev"}, {"host-1", "LAB", {"Windows", "26100"}}}; }
struct Fixture {
    pipeline::EndpointRecordFactory factory{context(), "device-1", std::string(64, 'b'), "boot_" + std::string(64, 'a'), 1};
    telemetry::RawProcessEvent raw(std::uint32_t pid, std::optional<std::string> guid,
        std::optional<std::uint32_t> parent = std::nullopt, std::optional<std::string> parent_guid = std::nullopt,
        std::optional<std::uint64_t> ticks = std::nullopt) {
        telemetry::RawProcessEvent result;
        result.source = {telemetry::TelemetrySourceKind::sysmon, "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational", 1};
        result.pid = pid; result.process_guid = guid; result.parent_pid = parent; result.parent_process_guid = parent_guid;
        result.start_time_ticks = ticks;
        result.process_start_time = telemetry::UtcTimestamp{std::chrono::nanoseconds{1725526400000000100ll}};
        result.executable = "C:\\fixture.exe"; return result;
    }
    Json start(const telemetry::RawProcessEvent& raw) {
        panopticon::officer::enrichment::EnrichedProcessEvent enriched; enriched.raw = raw;
        std::string error; const auto normalized = pipeline::normalize_process_event(enriched, context(), error);
        require(normalized.has_value(), "fixture normalization failed");
        return factory.observation(telemetry::RawEvent{raw}, *normalized);
    }
    Json stop(telemetry::RawProcessEvent raw) {
        raw.terminated = true; raw.termination_time = raw.process_start_time + std::chrono::seconds(1);
        raw.termination_time_ticks = 133700000000000999ull; raw.exit_code = 0;
        return factory.process_stop(raw);
    }
};
std::string entity(const Json& record) { return record.at("subject").at("entity_id").get<std::string>(); }
void owned_sql(const std::filesystem::path& path, const char* sql) {
    sqlite3* database = nullptr;
    require(sqlite3_open16((path / L"journal.db").c_str(), &database) == SQLITE_OK, "owned SQL fixture open");
    const auto rc = sqlite3_exec(database, sql, nullptr, nullptr, nullptr); sqlite3_close(database);
    require(rc == SQLITE_OK, "owned SQL fixture mutation");
}
Json cases() {
    Fixture fixture; Scratch scratch;
    const auto child_raw = fixture.raw(22, "{child}", 11, "{parent}");
    const auto child = fixture.start(child_raw);
    const auto parent_raw = fixture.raw(11, "{parent}");
    const auto parent_stop = fixture.stop(parent_raw), parent = fixture.start(parent_raw);
    const auto fact = panopticon::officer::core::process_graph_fact(child);
    require(fact.interpretable && fact.parent_entity_id && fact.entity_id == entity(child), "exact decoded parent fact refused");
    auto forged = child; forged["subject"]["entity_id"] = "proc_" + std::string(64, 'f');
    require(!panopticon::officer::core::process_graph_fact(forged).interpretable, "forged subject promoted");
    auto drift = child; drift["provenance"]["provider"] = "different-provider";
    require(!panopticon::officer::core::process_graph_fact(drift).interpretable, "cross-source identity drift accepted");
    auto no_parent_guid = fixture.start(fixture.raw(44, "{no-parent}", 11));
    require(!panopticon::officer::core::process_graph_fact(no_parent_guid).parent_entity_id, "PID-only parent joined");
    Json saved;
    {
        delivery::DurableJournal journal{{scratch.path}};
        journal.append(child.dump());
        auto before = journal.process_ancestry(entity(child));
        require(before["nodes"].size() == 2 && before["nodes"][1]["evidence"].empty(), "unobserved parent became a birth");
        journal.append(parent_stop.dump()); journal.append(parent.dump()); journal.append(child.dump());
        journal.append(no_parent_guid.dump()); journal.append(forged.dump());
        auto graph = journal.process_ancestry(entity(child));
        require(graph["nodes"].size() == 2 && graph["edges"].size() == 1 && graph["nodes"][1]["birth_observed"] == true &&
            graph["nodes"][1]["stop_observed"] == true && graph["nodes"][1]["liveness"].is_null(), "late/reordered lifecycle graph failure");
        require(graph["retained_evidence_traversal_complete"] == true && graph["creator_relationship_verified"] == false &&
            graph["source_coverage_complete"] == false, "traversal overclaimed creator or coverage");
        require(journal.process_ancestry(entity(no_parent_guid))["edges"].empty(), "PID-only source became ancestry");
        require(journal.stats().process_graph_indexed == 5 && journal.stats().process_graph_unresolved == 1, "index/refusal accounting incorrect");
        const auto narrow = journal.process_ancestry(entity(child), 64, 16, 1);
        require(narrow["truncated"] == true && narrow["retained_evidence_traversal_complete"] == false, "evidence limit falsely complete");
        require(journal.process_ancestry(entity(child), 1)["truncated"] == true, "node budget ignored");
        require(journal.process_ancestry(entity(child), 64, 1)["truncated"] == true, "depth budget ignored");
        refusal([&] { (void)journal.process_ancestry("PID-22"); }, "PID-only graph query accepted");
        auto batch = journal.peek(1000, 1024 * 1024); require(batch.has_value(), "fixture ACK batch missing");
        journal.acknowledge(*batch, Json{{"batch_id", batch->id}, {"received", batch->entries.size()},
            {"accepted", batch->entries.size()}, {"duplicates", 0u}, {"rejected", Json::array()}}.dump());
        saved = journal.process_ancestry(entity(child));
        require(saved == graph && journal.stats().pending_events == 0, "delivery retirement erased graph");
    }
    {
        delivery::DurableJournal reopened{{scratch.path}};
        require(reopened.process_ancestry(entity(child)) == saved, "restart altered exact graph evidence");
    }
    // Actual schema-five archive migration has no graph index. Bounded rebuild
    // must preserve immutable encrypted originals and never skip a large head.
    owned_sql(scratch.path, "DROP TRIGGER process_graph_insert; DROP TABLE process_graph_index;"
        "DELETE FROM counters WHERE name IN ('process_graph_count','process_graph_unresolved'); PRAGMA user_version=5;");
    {
        delivery::DurableJournal migrated{{scratch.path}};
        require(migrated.stats().process_graph_indexed == 0 && migrated.stats().process_history_records == 5,
            "schema-five backlog was hidden");
        require(migrated.process_ancestry(entity(child))["retained_evidence_traversal_complete"] == false, "unindexed archive called complete");
        refusal([&] { (void)migrated.rebuild_process_graph(1, 1); }, "backfill skipped oversized first record");
        require(migrated.stats().process_graph_indexed == 0, "refused rebuild mutated index");
        require(migrated.rebuild_process_graph(1, 1024 * 1024) == 1 &&
            migrated.rebuild_process_graph(1000, 1024 * 1024) == 4 &&
            migrated.rebuild_process_graph(1000, 1024 * 1024) == 0, "bounded idempotent backfill failed");
        require(migrated.process_ancestry(entity(child)) == saved, "rebuild changed graph claims");
        const auto originals = migrated.inspect_process_history(0, 1000, 1024 * 1024);
        require(originals[0].original.body == child.dump() && originals[1].original.body == parent_stop.dump(), "backfill rewrote originals");
    }
    owned_sql(scratch.path, "UPDATE process_graph_index SET parent_digest='corrupted' WHERE history_seq=1;");
    {
        delivery::DurableJournal corrupted{{scratch.path}};
        refusal([&] { (void)corrupted.process_ancestry(entity(child)); }, "index corruption bypassed immutable evidence comparison");
        require(corrupted.inspect_process_history(0, 1, 1024 * 1024)[0].original.body == child.dump(), "corruption deleted original");
    }
    Scratch other;
    {
        delivery::DurableJournal journal{{other.path}};
        const auto native1 = fixture.start(fixture.raw(88, std::nullopt, 11, std::nullopt, 100));
        const auto native2 = fixture.start(fixture.raw(88, std::nullopt, 11, std::nullopt, 200));
        journal.append(native1.dump()); journal.append(native2.dump());
        require(entity(native1) != entity(native2) && journal.process_ancestry(entity(native1))["nodes"][0]["evidence"].size() == 1,
            "PID reuse conflated native instances");
        auto scoped_raw = fixture.raw(22, "{child}"); scoped_raw.source.provider = "Another-source";
        const auto other_source = fixture.start(scoped_raw);
        journal.append(other_source.dump());
        require(entity(other_source) != entity(child) && journal.process_ancestry(entity(other_source))["edges"].empty(),
            "same source GUID was aliased across providers");
        const auto a = fixture.start(fixture.raw(90, "{a}", 91, "{b}"));
        const auto b = fixture.start(fixture.raw(91, "{b}", 90, "{a}"));
        journal.append(a.dump()); journal.append(b.dump());
        const auto cycle = journal.process_ancestry(entity(a));
        require(cycle["nodes"].size() == 2 && cycle["edges"].size() == 2 && cycle["edges"][1]["cycle_detected"] == true,
            "reported parent cycle lost or unbounded");
        const auto conflict = fixture.start(fixture.raw(22, "{child}", 91, "{b}"));
        journal.append(child.dump()); journal.append(conflict.dump()); journal.append(parent.dump());
        const auto claims = journal.process_ancestry(entity(child));
        require(claims["nodes"][0]["parent_claims_conflict"] == true && claims["edges"].size() >= 2,
            "conflicting parents silently replaced");
    }
    return Json::array({child, parent_stop, parent, no_parent_guid});
}
}
int main(int argc, char** argv) {
    try {
        if (argc == 4 && std::string_view(argv[1]) == "--read-ancestry") {
            delivery::DurableJournal journal{{std::filesystem::path{argv[2]}}};
            std::cout << journal.process_ancestry(argv[3]).dump() << '\n'; return 0;
        }
        if (argc != 1 && !(argc == 2 && std::string_view(argv[1]) == "--emit-fixtures"))
            throw std::invalid_argument("invalid graph probe arguments");
        const auto fixtures = cases();
        if (argc == 2) std::cout << fixtures.dump() << '\n';
        else std::cout << "Process graph encrypted archive/rebuild/identity/ancestry fixtures passed; live ETW and creator qualification unverified\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

#include "panopticon/officer/delivery/journal.hpp"
#include "panopticon/officer/delivery/spool.hpp"
#include <nlohmann/json.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <algorithm>
#include <limits>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

namespace {
namespace delivery = panopticon::officer::delivery;
namespace fs = std::filesystem;
using Json = nlohmann::json;
int failures = 0;
void expect(bool value, const char* message) {
    if (!value) { ++failures; std::cerr << "FAIL: " << message << '\n'; }
}
template<class Action> void expect_failure(Action action, const char* message) {
    try { action(); expect(false, message); } catch (const std::exception&) {}
}
struct Scratch {
    fs::path path = fs::temp_directory_path() / ("officer-journal-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    ~Scratch() {
        std::error_code ec;
        if (!fs::equivalent(path.parent_path(), fs::temp_directory_path(), ec) || ec ||
            !path.filename().string().starts_with("officer-journal-")) return;
        fs::remove_all(path, ec);
    }
};
std::string observation(int id) {
    return Json{{"event", {{"id", "evt_" + std::to_string(id)}}}, {"private", "secret-user-command-" + std::to_string(id)}}.dump();
}
Json receipt(const delivery::JournalBatch& batch) {
    return Json{{"batch_id", batch.id}, {"received", batch.entries.size()}, {"accepted", batch.entries.size()}, {"duplicates", 0u}, {"rejected", Json::array()}};
}

void test_read_only_inspection_paging() {
    Scratch scratch; std::uint64_t cursor = 0;
    const std::string canonical = R"({"schema_version":"1.0","kind":"state","record_id":"inspection-state"})";
    const std::vector<std::string> bodies{observation(1), canonical, observation(3)};
    {
        delivery::DurableJournal journal{{scratch.path}};
        for (const auto& body : bodies) journal.append(body);
        const auto bytes = journal.inspect_pending(0, 1000, bodies[0].size() + 1);
        expect(bytes.size() == 1 && bytes[0].original.body == bodies[0], "inspection obeys byte cap and preserves exact first record");
        for (std::size_t index = 0; index < bodies.size(); ++index) {
            const auto page = journal.inspect_pending(cursor, 1, 4096);
            expect(page.size() == 1 && page[0].original.body == bodies[index] && page[0].local_sequence > cursor,
                "inspection cursor traverses exact originals in local journal order across protocols");
            if (page.empty()) return;
            expect(page[0].protocol == (index == 1 ? 2u : 1u), "inspection retains each original protocol without transport partitioning");
            cursor = page[0].local_sequence;
        }
        expect(journal.inspect_pending(cursor, 1000, 4096).empty(), "inspection end is explicit without repeating head");
        expect(journal.stats().pending_events == 3 && journal.stats().acknowledged_events == 0,
            "inspection never acknowledges, retires or modifies pending evidence");
        expect_failure([&] { (void)journal.inspect_pending(0, 1000, 1); }, "too-small inspection page refuses instead of skipping evidence");
        expect_failure([&] { (void)journal.inspect_pending(UINT64_MAX, 1, 4096); }, "out-of-range local cursor cannot wrap into journal head");
        const auto legacy = journal.peek(1000, 4096);
        journal.acknowledge(*legacy, receipt(*legacy).dump());
        const auto retained = journal.inspect_pending(0, 1000, 4096);
        expect(retained.size() == 1 && retained[0].original.body == canonical,
            "inspection omits acknowledged rows and preserves pending records through sequence holes");
    }
    delivery::DurableJournal reopened{{scratch.path}};
    const auto retained = reopened.inspect_pending(0, 1000, 4096);
    expect(retained.size() == 1 && retained[0].original.body == canonical && retained[0].local_sequence < cursor,
        "inspection ordering/retained bytes survive journal reopen independently of an old exhausted cursor");
}

void test_restart_encryption_and_ack() {
    Scratch scratch;
    {
        delivery::DurableJournal journal{{scratch.path}};
        journal.append(observation(1));
        journal.append(observation(2));
        journal.append(observation(1));
        expect(journal.stats().pending_events == 2, "identical observation deduplicates within journal");
        for (const auto& file : fs::directory_iterator(scratch.path)) {
            if (!file.is_regular_file()) continue;
            std::ifstream stream(file.path(), std::ios::binary);
            const std::string bytes((std::istreambuf_iterator<char>(stream)), {});
            expect(bytes.find("secret-user-command") == std::string::npos, "database and WAL contain no plaintext observation payload");
        }
    }
    delivery::DurableJournal recovered{{scratch.path}};
    auto batch = recovered.peek(1000, 8u * 1024 * 1024);
    expect(batch && batch->entries.size() == 2 && batch->entries[0].body == observation(1), "restart recovers exact original bytes in order");
    if (!batch) return;
    auto ack = receipt(*batch);
    ack["batch_id"] = "unrelated-batch";
    expect_failure([&] { recovered.acknowledge(*batch, ack.dump()); }, "wrong batch receipt is rejected");
    ack = receipt(*batch); ack["accepted"] = 1u;
    expect_failure([&] { recovered.acknowledge(*batch, ack.dump()); }, "incomplete receipt is rejected");
    expect_failure([&] { recovered.acknowledge(*batch, "{}"); }, "HTTP 200 with empty JSON cannot dispose evidence");
    ack = receipt(*batch); ack["accepted"] = 2.0;
    expect_failure([&] { recovered.acknowledge(*batch, ack.dump()); }, "noninteger receipt count is rejected");
    expect(recovered.stats().pending_events == 2, "invalid receipts leave every record pending");
    ack = receipt(*batch);
    ack["accepted"] = 1u;
    ack["rejected"].push_back({{"line", 2u}, {"event_id", "evt_2"}, {"reason", "schema_invalid"}, {"detail", "fixture schema rejection"}});
    auto invalid = ack; invalid["rejected"][0]["event_id"] = "evt_another";
    expect_failure([&] { recovered.acknowledge(*batch, invalid.dump()); }, "rejection must identify submitted event");
    recovered.acknowledge(*batch, ack.dump());
    expect(recovered.stats().pending_events == 0 && recovered.stats().dead_letter_events == 1 && recovered.stats().acknowledged_events == 1,
           "partial success atomically acknowledges accepted event and retains rejected original");
    recovered.acknowledge(*batch, ack.dump());
    expect(recovered.stats().acknowledged_events == 1, "duplicate receipt cannot inflate acknowledgment counters");
    delivery::DurableJournal reopened{{scratch.path}};
    expect(reopened.stats().dead_letter_events == 1 && reopened.stats().pending_events == 0, "rejection and acknowledgment survive reopen");
    const auto dead = reopened.dead_letters(1000);
    expect(dead.size() == 1 && dead[0].original.body == observation(2) && dead[0].reason == "schema_invalid: fixture schema rejection",
           "dead-letter inspection recovers encrypted original and reason after restart");
}

void test_quota_and_bounds() {
    Scratch scratch;
    const auto first = observation(3);
    delivery::DurableJournal journal{{scratch.path, first.size()}};
    journal.append(first);
    expect_failure([&] { journal.append(observation(4)); }, "quota exhaustion is reported");
    expect(journal.stats().pending_events == 1 && journal.peek(1, 4096)->entries[0].body == first, "quota exhaustion never evicts retained evidence");
    expect_failure([&] { journal.append("{}\n{}"); }, "multiline observation is rejected");
    expect_failure([&] { journal.append(" \t "); }, "whitespace-only observation cannot create an unacknowledgeable batch");
    expect_failure([&] { (void)journal.peek(1001, 4096); }, "batch event ceiling is enforced");
    expect_failure([&] { (void)journal.peek(1, 1); }, "untransportable head is reported without removal");
}

void test_physical_admission_preserves_evidence() {
    Scratch scratch;
    std::string installation;
    {
        delivery::DurableJournal journal{{scratch.path}};
        installation = journal.persistent_identifier("installation");
        journal.append(observation(71));
        journal.receive_command("scope", "ready", "exact command");
        expect(journal.begin_command("scope", "ready"), "execution intent commits before storage pressure");
    }
    {
        delivery::JournalConfig config{scratch.path};
        config.physical_admission_limit = 1;
        delivery::DurableJournal journal{config};
        journal.append(observation(71)); // Existing identical evidence needs no new allocation.
        expect(journal.persistent_identifier("installation") == installation, "existing identity readable under physical pressure");
        journal.receive_command("scope", "ready", "exact command");
        expect(!journal.begin_command("scope", "ready"), "already executing command does not require new storage admission");
        expect_failure([&] { journal.append(observation(72)); }, "physical budget refuses new encrypted observation");
        expect_failure([&] { journal.receive_command("scope", "new", "new command"); }, "physical budget refuses new command");
        expect_failure([&] { journal.finish_command("scope", "ready", "exact outcome"); }, "physical budget refuses outcome growth without losing intent");
        expect_failure([&] { (void)journal.next_collector_generation(); }, "physical budget refuses identity generation write");
        const auto batch = journal.peek(10, 4096);
        auto rejected = receipt(*batch);
        rejected["accepted"] = 0u;
        rejected["rejected"].push_back({{"line", 1u}, {"event_id", "evt_71"}, {"reason", "schema_invalid"}, {"detail", "retained reason"}});
        expect_failure([&] { journal.acknowledge(*batch, rejected.dump()); }, "physical budget refuses rejection metadata atomically");
        const auto stats = journal.stats();
        expect(stats.pending_events == 1 && stats.dead_letter_events == 0 && stats.storage_admission_refusals == 5,
            "pressure leaves observation pending and reports exact in-memory refusal count");
        expect(stats.disk_bytes > config.physical_admission_limit && stats.caller_available_bytes > 0,
            "physical sample reports oversize retained journal rather than deleting it");
        journal.acknowledge(*batch, receipt(*batch).dump());
        expect(journal.stats().pending_events == 0, "valid acceptance ACK may reclaim under admission pressure");
    }
    {
        delivery::JournalConfig config{scratch.path};
        config.minimum_free_bytes = std::numeric_limits<std::uint64_t>::max();
        delivery::DurableJournal journal{config};
        expect_failure([&] { journal.append(observation(73)); }, "caller-available headroom independently refuses admission");
        const auto commands = journal.pending_commands("scope", 10);
        expect(commands.size() == 1 && commands[0].body == "exact command" && commands[0].state == "executing" && commands[0].result.empty(),
            "reopen under headroom pressure preserves exact command and committed intent");
        expect(journal.stats().storage_admission_refusals == 1, "refusal counter explicitly starts fresh on reopen");
    }
    delivery::DurableJournal restored{{scratch.path}};
    restored.finish_command("scope", "ready", "exact outcome");
    restored.mark_command_outboxed("scope", "ready");
    expect(restored.stats().commands_outboxed == 1, "normal budget restores outcome and handoff progress");
}

void test_protocol_partition_and_install_identity() {
    Scratch scratch;
    std::string installation;
    {
        delivery::DurableJournal journal{{scratch.path}};
        installation = journal.persistent_identifier("installation");
        journal.append(observation(31));
        journal.append(R"({"schema_version":"1.0","kind":"state","record_id":"record-32"})");
        journal.append(observation(33));
        const auto legacy = journal.peek(1000, 4096);
        expect(legacy && legacy->protocol == 1 && legacy->entries.size() == 2, "legacy and canonical records never share an incompatible transport batch");
        journal.acknowledge(*legacy, receipt(*legacy).dump());
        const auto canonical = journal.peek(1000, 4096);
        expect(canonical && canonical->protocol == 2 && canonical->entries.size() == 1, "canonical record routes through protocol 2");
        auto ack = receipt(*canonical);
        ack["accepted"] = 0u;
        ack["rejected"].push_back({{"line", 1u}, {"event_id", "record-32"}, {"reason", "schema_invalid"}, {"detail", "fixture"}});
        journal.acknowledge(*canonical, ack.dump());
        expect(journal.stats().dead_letter_events == 1, "canonical record-ID rejection retains original evidence");
    }
    delivery::DurableJournal reopened{{scratch.path}};
    expect(reopened.persistent_identifier("installation") == installation && installation.size() == 64, "installation identity persists independently of boot and collector epochs");
}

void test_immutable_legacy_migration() {
    Scratch scratch;
    delivery::SpoolConfig config;
    config.directory = scratch.path;
    {
        delivery::SegmentSpool old{config};
        old.recover();
        old.append("legacy-batch", observation(5) + '\n' + observation(6) + '\n');
    }
    fs::path original;
    for (const auto& file : fs::directory_iterator(scratch.path))
        if (file.path().filename().string().starts_with("segment-")) original = file.path();
    {
        std::ofstream stream(original, std::ios::binary | std::ios::app);
        stream.write("bad", 3); // torn final header
    }
    const auto size = fs::file_size(original);
    {
        delivery::DurableJournal migrated{{scratch.path}};
        expect(migrated.stats().pending_events == 2 && migrated.stats().legacy_gaps == 1, "migration recovers complete frames and accounts for torn legacy tail");
        auto batch = migrated.peek(1000, 4096);
        expect(batch && batch->entries[0].body == observation(5), "migration preserves original JSON bytes");
        migrated.acknowledge(*batch, receipt(*batch).dump());
    }
    delivery::DurableJournal reopened{{scratch.path}};
    expect(reopened.stats().pending_events == 0 && reopened.stats().legacy_gaps == 1, "migration ledger prevents reimport after delivery and restart");
    expect(fs::file_size(original) == size, "migration leaves legacy source untouched");
}

void test_hard_process_exit() {
    Scratch scratch;
    wchar_t executable[32768]{};
    const auto length = GetModuleFileNameW(nullptr, executable, 32768);
    if (!length || length >= 32768) throw std::runtime_error("test executable path unavailable");
    auto command = L"\"" + std::wstring{executable} + L"\" --crash-writer \"" + scratch.path.wstring() + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
        throw std::runtime_error("crash writer could not be started");
    const auto wait = WaitForSingleObject(process.hProcess, 15000);
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 91);
        WaitForSingleObject(process.hProcess, 5000);
    }
    DWORD code = 0;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    expect(wait == WAIT_OBJECT_0 && code == 77, "child terminates abruptly after committed observations");
    delivery::DurableJournal recovered{{scratch.path}};
    const auto batch = recovered.peek(1000, 4096);
    const auto commands = recovered.pending_commands("crash-scope", 10);
    expect(commands.size() == 2 && commands[0].state == "received" && commands[1].state == "executing" &&
        commands[0].body == "committed queued body" && commands[1].body == "committed executing body",
        "abrupt owned-child termination preserves queued versus possibly executed intent without guessing completion");
    expect(recovered.next_collector_generation() == 2, "hard process exit cannot reuse a committed collector generation");
    expect(batch && batch->entries.size() == 10 && batch->entries.back().body == observation(109),
        "FULL/WAL commits survive process termination without destructors or orderly SQLite close");
}

void test_collector_generations() {
    Scratch scratch;
    {
        delivery::DurableJournal first{{scratch.path}};
        expect(first.next_collector_generation() == 1, "first generation commits before collection");
        delivery::DurableJournal concurrent{{scratch.path}};
        expect(concurrent.next_collector_generation() == 2 && first.next_collector_generation() == 3,
            "separate journal handles cannot reuse a committed generation");
    }
    delivery::DurableJournal reopened{{scratch.path}};
    expect(reopened.next_collector_generation() == 4, "restart preserves generation despite wall-clock changes");
    try { (void)reopened.persistent_identifier("__collector_generation"); expect(false, "reserved counter cannot become a random identity"); }
    catch (const std::invalid_argument&) {}
}

void test_command_inbox_transitions_and_immutability() {
    Scratch scratch;
    const std::string body = R"({"command_id":"owned-command","private":"secret-inbox-target"})";
    const std::string result = R"({"outcome":"indeterminate","private":"secret-inbox-outcome"})";
    {
        delivery::DurableJournal first{{scratch.path}};
        first.receive_command("scope-1", "key-1", body);
        first.receive_command("scope-1", "key-1", body);
        expect(first.pending_commands("scope-1", 10).size() == 1, "identical command admission is immutable/idempotent");
        expect_failure([&] { first.receive_command("scope-1", "key-1", body + " "); }, "same command key cannot change payload");
        expect_failure([&] { first.receive_command("scope-2", "key-1", body); }, "same command key cannot change scope");
        expect_failure([&] { first.finish_command("scope-1", "key-1", result); }, "outcome cannot precede committed intent");
        delivery::DurableJournal second{{scratch.path}};
        expect(first.begin_command("scope-1", "key-1"), "first held transaction commits execution intent");
        expect(!second.begin_command("scope-1", "key-1"), "another handle cannot acquire the same queued execution intent");
        expect(second.pending_commands("scope-1", 10).front().state == "executing", "separate handle sees committed intent");
        expect(second.stats().commands_executing == 1 && second.stats().commands_received == 0, "health distinguishes queued and executing states");
        first.finish_command("scope-1", "key-1", result);
        second.finish_command("scope-1", "key-1", result);
        expect_failure([&] { second.finish_command("scope-1", "key-1", result + " "); }, "committed outcome cannot be changed");
        expect(first.stats().retained_bytes == body.size() + result.size(), "inbox bodies and outcomes count against plaintext retention");
        for (const auto& file : fs::directory_iterator(scratch.path)) {
            if (!file.is_regular_file()) continue;
            std::ifstream stream{file.path(), std::ios::binary};
            const std::string bytes((std::istreambuf_iterator<char>(stream)), {});
            expect(bytes.find("secret-inbox-") == std::string::npos, "command and result bodies remain encrypted in DB/WAL");
        }
    }
    delivery::DurableJournal recovered{{scratch.path}};
    const auto pending = recovered.pending_commands("scope-1", 10);
    expect(pending.size() == 1 && pending.front().state == "result_ready" && pending.front().body == body && pending.front().result == result,
        "restart preserves exact inbox body and committed outcome");
    expect(recovered.pending_commands("scope-2", 10).empty(), "other identity scope cannot consume inbox");
    recovered.mark_command_outboxed("scope-1", "key-1");
    recovered.mark_command_outboxed("scope-1", "key-1");
    recovered.receive_command("scope-1", "key-1", body);
    expect(recovered.pending_commands("scope-1", 10).empty() && !recovered.begin_command("scope-1", "key-1"), "outboxed replay tombstone never becomes queued again");
    expect(recovered.stats().commands_outboxed == 1 && recovered.stats().command_results_ready == 0, "health retains terminal inbox tombstone accounting");
    Scratch limited;
    delivery::DurableJournal bounded{{limited.path, body.size() + result.size() - 1}};
    bounded.receive_command("scope-1", "key-1", body);
    expect(bounded.begin_command("scope-1", "key-1"), "bounded inbox retains committed intent");
    expect_failure([&] { bounded.finish_command("scope-1", "key-1", result); }, "outcome quota refusal never evicts prior intent");
    expect(bounded.pending_commands("scope-1", 10).front().state == "executing", "refused outcome preserves recoverable uncertain state");
}

void benchmark_commits() {
    Scratch scratch;
    delivery::DurableJournal journal{{scratch.path}};
    std::vector<double> latency;
    const auto begin = std::chrono::steady_clock::now();
    std::uint64_t payload_bytes = 0;
    for (int index = 0; index < 1000; ++index) {
        auto event = Json{{"event", {{"id", "evt_benchmark_" + std::to_string(index)}}}, {"padding", std::string(960, 'x')}}.dump();
        payload_bytes += event.size();
        const auto start = std::chrono::steady_clock::now();
        journal.append(event);
        latency.push_back(std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count());
    }
    const auto seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
    std::sort(latency.begin(), latency.end());
    std::cout << Json{{"benchmark", "single-thread DPAPI plus SQLite FULL/WAL commit"}, {"events", 1000}, {"payload_bytes", payload_bytes},
        {"elapsed_seconds", seconds}, {"events_per_second", 1000.0 / seconds}, {"commit_p50_ms", latency[500]},
        {"commit_p95_ms", latency[950]}, {"commit_max_ms", latency.back()}, {"journal_disk_bytes", journal.stats().disk_bytes}}.dump() << '\n';
}
}

int main(int argc, char** argv) {
    if (argc == 2 && std::string{argv[1]} == "--benchmark") {
        benchmark_commits();
        return 0;
    }
    if (argc == 3 && std::string{argv[1]} == "--crash-writer") {
        delivery::DurableJournal journal{{fs::path{argv[2]}}};
        (void)journal.next_collector_generation();
        for (int index = 100; index < 110; ++index) journal.append(observation(index));
        journal.receive_command("crash-scope", "queued-command", "committed queued body");
        journal.receive_command("crash-scope", "interrupted-command", "committed executing body");
        if (!journal.begin_command("crash-scope", "interrupted-command")) return 93;
        TerminateProcess(GetCurrentProcess(), 77);
        return 92;
    }
    try {
        test_restart_encryption_and_ack();
        test_read_only_inspection_paging();
        test_quota_and_bounds();
        test_physical_admission_preserves_evidence();
        test_protocol_partition_and_install_identity();
        test_collector_generations();
        test_command_inbox_transitions_and_immutability();
        test_immutable_legacy_migration();
        test_hard_process_exit();
    } catch (const std::exception& error) { expect(false, error.what()); }
    return failures ? 1 : 0;
}

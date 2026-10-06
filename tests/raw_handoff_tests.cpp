#include "panopticon/officer/pipeline/raw_handoff.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <chrono>
#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <barrier>
#include <nlohmann/json.hpp>

namespace p = panopticon::officer::pipeline;
namespace t = panopticon::officer::telemetry;
namespace d = panopticon::officer::delivery;
using namespace std::chrono_literals;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Scratch {
    std::filesystem::path path = std::filesystem::temp_directory_path() / ("officer-handoff-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    ~Scratch() {
        std::error_code error;
        if (std::filesystem::equivalent(path.parent_path(), std::filesystem::temp_directory_path(), error) && !error && path.filename().string().starts_with("officer-handoff-"))
            std::filesystem::remove_all(path, error);
    }
};
bool submit(p::RawHandoff& queue, const t::RawEvent& event) {
    // Arrange test-owned capacity admission. Production submits once.
    for (int i = 0; i < 1000; ++i) {
        if (queue.try_submit(event)) return true;
        std::this_thread::yield();
    }
    return false;
}
void blocked_storage_and_bounds(bool count_bound) {
    Scratch scratch; d::DurableJournal journal{{scratch.path}};
    std::promise<void> entered, release; auto released = release.get_future().share();
    t::RawProcessEvent raw{}; raw.pid = 42; raw.command_line = "exact owned command";
    const t::RawEvent event{raw}; const auto charge = p::raw_event_charge(event);
    p::RawHandoff queue{count_bound ? 1u : 2u, count_bound ? charge * 2 : charge, [&](t::RawEvent owned) {
        entered.set_value(); released.wait();
        require(owned == event, "handoff preserves exact observed source fields");
        journal.append(R"({"owned_raw_fact":"exact owned command"})");
    }};
    const bool admitted = submit(queue, event);
    const auto wait = entered.get_future().wait_for(5s);
    // Release on every assertion path so a failing test cannot hang the worker.
    const auto before = queue.stats();
    const bool refused = !queue.try_submit(event);
    const auto pending = journal.stats().pending_events;
    release.set_value(); queue.close();
    require(admitted && wait == std::future_status::ready, "owned event reaches blocked worker");
    require(before.owned_events == 1 && before.charged_bytes == charge && before.completed == 0 && pending == 0,
        "in-flight item remains charged and volatile admission never masquerades as commit");
    require(refused, "blocked storage does not block callback and in-flight item consumes limits");
    const auto after = queue.stats();
    require(after.completed == 1 && after.failed == 0 && after.owned_events == 0 && after.charged_bytes == 0 && after.refused >= 1,
        "release completes durable work and retains refusal accounting");
    require(journal.peek(1, 4096)->entries[0].body == R"({"owned_raw_fact":"exact owned command"})", "durable downstream retains exact bytes");
    require(!queue.try_submit(event), "closed queue refuses new ownership");
}
void failed_worker_and_byte_charge() {
    t::RawProcessEvent raw{}; raw.command_line = std::string{}; raw.command_line->reserve(100000);
    const auto capacity = raw.command_line->capacity();
    t::RawEvent reserved{std::move(raw)};
    require(p::raw_event_charge(reserved) >= capacity, "reserved capacity counts even with empty string");
    p::RawHandoff bounded{2, 1, [](t::RawEvent) { throw std::runtime_error("must not run"); }};
    require(!bounded.try_submit(std::move(reserved)), "oversize event refuses byte admission"); bounded.close();
    std::atomic_uint calls{0};
    p::RawHandoff queue{100, 1024 * 1024, [&](t::RawEvent) {
        if (++calls == 1) throw std::runtime_error("injected durable sink refusal");
    }};
    require(submit(queue, t::RawProcessEvent{}), "first event admitted");
    require(submit(queue, t::RawProcessEvent{}), "later event admitted"); queue.close();
    const auto stats = queue.stats();
    require(stats.failed == 1 && stats.completed == 1 && stats.admitted == stats.completed + stats.failed + stats.owned_events,
        "worker exception is counted and does not kill subsequent processing");
    t::RawRegistryEvent registry{}; registry.value_data = std::string(1000, 'v');
    registry.process.cached_context.emplace(); registry.process.cached_context->process_guid = std::string(2000, 'g');
    require(p::raw_event_charge(t::RawEvent{registry}) >= 3000, "registry data and separate cached context are charged");
}
void concurrent_pressure(bool require_no_refusal, bool blocked = false) {
    constexpr std::size_t producers = 4, per_producer = 1000, total = producers * per_producer;
    std::vector<bool> observed(total, false);
    std::promise<void> release; auto released = release.get_future().share();
    p::RawHandoff queue{8192, 64 * 1024 * 1024, [&](t::RawEvent event) {
        if (blocked) released.wait();
        const auto pid = std::get<t::RawProcessEvent>(event).pid;
        require(pid < total && !observed[pid], "worker receives each admitted event once");
        observed[pid] = true;
    }};
    std::barrier start{static_cast<std::ptrdiff_t>(producers)};
    std::vector<std::thread> workers;
    for (std::size_t producer = 0; producer < producers; ++producer) {
        workers.emplace_back([&, producer] {
            start.arrive_and_wait();
            for (std::size_t index = 0; index < per_producer; ++index) {
                t::RawProcessEvent event{}; event.pid = static_cast<std::uint32_t>(producer * per_producer + index);
                (void)queue.try_submit(std::move(event)); // One attempt, no hidden replay.
            }
        });
    }
    for (auto& worker : workers) worker.join();
    release.set_value();
    queue.close(); const auto stats = queue.stats();
    std::cout << nlohmann::json{{"check", "four producer handoff pressure; lightweight owned handler"},
        {"submitted", total}, {"admitted", stats.admitted}, {"completed", stats.completed},
        {"refused", stats.refused}, {"contention_refused", stats.contention_refused}, {"handler_blocked_during_submission", blocked}}.dump() << '\n';
    require(stats.admitted + stats.refused == total && stats.admitted == stats.completed && stats.failed == 0,
        "concurrent producer receipts account for every submitted observation");
    if (require_no_refusal) require(stats.completed == total && stats.refused == 0, "spare capacity never refuses merely because queue mutex is busy");
}
void ring_wrap_preserves_order() {
    std::uint32_t expected = 0;
    p::RawHandoff queue{2, 1024 * 1024, [&](t::RawEvent event) {
        require(std::get<t::RawProcessEvent>(event).pid == expected++, "ring reuse preserves FIFO without stale slot replay");
    }};
    for (std::uint32_t index = 0; index < 40; ++index) {
        t::RawProcessEvent event{}; event.pid = index;
        require(queue.try_submit(std::move(event)), "empty reused ring admits the next owned event");
        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (queue.stats().completed < index + 1 && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
        require(queue.stats().completed == index + 1, "reused slot completes without corruption");
    }
    queue.close(); require(expected == 40 && queue.stats().failed == 0, "all ring wraps retain exact order");
}
int main(int argc, char** argv) {
    if (argc == 2 && std::string{argv[1]} == "--pressure") { concurrent_pressure(false); return 0; }
    try { blocked_storage_and_bounds(true); blocked_storage_and_bounds(false); failed_worker_and_byte_charge(); concurrent_pressure(true); concurrent_pressure(true, true); ring_wrap_preserves_order(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    return 0;
}

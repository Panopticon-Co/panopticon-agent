#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/http_client.hpp"
#include "panopticon/officer/delivery/uploader.hpp"

#include <chrono>
#include <iostream>
#include <thread>

namespace {

using namespace std::chrono_literals;
namespace delivery = panopticon::officer::delivery;

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

void test_config_defaults() {
    delivery::DeliveryConfig config;
    expect(config.manager_url.empty(), "manager_url is empty by default (network path opt-in)");
    expect(config.verify_tls, "TLS verification defaults on -- --insecure-tls must be explicit");
    expect(config.batch_max_events == 1000, "batch_max_events matches ADR 002's 1000-event cap");
    expect(config.flush_interval_ms == 5000, "flush_interval_ms has a sane default");
}

// No fake manager available in this environment -- this asserts the
// transport-failure path only (unreachable host), which needs no server.
// The happy-path round trip against a real manager is exercised by Phase 2's
// fake_agent/load harness and by hand on the Windows VM, not here.
void test_post_to_unreachable_host_fails_cleanly() {
    delivery::HttpClient client{/*verify_tls=*/false, /*timeout_ms=*/1000};
    std::string error;
    const auto response =
        client.post("https://127.0.0.1:1/api/v1/ingest", {}, "{}", error);
    expect(!response.has_value(), "connecting to a closed port is a transport failure, not a response");
    expect(!error.empty(), "a transport failure sets an error message");
}

void test_uploader_construct_enqueue_stop_does_not_hang() {
    delivery::DeliveryConfig config;
    config.manager_url = "https://127.0.0.1:1";
    config.verify_tls = false;
    config.batch_max_events = 2;
    config.flush_interval_ms = 50;

    delivery::Uploader uploader{config, "test-agent"};
    uploader.enqueue(R"({"schema_version":"0.3"})");
    uploader.enqueue(R"({"schema_version":"0.3"})");
    std::this_thread::sleep_for(200ms);
    uploader.stop();  // must return promptly, not hang, even though every flush fails
    expect(true, "uploader constructed, enqueued, and stopped without hanging or crashing");
}

}  // namespace

int main() {
    test_config_defaults();
    test_post_to_unreachable_host_fails_cleanly();
    test_uploader_construct_enqueue_stop_does_not_hang();

    if (failures == 0) {
        std::cout << "All Officer delivery tests passed.\n";
        return 0;
    }
    return 1;
}

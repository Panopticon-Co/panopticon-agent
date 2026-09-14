#include "panopticon/officer/delivery/config.hpp"
#include "panopticon/officer/delivery/http_client.hpp"
#include "panopticon/officer/delivery/uploader.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

namespace {

using namespace std::chrono_literals;
namespace delivery = panopticon::officer::delivery;
namespace fs = std::filesystem;

int failures = 0;

void expect(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        ++failures;
    }
}

// Every test that constructs an Uploader must point spool_directory at an
// isolated scratch path -- the default ("spool", relative to the process's
// CWD) would otherwise collide across test runs and leave junk behind.
class ScratchSpoolDir {
public:
    ScratchSpoolDir() {
        const auto seed = std::chrono::steady_clock::now().time_since_epoch().count();
        path_ = fs::temp_directory_path() / ("officer-delivery-test-spool-" + std::to_string(seed));
    }
    ~ScratchSpoolDir() {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
    const fs::path& path() const { return path_; }

private:
    fs::path path_;
};

void test_config_defaults() {
    delivery::DeliveryConfig config;
    expect(config.manager_url.empty(), "manager_url is empty by default (network path opt-in)");
    expect(config.verify_tls, "TLS verification defaults on -- --insecure-tls must be explicit");
    expect(config.batch_max_events == 1000, "batch_max_events matches ADR 002's 1000-event cap");
    expect(config.flush_interval_ms == 5000, "flush_interval_ms has a sane default");
    expect(!config.spool_directory.empty(), "spool_directory has a non-empty default (durability is not silently off)");
    expect(config.spool_max_total_bytes >= config.spool_max_segment_bytes,
           "default quota is never smaller than one segment");
    expect(config.spool_max_delivery_attempts > 0, "retry is bounded but never zero (never even try once)");
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
    ScratchSpoolDir spool_dir;
    delivery::DeliveryConfig config;
    config.manager_url = "https://127.0.0.1:1";
    config.verify_tls = false;
    config.batch_max_events = 2;
    config.flush_interval_ms = 50;
    config.spool_directory = spool_dir.path().string();

    delivery::Uploader uploader{config, "test-agent"};
    uploader.enqueue(R"({"schema_version":"0.3"})");
    uploader.enqueue(R"({"schema_version":"0.3"})");
    std::this_thread::sleep_for(200ms);
    uploader.stop();  // must return promptly, not hang, even though every send fails
    expect(true, "uploader constructed, enqueued, and stopped without hanging or crashing");
}

// Regression for the Phase 1 gap this phase closes: a batch that can never
// reach the manager (connection refused, in this case) used to be logged
// and dropped with nothing left behind. It must now survive on disk.
void test_failed_batch_is_persisted_to_the_spool_not_dropped() {
    ScratchSpoolDir spool_dir;
    delivery::DeliveryConfig config;
    config.manager_url = "https://127.0.0.1:1";  // nothing listens here
    config.verify_tls = false;
    config.batch_max_events = 1;
    config.flush_interval_ms = 20;
    config.spool_directory = spool_dir.path().string();

    {
        delivery::Uploader uploader{config, "test-agent"};
        uploader.enqueue(R"({"schema_version":"0.3","event_id":"evt_spool_test"})");
        std::this_thread::sleep_for(300ms);
        uploader.stop();
    }

    bool found_segment = false;
    if (fs::exists(spool_dir.path())) {
        for (const auto& entry : fs::directory_iterator(spool_dir.path())) {
            if (entry.path().filename().string().rfind("segment-", 0) == 0) {
                found_segment = true;
            }
        }
    }
    expect(found_segment, "a batch that can never be delivered is durably persisted to a spool segment file, not dropped");
}

}  // namespace

int main() {
    test_config_defaults();
    test_post_to_unreachable_host_fails_cleanly();
    test_uploader_construct_enqueue_stop_does_not_hang();
    test_failed_batch_is_persisted_to_the_spool_not_dropped();

    if (failures == 0) {
        std::cout << "All Officer delivery tests passed.\n";
        return 0;
    }
    return 1;
}

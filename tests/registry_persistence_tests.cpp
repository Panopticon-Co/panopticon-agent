#include "../src/state/persistence_native.hpp"
#include "panopticon/officer/health/state_freshness.hpp"
#include <iostream>
#include <stdexcept>
using namespace panopticon::officer;
using namespace state::native_persistence;
void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
struct Scratch {
    std::wstring path;
    HKEY key = nullptr;
    Scratch() {
        GUID id{}; require(SUCCEEDED(CoCreateGuid(&id)), "fixture GUID failed");
        wchar_t name[40]{}; require(StringFromGUID2(id, name, 40) != 0, "fixture GUID conversion failed");
        path = L"Software\\PanopticonValidation\\RegistryPersistence-" + std::wstring(name);
        DWORD disposition = 0;
        require(RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, &disposition) == ERROR_SUCCESS
            && disposition == REG_CREATED_NEW_KEY, "owned scratch key creation failed");
    }
    ~Scratch() {
        if (key) RegCloseKey(key);
        // Delete only the GUID-named namespace created by this fixture.
        RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
        RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
    }
    void set(const wchar_t* subkey, const wchar_t* name, const std::wstring& value) {
        HKEY child = nullptr;
        require(RegCreateKeyExW(key, subkey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &child, nullptr) == ERROR_SUCCESS, "fixture subkey failed");
        const auto result = RegSetValueExW(child, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()),
            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(child); require(result == ERROR_SUCCESS, "fixture value failed");
    }
};
int main() {
    try {
        Scratch scratch;
        const std::wstring inert = L"%PANOPTICON_NEVER_EXPAND%\\not-an-executable.txt";
        scratch.set(L"Software\\Microsoft\\Active Setup\\Installed Components\\fixture", L"StubPath", inert);
        scratch.set(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\fixture.exe", L"Debugger", inert);
        scratch.set(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\fixture.exe\\filter", L"FilterFullPath", inert);
        scratch.set(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\fixture.exe", L"MonitorProcess", inert);
        scratch.set(L"System\\CurrentControlSet\\Control\\Session Manager", L"BootExecute", inert);
        scratch.set(L"Software\\Classes\\CLSID\\{fixture}\\InprocServer32", L"", inert);
        scratch.set(L"Software\\Classes\\CLSID\\{fixture}\\LocalServer32", L"ServerExecutable", inert);
        scratch.set(L"Software\\Classes\\CLSID\\{fixture}\\TreatAs", L"", L"{unresolved-target}");
        scratch.set(L"Software\\Classes\\AppID\\{fixture}", L"DllSurrogate", inert);
        scratch.set(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run", L"fixture", inert);
        scratch.set(L"Software\\Google\\Chrome\\Extensions\\fixture", L"path", inert);
        scratch.set(L"Software\\Microsoft\\Edge\\NativeMessagingHosts\\fixture", L"", inert);
        scratch.set(L"Software\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist", L"1", inert);
        scratch.set(L"Software\\Microsoft\\Office\\Word\\Addins\\fixture", L"Manifest", inert);
        for (const auto source : {state::PersistenceSource::active_setup, state::PersistenceSource::image_execution,
            state::PersistenceSource::com_activation, state::PersistenceSource::startup_approval,
            state::PersistenceSource::browser_registration, state::PersistenceSource::office_addins}) {
            state::PersistenceLimits limits; limits.page_entries = 3;
            std::size_t rows = 0, matches = 0, page_index = 0;
            bool saw32 = false, saw64 = false;
            const std::function<bool(Json)> sink = [&](Json page) {
                require(page["page_index"] == std::to_string(page_index++), "page order lost");
                for (const auto& row : page["entries"]) {
                    ++rows;
                    require(row["mechanism"] == state::persistence_source_name(source), "mechanism provenance lost");
                    if (row.contains("registry_view")) { saw32 |= row["registry_view"] == "32"; saw64 |= row["registry_view"] == "64"; }
                    if (row.contains("query") && row["query"].value("value", Json(nullptr)) == "%PANOPTICON_NEVER_EXPAND%\\not-an-executable.txt") {
                        ++matches; require(row["environment_expanded"] == false && row["process_entity_id"].is_null(), "execution or actor fabricated");
                        require(row["query"]["raw_bytes_hex"].is_string(), "original registry bytes missing");
                    }
                }
                return true;
            };
            const std::function<bool()> cancelled;
            Pager pager{limits, state::persistence_source_name(source), sink, cancelled};
            const bool complete = registry_mechanism_scope(pager, source, scratch.key, "owned-test-hive");
            const auto report = pager.finish("owned inert registry fixture", complete);
            require(matches && saw32 && saw64 && report["entries_delivered"] == std::to_string(rows), "native fixture missing or miscounted");
            require(report["inventory_complete"] == false && report["enumeration_complete"] == true, "fixture traversal claim incorrect");
        }
        // Verify a full branch prefix cannot silently claim enumeration of later keys.
        for (unsigned i = 0; i < 257; ++i) {
            const auto key = L"Software\\Microsoft\\Active Setup\\Installed Components\\bounded-" + std::to_wstring(i);
            scratch.set(key.c_str(), L"StubPath", inert);
        }
        bool limited = false;
        const std::function<bool(Json)> sink = [&](Json page) {
            for (const auto& row : page["entries"]) if (row.value("subkey_index_limit_exceeded", false)) limited = true;
            return true;
        };
        const std::function<bool()> cancel;
        Pager pager{{}, "active_setup_inventory", sink, cancel};
        const bool complete = registry_mechanism_scope(pager, state::PersistenceSource::active_setup, scratch.key, "owned-test-hive");
        const auto report = pager.finish("bounded fixture", complete);
        require(limited && report["enumeration_complete"] == false, "subkey prefix limit hidden");
        const std::function<bool(Json)> refuse = [](Json) { return false; };
        state::PersistenceLimits limits; limits.page_entries = 1;
        Pager refused{limits, "active_setup_inventory", refuse, cancel};
        (void)registry_mechanism_scope(refused, state::PersistenceSource::active_setup, scratch.key, "owned-test-hive");
        require(refused.finish("refusal", false)["consumer_refused"] == true, "consumer refusal ignored");
        Json health{{"active_setup_inventory", {{"state", "degraded"}, {"last_committed_record_id", "capture"},
            {"last_committed_capture_started_uptime_ms", "1"}, {"last_committed_uptime_ms", "2"}}},
            {"capabilities", Json::array({{{"id", "state.active_setup_inventory"}, {"state", "degraded"}},
                {{"id", "J.persistence"}, {"state", "unavailable"}}})}};
        health::apply_state_capture_freshness(health, 10);
        require(health["capabilities"][1]["state"] == "degraded", "fresh independent mechanism absent from domain health");
        health::apply_state_capture_freshness(health, 400000);
        require(health["active_setup_inventory"]["state"] == "blind" && health["capabilities"][1]["state"] == "blind", "stale persistence remains fresh");
        std::cout << "native registry persistence fixtures, raw bytes, explicit views, branch bounds, refusal and health passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

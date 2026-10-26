#include "panopticon/officer/collectors/windows_event_log.hpp"
#include "panopticon/officer/collectors/authentication_telemetry.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
using namespace panopticon::officer;
using Json = nlohmann::json;
namespace fs = std::filesystem;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::string data(const char* name, const char* value) { return "<Data Name='" + std::string{name} + "'>" + value + "</Data>"; }
std::string xml(unsigned id = 4624, unsigned version = 2, const std::string& extra = "", const char* target_luid = "0xffffffffffffffff") {
    // Synthetic fixture, not captured output. Writer PID deliberately differs from requester.
    return "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><Channel>Security</Channel><EventID>" + std::to_string(id) +
        "</EventID><Version>" + std::to_string(version) + "</Version><EventRecordID>12</EventRecordID><TimeCreated SystemTime='2026-10-22T10:00:00.1234567Z'/>"
        "<Execution ProcessID='4'/></System><EventData>" +
        data("SubjectUserSid", "S-1-5-18") + data("SubjectUserName", "SYSTEM") + data("SubjectDomainName", "NT AUTHORITY") + data("SubjectLogonId", "0x3e7") +
        data("TargetUserSid", "S-1-5-21-1-2-3-1001") + data("TargetUserName", "synthetic-user") + data("TargetDomainName", "LAB") + data("TargetLogonId", target_luid) +
        data("LogonType", "3") + data("ProcessId", "0x44c") + data("ProcessName", "C:\\Windows\\System32\\svchost.exe") +
        data("IpAddress", "192.0.2.1") + data("IpPort", "0") + data("WorkstationName", "synthetic-client") + data("ElevatedToken", "%%1842") +
        data("AuthenticationPackageName", "Negotiate") + data("Status", "0x0") + extra + "</EventData></Event>";
}
Json auth(const std::string& input) { return collectors::decode_windows_event_xml(input, "Security").data.at("authentication"); }
pipeline::EndpointRecordFactory factory() {
    pipeline::NormalizationContext context{{"agent-auth-test", "dev"}, {"host-auth-test", "LAB", {"Windows", "native"}}};
    return pipeline::EndpointRecordFactory{context, "device", std::string(64, 'b'), "boot_" + std::string(64, 'a'), 1};
}
}
int main(int argc, char** argv) {
    try {
        if (argc == 3) {
            require(!fs::exists(argv[2]), "preserve existing evidence");
            require(fs::file_size(argv[1]) <= 196608, "native XML admission bound");
            std::ifstream in(argv[1], std::ios::binary); std::string source{std::istreambuf_iterator<char>(in), {}};
            const auto decoded = collectors::decode_windows_event_xml(source, "Security");
            require(decoded.data.contains("authentication") && decoded.data["decode_state"] == "healthy", "supported native Security event required");
            auto records = factory(); const auto record = records.windows_event_log("Security", decoded.data, decoded.event_time);
            std::ofstream out(argv[2], std::ios::binary); out << record.dump(2) << '\n'; require(bool(out), "native canonical evidence saved"); return 0;
        }
        require(argc == 1, "optional input XML and new canonical output file required");
        const auto success = auth(xml());
        require(success["target"]["logon_id"] == "18446744073709551615" && success["subject"]["logon_id"] == "999", "full LUID bits and subject/target roles preserved");
        require(success["logon_type"] == 3 && success["source"]["port"] == "0" && success["elevated_token"] == true, "typed zero, type and resource Boolean preserved");
        require(success["process"]["observed_pid"] == "1100" && success["process_instance"].is_null() && success["logon_session_entity"].is_null(), "writer PID and current boot never become a historical instance or session");
        require(auth(xml(4625, 0))["session_role"] == "subject_logon" && auth(xml(4625, 0))["session_observed_logon_id"] == "999", "failed target logon never creates a session");
        require(auth(xml(4648, 0))["outcome"] == "not_reported" && auth(xml(4672, 0))["session_observed_logon_id"] == "999", "explicit credentials and privilege assignment retain correct role");
        const auto duplicate = auth(xml(4624, 2, data("TargetLogonId", "0x5")));
        require(duplicate["target"]["logon_id"].is_null() && duplicate["state"] == "partial", "duplicate LUID cannot silently replace trusted selection");
        require(auth(xml(4624, 2, "", "0x10000000000000000"))["target"]["logon_id"].is_null(), "overflow cannot create a narrowed session token");
        require(auth(xml(4624, 99))["state"] == "degraded" && !auth(xml(4624, 99)).contains("target"), "unknown versions stay uninterpreted");
        auto ambiguous = xml(); ambiguous.insert(ambiguous.find("</Event>"), "<EventData><Data Name='TargetLogonId'>0x5</Data></EventData>");
        require(auth(ambiguous)["state"] == "degraded" && !auth(ambiguous).contains("target"), "multiple EventData blocks cannot hide a conflicting session");
        auto spoof = xml(); const std::string provider = "Microsoft-Windows-Security-Auditing";
        spoof.replace(spoof.find(provider), provider.size(), "spoofed");
        require(!collectors::decode_windows_event_xml(spoof, "Security").data.contains("authentication"), "wrong provider cannot supply authentication semantics");
        require(!collectors::decode_authentication(Json::array()), "non-object source refused");
        const auto ticket = auth(xml(4768, 2, data("TargetSid", "S-1-5-21-4-5-6-1001")));
        require(ticket["target"]["sid"] == "S-1-5-21-4-5-6-1001" && ticket["session_role"] == "not_reported", "KDC target SID and lack of local session remain distinct");
        const auto ntlm = auth(xml(4776, 0, data("PackageName", "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0") + data("Workstation", "native-client")));
        require(ntlm["source"]["workstation"] == "native-client" && ntlm["session_observed_logon_id"].is_null(), "credential validation cannot invent destination or local session");
        const auto root = fs::temp_directory_path() / ("officer-auth-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        require(fs::create_directory(root), "unique owned journal directory");
        auto records = factory(); Json originals = Json::array();
        { delivery::DurableJournal journal{{root}};
          for (unsigned id : {4624u,4625u,4634u,4648u,4672u,4768u,4769u,4776u}) {
              auto decoded = collectors::decode_windows_event_xml(xml(id, id == 4624 ? 2 : 0), "Security");
              auto record = records.windows_event_log("Security", decoded.data, decoded.event_time);
              require(record["subject"].is_null() && record["data"]["event_boot_id"].is_null(), "canonical replay retains unknown actor and event boot");
              journal.append(record.dump()); originals.push_back(record);
          } }
        { delivery::DurableJournal journal{{root}}; const auto batch = journal.peek(10, 1024 * 1024);
          require(batch && batch->entries.size() == 8, "all authentication families persist");
          for (std::size_t i = 0; i < originals.size(); ++i) require(batch->entries[i].body == originals[i].dump(), "original authentication bytes recover exactly"); }
        // This exact, newly created directory is the only cleanup target.
        fs::remove_all(root);
        std::cout << "Authentication field/role/version/bounds/provenance and journal regressions passed\n"; return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

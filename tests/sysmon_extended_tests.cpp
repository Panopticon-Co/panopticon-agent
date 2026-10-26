#include "panopticon/officer/collectors/sysmon_telemetry_decoder.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/pipeline/source_facts.hpp"
#include "panopticon/officer/pipeline/raw_handoff.hpp"
#include "panopticon/officer/delivery/journal.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <source_location>

using namespace panopticon::officer;
using Json = nlohmann::json;
namespace fs = std::filesystem;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
std::string fixture(const char* name) {
    std::ifstream file(fs::path(OFFICER_SYSMON_FIXTURE_DIR) / name);
    if (!file) throw std::runtime_error("missing Sysmon fixture");
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
void replace(std::string& xml, const std::string& old_value, const std::string& new_value) {
    const auto at = xml.find(old_value);
    require(at != std::string::npos, "fixture mutation has a real input boundary");
    xml.replace(at, old_value.size(), new_value);
}
telemetry::RawSysmonExtendedEvent decode(const std::string& xml) {
    std::string error;
    const auto raw = collectors::SysmonTelemetryDecoder::decode_xml(xml, error);
    if (!raw) throw std::runtime_error("fixture decode: " + error);
    require(std::holds_alternative<telemetry::RawSysmonExtendedEvent>(*raw), "closed extension variant");
    return std::get<telemetry::RawSysmonExtendedEvent>(*raw);
}
void refused(const std::string& xml, const std::source_location where = std::source_location::current()) {
    std::string error;
    if (collectors::SysmonTelemetryDecoder::decode_xml(xml, error) || error.empty())
        throw std::runtime_error("malformed or ambiguous Sysmon input must be refused at line " + std::to_string(where.line()));
}
struct Scratch {
    fs::path root = fs::weakly_canonical(fs::temp_directory_path());
    fs::path path = root / ("officer-sysmon-extended-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    Scratch() { require(fs::create_directory(path), "new scratch directory required"); }
    ~Scratch() { std::error_code error; if (path.parent_path() == root && path.filename().string().starts_with("officer-sysmon-extended-")) fs::remove_all(path, error); }
};
}
int main(int argc, char** argv) {
    try {
        const auto access_xml = fixture("sysmon_process_access.xml");
        const auto thread_xml = fixture("sysmon_remote_thread.xml");
        const auto dns_xml = fixture("sysmon_dns_query.xml");
        const auto access = decode(access_xml), thread = decode(thread_xml), dns = decode(dns_xml);
        require(access.event_id == 10 && access.granted_access == 0x1fffff && access.target && access.target->pid == 712,
            "source/target/access bits decode without conflation");
        require(thread.event_id == 8 && thread.new_thread_id == 10204 && thread.start_address == 0x00007FFB9285E540ull,
            "remote thread facts preserve native values");
        require(dns.event_id == 22 && dns.query_status == 0 && dns.event_time_field == "EventData/UtcTime", "DNS zero success and source clock are not missing");
        pipeline::NormalizationContext context{{"agent-sysmon-test", "dev"}, {"host-sysmon-test", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device", std::string(64, 'b'), "boot_" + std::string(64, 'a'), 1};
        Json records = Json::array({factory.sysmon_extended(access), factory.sysmon_extended(thread), factory.sysmon_extended(dns)});
        require(records[0]["category"] == "process_access" && records[1]["category"] == "remote_thread" && records[2]["category"] == "dns", "canonical family categories");
        const auto& actor = records[0]["subject"];
        const auto& target = records[0]["data"]["process_access"]["target"]["identity"];
        require(actor["resolution"] == "source_scoped" && target["resolution"] == "source_scoped" && actor["entity_id"] != target["entity_id"] &&
            actor["native_creation_ticks"].is_null() && target["native_creation_ticks"].is_null(), "separate source GUID references never invent native process identity");
        require(records[0]["data"]["source_facts"]["windows_event_data"]["GrantedAccess"] == "0x1fffff" &&
            records[0]["data"]["process_access"]["granted_access"] == "2097151", "original hex and typed full bits remain distinguishable");
        const auto& answers = records[2]["data"]["dns"]["answers"];
        require(answers.size() == 2 && answers[0]["kind"] == "cname" && answers[1]["kind"] == "ip" && answers[1]["family"] == "ipv6",
            "Sysmon CNAME plus mapped IPv6 answer list is parsed conservatively");
        require(records[2]["data"]["dns"]["query_type"].is_null(), "IP presentation cannot invent the requested DNS RR type");
        auto changed = access;
        changed.process.process_guid = "same-pid-different-instance";
        require(factory.sysmon_extended(changed)["subject"]["entity_id"] != actor["entity_id"], "PID reuse keeps source GUID incarnations distinct");
        changed = access; changed.process.process_guid.reset(); changed.target->process_guid.reset();
        const auto unresolved = factory.sysmon_extended(changed);
        require(unresolved["subject"]["entity_id"].is_null() && unresolved["data"]["process_access"]["target"]["entity_id"].is_null(), "PID alone remains unresolved on both sides");
        changed = access; changed.call_trace = std::string(16383, 'a') + "\xc3\xa9";
        const auto bounded = factory.sysmon_extended(changed)["data"]["process_access"]["call_trace"];
        require(bounded["truncated"] == true && bounded["original_bytes"] == "16385" && bounded["text"].get<std::string>().size() == 16383 &&
            pipeline::valid_utf8(bounded["text"].get<std::string>()), "trace truncation is explicit and never splits a UTF-8 sequence");
        changed = access; changed.call_trace.reset(); changed.granted_access.reset();
        require(factory.sysmon_extended(changed)["data"]["process_access"]["granted_access"].is_null(), "missing access mask is not zero");
        auto unusual_dns = dns; unusual_dns.query_results = "192.0.2.1;unrecognized answer;2001:db8::1;";
        const auto parsed = factory.sysmon_extended(unusual_dns)["data"]["dns"];
        require(parsed["answers"].size() == 2 && parsed["unparsed_tokens"].size() == 1, "unknown answer syntax stays explicit without preventing known typed answers");
        unusual_dns.query_results = std::string{};
        for (int i = 0; i < 300; ++i) *unusual_dns.query_results += "192.0.2.1;";
        require(factory.sysmon_extended(unusual_dns)["data"]["dns"]["bound_exceeded"] == true, "answer/token work bound is visible");
        auto mutation = access_xml;
        replace(mutation, "<Data Name=\"SourceProcessId\">4300</Data>", ""); refused(mutation);
        mutation = access_xml; replace(mutation, ">712</Data>", ">4294967296</Data>"); refused(mutation);
        mutation = access_xml; replace(mutation, "0x1fffff", "0x100000000"); refused(mutation);
        mutation = access_xml; replace(mutation, "</EventData>", "<Data Name=\"GrantedAccess\">0</Data></EventData>"); refused(mutation);
        mutation = access_xml; replace(mutation, "</EventData>", "<Data Name=\"SourceProcessGuid\">conflict</Data></EventData>"); refused(mutation);
        mutation = thread_xml; replace(mutation, "0x00007FFB9285E540", "0xnothex"); refused(mutation);
        mutation = thread_xml; replace(mutation, "0x00007FFB9285E540", "0xffffffffffffffff");
        require(factory.sysmon_extended(decode(mutation))["data"]["remote_thread"]["start_address"] == "18446744073709551615", "full-width address bits survive JSON exactly");
        mutation = dns_xml; replace(mutation, "<Data Name=\"QueryStatus\">0</Data>", "<Data Name=\"QueryStatus\">-1</Data>"); refused(mutation);
        mutation = dns_xml; replace(mutation, "13:02:42.509", "13:02:42.509Zjunk"); refused(mutation);
        mutation = dns_xml; replace(mutation, "2026-08-18 13:02:42.509", "9999-08-18 13:02:42.509"); refused(mutation);
        mutation = access_xml; replace(mutation, "</System>", "<EventID>10</EventID></System>"); refused(mutation);
        mutation = access_xml; replace(mutation, "</EventData>", "<Data>unnamed</Data></EventData>"); refused(mutation);
        mutation = access_xml; replace(mutation, "Name=\"Microsoft-Windows-Sysmon\"", "Name=\"spoofed\""); refused(mutation);
        refused(access_xml + std::string(1, '\0') + "trailing");
        refused(std::string(256u * 1024 + 1, 'x'));
        changed = access; changed.target->executable = std::string(10000, 't'); changed.source_fields.emplace_back("LargeSourceFact", std::string(20000, 's'));
        require(pipeline::raw_event_charge(telemetry::RawEvent{std::move(changed)}) >= 30000, "target context and original source fields are charged to bounded ownership");
        Scratch scratch;
        { delivery::DurableJournal journal{{scratch.path}}; for (const auto& record : records) journal.append(record.dump()); }
        { delivery::DurableJournal reopened{{scratch.path}}; const auto batch = reopened.peek(10, 1024 * 1024);
          require(batch && batch->protocol == 2 && batch->entries.size() == 3, "all new families survive journal reopen on protocol 2");
          for (std::size_t i = 0; i < records.size(); ++i) require(batch->entries[i].body == records[i].dump(), "canonical original bytes survive restart exactly"); }
        if (argc == 2 && std::string{argv[1]} == "--emit-fixtures") std::cout << records.dump() << '\n';
        else std::cout << "Sysmon 8/10/22 canonical decode/identity/DNS/bounds/restart regressions passed\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

#include "panopticon/officer/collectors/windows_event_log.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winevt.h>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
namespace {
namespace collectors = panopticon::officer::collectors;
namespace delivery = panopticon::officer::delivery;
namespace pipeline = panopticon::officer::pipeline;
namespace fs = std::filesystem;
using Json = nlohmann::json;
int failures = 0;
void expect(bool value, const char* message) { if (!value) { ++failures; std::cerr << "FAIL: " << message << '\n'; } }
template<class F> void refuses(F&& action, const char* message) { try { action(); expect(false,message); } catch (const std::exception&) {} }
struct Scratch {
    fs::path path = fs::temp_directory_path() / ("officer-winevt-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    ~Scratch() { std::error_code error; if (fs::equivalent(path.parent_path(), fs::temp_directory_path(), error) && !error && path.filename().string().starts_with("officer-winevt-")) fs::remove_all(path,error); }
};
std::string xml(const std::string& channel = "Security", const std::string& time = "2026-10-06T01:02:03.1234567Z") {
    return "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><EventRecordID>18446744073709551615</EventRecordID><TimeCreated SystemTime='" + time + "'/><Execution ProcessID='4' ThreadID='8'/><Channel>" + channel + "</Channel></System><EventData><Data Name='SubjectUserSid'>S-1-5-18</Data><Data Name='TargetUserName'>alice</Data><Data Name='ProcessId'>0x1234</Data><Data Name='LogonType'>3</Data><Data Name='Duplicate'>one</Data><Data Name='Duplicate'>two</Data><Data Name='Empty'/></EventData></Event>";
}
void decoder_tests() {
    auto event = collectors::decode_windows_event_xml(xml(), "Security");
    expect(event.data["decode_state"] == "healthy" && event.data["semantic_family"] == "security_audit", "native metadata and security source retained");
    expect(event.data["semantic_event"] == "logon_success", "security native event classification retained without actor inference");
    expect(event.data["event_record_id"] == "18446744073709551615", "native uint64 record ID remains decimal text");
    expect(event.data["event_data"].size() == 7 && event.data["event_data"][4]["text"] == "one" && event.data["event_data"][5]["text"] == "two", "duplicate data names retain ordered values");
    expect(event.data["execution"]["reported_writer_pid"] == "4" && event.data["actor_verified"] == false && event.data["process_reference"].is_null(), "writer PID cannot become security subject identity");
    expect(event.event_time && event.event_time->time_since_epoch().count() % 1000000000 == 123456700, "native seven digit timestamp has exact 100ns precision");
    for (const auto& bad : {"2026-02-30T00:00:00Z", "2026-10-06T01:02:03.12345678Z", "2026-10-06T01:02:03+00:00", "9999-10-06T01:02:03Z"}) {
        const auto decoded = collectors::decode_windows_event_xml(xml("Security",bad), "Security");
        expect(!decoded.event_time && decoded.data["decode_state"] == "degraded" && decoded.data["rendered_xml"] == xml("Security",bad), "invalid/out-of-envelope time retains original XML without fabricated event time");
    }
    auto duplicate = xml(); duplicate.insert(duplicate.find("</System>"), "<EventRecordID>5</EventRecordID>");
    auto decoded = collectors::decode_windows_event_xml(duplicate,"Security");
    expect(!decoded.event_time && decoded.data["event_record_id"].is_null() && decoded.data["validation_error"] == "ambiguous_system_fields", "ambiguous System metadata cannot become trusted provenance");
    decoded = collectors::decode_windows_event_xml("<Event>","Security");
    expect(!decoded.event_time && decoded.data["rendered_xml"] == "<Event>", "unparsed evidence retained");
    pipeline::NormalizationContext context{{"agent","dev"},{"host","LAB",{"Windows","26220"}}};
    pipeline::EndpointRecordFactory factory{context,"device",std::string(64,'b'),"boot_" + std::string(64,'a'),1};
    auto record = factory.windows_event_log("Security",event.data,event.event_time);
    expect(record["kind"] == "observation" && record["subject"].is_null() && record["provenance"]["native_record_id"] == "18446744073709551615", "canonical log envelope preserves native provenance without a process actor");
    record = factory.windows_event_log("Security",decoded.data,decoded.event_time);
    expect(record["kind"] == "evidence" && record["data"]["envelope_event_time_semantics"] == "capture_time_native_event_time_uninterpreted", "unknown native event time is explicitly capture-time evidence");
    auto fragment = xml("Microsoft-Windows-PowerShell/Operational");
    fragment.replace(fragment.find("Microsoft-Windows-Security-Auditing"),std::string("Microsoft-Windows-Security-Auditing").size(),"Microsoft-Windows-PowerShell");
    fragment.replace(fragment.find("4624"),4,"4104");
    auto script = collectors::decode_windows_event_xml(fragment,"Microsoft-Windows-PowerShell/Operational");
    expect(script.data["semantic_event"] == "powershell_script_block_fragment" && script.data["script_block_assembled"] == false,
        "script-block fragment cannot claim complete assembled script");
}
void checkpoint_tests() {
    Scratch scratch;
    const auto line = Json{{"event",{{"id","cursor-one"}}},{"data","private-record"}}.dump();
    const auto next = Json{{"event",{{"id","cursor-two"}}}}.dump();
    const std::string cursor = "<BookmarkList><Bookmark Channel='Application' RecordId='9001' IsCurrent='true'/></BookmarkList>";
    {
        delivery::DurableJournal journal{{scratch.path}};
        expect(!journal.source_checkpoint("source"), "new source has no invented bookmark");
        journal.append_checkpointed(line,"source",cursor,0);
        journal.append_checkpointed(line,"source",cursor,0);
        expect(journal.stats().pending_events == 1 && journal.source_checkpoint("source")->revision == 1, "identical record/cursor retry is idempotent");
        refuses([&] { journal.append_checkpointed(next,"source","changed",0); }, "stale revision fences competing source writer");
        expect(journal.stats().pending_events == 1 && journal.source_checkpoint("source")->value == cursor, "conflict changes neither evidence nor cursor");
        auto batch = journal.peek(100,100000);
        const auto receipt = Json{{"batch_id",batch->id},{"received",batch->entries.size()},{"accepted",batch->entries.size()},{"duplicates",0},{"rejected",Json::array()}}.dump();
        journal.acknowledge(*batch,receipt);
        journal.append_checkpointed(line,"source",cursor,0);
        expect(journal.stats().pending_events == 0 && journal.source_checkpoint("source")->revision == 1, "receipt retirement preserves bookmark and idempotent commit tombstone");
    }
    {
        delivery::DurableJournal reopened{{scratch.path}};
        expect(reopened.source_checkpoint("source")->value == cursor, "encrypted source cursor survives journal reopen");
        reopened.append_checkpointed(next,"source","second-bookmark",1);
        expect(reopened.source_checkpoint("source")->revision == 2 && reopened.stats().pending_events == 1, "reopened reader advances cursor only with new record acceptance");
    }
    for (const auto& entry : fs::directory_iterator(scratch.path)) if (entry.is_regular_file()) {
        std::ifstream stream(entry.path(),std::ios::binary); const std::string bytes((std::istreambuf_iterator<char>(stream)),{});
        expect(bytes.find(cursor) == std::string::npos && bytes.find("second-bookmark") == std::string::npos && bytes.find("private-record") == std::string::npos, "bookmark and event payload absent from plaintext storage");
    }
    Scratch quota; delivery::JournalConfig config{quota.path}; config.retained_payload_limit = line.size() + 2;
    delivery::DurableJournal bounded{config};
    refuses([&] { bounded.append_checkpointed(line,"source",cursor,0); }, "checkpoint quota refuses entire combined transaction");
    expect(bounded.stats().pending_events == 0 && !bounded.source_checkpoint("source") && bounded.stats().retained_bytes == 0, "cursor quota rollback removes uncommitted inserted observation");
    bounded.append_checkpointed(line,"source","x",0);
    refuses([&] { bounded.append_checkpointed(next,"source","y",1); }, "later payload quota cannot advance saved cursor");
    expect(bounded.source_checkpoint("source")->revision == 1 && bounded.stats().pending_events == 1, "later refusal retains original committed record and cursor");
}
struct Native { EVT_HANDLE value; ~Native() { if (value) EvtClose(value); } };
std::string latest_bookmark() {
    Native query{EvtQuery(nullptr,L"Application",L"*",EvtQueryChannelPath | EvtQueryReverseDirection)};
    if (!query.value) throw std::runtime_error("live Application query failed");
    EVT_HANDLE handle = nullptr; DWORD count = 0;
    if (!EvtNext(query.value,1,&handle,1000,0,&count)) {
        if (GetLastError() == ERROR_NO_MORE_ITEMS) return {};
        throw std::runtime_error("live Application latest event failed");
    }
    Native event{handle}, bookmark{EvtCreateBookmark(nullptr)};
    if (!bookmark.value || !EvtUpdateBookmark(bookmark.value,event.value)) throw std::runtime_error("live native bookmark failed");
    DWORD size = 0, properties = 0;
    EvtRender(nullptr,bookmark.value,EvtRenderBookmark,0,nullptr,&size,&properties);
    std::vector<wchar_t> buffer(size / sizeof(wchar_t));
    if (!size || !EvtRender(nullptr,bookmark.value,EvtRenderBookmark,size,buffer.data(),&size,&properties)) throw std::runtime_error("live bookmark render failed");
    const int chars = static_cast<int>(wcslen(buffer.data()));
    const int required = WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,buffer.data(),chars,nullptr,0,nullptr,nullptr);
    std::string result(required,'\0'); WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,buffer.data(),chars,result.data(),required,nullptr,nullptr);
    return result;
}
void report(const std::string& token) {
    const std::wstring value(token.begin(),token.end()); const wchar_t* values[]{value.c_str()};
    const auto source = RegisterEventSourceW(nullptr,L"Panopticon-WindowsLog-Validation");
    if (!source) throw std::runtime_error("owned benign native log source failed");
    const bool written = ReportEventW(source,EVENTLOG_INFORMATION_TYPE,0,1101,nullptr,1,0,values,nullptr) != FALSE;
    DeregisterEventSource(source);
    if (!written) throw std::runtime_error("owned benign native log event refused");
}
template<class F> bool until(F&& ready, unsigned timeout = 12000) {
    const auto started = GetTickCount64(); while (GetTickCount64() - started < timeout) { if (ready()) return true; Sleep(50); } return false;
}
void live_tests() {
    Scratch scratch; delivery::DurableJournal journal{{scratch.path}};
    const std::string source = "winevt:v1:Application";
    const auto baseline = latest_bookmark();
    if (!baseline.empty()) journal.append_checkpointed(R"({"event":{"id":"owned-log-baseline"},"gap":"test_only_skip_prior_application_history"})",source,baseline,0);
    const auto saved = journal.source_checkpoint(source);
    const auto revision = saved ? saved->revision : 0;
    std::atomic<bool> reject{true}, pending{false}, first_accepted{false}, second_accepted{false};
    std::mutex mutex; std::string immutable_pending; unsigned retries = 0; bool same_retry = true;
    std::atomic_uint64_t sequence{0};
    const auto token = "panopticon-winevt-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
    const auto second = token + "-restart";
    collectors::WindowsLogCallbacks callbacks;
    callbacks.load = [&](const std::string& key) { return journal.source_checkpoint(key); };
    callbacks.make_record = [&](const std::string& channel, const collectors::DecodedWindowsEvent& event, bool gap) {
        return Json{{"event",{{"id","live-log-" + std::to_string(++sequence)}}},{"channel",channel},{"gap",gap},{"data",event.data}}.dump();
    };
    callbacks.commit = [&](const std::string& line, const std::string& key, const std::string& cursor, std::uint64_t expected) {
        if (!cursor.empty() && reject.load()) {
            std::scoped_lock lock{mutex}; if (immutable_pending.empty()) immutable_pending = line; else same_retry = same_retry && immutable_pending == line;
            ++retries; pending.store(true); return false;
        }
        if (cursor.empty()) journal.append(line); else journal.append_checkpointed(line,key,cursor,expected);
        if (line.find(token) != std::string::npos && line.find(second) == std::string::npos) first_accepted.store(true);
        if (line.find(second) != std::string::npos) second_accepted.store(true);
        return true;
    };
    {
        collectors::WindowsEventLog logs{callbacks,{"Application"}};
        expect(until([&] { return logs.snapshot()["channels"][0]["reason"] == "native pull subscription active; audit/provider policy and continuity unverified"; }), "real Application pull subscription established");
        report(token);
        expect(until([&] { std::scoped_lock lock{mutex}; return retries >= 2; }), "real source refuses and retries pending event");
        const auto unchanged = journal.source_checkpoint(source);
        { std::scoped_lock lock{mutex}; expect((unchanged ? unchanged->revision : 0) == revision && same_retry && pending.load(), "actual collector refusal preserves cursor and immutable record bytes"); }
        reject.store(false);
        expect(until([&] { return first_accepted.load(); }), "real ReportEvent token observed and durably checkpointed");
        logs.stop();
        expect(logs.snapshot()["channels"][0]["state"] == "disabled" && logs.snapshot()["channels"][0]["worker_stopped"] == true,
            "stopped worker cannot claim an active subscription");
        expect(journal.source_checkpoint(source)->revision > revision, "actual collector advances native bookmark after durable admission");
    }
    report(second);
    {
        collectors::WindowsEventLog restarted{callbacks,{"Application"}};
        expect(until([&] { return second_accepted.load(); }), "strict native bookmark resume reads event written while collector stopped");
        restarted.stop();
    }
    std::size_t first_count = 0, second_count = 0; std::uint64_t cursor = 0;
    for (;;) {
        auto page = journal.inspect_pending(cursor,1000,8*1024*1024); if (page.empty()) break;
        for (const auto& entry : page) {
            cursor = entry.local_sequence;
            if (entry.original.body.find(second) != std::string::npos) ++second_count;
            else if (entry.original.body.find(token) != std::string::npos) ++first_count;
        }
    }
    expect(first_count == 1 && second_count == 1, "actual strict restart avoids re-consuming accepted native record");
    collectors::WindowsEventLog missing{callbacks,{"Panopticon-Nonexistent-Validation-Channel"}};
    expect(until([&] { auto health = missing.snapshot()["channels"][0]; return health["state"] == "unavailable" && health.value("native_error",0ul) != 0; }), "missing channel reported unavailable rather than healthy empty");
    missing.stop();
    std::cout << "real Windows Application pull/bookmark/refusal/restart verified; token_records=" << first_count + second_count << '\n';
}
void hard_exit_test() {
    Scratch scratch;
    wchar_t executable[32768]{};
    if (!GetModuleFileNameW(nullptr,executable,32768)) throw std::runtime_error("owned test executable path failed");
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --crash-checkpoint \"" + scratch.path.wstring() + L"\"";
    STARTUPINFOW startup{}; startup.cb = sizeof(startup); PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process))
        throw std::runtime_error("owned crash writer could not start");
    const auto wait = WaitForSingleObject(process.hProcess,10000);
    if (wait != WAIT_OBJECT_0) { TerminateProcess(process.hProcess,98); WaitForSingleObject(process.hProcess,5000); }
    DWORD code = 0; GetExitCodeProcess(process.hProcess,&code); CloseHandle(process.hThread); CloseHandle(process.hProcess);
    expect(wait == WAIT_OBJECT_0 && code == 77, "owned writer terminated after checkpoint transaction commit");
    delivery::DurableJournal recovered{{scratch.path}};
    const auto checkpoint = recovered.source_checkpoint("crash-source");
    expect(checkpoint && checkpoint->revision == 1 && checkpoint->value == "crash-bookmark" && recovered.stats().pending_events == 1,
        "FULL/WAL accepted event and encrypted cursor survive abrupt process termination together");
}
Json fixtures() {
    pipeline::NormalizationContext context{{"agent","dev"},{"host","LAB",{"Windows","26220"}}};
    pipeline::EndpointRecordFactory factory{context,"device",std::string(64,'b'),"boot_" + std::string(64,'a'),1};
    Json records = Json::array();
    for (const auto& channel : collectors::WindowsEventLog::default_channels()) {
        auto event = collectors::decode_windows_event_xml(xml(channel),channel);
        records.push_back(factory.windows_event_log(channel,event.data,event.event_time));
    }
    auto invalid = collectors::decode_windows_event_xml("<Event>","Security");
    records.push_back(factory.windows_event_log("Security",invalid.data,invalid.event_time));
    records.push_back(factory.gap("winevt:Security",{{"reason","native_log_source_refused"},{"lost_native_events",nullptr}}));
    return records;
}
}
int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--crash-checkpoint") {
        delivery::DurableJournal journal{{fs::path(argv[2])}};
        journal.append_checkpointed(R"({"event":{"id":"crash-record"}})","crash-source","crash-bookmark",0);
        TerminateProcess(GetCurrentProcess(),77); return 99;
    }
    if (argc == 2 && std::string(argv[1]) == "--emit-fixtures") { std::cout << fixtures().dump() << '\n'; return 0; }
    try { decoder_tests(); checkpoint_tests(); hard_exit_test(); live_tests(); } catch (const std::exception& error) { expect(false,error.what()); }
    return failures ? 1 : 0;
}

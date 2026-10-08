#include "panopticon/officer/collectors/usn_journal.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <array>
#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <memory>
#include <stdexcept>
using Json = nlohmann::json;
namespace col = panopticon::officer::collectors;
namespace delivery = panopticon::officer::delivery;
namespace pipeline = panopticon::officer::pipeline;
namespace fs = std::filesystem;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
template<class F> void refuses(F action) { bool refused = false; try { action(); } catch (const std::exception&) { refused = true; } require(refused, "malformed USN input accepted"); }
template<class T> void put(std::vector<std::byte>& bytes, std::size_t offset, T value) { std::memcpy(bytes.data() + offset, &value, sizeof(value)); }
std::vector<std::byte> fixture(unsigned version, std::wstring name = L"owned-name") {
    const std::size_t extra = version == 3 ? 16 : 0;
    const auto length = (60 + extra + name.size() * 2 + 7) & ~std::size_t(7);
    std::vector<std::byte> b(8 + length); put(b, 0, std::int64_t{256}); put(b, 8, static_cast<std::uint32_t>(length));
    put(b, 12, static_cast<std::uint16_t>(version)); put(b, 14, std::uint16_t{0});
    put(b, 16, UINT64_MAX); put(b, 24 + extra, std::uint64_t{0x1122334455667788});
    put(b, 32 + extra, std::int64_t{128}); put(b, 40 + extra, std::int64_t{133700000000000001});
    put(b, 48 + extra, std::uint32_t{UINT32_MAX}); put(b, 52 + extra, std::uint32_t{8});
    put(b, 56 + extra, std::uint32_t{42}); put(b, 60 + extra, std::uint32_t{32});
    put(b, 64 + extra, static_cast<std::uint16_t>(name.size() * 2)); put(b, 66 + extra, static_cast<std::uint16_t>(60 + extra));
    std::memcpy(b.data() + 68 + extra, name.data(), name.size() * 2); return b;
}
void decoder_tests() {
    require(col::decode_usn_cursor(col::encode_usn_cursor({UINT64_MAX, INT64_MAX})).next_usn == INT64_MAX,
        "opaque 64-bit cursor precision");
    refuses([] { (void)col::decode_usn_cursor(R"({"format":"windows_usn_cursor_v1","journal_id":"01","next_usn":"0"})"); });
    refuses([] { (void)col::decode_usn_cursor(R"({"format":"windows_usn_cursor_v1","journal_id":"1","next_usn":"9223372036854775808"})"); });
    refuses([] { (void)col::decode_usn_cursor(R"({"format":"other","journal_id":"1","next_usn":"0"})"); });
    for (unsigned version : {2, 3}) {
        auto b = fixture(version); const auto decoded = col::decode_usn_buffer(b, 64);
        const auto& row = decoded["entries"][0];
        require(row["filename"] == "owned-name" && row["usn"] == "128" && row["reason_mask"] == "4294967295"
            && row["file_id_width_bits"] == (version == 3 ? 128 : 64), "native version and scalar decoding");
        require(row["path"].is_null() && row["process_reference"].is_null() && row["rename_pair_verified"] == false,
            "USN does not invent path/process/rename relationship");
        b.resize(b.size() - 1); refuses([&] { (void)col::decode_usn_buffer(b, 64); });
        b = fixture(version); put(b, 64 + (version == 3 ? 16 : 0), std::uint16_t{3});
        refuses([&] { (void)col::decode_usn_buffer(b, 64); });
    }
    auto b = fixture(2); put(b, 12, std::uint16_t{4});
    auto unknown = col::decode_usn_buffer(b, 64);
    require(unknown["uninterpreted_version_records"] == "1" && unknown["entries"][0]["state"] == "unsupported"
        && unknown["full_native_buffer_retained"] == true, "unknown version retained opaque");
    b = fixture(2); put(b, 8, std::uint32_t{0}); refuses([&] { (void)col::decode_usn_buffer(b, 64); });
    b = fixture(2); put(b, 0, std::int64_t{63}); refuses([&] { (void)col::decode_usn_buffer(b, 64); });
    b = fixture(2); put(b, 32, std::int64_t{256}); refuses([&] { (void)col::decode_usn_buffer(b, 64); });
    b = fixture(2, std::wstring(1, wchar_t{0xd800}));
    const auto malformed_name = col::decode_usn_buffer(b, 64);
    require(malformed_name["entries"][0]["filename"].is_null() && malformed_name["entries"][0]["filename_utf16le_hex"] == "00d8",
        "malformed UTF16 retained without lossy replacement");
}
template<class F> bool until(F predicate, unsigned milliseconds = 15000) {
    const auto started = GetTickCount64(); while (GetTickCount64() - started < milliseconds) { if (predicate()) return true; Sleep(50); } return false;
}
struct Scratch {
    fs::path root = fs::temp_directory_path() / ("officer-usn-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
    Scratch() { require(fs::create_directory(root), "unique owned native fixture directory"); }
    ~Scratch() {
        std::error_code error;
        const auto actual = fs::weakly_canonical(root, error), temp = fs::weakly_canonical(fs::temp_directory_path(), error);
        if (!error && actual.parent_path() == temp && actual.filename().wstring().starts_with(L"officer-usn-")) fs::remove_all(actual, error);
    }
};
void write(const fs::path& path, const char* content) {
    std::ofstream stream(path, std::ios::binary); stream << content; require(bool(stream), "owned file write");
}
Json live_tests(bool required) {
    Scratch scratch; std::array<wchar_t, 1024> mount{}, volume_name{};
    require(GetVolumePathNameW(scratch.root.c_str(), mount.data(), static_cast<DWORD>(mount.size()))
        && GetVolumeNameForVolumeMountPointW(mount.data(), volume_name.data(), static_cast<DWORD>(volume_name.size())), "native temporary volume GUID");
    std::wstring native_volume(volume_name.data()); native_volume.pop_back();
    HANDLE native = CreateFileW(native_volume.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    USN_JOURNAL_DATA_V0 info{}; DWORD returned = 0;
    DWORD error = native == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    bool usable = native != INVALID_HANDLE_VALUE && DeviceIoControl(native, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &info, sizeof(info), &returned, nullptr);
    if (native != INVALID_HANDLE_VALUE) { if (!usable) error = GetLastError(); CloseHandle(native); }
    if (!usable) {
        require(!required, "required real Windows journal query unavailable");
        std::cout << "native USN live test unavailable Win32=" << error << "; decoder/durable component evidence only\n";
        return {{"real_windows_usn_verified", false}, {"native_error", std::to_string(error)}};
    }
    std::string volume; for (auto c : std::wstring(volume_name.data())) volume += static_cast<char>(c);
    auto journal = std::make_unique<delivery::DurableJournal>(delivery::JournalConfig{scratch.root / "spool"});
    pipeline::NormalizationContext context{{"agent-usn-test", "dev"}, {"host-usn-test", "LAB", {"Windows", "native"}}};
    std::string boot_error;
    const auto collection_boot = panopticon::officer::core::query_native_boot_id(boot_error);
    pipeline::EndpointRecordFactory factory{context, "device-usn-test", std::string(64, 'b'), collection_boot, 1};
    std::mutex mutex; Json records = Json::array(); std::string refused_line; unsigned retries = 0;
    std::atomic<bool> reject{false};
    col::UsnCallbacks callbacks;
    callbacks.load = [&](const std::string& source) { return journal->source_checkpoint(source); };
    callbacks.make_record = [&](const std::string& v, Json body, bool gap) { return factory.usn_journal(v, std::move(body), gap).dump(); };
    callbacks.commit = [&](const std::string& line, const std::string& source, const std::string& cursor, std::uint64_t revision) {
        if (reject.load()) {
            std::scoped_lock lock{mutex}; if (refused_line.empty()) refused_line = line;
            require(refused_line == line, "real USN refusal must retry immutable canonical bytes"); ++retries; return false;
        }
        journal->append_checkpointed(line, source, cursor, revision);
        { std::scoped_lock lock{mutex}; records.push_back(Json::parse(line)); } return true;
    };
    const auto prefix = scratch.root.filename().string();
    const auto name_a = prefix + "-a.txt", name_b = prefix + "-b.txt", name_replay = prefix + "-replay.txt";
    const auto a = scratch.root / name_a, b = scratch.root / name_b, replay = scratch.root / name_replay;
    std::string owned_file_id, owned_file_id128;
    const auto reasons = [&](const std::string& name) {
        std::scoped_lock lock{mutex}; std::uint32_t masks = 0;
        for (const auto& r : records) if (r["category"] == "filesystem_usn_batch")
            for (const auto& row : r["data"]["entries"]) if (row.value("filename", Json(nullptr)) == name)
                masks |= static_cast<std::uint32_t>(std::stoul(row["reason_mask"].get<std::string>()));
        return masks;
    };
    std::string source;
    {
        col::UsnJournal sensor{callbacks, {volume}};
        require(until([&] { return sensor.snapshot()["volumes"][0]["durable_gaps"] != "0"; }), "real journal initial baseline durably accepted");
        source = sensor.snapshot()["volumes"][0]["source"].get<std::string>();
        const auto saved = journal->source_checkpoint(source); require(bool(saved), "real source cursor exists");
        reject.store(true); write(a, "benign fixture data\n");
        HANDLE owned = CreateFileW(a.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        require(owned != INVALID_HANDLE_VALUE, "owned file metadata handle");
        BY_HANDLE_FILE_INFORMATION owned_info{};
        FILE_ID_INFO extended_info{};
        const bool owned_queried = GetFileInformationByHandle(owned, &owned_info) != FALSE;
        const bool extended_queried = GetFileInformationByHandleEx(owned, FileIdInfo, &extended_info, sizeof(extended_info)) != FALSE;
        CloseHandle(owned);
        require(owned_queried, "independent native file index query");
        require(extended_queried, "independent native 128-bit file ID query");
        const auto index = (std::uint64_t(owned_info.nFileIndexHigh) << 32) | owned_info.nFileIndexLow;
        std::array<unsigned char, 8> bytes{}; std::memcpy(bytes.data(), &index, sizeof(index));
        constexpr char digits[] = "0123456789abcdef";
        for (auto value : bytes) { owned_file_id += digits[value >> 4]; owned_file_id += digits[value & 15]; }
        for (auto value : extended_info.FileId.Identifier) { owned_file_id128 += digits[value >> 4]; owned_file_id128 += digits[value & 15]; }
        require(until([&] { std::scoped_lock lock{mutex}; return retries >= 2; }), "real native read retries refused batch");
        require(journal->source_checkpoint(source)->revision == saved->revision, "refusal leaves durable cursor unchanged");
        reject.store(false);
        require(until([&] { return (reasons(name_a) & USN_REASON_FILE_CREATE) != 0; }), "actual owned file create observed");
        write(fs::path(a.wstring() + L":panopticon-fixture"), "benign ADS data\n");
        require(until([&] { return (reasons(name_a) & (USN_REASON_NAMED_DATA_EXTEND | USN_REASON_NAMED_DATA_OVERWRITE)) != 0; }), "actual owned named stream mutation observed");
        require(MoveFileW(a.c_str(), b.c_str()), "owned native rename");
        require(DeleteFileW(b.c_str()), "owned native delete");
        require(until([&] { return (reasons(name_a) & USN_REASON_RENAME_OLD_NAME)
            && (reasons(name_b) & USN_REASON_RENAME_NEW_NAME) && (reasons(name_b) & USN_REASON_FILE_DELETE); }),
            "actual native rename halves and deletion observed without inferred pairing");
        sensor.stop(); require(sensor.snapshot()["volumes"][0]["state"] == "disabled", "source stop reports disabled");
    }
    const auto saved = journal->source_checkpoint(source);
    journal.reset();
    write(replay, "created while collector and durable journal closed\n");
    journal = std::make_unique<delivery::DurableJournal>(delivery::JournalConfig{scratch.root / "spool"});
    const auto reopened = journal->source_checkpoint(source);
    require(reopened && reopened->revision == saved->revision && reopened->value == saved->value,
        "closed durable journal reopens exact native checkpoint");
    {
        col::UsnJournal sensor{callbacks, {volume}};
        require(until([&] { return (reasons(name_replay) & USN_REASON_FILE_CREATE) != 0; }), "native restart resumes durable cursor and replays offline mutation");
        sensor.stop();
    }
    require(journal->source_checkpoint(source)->revision > saved->revision, "replay cursor advanced after acceptance");
    {
        std::scoped_lock lock{mutex}; std::size_t checked = 0;
        for (const auto& record : records) if (record["category"] == "filesystem_usn_batch")
            for (const auto& row : record["data"]["entries"]) if (row.value("filename", Json(nullptr)) == name_a || row.value("filename", Json(nullptr)) == name_b) {
                require(row["file_id_native_bytes_hex"] == (row["file_id_width_bits"] == 128 ? owned_file_id128 : owned_file_id),
                    "owned NTFS create/stream/rename/delete file ID agrees with independent held-file index"); ++checked;
            }
        require(checked >= 4, "actual owned native identity comparisons exercised");
    }
    // Fault only isolated owned checkpoint stores. Never change the real volume's
    // journal ID, retention, policy or contents to manufacture a fault.
    Json cursor_faults = Json::array();
    const auto fault = [&](const char* label, const std::string& stored, const char* expected_reason, bool malformed) {
        journal.reset();
        journal = std::make_unique<delivery::DurableJournal>(delivery::JournalConfig{scratch.root / label});
        const auto seed = factory.usn_journal(volume,
            {{"format", "windows_usn_test_checkpoint_seed_v1"}, {"test_only", true}, {"case", label}}, true).dump();
        journal->append_checkpointed(seed, source, stored, 0);
        std::size_t before;
        { std::scoped_lock lock{mutex}; before = records.size(); }
        Json health;
        {
            col::UsnJournal sensor{callbacks, {volume}};
            require(until([&] {
                health = sensor.snapshot()["volumes"][0];
                return malformed ? health["state"] == "blind" && health["source_failures"] != "0"
                    : health["durable_gaps"] != "0";
            }), "saved checkpoint fault produces explicit source state");
            sensor.stop();
        }
        const auto checkpoint = journal->source_checkpoint(source);
        require(bool(checkpoint), "fault checkpoint remains inspectable");
        Json accepted = Json::array();
        { std::scoped_lock lock{mutex}; for (std::size_t i = before; i < records.size(); ++i) accepted.push_back(records[i]); }
        if (malformed) {
            require(checkpoint->revision == 1 && checkpoint->value == stored && accepted.empty(),
                "malformed checkpoint remains blind, unmodified and never reset");
        } else {
            require(!accepted.empty() && accepted[0]["category"] == "filesystem_usn_gap"
                && accepted[0]["data"]["reason"] == expected_reason,
                "native query produces correct durable checkpoint discontinuity");
            const auto& body = accepted[0]["data"];
            require(body["source_checkpoint_expected_revision"] == "1"
                && body["previous_cursor"] == Json::parse(stored)
                && body["lost_native_events"].is_null(), "gap preserves prior cursor and unknown loss");
            const auto& bounds = body["native_journal"];
            const auto first = std::max(std::stoll(bounds["first_usn"].get<std::string>()),
                std::stoll(bounds["lowest_valid_usn"].get<std::string>()));
            require(body["replacement_cursor"]["journal_id"] == bounds["journal_id"]
                && body["replacement_cursor"]["next_usn"] == std::to_string(first)
                && body["source_checkpoint_next_cursor"] == body["replacement_cursor"],
                "gap replacement derives from actual retained native bounds");
            require(checkpoint->revision >= 2, "discontinuity committed before advancement");
        }
        cursor_faults.push_back({{"case", label}, {"verified", true}, {"malformed", malformed},
            {"source_health", health}, {"records", accepted}, {"native_journal_modified", false}});
    };
    fault("mismatched-journal", col::encode_usn_cursor({info.UsnJournalID ^ 1ull, info.NextUsn}),
        "native_journal_instance_changed", false);
    require(info.NextUsn < INT64_MAX, "native journal has representable ahead cursor");
    fault("ahead-cursor", col::encode_usn_cursor({info.UsnJournalID, INT64_MAX}),
        "saved_cursor_ahead_of_native_journal", false);
    if (std::max(info.FirstUsn, info.LowestValidUsn) > 0)
        fault("expired-cursor", col::encode_usn_cursor({info.UsnJournalID, 0}),
            "saved_cursor_before_retained_or_valid_journal_range", false);
    fault("malformed-cursor", "{\"format\":\"windows_usn_cursor_v1\",\"journal_id\":\"01\",\"next_usn\":\"0\"}", "", true);
    return {{"real_windows_usn_verified", true}, {"create_ads_rename_delete_verified", true}, {"refusal_cursor_immutable_verified", true},
        {"stopped_source_replay_verified", true}, {"durable_journal_reopen_replay_verified", true},
        {"checkpoint_faults", cursor_faults}, {"held_file_index_verified", true}, {"records", records}, {"full_file_coverage_verified", false}};
}
int main(int argc, char** argv) {
    try {
        bool required = false; std::string report;
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i]; if (arg == "--require-live") required = true;
            else if (arg == "--report" && i + 1 < argc) report = argv[++i]; else throw std::invalid_argument("unknown USN test argument");
        }
        decoder_tests(); auto result = live_tests(required);
        pipeline::NormalizationContext context{{"agent-usn-fixture", "dev"}, {"host-usn-fixture", "LAB", {"Windows", "fixture"}}};
        pipeline::EndpointRecordFactory factory{context, "device-usn-fixture", std::string(64, 'c'), "boot_" + std::string(64, 'd'), 1};
        result["synthetic_contract_fixtures"] = Json::array();
        for (unsigned version : {2, 3}) result["synthetic_contract_fixtures"].push_back(factory.usn_journal("synthetic-volume",
            col::decode_usn_buffer(fixture(version), 64), false));
        result["synthetic_contract_fixtures"].push_back(factory.usn_journal("synthetic-volume",
            {{"reason", "synthetic_gap"}, {"lost_native_events", nullptr}}, true));
        if (!report.empty()) { require(!fs::exists(report), "preserve existing native USN test report"); std::ofstream out(report, std::ios::binary); out << result.dump(); require(bool(out), "native report writes"); }
        std::cout << "USN decoder and native/durable tests passed; live=" << result["real_windows_usn_verified"] << '\n'; return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}

#include "panopticon/officer/delivery/journal.hpp"
#include "panopticon/officer/core/entity_id.hpp"
#include "panopticon/officer/core/process_graph.hpp"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <winsqlite/winsqlite3.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <unordered_set>
#include <unordered_map>

namespace panopticon::officer::delivery {
namespace {

using Json = nlohmann::json;
struct DbCloser { void operator()(sqlite3* p) const noexcept { sqlite3_close(p); } };
struct StatementCloser { void operator()(sqlite3_stmt* p) const noexcept { sqlite3_finalize(p); } };
struct LocalCloser { void operator()(void* p) const noexcept { LocalFree(p); } };
using Database = std::unique_ptr<sqlite3, DbCloser>;
using Statement = std::unique_ptr<sqlite3_stmt, StatementCloser>;

void check(sqlite3* db, int rc) {
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW)
        throw std::runtime_error("journal SQLite failure (" + std::to_string(rc) + "): " + sqlite3_errmsg(db));
}
void exec(sqlite3* db, const char* sql) { check(db, sqlite3_exec(db, sql, nullptr, nullptr, nullptr)); }
Statement prepare(sqlite3* db, const char* sql) {
    sqlite3_stmt* p = nullptr;
    check(db, sqlite3_prepare_v2(db, sql, -1, &p, nullptr));
    return Statement{p};
}
void bind_text(sqlite3* db, sqlite3_stmt* statement, int index, const std::string& value) {
    if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw std::length_error("journal field too large");
    check(db, sqlite3_bind_text(statement, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT));
}
std::string column(sqlite3_stmt* p, int index) {
    const auto* bytes = static_cast<const char*>(sqlite3_column_blob(p, index));
    return bytes ? std::string(bytes, static_cast<std::size_t>(sqlite3_column_bytes(p, index))) : std::string{};
}
std::string text_column(sqlite3_stmt* p, int index) {
    const auto* bytes = sqlite3_column_text(p, index);
    return bytes ? std::string(reinterpret_cast<const char*>(bytes), static_cast<std::size_t>(sqlite3_column_bytes(p, index))) : std::string{};
}
std::string digest(const std::string& input) {
    std::string error;
    auto value = core::sha256_hex(input, error);
    if (!value) throw std::runtime_error(error);
    return *value;
}
class Transaction {
public:
    explicit Transaction(sqlite3* db, bool write = true) : db_(db) { exec(db_, write ? "BEGIN IMMEDIATE" : "BEGIN"); }
    ~Transaction() { if (!committed_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); }
    void commit() { exec(db_, "COMMIT"); committed_ = true; }
private:
    sqlite3* db_;
    bool committed_ = false;
};

// User-scoped DPAPI deliberately binds the journal to its service identity.
// Changing the runtime account requires an explicit export/migration procedure.
std::string protect(const std::string& input, const std::string& key, bool encrypt) {
    DATA_BLOB source{static_cast<DWORD>(input.size()), reinterpret_cast<BYTE*>(const_cast<char*>(input.data()))};
    DATA_BLOB entropy{static_cast<DWORD>(key.size()), reinterpret_cast<BYTE*>(const_cast<char*>(key.data()))};
    DATA_BLOB output{};
    const BOOL ok = encrypt
        ? CryptProtectData(&source, L"Panopticon endpoint journal v1", &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output)
        : CryptUnprotectData(&source, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output);
    if (!ok) throw std::runtime_error("journal DPAPI failure: " + std::to_string(GetLastError()));
    std::unique_ptr<void, LocalCloser> allocation{output.pbData};
    return std::string(reinterpret_cast<const char*>(output.pbData), output.cbData);
}

void secure_directory(const std::filesystem::path& directory) {
    if (directory.empty()) throw std::invalid_argument("journal directory is empty");
    const auto absolute = std::filesystem::absolute(directory).lexically_normal();
    // Avoid following an existing junction/symlink in any path component.
    for (auto p = absolute; !p.empty(); p = p.parent_path()) {
        const DWORD attributes = GetFileAttributesW(p.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("journal path contains a reparse point");
        if (p == p.parent_path()) break;
    }
    std::filesystem::create_directories(absolute);
    PSECURITY_DESCRIPTOR raw = nullptr;
    // Owner, LocalSystem and administrators; inheritable and protected DACL.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)", SDDL_REVISION_1, &raw, nullptr))
        throw std::runtime_error("journal security descriptor creation failed");
    std::unique_ptr<void, LocalCloser> descriptor{raw};
    if (!SetFileSecurityW(absolute.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, raw))
        throw std::runtime_error("journal directory ACL could not be protected");
    for (const auto* name : {L"journal.db", L"journal.db-wal", L"journal.db-shm"}) {
        const auto file = absolute / name;
        const DWORD attributes = GetFileAttributesW(file.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) continue;
        if (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
            throw std::runtime_error("journal database path is not a regular file");
        if (!SetFileSecurityW(file.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, raw))
            throw std::runtime_error("journal file ACL could not be protected");
    }
}

std::uint32_t crc32(const std::string& bytes) {
    std::uint32_t crc = 0xffffffffu;
    for (unsigned char b : bytes) {
        crc ^= b;
        for (int bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320u : 0u);
    }
    return crc ^ 0xffffffffu;
}

std::uint64_t receipt_count(const Json& value, const char* name) {
    const auto& field = value.at(name);
    if (!field.is_number_unsigned()) throw std::runtime_error("journal receipt count is not an unsigned integer");
    return field.get<std::uint64_t>();
}
}  // namespace

struct DurableJournal::Impl {
    JournalConfig config;
    Database db;
    mutable std::mutex mutex;
    std::uint64_t storage_admission_refusals = 0;

    std::pair<std::uint64_t, std::uint64_t> storage_sample() const {
        std::uint64_t bytes = 0;
        for (const auto* name : {L"journal.db", L"journal.db-wal", L"journal.db-shm"}) {
            std::error_code error;
            const auto size = std::filesystem::file_size(config.directory / name, error);
            if (error == std::errc::no_such_file_or_directory) continue;
            if (error) throw std::runtime_error("journal physical size query failed: " + error.message());
            if (size > std::numeric_limits<std::uint64_t>::max() - bytes)
                throw std::runtime_error("journal physical size overflow");
            bytes += size;
        }
        ULARGE_INTEGER available{};
        if (!GetDiskFreeSpaceExW(config.directory.c_str(), &available, nullptr, nullptr))
            throw std::runtime_error("journal caller-available storage query failed: " + std::to_string(GetLastError()));
        return {bytes, available.QuadPart};
    }

    void admit_growth(std::size_t encrypted_bytes) {
        try {
            const auto [bytes, available] = storage_sample();
            // Conservative allowance for pages, indexes, encryption and WAL.
            // Not an upper bound: checkpointing, other handles and writers race
            // this sample. SQLite FULL commit remains the acceptance boundary.
            const auto allowance = 128ull * 1024 + 4ull * encrypted_bytes;
            if (allowance > config.physical_admission_limit || bytes > config.physical_admission_limit - allowance)
                throw std::runtime_error("journal physical admission budget exhausted; retained evidence preserved");
            if (available < config.minimum_free_bytes || allowance > available - config.minimum_free_bytes)
                throw std::runtime_error("journal caller-available storage headroom exhausted; retained evidence preserved");
        } catch (...) {
            if (storage_admission_refusals != std::numeric_limits<std::uint64_t>::max()) ++storage_admission_refusals;
            throw;
        }
    }

    explicit Impl(JournalConfig value) : config(std::move(value)) {
        if (!config.retained_payload_limit || !config.physical_admission_limit || !config.event_size_limit || config.event_size_limit > 8u * 1024 * 1024)
            throw std::invalid_argument("invalid journal limits");
        secure_directory(config.directory);
        config.directory = std::filesystem::absolute(config.directory).lexically_normal();
        sqlite3* raw = nullptr;
        const auto path = config.directory / L"journal.db";
        const int rc = sqlite3_open16(path.c_str(), &raw);
        db.reset(raw);
        check(db.get(), rc);
        check(db.get(), sqlite3_busy_timeout(db.get(), 5000));
        auto version = prepare(db.get(), "PRAGMA user_version");
        check(db.get(), sqlite3_step(version.get()));
        const auto schema = sqlite3_column_int(version.get(), 0);
        if (schema < 0 || schema > 6) throw std::runtime_error("unsupported journal schema version");
        version.reset();
        auto mode = prepare(db.get(), "PRAGMA journal_mode=WAL");
        check(db.get(), sqlite3_step(mode.get()));
        if (text_column(mode.get(), 0) != "wal") throw std::runtime_error("journal WAL mode unavailable");
        mode.reset();
        exec(db.get(), "PRAGMA synchronous=FULL; PRAGMA wal_autocheckpoint=256; PRAGMA secure_delete=ON;");
        exec(db.get(),
            "CREATE TABLE IF NOT EXISTS observations (seq INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL, payload BLOB NOT NULL, bytes INTEGER NOT NULL, state TEXT NOT NULL DEFAULT 'pending', reason BLOB, protocol INTEGER NOT NULL DEFAULT 1);"
            "CREATE TABLE IF NOT EXISTS identifiers (name TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS imports (origin TEXT PRIMARY KEY);"
            "CREATE TABLE IF NOT EXISTS gaps (origin TEXT PRIMARY KEY, reason TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);"
            "INSERT OR IGNORE INTO counters VALUES ('acknowledged',0);"
            "INSERT OR IGNORE INTO counters SELECT 'retained',COALESCE(SUM(bytes),0) FROM observations;"
            "INSERT OR IGNORE INTO counters SELECT 'pending',COALESCE(SUM(state='pending'),0) FROM observations;"
            "INSERT OR IGNORE INTO counters SELECT 'dead',COALESCE(SUM(state='dead'),0) FROM observations;"
            "CREATE INDEX IF NOT EXISTS observations_state_sequence ON observations(state,seq);"
            "CREATE TRIGGER IF NOT EXISTS retained_insert AFTER INSERT ON observations BEGIN UPDATE counters SET value=value+NEW.bytes WHERE name='retained'; END;"
            "CREATE TRIGGER IF NOT EXISTS retained_delete AFTER DELETE ON observations BEGIN UPDATE counters SET value=value-OLD.bytes WHERE name='retained'; END;"
            "CREATE TRIGGER IF NOT EXISTS retained_update AFTER UPDATE OF bytes ON observations BEGIN UPDATE counters SET value=value+NEW.bytes-OLD.bytes WHERE name='retained'; END;"
            "CREATE TRIGGER IF NOT EXISTS state_insert AFTER INSERT ON observations BEGIN UPDATE counters SET value=value+1 WHERE name=NEW.state; END;"
            "CREATE TRIGGER IF NOT EXISTS state_delete AFTER DELETE ON observations BEGIN UPDATE counters SET value=value-1 WHERE name=OLD.state; END;"
            "CREATE TRIGGER IF NOT EXISTS state_update AFTER UPDATE OF state ON observations BEGIN UPDATE counters SET value=value-1 WHERE name=OLD.state; UPDATE counters SET value=value+1 WHERE name=NEW.state; END;"
            );
        if (schema == 1) exec(db.get(), "ALTER TABLE observations ADD COLUMN protocol INTEGER NOT NULL DEFAULT 1");
        exec(db.get(), "CREATE INDEX IF NOT EXISTS observations_protocol_state ON observations(protocol,state,seq);"
            "CREATE TABLE IF NOT EXISTS commands (key TEXT PRIMARY KEY, scope TEXT NOT NULL, digest TEXT NOT NULL,"
            "payload BLOB NOT NULL, state TEXT NOT NULL DEFAULT 'received', result BLOB, bytes INTEGER NOT NULL);"
            "CREATE INDEX IF NOT EXISTS commands_scope_state ON commands(scope,state);"
            "CREATE TABLE IF NOT EXISTS source_checkpoints (source TEXT PRIMARY KEY, revision TEXT NOT NULL,"
            "value BLOB NOT NULL, record_digest TEXT NOT NULL, bytes INTEGER NOT NULL);");
        {
            Transaction migration{db.get()};
            exec(db.get(), "CREATE TABLE IF NOT EXISTS process_history (seq INTEGER PRIMARY KEY, key TEXT UNIQUE NOT NULL, payload BLOB NOT NULL, bytes INTEGER NOT NULL);"
                "INSERT OR IGNORE INTO counters SELECT 'process_history_bytes',COALESCE(SUM(bytes),0) FROM process_history;"
                "INSERT OR IGNORE INTO counters SELECT 'process_history_count',COUNT(*) FROM process_history;"
                "CREATE TRIGGER IF NOT EXISTS process_history_insert AFTER INSERT ON process_history BEGIN "
                "UPDATE counters SET value=value+NEW.bytes WHERE name='process_history_bytes';"
                "UPDATE counters SET value=value+1 WHERE name='process_history_count'; END;"
                "CREATE TABLE IF NOT EXISTS process_graph_index (history_seq INTEGER PRIMARY KEY, entity_digest TEXT NOT NULL, parent_digest TEXT NOT NULL, quality INTEGER NOT NULL);"
                "CREATE INDEX IF NOT EXISTS process_graph_entity ON process_graph_index(entity_digest,history_seq);"
                "CREATE INDEX IF NOT EXISTS process_graph_parent ON process_graph_index(parent_digest,history_seq);"
                "INSERT OR IGNORE INTO counters SELECT 'process_graph_count',COUNT(*) FROM process_graph_index;"
                "INSERT OR IGNORE INTO counters SELECT 'process_graph_unresolved',COALESCE(SUM(quality<>0),0) FROM process_graph_index;"
                "CREATE TRIGGER IF NOT EXISTS process_graph_insert AFTER INSERT ON process_graph_index BEGIN "
                "UPDATE counters SET value=value+1 WHERE name='process_graph_count';"
                "UPDATE counters SET value=value+(NEW.quality<>0) WHERE name='process_graph_unresolved'; END;"
                "PRAGMA user_version=6;");
            migration.commit();
        }
        auto integrity = prepare(db.get(), "PRAGMA quick_check");
        check(db.get(), sqlite3_step(integrity.get()));
        if (text_column(integrity.get(), 0) != "ok") throw std::runtime_error("journal integrity check failed; original database retained");
        integrity.reset();
        import_legacy();
    }

    std::uint64_t retained() const {
        auto statement = prepare(db.get(), "SELECT value + COALESCE((SELECT SUM(bytes) FROM commands),0) + "
            "COALESCE((SELECT SUM(bytes) FROM source_checkpoints),0) + "
            "COALESCE((SELECT value FROM counters WHERE name='process_history_bytes'),0) FROM counters WHERE name='retained'");
        check(db.get(), sqlite3_step(statement.get()));
        return static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    }
    void index_process(std::uint64_t sequence, const Json& document) {
        const auto fact = core::process_graph_fact(document);
        auto index = prepare(db.get(), "INSERT OR IGNORE INTO process_graph_index(history_seq,entity_digest,parent_digest,quality) VALUES (?,?,?,?)");
        check(db.get(), sqlite3_bind_int64(index.get(), 1, static_cast<sqlite3_int64>(sequence)));
        bind_text(db.get(), index.get(), 2, fact.entity_id ? digest(*fact.entity_id) : "");
        bind_text(db.get(), index.get(), 3, fact.parent_entity_id ? digest(*fact.parent_entity_id) : "");
        check(db.get(), sqlite3_bind_int(index.get(), 4, fact.interpretable ? (fact.entity_id ? 0 : 1) : 2));
        check(db.get(), sqlite3_step(index.get()));
    }
    void insert(const std::string& line, const std::string& key) {
        auto exists = prepare(db.get(), "SELECT 1 FROM observations WHERE key=?");
        bind_text(db.get(), exists.get(), 1, key);
        const int rc = sqlite3_step(exists.get());
        check(db.get(), rc);
        const bool pending_exists = rc == SQLITE_ROW;
        const auto document = Json::parse(line, nullptr, false);
        const unsigned protocol = document.is_object() && document.contains("schema_version") && document.at("schema_version").is_string() && document.at("schema_version") == "1.0" && document.contains("kind") ? 2u : 1u;
        // Archive exact canonical lifecycle evidence only. Do not turn a
        // family event's PID context or a state snapshot into a birth claim.
        const bool lifecycle = protocol == 2 && document.value("kind", Json{}) == "observation" &&
            (document.value("category", Json{}) == "process_stop" ||
             (document.value("category", Json{}) == "process" && document.contains("data") && document["data"].is_object() &&
              document["data"].contains("event") && document["data"]["event"].is_object() && document["data"]["event"].value("type", Json{}) == "start"));
        bool archive_exists = false;
        if (lifecycle) {
            auto archived = prepare(db.get(), "SELECT 1 FROM process_history WHERE key=?");
            bind_text(db.get(), archived.get(), 1, key);
            const auto archive_rc = sqlite3_step(archived.get()); check(db.get(), archive_rc);
            archive_exists = archive_rc == SQLITE_ROW;
        }
        if (pending_exists && (!lifecycle || archive_exists)) return;
        const auto bytes = retained();
        const auto copies = static_cast<std::uint64_t>(!pending_exists) + static_cast<std::uint64_t>(lifecycle && !archive_exists);
        if (line.size() > config.retained_payload_limit / copies || bytes > config.retained_payload_limit - copies * line.size())
            throw std::runtime_error("journal retention quota exhausted; existing evidence retained");
        const auto encrypted = protect(line, key, true);
        admit_growth(encrypted.size() * copies);
        if (lifecycle && !archive_exists) {
            auto archive = prepare(db.get(), "INSERT INTO process_history(key,payload,bytes) VALUES (?,?,?)");
            bind_text(db.get(), archive.get(), 1, key);
            check(db.get(), sqlite3_bind_blob(archive.get(), 2, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_TRANSIENT));
            check(db.get(), sqlite3_bind_int64(archive.get(), 3, static_cast<sqlite3_int64>(line.size())));
            check(db.get(), sqlite3_step(archive.get()));
            index_process(static_cast<std::uint64_t>(sqlite3_last_insert_rowid(db.get())), document);
        }
        if (pending_exists) return;
        auto statement = prepare(db.get(), "INSERT INTO observations(key,payload,bytes,protocol) VALUES (?,?,?,?)");
        bind_text(db.get(), statement.get(), 1, key);
        check(db.get(), sqlite3_bind_blob(statement.get(), 2, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_TRANSIENT));
        check(db.get(), sqlite3_bind_int64(statement.get(), 3, static_cast<sqlite3_int64>(line.size())));
        check(db.get(), sqlite3_bind_int(statement.get(), 4, static_cast<int>(protocol)));
        check(db.get(), sqlite3_step(statement.get()));
    }
    void gap(const std::string& origin, const std::string& reason) {
        auto existing = prepare(db.get(), "SELECT 1 FROM gaps WHERE origin=?");
        bind_text(db.get(), existing.get(), 1, origin);
        const auto rc = sqlite3_step(existing.get());
        check(db.get(), rc);
        if (rc == SQLITE_ROW) return;
        existing.reset();
        admit_growth(origin.size() + reason.size());
        auto statement = prepare(db.get(), "INSERT OR IGNORE INTO gaps VALUES (?,?)");
        bind_text(db.get(), statement.get(), 1, origin);
        bind_text(db.get(), statement.get(), 2, reason);
        check(db.get(), sqlite3_step(statement.get()));
    }

    void import_legacy() {
        std::vector<std::filesystem::path> paths;
        for (const auto& entry : std::filesystem::directory_iterator(config.directory)) {
            const auto name = entry.path().filename().string();
            if (name.starts_with("segment-") && name.ends_with(".dat")) paths.push_back(entry.path());
        }
        std::sort(paths.begin(), paths.end());
        for (const auto& path : paths) {
            const auto attributes = GetFileAttributesW(path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
                throw std::runtime_error("unsafe legacy spool path");
            std::ifstream stream(path, std::ios::binary);
            if (!stream) throw std::runtime_error("legacy spool could not be read");
            while (stream.peek() != std::char_traits<char>::eof()) {
                const auto offset = static_cast<std::uint64_t>(stream.tellg());
                const auto origin = path.filename().string() + ":" + std::to_string(offset);
                std::uint32_t size = 0, crc = 0;
                stream.read(reinterpret_cast<char*>(&size), 4);
                stream.read(reinterpret_cast<char*>(&crc), 4);
                if (!stream || size < 2 || size > 8u * 1024 * 1024 + 65537u) {
                    gap(origin, "legacy invalid frame header or truncated tail; original retained");
                    break; // No trustworthy length: do not guess a resynchronization.
                }
                std::string payload(size, '\0');
                stream.read(payload.data(), size);
                if (!stream) { gap(origin, "legacy truncated payload; original retained"); break; }
                std::uint16_t id_size = 0;
                std::memcpy(&id_size, payload.data(), sizeof(id_size));
                if (crc32(payload) != crc || static_cast<std::size_t>(id_size) + 2 > payload.size()) {
                    gap(origin, "legacy checksum or batch-ID framing failure; original retained");
                    continue;
                }
                auto imported = prepare(db.get(), "SELECT 1 FROM imports WHERE origin=?");
                bind_text(db.get(), imported.get(), 1, origin);
                const auto rc = sqlite3_step(imported.get());
                check(db.get(), rc);
                if (rc == SQLITE_ROW) continue;
                imported.reset();
                Transaction transaction{db.get()};
                const auto body = payload.substr(2 + id_size);
                std::size_t begin = 0, index = 0;
                while (begin < body.size()) {
                    const auto end = body.find('\n', begin);
                    const auto line = body.substr(begin, end == std::string::npos ? end : end - begin);
                    if (line.find_first_not_of(" \t\r") != std::string::npos)
                        insert(line, digest("legacy:" + origin + ":" + std::to_string(index) + ":" + line));
                    ++index;
                    if (end == std::string::npos) break;
                    begin = end + 1;
                }
                auto mark = prepare(db.get(), "INSERT INTO imports VALUES (?)");
                admit_growth(origin.size());
                bind_text(db.get(), mark.get(), 1, origin);
                check(db.get(), sqlite3_step(mark.get()));
                transaction.commit();
            }
            if (stream.bad()) throw std::runtime_error("legacy spool read failed; migration incomplete");
        }
    }
};

std::string JournalBatch::ndjson() const {
    std::string body;
    for (const auto& entry : entries) { body += entry.body; body += '\n'; }
    return body;
}

DurableJournal::DurableJournal(JournalConfig config) : impl_(std::make_unique<Impl>(std::move(config))) {}
DurableJournal::~DurableJournal() = default;

void DurableJournal::append(const std::string& line) {
    if (line.find_first_not_of(" \t") == std::string::npos || line.find('\n') != std::string::npos || line.find('\r') != std::string::npos || line.size() > impl_->config.event_size_limit)
        throw std::invalid_argument("journal observation is empty, multiline or over the event size limit");
    std::scoped_lock lock{impl_->mutex};
    Transaction transaction{impl_->db.get()};
    impl_->insert(line, digest(line));
    transaction.commit();
}
namespace {
void validate_source(const std::string& source) {
    if (source.empty() || source.size() > 512 || source.find_first_of("\r\n") != std::string::npos ||
        source.find('\0') != std::string::npos) throw std::invalid_argument("invalid source checkpoint key");
}
std::uint64_t checkpoint_revision(const std::string& text) {
    std::uint64_t value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || (text.size() > 1 && text.front() == '0') || parsed.ec != std::errc{} ||
        parsed.ptr != text.data() + text.size() || !value) throw std::runtime_error("invalid retained source checkpoint revision");
    return value;
}
}
std::optional<SourceCheckpoint> DurableJournal::source_checkpoint(const std::string& source) const {
    validate_source(source); std::scoped_lock lock{impl_->mutex};
    auto row = prepare(impl_->db.get(), "SELECT revision,value FROM source_checkpoints WHERE source=?");
    bind_text(impl_->db.get(), row.get(), 1, source);
    const auto rc = sqlite3_step(row.get()); check(impl_->db.get(), rc);
    if (rc == SQLITE_DONE) return std::nullopt;
    return SourceCheckpoint{checkpoint_revision(text_column(row.get(), 0)), protect(column(row.get(), 1), "source:" + source, false)};
}
void DurableJournal::append_checkpointed(const std::string& line, const std::string& source,
    const std::string& checkpoint, std::uint64_t expected) {
    validate_source(source);
    if (checkpoint.empty() || checkpoint.size() > 16384 || expected == std::numeric_limits<std::uint64_t>::max())
        throw std::invalid_argument("invalid source checkpoint or exhausted revision");
    if (line.find_first_not_of(" \t") == std::string::npos || line.find_first_of("\r\n") != std::string::npos ||
        line.size() > impl_->config.event_size_limit) throw std::invalid_argument("invalid checkpointed observation");
    const auto key = digest(line);
    std::scoped_lock lock{impl_->mutex}; auto* db = impl_->db.get(); Transaction transaction{db};
    auto existing = prepare(db, "SELECT revision,value,record_digest,bytes FROM source_checkpoints WHERE source=?");
    bind_text(db, existing.get(), 1, source); const auto rc = sqlite3_step(existing.get()); check(db, rc);
    const auto revision = rc == SQLITE_ROW ? checkpoint_revision(text_column(existing.get(), 0)) : 0;
    const auto old_bytes = rc == SQLITE_ROW ? static_cast<std::uint64_t>(sqlite3_column_int64(existing.get(), 3)) : 0;
    if (revision != expected) {
        if (revision == expected + 1 && text_column(existing.get(), 2) == key &&
            protect(column(existing.get(), 1), "source:" + source, false) == checkpoint) { transaction.commit(); return; }
        throw std::runtime_error("source checkpoint revision conflict; retained cursor preserved");
    }
    existing.reset();
    if (!revision) {
        auto count = prepare(db, "SELECT COUNT(*) FROM source_checkpoints"); check(db, sqlite3_step(count.get()));
        if (sqlite3_column_int64(count.get(), 0) >= 64) throw std::runtime_error("source checkpoint count limit");
    }
    impl_->insert(line, key);
    const auto retained = impl_->retained();
    if (retained < old_bytes || checkpoint.size() > impl_->config.retained_payload_limit ||
        retained - old_bytes > impl_->config.retained_payload_limit - checkpoint.size())
        throw std::runtime_error("source checkpoint retention quota exhausted; record and cursor unchanged");
    const auto encrypted = protect(checkpoint, "source:" + source, true); impl_->admit_growth(encrypted.size());
    auto save = prepare(db, "INSERT INTO source_checkpoints VALUES (?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
        "revision=excluded.revision,value=excluded.value,record_digest=excluded.record_digest,bytes=excluded.bytes");
    bind_text(db, save.get(), 1, source); bind_text(db, save.get(), 2, std::to_string(expected + 1));
    check(db, sqlite3_bind_blob(save.get(), 3, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_TRANSIENT));
    bind_text(db, save.get(), 4, key); check(db, sqlite3_bind_int64(save.get(), 5, static_cast<sqlite3_int64>(checkpoint.size())));
    check(db, sqlite3_step(save.get())); transaction.commit();
}

std::optional<JournalBatch> DurableJournal::peek(std::size_t max_events, std::size_t max_bytes) {
    if (!max_events || max_events > 1000 || !max_bytes || max_bytes > 8u * 1024 * 1024)
        throw std::invalid_argument("invalid journal batch limits");
    std::scoped_lock lock{impl_->mutex};
    auto head = prepare(impl_->db.get(), "SELECT protocol FROM observations WHERE state='pending' ORDER BY seq LIMIT 1");
    auto head_rc = sqlite3_step(head.get());
    check(impl_->db.get(), head_rc);
    if (head_rc == SQLITE_DONE) return std::nullopt;
    const auto protocol = sqlite3_column_int(head.get(), 0);
    head.reset();
    auto statement = prepare(impl_->db.get(), "SELECT key,payload FROM observations WHERE state='pending' AND protocol=? ORDER BY seq LIMIT ?");
    check(impl_->db.get(), sqlite3_bind_int(statement.get(), 1, protocol));
    check(impl_->db.get(), sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(max_events)));
    JournalBatch batch;
    batch.protocol = static_cast<unsigned>(protocol);
    std::size_t size = 0;
    std::string keys;
    for (;;) {
        const int rc = sqlite3_step(statement.get());
        check(impl_->db.get(), rc);
        if (rc == SQLITE_DONE) break;
        auto key = text_column(statement.get(), 0);
        auto body = protect(column(statement.get(), 1), key, false);
        if (body.size() + 1 > max_bytes - size) {
            if (batch.entries.empty()) throw std::runtime_error("journal head exceeds transport batch ceiling");
            break;
        }
        size += body.size() + 1;
        keys += key + '\n';
        batch.entries.push_back({std::move(key), std::move(body)});
    }
    if (batch.entries.empty()) return std::nullopt;
    batch.id = "journal_" + digest(keys);
    return batch;
}

std::vector<JournalInspectionEntry> DurableJournal::inspect_pending(std::uint64_t after, std::size_t max_events, std::size_t max_bytes) const {
    if (!max_events || max_events > 1000 || !max_bytes || max_bytes > 8u * 1024 * 1024 || after > INT64_MAX)
        throw std::invalid_argument("invalid journal inspection limits or cursor");
    std::scoped_lock lock{impl_->mutex};
    auto query = prepare(impl_->db.get(), "SELECT seq,protocol,key,payload FROM observations WHERE state='pending' AND seq>? ORDER BY seq LIMIT ?");
    check(impl_->db.get(), sqlite3_bind_int64(query.get(), 1, static_cast<sqlite3_int64>(after)));
    check(impl_->db.get(), sqlite3_bind_int64(query.get(), 2, static_cast<sqlite3_int64>(max_events)));
    std::vector<JournalInspectionEntry> entries; std::size_t bytes = 0;
    for (;;) {
        const auto rc = sqlite3_step(query.get()); check(impl_->db.get(), rc);
        if (rc == SQLITE_DONE) break;
        const auto sequence = sqlite3_column_int64(query.get(), 0);
        if (sequence <= 0) throw std::runtime_error("invalid local inspection sequence");
        auto key = text_column(query.get(), 2); auto body = protect(column(query.get(), 3), key, false);
        if (body.size() + 1 > max_bytes - bytes) {
            if (entries.empty()) throw std::runtime_error("journal inspection record exceeds page byte ceiling");
            break;
        }
        bytes += body.size() + 1;
        entries.push_back({static_cast<std::uint64_t>(sequence), static_cast<unsigned>(sqlite3_column_int(query.get(), 1)), {std::move(key), std::move(body)}});
    }
    return entries;
}

std::vector<JournalInspectionEntry> DurableJournal::inspect_process_history(std::uint64_t after, std::size_t max_events, std::size_t max_bytes) const {
    if (!max_events || max_events > 1000 || !max_bytes || max_bytes > 8u * 1024 * 1024 || after > INT64_MAX)
        throw std::invalid_argument("invalid process history limits or cursor");
    std::scoped_lock lock{impl_->mutex};
    auto query = prepare(impl_->db.get(), "SELECT seq,key,payload FROM process_history WHERE seq>? ORDER BY seq LIMIT ?");
    check(impl_->db.get(), sqlite3_bind_int64(query.get(), 1, static_cast<sqlite3_int64>(after)));
    check(impl_->db.get(), sqlite3_bind_int64(query.get(), 2, static_cast<sqlite3_int64>(max_events)));
    std::vector<JournalInspectionEntry> entries; std::size_t bytes = 0;
    for (;;) {
        const auto rc = sqlite3_step(query.get()); check(impl_->db.get(), rc);
        if (rc == SQLITE_DONE) break;
        const auto sequence = sqlite3_column_int64(query.get(), 0);
        if (sequence <= 0) throw std::runtime_error("invalid local process history sequence");
        auto key = text_column(query.get(), 1); auto body = protect(column(query.get(), 2), key, false);
        if (body.size() + 1 > max_bytes - bytes) {
            if (entries.empty()) throw std::runtime_error("process history record exceeds page byte ceiling");
            break;
        }
        bytes += body.size() + 1;
        entries.push_back({static_cast<std::uint64_t>(sequence), 2u, {std::move(key), std::move(body)}});
    }
    return entries;
}

std::size_t DurableJournal::rebuild_process_graph(std::size_t max_events, std::size_t max_bytes) {
    if (!max_events || max_events > 1000 || !max_bytes || max_bytes > 8u * 1024 * 1024)
        throw std::invalid_argument("invalid process graph rebuild bounds");
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    Transaction transaction{db};
    auto query = prepare(db, "SELECT h.seq,h.key,h.payload FROM process_history h LEFT JOIN process_graph_index g "
        "ON g.history_seq=h.seq WHERE g.history_seq IS NULL ORDER BY h.seq LIMIT ?");
    check(db, sqlite3_bind_int64(query.get(), 1, static_cast<sqlite3_int64>(max_events)));
    std::size_t count = 0, bytes = 0;
    for (;;) {
        const auto rc = sqlite3_step(query.get()); check(db, rc);
        if (rc == SQLITE_DONE) break;
        const auto sequence = sqlite3_column_int64(query.get(), 0);
        if (sequence <= 0) throw std::runtime_error("invalid process graph archive sequence");
        auto body = protect(column(query.get(), 2), text_column(query.get(), 1), false);
        if (body.size() + 1 > max_bytes - bytes) {
            if (!count) throw std::runtime_error("process graph rebuild head exceeds byte bound; no evidence skipped");
            break;
        }
        impl_->admit_growth(256);
        impl_->index_process(static_cast<std::uint64_t>(sequence), Json::parse(body, nullptr, false));
        bytes += body.size() + 1; ++count;
    }
    query.reset(); transaction.commit(); return count;
}

nlohmann::json DurableJournal::process_ancestry(const std::string& entity_id, std::size_t max_nodes,
    std::size_t max_depth, std::size_t max_evidence, std::size_t max_bytes) const {
    if (entity_id.size() != 69 || !entity_id.starts_with("proc_") ||
        entity_id.find_first_not_of("0123456789abcdef", 5) != std::string::npos ||
        !max_nodes || max_nodes > 256 || !max_depth || max_depth > 64 ||
        !max_evidence || max_evidence > 1000 || max_bytes < 4096 || max_bytes > 8u * 1024 * 1024)
        throw std::invalid_argument("invalid process ancestry identity or bounds");
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    Transaction snapshot{db, false};
    auto counts = prepare(db, "SELECT (SELECT value FROM counters WHERE name='process_history_count')-"
        "(SELECT value FROM counters WHERE name='process_graph_count')");
    check(db, sqlite3_step(counts.get()));
    const auto backlog = sqlite3_column_int64(counts.get(), 0);
    if (backlog < 0) throw std::runtime_error("process graph index accounting mismatch");
    counts.reset();
    Json result{{"format", "process_ancestry_v1"}, {"state", "degraded"}, {"root_entity_id", entity_id},
        {"nodes", Json::array()}, {"edges", Json::array()}, {"truncated", false},
        {"index_backlog", std::to_string(backlog)}, {"source_coverage_complete", false},
        {"creator_relationship_verified", false}, {"alias_promotion_performed", false},
        {"snapshot_consistency", "one SQLite read transaction over retained originals and index"},
        {"scope", "exact rederived identity only; observed parent reports may be spoofed; missing evidence never proves absence or liveness"}};
    struct Pending { std::string entity; std::vector<std::string> path; };
    std::vector<Pending> pending{{entity_id, {entity_id}}};
    std::unordered_set<std::string> queued{entity_id};
    std::unordered_set<std::string> visited;
    std::size_t evidence_count = 0, consumed = result.dump().size();
    bool truncated = false;
    for (std::size_t cursor = 0; cursor < pending.size(); ++cursor) {
        const auto current = pending[cursor];
        if (visited.contains(current.entity)) continue;
        if (visited.size() >= max_nodes) { truncated = true; break; }
        visited.insert(current.entity);
        Json node{{"entity_id", current.entity}, {"evidence", Json::array()},
            {"birth_observed", false}, {"stop_observed", false}, {"liveness", nullptr},
            {"parent_claims_conflict", false}, {"retained_evidence_read_complete", true}};
        std::unordered_set<std::string> parents;
        auto query = prepare(db, "SELECT h.seq,h.key,h.payload,g.parent_digest FROM process_graph_index g "
            "JOIN process_history h ON h.seq=g.history_seq WHERE g.entity_digest=? ORDER BY h.seq LIMIT ?");
        bind_text(db, query.get(), 1, digest(current.entity));
        check(db, sqlite3_bind_int64(query.get(), 2, static_cast<sqlite3_int64>(max_evidence - evidence_count + 1)));
        for (;;) {
            const auto rc = sqlite3_step(query.get()); check(db, rc);
            if (rc == SQLITE_DONE) break;
            if (evidence_count >= max_evidence) { truncated = true; node["retained_evidence_read_complete"] = false; break; }
            const auto sequence = sqlite3_column_int64(query.get(), 0);
            const auto body = protect(column(query.get(), 2), text_column(query.get(), 1), false);
            const auto fact = core::process_graph_fact(Json::parse(body));
            if (sequence <= 0 || !fact.interpretable || fact.entity_id != current.entity ||
                text_column(query.get(), 3) != (fact.parent_entity_id ? digest(*fact.parent_entity_id) : ""))
                throw std::runtime_error("process graph index does not match immutable evidence");
            Json evidence{{"archive_sequence", std::to_string(sequence)}, {"record_id", fact.record_id},
                {"operation", fact.stop ? "stop" : "start"}, {"identity", fact.identity},
                {"reported_parent_identity", fact.parent_identity}};
            Json edge = nullptr;
            if (fact.parent_entity_id) {
                edge = {{"child_entity_id", current.entity}, {"parent_entity_id", *fact.parent_entity_id},
                    {"record_id", fact.record_id}, {"basis", "exact decoded source GUID plus observed parent PID"},
                    {"relationship", "source_reported_parent"}, {"creator_verified", false},
                    {"cycle_detected", std::find(current.path.begin(), current.path.end(), *fact.parent_entity_id) != current.path.end()}};
            }
            const auto charge = body.size() + evidence.dump().size() + (edge.is_null() ? 0 : edge.dump().size()) + 2;
            if (charge > max_bytes - consumed) { truncated = true; node["retained_evidence_read_complete"] = false; break; }
            consumed += charge; ++evidence_count;
            node["evidence"].push_back(std::move(evidence));
            node[fact.stop ? "stop_observed" : "birth_observed"] = true;
            if (!fact.parent_identity.is_null()) parents.insert(fact.parent_identity.dump());
            if (fact.parent_entity_id) {
                const bool cycle = edge.at("cycle_detected").get<bool>();
                result["edges"].push_back(std::move(edge));
                if (!cycle && queued.contains(*fact.parent_entity_id)) {
                    // Shared ancestors are visited once without becoming cycles
                    // or falsely incomplete traversal claims.
                } else if (!cycle && current.path.size() < max_depth && pending.size() < max_nodes) {
                    auto path = current.path; path.push_back(*fact.parent_entity_id);
                    queued.insert(*fact.parent_entity_id);
                    pending.push_back({*fact.parent_entity_id, std::move(path)});
                } else if (!cycle) truncated = true;
            }
        }
        node["parent_claims_conflict"] = parents.size() > 1;
        const auto node_bytes = node.dump().size();
        // This includes a conservative second charge for derived node content;
        // all copied originals and returned JSON must fit the caller's bound.
        if (node_bytes > max_bytes - consumed) { truncated = true; break; }
        consumed += node_bytes; result["nodes"].push_back(std::move(node));
        if (evidence_count >= max_evidence) break;
    }
    result["truncated"] = truncated || visited.size() < pending.size();
    // Detect cycles across shared ancestry branches too, not only the first
    // path that reached a node. This is scoped to the returned edge set.
    std::unordered_map<std::string, std::vector<std::string>> adjacency;
    for (const auto& edge : result["edges"])
        adjacency[edge.at("child_entity_id").get<std::string>()].push_back(edge.at("parent_entity_id").get<std::string>());
    for (auto& edge : result["edges"]) {
        const auto child = edge.at("child_entity_id").get<std::string>();
        std::vector<std::string> search{edge.at("parent_entity_id").get<std::string>()};
        std::unordered_set<std::string> examined;
        bool cycle = false;
        for (std::size_t i = 0; i < search.size(); ++i) {
            if (search[i] == child) { cycle = true; break; }
            if (!examined.insert(search[i]).second) continue;
            const auto found = adjacency.find(search[i]);
            if (found != adjacency.end()) search.insert(search.end(), found->second.begin(), found->second.end());
        }
        edge["cycle_detected"] = cycle;
        edge["cycle_detection_scope"] = "returned edge set only";
    }
    result["evidence_records_read"] = std::to_string(evidence_count);
    result["retained_evidence_traversal_complete"] = !result["truncated"].get<bool>() && backlog == 0;
    if (result.dump().size() > max_bytes) throw std::runtime_error("process ancestry output exceeds byte ceiling");
    snapshot.commit(); return result;
}

void DurableJournal::acknowledge(const JournalBatch& batch, const std::string& receipt) {
    if (batch.entries.empty() || receipt.size() > 256u * 1024) throw std::runtime_error("invalid journal receipt size");
    const auto ack = Json::parse(receipt);
    const auto received = receipt_count(ack, "received");
    const auto accepted = receipt_count(ack, "accepted");
    const auto duplicates = receipt_count(ack, "duplicates");
    if (ack.at("batch_id") != batch.id || received != batch.entries.size() || accepted > received || duplicates > received || !ack.at("rejected").is_array())
        throw std::runtime_error("journal receipt does not match submitted batch");
    const auto& rejected = ack.at("rejected");
    if (accepted + duplicates + rejected.size() != received)
        throw std::runtime_error("journal receipt does not account for every observation");
    std::vector<std::optional<std::string>> reasons(batch.entries.size());
    for (const auto& rejection : rejected) {
        const auto line = receipt_count(rejection, "line");
        if (line == 0 || line > received || reasons[static_cast<std::size_t>(line - 1)])
            throw std::runtime_error("journal receipt has invalid or repeated rejection line");
        auto reason = rejection.at("reason").get<std::string>();
        if (reason != "schema_invalid" && reason != "unsupported_schema_version" && reason != "json_invalid")
            throw std::runtime_error("journal receipt has unknown rejection semantics");
        auto detail = rejection.at("detail").get<std::string>();
        if (detail.size() > 16384) throw std::runtime_error("journal rejection detail exceeds limit");
        const auto payload = Json::parse(batch.entries[static_cast<std::size_t>(line - 1)].body, nullptr, false);
        if (rejection.contains("event_id") && !rejection.at("event_id").is_null()) {
            if (!payload.is_object() || !payload.contains("event") || !payload.at("event").is_object() ||
                payload.at("event").value("id", std::string{}) != rejection.at("event_id").get<std::string>()) {
                if (!payload.is_object() || payload.value("record_id", std::string{}) != rejection.at("event_id").get<std::string>())
                throw std::runtime_error("journal rejection identifies another observation");
            }
        }
        reasons[static_cast<std::size_t>(line - 1)] = reason + ": " + detail;
    }
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    Transaction transaction{db};
    for (std::size_t index = 0; index < batch.entries.size(); ++index) {
        auto statement = prepare(db, reasons[index]
            ? "UPDATE observations SET state='dead',reason=?,bytes=bytes+? WHERE key=? AND state='pending'"
            : "DELETE FROM observations WHERE key=? AND state='pending'");
        if (reasons[index]) {
            auto existing = prepare(db, "SELECT 1 FROM observations WHERE key=? AND state='pending'");
            bind_text(db, existing.get(), 1, batch.entries[index].key);
            const auto rc = sqlite3_step(existing.get());
            check(db, rc);
            if (rc == SQLITE_ROW && (reasons[index]->size() > impl_->config.retained_payload_limit ||
                impl_->retained() > impl_->config.retained_payload_limit - reasons[index]->size()))
                throw std::runtime_error("journal rejection metadata quota exhausted; pending evidence retained");
            const auto encrypted = protect(*reasons[index], batch.entries[index].key, true);
            if (rc == SQLITE_ROW) impl_->admit_growth(encrypted.size());
            check(db, sqlite3_bind_blob(statement.get(), 1, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_TRANSIENT));
            check(db, sqlite3_bind_int64(statement.get(), 2, static_cast<sqlite3_int64>(reasons[index]->size())));
        }
        bind_text(db, statement.get(), reasons[index] ? 3 : 1, batch.entries[index].key);
        check(db, sqlite3_step(statement.get()));
        if (!reasons[index] && sqlite3_changes(db) == 1)
            exec(db, "UPDATE counters SET value=value+1 WHERE name='acknowledged'");
    }
    transaction.commit();
}

JournalStats DurableJournal::stats() const {
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    JournalStats stats;
    auto statement = prepare(db, "SELECT (SELECT value FROM counters WHERE name='pending'),(SELECT value FROM counters WHERE name='dead'),(SELECT value FROM counters WHERE name='retained')+COALESCE((SELECT SUM(bytes) FROM commands),0)");
    check(db, sqlite3_step(statement.get()));
    stats.pending_events = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    stats.dead_letter_events = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
    stats.retained_bytes = impl_->retained();
    statement = prepare(db, "SELECT (SELECT value FROM counters WHERE name='process_history_count'),(SELECT value FROM counters WHERE name='process_history_bytes')");
    check(db, sqlite3_step(statement.get()));
    stats.process_history_records = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    stats.process_history_bytes = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
    statement = prepare(db, "SELECT (SELECT value FROM counters WHERE name='process_graph_count'),"
        "(SELECT value FROM counters WHERE name='process_graph_unresolved')");
    check(db, sqlite3_step(statement.get()));
    stats.process_graph_indexed = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    stats.process_graph_unresolved = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
    if (stats.process_graph_indexed > stats.process_history_records || stats.process_graph_unresolved > stats.process_graph_indexed)
        throw std::runtime_error("process graph counter accounting inconsistent");
    statement = prepare(db, "SELECT value FROM counters WHERE name='acknowledged'");
    check(db, sqlite3_step(statement.get()));
    stats.acknowledged_events = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    statement = prepare(db, "SELECT COUNT(*) FROM gaps");
    check(db, sqlite3_step(statement.get()));
    stats.legacy_gaps = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    statement = prepare(db, "SELECT SUM(state='received'),SUM(state='executing'),SUM(state='result_ready'),SUM(state='outboxed'),SUM(state NOT IN ('received','executing','result_ready','outboxed')) FROM commands");
    check(db, sqlite3_step(statement.get()));
    stats.commands_received = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
    stats.commands_executing = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 1));
    stats.command_results_ready = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 2));
    stats.commands_outboxed = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 3));
    stats.commands_unknown_state = static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 4));
    const auto [bytes, available] = impl_->storage_sample();
    stats.disk_bytes = bytes;
    stats.caller_available_bytes = available;
    stats.physical_admission_limit = impl_->config.physical_admission_limit;
    stats.minimum_free_bytes = impl_->config.minimum_free_bytes;
    stats.storage_admission_refusals = impl_->storage_admission_refusals;
    return stats;
}

std::vector<JournalDeadLetter> DurableJournal::dead_letters(std::size_t limit) const {
    if (!limit || limit > 1000) throw std::invalid_argument("invalid dead-letter inspection limit");
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    auto statement = prepare(db, "SELECT key,payload,reason FROM observations WHERE state='dead' ORDER BY seq LIMIT ?");
    check(db, sqlite3_bind_int64(statement.get(), 1, static_cast<sqlite3_int64>(limit)));
    std::vector<JournalDeadLetter> result;
    for (;;) {
        const auto rc = sqlite3_step(statement.get());
        check(db, rc);
        if (rc == SQLITE_DONE) break;
        const auto key = text_column(statement.get(), 0);
        result.push_back({{key, protect(column(statement.get(), 1), key, false)}, protect(column(statement.get(), 2), key, false)});
    }
    return result;
}
std::string DurableJournal::persistent_identifier(const std::string& name) {
    if (name.empty() || name.size() > 128 || name.starts_with("__")) throw std::invalid_argument("invalid persistent identifier name");
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    Transaction transaction{db};
    auto statement = prepare(db, "SELECT value FROM identifiers WHERE name=?");
    bind_text(db, statement.get(), 1, name);
    const auto rc = sqlite3_step(statement.get());
    check(db, rc);
    if (rc == SQLITE_ROW) { auto result = text_column(statement.get(), 0); transaction.commit(); return result; }
    std::string random(32, '\0');
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(random.data()), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        throw std::runtime_error("identifier entropy unavailable");
    const auto value = digest(random);
    impl_->admit_growth(name.size() + value.size());
    statement = prepare(db, "INSERT INTO identifiers VALUES (?,?)");
    bind_text(db, statement.get(), 1, name); bind_text(db, statement.get(), 2, value);
    check(db, sqlite3_step(statement.get()));
    transaction.commit();
    return value;
}
std::uint64_t DurableJournal::next_collector_generation() {
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    Transaction transaction{db};
    auto statement = prepare(db, "SELECT value FROM identifiers WHERE name='__collector_generation'");
    const auto rc = sqlite3_step(statement.get());
    check(db, rc);
    std::uint64_t previous = 0;
    if (rc == SQLITE_ROW) {
        const auto value = text_column(statement.get(), 0);
        const auto parsed = std::from_chars(value.data(), value.data() + value.size(), previous);
        if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || value.empty())
            throw std::runtime_error("collector generation metadata corrupt; refusing identity rollback");
    }
    if (previous == std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("collector generation exhausted");
    impl_->admit_growth(64);
    statement = prepare(db, "INSERT INTO identifiers(name,value) VALUES ('__collector_generation',?) "
        "ON CONFLICT(name) DO UPDATE SET value=excluded.value");
    bind_text(db, statement.get(), 1, std::to_string(previous + 1));
    check(db, sqlite3_step(statement.get()));
    transaction.commit();
    return previous + 1;
}
void DurableJournal::receive_command(const std::string& scope, const std::string& key, const std::string& body) {
    if (scope.empty() || scope.size() > 128 || key.empty() || key.size() > 128 || body.empty() || body.size() > 8192)
        throw std::invalid_argument("command inbox admission bounds");
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    Transaction tx{db};
    auto query = prepare(db, "SELECT scope,digest,payload FROM commands WHERE key=?");
    bind_text(db, query.get(), 1, key);
    const auto rc = sqlite3_step(query.get()); check(db, rc);
    const auto hash = digest(body);
    if (rc == SQLITE_ROW) {
        if (text_column(query.get(), 0) != scope || text_column(query.get(), 1) != hash ||
            protect(column(query.get(), 2), scope + key + "/command", false) != body)
            throw std::runtime_error("immutable command identity collision; existing command retained");
        tx.commit(); return;
    }
    query.reset();
    query = prepare(db, "SELECT COUNT(*) FROM commands"); check(db, sqlite3_step(query.get()));
    if (sqlite3_column_int64(query.get(), 0) >= 65536) throw std::runtime_error("command tombstone admission limit reached");
    query.reset();
    const auto used = impl_->retained();
    if (body.size() > impl_->config.retained_payload_limit || used > impl_->config.retained_payload_limit - body.size())
        throw std::runtime_error("command inbox quota exhausted; retained commands preserved");
    const auto encrypted = protect(body, scope + key + "/command", true);
    impl_->admit_growth(encrypted.size());
    query = prepare(db, "INSERT INTO commands(key,scope,digest,payload,bytes) VALUES (?,?,?,?,?)");
    bind_text(db, query.get(), 1, key); bind_text(db, query.get(), 2, scope); bind_text(db, query.get(), 3, hash);
    check(db, sqlite3_bind_blob(query.get(), 4, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_TRANSIENT));
    check(db, sqlite3_bind_int64(query.get(), 5, static_cast<sqlite3_int64>(body.size())));
    check(db, sqlite3_step(query.get())); tx.commit();
}

std::vector<JournalCommand> DurableJournal::pending_commands(const std::string& scope, std::size_t limit) const {
    if (scope.empty() || scope.size() > 128 || !limit || limit > 1000) throw std::invalid_argument("command inbox read bounds");
    std::scoped_lock lock{impl_->mutex};
    auto* db = impl_->db.get();
    auto query = prepare(db, "SELECT key,payload,state,result FROM commands WHERE scope=? AND state<>'outboxed' ORDER BY rowid LIMIT ?");
    bind_text(db, query.get(), 1, scope); check(db, sqlite3_bind_int64(query.get(), 2, static_cast<sqlite3_int64>(limit)));
    std::vector<JournalCommand> out;
    for (;;) {
        const auto rc = sqlite3_step(query.get()); check(db, rc); if (rc == SQLITE_DONE) break;
        const auto key = text_column(query.get(), 0), state = text_column(query.get(), 2);
        if (state != "received" && state != "executing" && state != "result_ready") throw std::runtime_error("unknown command state; inbox retained");
        out.push_back({key, scope, protect(column(query.get(), 1), scope + key + "/command", false), state,
            sqlite3_column_type(query.get(), 3) == SQLITE_NULL ? std::string{} : protect(column(query.get(), 3), scope + key + "/result", false)});
    }
    return out;
}

bool DurableJournal::begin_command(const std::string& scope, const std::string& key) {
    std::scoped_lock lock{impl_->mutex}; auto* db = impl_->db.get(); Transaction tx{db};
    auto existing = prepare(db, "SELECT state FROM commands WHERE scope=? AND key=?");
    bind_text(db, existing.get(), 1, scope); bind_text(db, existing.get(), 2, key);
    const auto rc = sqlite3_step(existing.get()); check(db, rc);
    if (rc == SQLITE_DONE || text_column(existing.get(), 0) != "received") { tx.commit(); return false; }
    existing.reset();
    impl_->admit_growth(0);
    auto query = prepare(db, "UPDATE commands SET state='executing' WHERE scope=? AND key=? AND state='received'");
    bind_text(db, query.get(), 1, scope); bind_text(db, query.get(), 2, key); check(db, sqlite3_step(query.get()));
    const bool changed = sqlite3_changes(db) == 1; tx.commit(); return changed;
}

void DurableJournal::finish_command(const std::string& scope, const std::string& key, const std::string& result) {
    if (result.empty() || result.size() > impl_->config.event_size_limit) throw std::invalid_argument("command outcome bounds");
    std::scoped_lock lock{impl_->mutex}; auto* db = impl_->db.get(); Transaction tx{db};
    auto query = prepare(db, "SELECT state,result FROM commands WHERE scope=? AND key=?");
    bind_text(db, query.get(), 1, scope); bind_text(db, query.get(), 2, key);
    const auto rc = sqlite3_step(query.get()); check(db, rc);
    if (rc != SQLITE_ROW) throw std::runtime_error("command outcome has no scoped inbox entry");
    const auto state = text_column(query.get(), 0);
    if (state == "result_ready" || state == "outboxed") {
        if (protect(column(query.get(), 1), scope + key + "/result", false) != result) throw std::runtime_error("immutable command outcome collision");
        tx.commit(); return;
    }
    if (state != "executing") throw std::runtime_error("outcome requires committed execution intent");
    query.reset(); const auto used = impl_->retained();
    if (result.size() > impl_->config.retained_payload_limit || used > impl_->config.retained_payload_limit - result.size())
        throw std::runtime_error("outcome quota exhausted; execution intent retained");
    const auto encrypted = protect(result, scope + key + "/result", true);
    impl_->admit_growth(encrypted.size());
    query = prepare(db, "UPDATE commands SET state='result_ready',result=?,bytes=bytes+? WHERE scope=? AND key=?");
    check(db, sqlite3_bind_blob(query.get(), 1, encrypted.data(), static_cast<int>(encrypted.size()), SQLITE_TRANSIENT));
    check(db, sqlite3_bind_int64(query.get(), 2, static_cast<sqlite3_int64>(result.size())));
    bind_text(db, query.get(), 3, scope); bind_text(db, query.get(), 4, key); check(db, sqlite3_step(query.get())); tx.commit();
}

void DurableJournal::mark_command_outboxed(const std::string& scope, const std::string& key) {
    std::scoped_lock lock{impl_->mutex}; auto* db = impl_->db.get(); Transaction tx{db};
    auto query = prepare(db, "SELECT state FROM commands WHERE scope=? AND key=?");
    bind_text(db, query.get(), 1, scope); bind_text(db, query.get(), 2, key);
    const auto rc = sqlite3_step(query.get()); check(db, rc);
    if (rc != SQLITE_ROW || (text_column(query.get(), 0) != "result_ready" && text_column(query.get(), 0) != "outboxed"))
        throw std::runtime_error("outbox handoff requires retained outcome");
    if (text_column(query.get(), 0) == "outboxed") { tx.commit(); return; }
    impl_->admit_growth(0);
    query.reset(); query = prepare(db, "UPDATE commands SET state='outboxed' WHERE scope=? AND key=?");
    bind_text(db, query.get(), 1, scope); bind_text(db, query.get(), 2, key); check(db, sqlite3_step(query.get())); tx.commit();
}
}  // namespace panopticon::officer::delivery

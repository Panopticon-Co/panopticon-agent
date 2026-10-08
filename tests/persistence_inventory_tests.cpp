#include "panopticon/officer/state/persistence_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "../src/state/persistence_native.hpp"
#include <array>
#include <iostream>
#include <stdexcept>
#include <limits>
#include <cstring>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
void decoders() {
    constexpr std::array bytes{std::byte{0xff}, std::byte{0xff}, std::byte{0xff}, std::byte{0xff}};
    require(state::detail::persistence_registry_data(REG_DWORD, bytes)["value"] == "4294967295", "registry high bits lost");
    constexpr std::array endian{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    require(state::detail::persistence_registry_data(REG_DWORD_BIG_ENDIAN, endian)["value"] == "16909060", "big endian DWORD decoded incorrectly");
    require(state::detail::persistence_registry_data(REG_DWORD, std::span(bytes).first(3))["state"] == "degraded", "bad scalar byte count interpreted");
    std::wstring expand = L"%PATH%\\never-run.exe"; expand += L'\0';
    const auto expanded = state::detail::persistence_registry_data(REG_EXPAND_SZ,
        {reinterpret_cast<const std::byte*>(expand.data()), expand.size() * sizeof(wchar_t)});
    require(expanded["value"] == "%PATH%\\never-run.exe" && expanded["environment_expanded"] == false, "registry text expanded or executed");
    const auto unterminated = state::detail::persistence_registry_data(REG_SZ,
        {reinterpret_cast<const std::byte*>(expand.data()), (expand.size() - 1) * sizeof(wchar_t)});
    require(unterminated["state"] == "degraded" && unterminated["value"].is_null() && unterminated["raw_bytes_hex"].is_string(), "unterminated text guessed or discarded");
    require(state::detail::persistence_registry_data(REG_SZ, std::span(bytes).first(3))["reason"] == "odd_utf16_byte_length", "odd registry bytes decoded");
    const auto task = state::detail::persistence_task_xml("<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\" version=\"1.4\"><Actions><Exec><Command>x.exe</Command></Exec></Actions><Actions><ComHandler><ClassId>unknown</ClassId></ComHandler></Actions><Unknown>opaque</Unknown></Task>");
    require(task["sections"].size() == 3 && task["sections"][1]["xml"].get<std::string>().find("ComHandler") != std::string::npos,
        "duplicate or unknown task sections overwritten");
    require(state::detail::persistence_task_xml("<Task><Actions/></Task>")["reason"] == "unqualified_task_namespace_or_multiple_roots", "unqualified XML assigned task semantics");
    require(state::detail::persistence_task_xml("<Task")["reason"] == "invalid_xml", "malformed task XML accepted");
    require(state::detail::persistence_task_xml("<!DOCTYPE Task><Task/>")["reason"] == "embedded_nul_or_doctype", "DTD assigned semantics");
    VARIANT value; VariantInit(&value); value.vt = VT_UI8; value.ullVal = std::numeric_limits<ULONGLONG>::max();
    require(state::detail::persistence_variant(&value, 1024)["value"] == "18446744073709551615", "WMI uint64 precision lost");
    value.vt = VT_BOOL; value.boolVal = VARIANT_FALSE;
    require(state::detail::persistence_variant(&value, 1024)["value"] == false, "WMI false became unknown");
    value.boolVal = 2;
    require(state::detail::persistence_variant(&value, 1024)["raw_scalar"] == "2" && state::detail::persistence_variant(&value, 1024)["value"].is_null(), "invalid Boolean guessed");
    value.vt = VT_BSTR; value.bstrVal = SysAllocStringByteLen("abc", 3);
    auto fact = state::detail::persistence_variant(&value, 1024); VariantClear(&value);
    require(fact["state"] == "degraded" && fact["raw_bytes_hex"] == "616263", "odd BSTR discarded or overread");
    value.vt = VT_BSTR; value.bstrVal = SysAllocString(L"bounded");
    require(state::detail::persistence_variant(&value, 2)["bound_exceeded"] == true, "BSTR application copy limit ignored"); VariantClear(&value);
    SAFEARRAYBOUND bounds{3, 7}; value.vt = VT_ARRAY | VT_UI1; value.parray = SafeArrayCreate(VT_UI1, 1, &bounds);
    require(value.parray != nullptr, "array allocation failed"); BYTE* data = nullptr;
    require(SUCCEEDED(SafeArrayAccessData(value.parray, reinterpret_cast<void**>(&data))), "array access failed");
    data[0] = 0; data[1] = 0x80; data[2] = 0xff; SafeArrayUnaccessData(value.parray);
    fact = state::detail::persistence_variant(&value, 3);
    require(fact["value"] == "0080ff" && fact["lower_bound"] == "7", "CreatorSID byte array or native index lost");
    require(state::detail::persistence_variant(&value, 2)["bound_exceeded"] == true, "array bound ignored"); VariantClear(&value);
    value.vt = VT_BYREF | VT_BSTR; value.pbstrVal = nullptr;
    require(state::detail::persistence_variant(&value, 1024)["state"] == "degraded", "BYREF dereferenced or guessed");
}
void paging() {
    using namespace state::native_persistence;
    state::PersistenceLimits limits; limits.page_entries = 1; limits.encoded_bytes = 4096;
    std::size_t calls = 0;
    const std::function<bool(Json)> refuse = [&](Json) { ++calls; return false; };
    const std::function<bool()> cancel;
    Pager pager{limits, "startup_inventory", refuse, cancel};
    require(pager.add({{"token", "first"}}), "initial row admission failed");
    require(!pager.add({{"token", "second"}}), "consumer refusal ignored");
    const auto manifest = pager.finish("test", true);
    require(calls == 1 && manifest["consumer_refused"] == true && manifest["entries_delivered"] == "0" &&
        manifest["pages_produced"] == "1" && manifest["enumeration_complete"] == false, "refused page counted as durable or enumeration continued");
    Json page;
    const std::function<bool(Json)> accept = [&](Json value) { page = std::move(value); return true; };
    Pager oversized{limits, "startup_inventory", accept, cancel};
    oversized.add({{"huge", std::string(8192, 'x')}});
    const auto bounded = oversized.finish("test", true);
    require(page["entries"][0]["entry_kind"] == "row_copy_refusal" && page.dump().size() <= limits.encoded_bytes
        && bounded["copy_refusal_count"] == "1" && bounded["enumeration_complete"] == false, "oversize row silently lost or full coverage inferred");
}
int main(int argc, char** argv) {
    try {
        decoders(); paging();
        Json records = Json::array(), reports = Json::array();
        pipeline::NormalizationContext context{{"agent-1", "1.0-dev"}, {"host-1", "LAB", {"Windows", "26100"}}};
        pipeline::EndpointRecordFactory factory{context, "device-1", std::string(64, 'b'), std::nullopt, 1};
        for (auto source : {state::PersistenceSource::scheduled_tasks, state::PersistenceSource::wmi_subscriptions, state::PersistenceSource::startup}) {
            const std::string category = state::persistence_source_name(source);
            state::PersistenceLimits limits; limits.page_entries = 16; limits.soft_budget_ms = 15000;
            Json ids = Json::array(); std::size_t rows = 0;
            const auto begin = factory.state(category + "_begin", {{"format", "paged_" + category + "_begin_v1"}, {"inventory_complete", false}});
            records.push_back(begin);
            auto manifest = state::collect_persistence_inventory_pages(source, [&](Json page) {
                require(page.dump().size() <= limits.encoded_bytes && page["entries"].size() <= limits.page_entries, "native page exceeds resource limits");
                rows += page["entries"].size(); page["capture_id"] = begin["record_id"];
                auto record = factory.state(category + "_page", std::move(page)); require(record["subject"].is_null(), "native inventory invented actor");
                ids.push_back(record["record_id"]); records.push_back(std::move(record)); return true;
            }, limits);
            require(manifest["inventory_complete"] == false && manifest["entries_delivered"] == std::to_string(rows), "native census claim or accounting mismatch");
            manifest["capture_id"] = begin["record_id"]; manifest["page_record_ids"] = ids; manifest["format"] = "paged_" + category + "_v1";
            records.push_back(factory.state(category, manifest));
            reports.push_back({{"source", category}, {"entries", rows}, {"pages", ids.size()}, {"state", manifest["state"]},
                {"enumeration_complete", manifest["enumeration_complete"]}, {"query_failure_count", manifest["query_failure_count"]}});
        }
        std::size_t refused_pages = 0;
        state::PersistenceLimits refusal_limits; refusal_limits.page_entries = 1;
        const auto refused = state::collect_persistence_inventory_pages(state::PersistenceSource::startup,
            [&](Json) { ++refused_pages; return false; }, refusal_limits);
        require(refused_pages == 1 && refused["consumer_refused"] == true && refused["enumeration_complete"] == false
            && refused["entries_delivered"] == "0", "live native source advanced after refusal");
        const auto cancelled = state::collect_persistence_inventory_pages(state::PersistenceSource::startup, [](Json) { return true; }, {}, [] { return true; });
        require(cancelled["cancelled"] == true && cancelled["enumeration_complete"] == false, "cancelled capture became complete");
        if (argc == 2 && std::string_view{argv[1]} == "--emit-live") std::cout << records.dump() << '\n';
        else std::cout << reports.dump() << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}

#include "persistence_native.hpp"
#include <taskschd.h>
#include <deque>
#include <cmath>

namespace panopticon::officer::state::native_persistence {
namespace {
Json task_row(IRegisteredTask* task, Pager& pager) {
    Json row{{"entry_kind", "registered_task"}, {"state", "degraded"}, {"fields", Json::object()},
        {"source", "TaskScheduler/local/IRegisteredTask"}, {"process_entity_id", nullptr},
        {"consistency", "held COM proxy; properties non_atomic; task/definition/file/execution instances unverified"}};
    const auto retain = [&](const char* key, Json value) { pager.field(value); row["fields"][key] = std::move(value); };
    const auto string_query = [&](const char* key, auto getter) {
        Bstr output; const auto status = (task->*getter)(&output.value);
        auto fact = FAILED(status) ? failure(key, static_cast<std::uint32_t>(status)) : bstr(output.value, pager.limits.field_bytes);
        fact["query_hresult"] = std::to_string(static_cast<std::uint32_t>(status)); retain(key, std::move(fact));
    };
    string_query("name", &IRegisteredTask::get_Name); string_query("path", &IRegisteredTask::get_Path);
    string_query("definition_xml", &IRegisteredTask::get_Xml);
    const auto& xml = row["fields"]["definition_xml"];
    if (xml["state"] == "healthy" && xml["value"].is_string()) row["definition_sections"] = detail::persistence_task_xml(xml["value"].get_ref<const std::string&>());
    VARIANT_BOOL enabled = 0; auto status = task->get_Enabled(&enabled);
    Variant boolean; boolean.value.vt = VT_BOOL; boolean.value.boolVal = enabled;
    retain("enabled", FAILED(status) ? failure("get_Enabled", static_cast<std::uint32_t>(status)) : detail::persistence_variant(&boolean.value, 0));
    TASK_STATE state = TASK_STATE_UNKNOWN; status = task->get_State(&state);
    retain("reported_state", FAILED(status) ? failure("get_State", static_cast<std::uint32_t>(status)) :
        Json{{"state", "healthy"}, {"value", std::to_string(static_cast<int>(state))}, {"interpretation", "raw_TASK_STATE"}});
    const auto date_query = [&](const char* key, auto getter) {
        DATE value = 0; const auto result = (task->*getter)(&value); std::uint64_t bits = 0; std::memcpy(&bits, &value, sizeof(bits));
        retain(key, FAILED(result) ? failure(key, static_cast<std::uint32_t>(result)) :
            Json{{"state", "healthy"}, {"raw_float64_bits", std::to_string(bits)}, {"value", std::isfinite(value) ? Json(value) : Json(nullptr)},
                {"representation", "native_OLE_DATE"}, {"utc_time", nullptr}, {"timezone_and_sentinel_interpretation", "unverified"}});
    };
    date_query("last_run_time", &IRegisteredTask::get_LastRunTime); date_query("next_run_time", &IRegisteredTask::get_NextRunTime);
    LONG last = 0; status = task->get_LastTaskResult(&last);
    retain("last_task_result", FAILED(status) ? failure("get_LastTaskResult", static_cast<std::uint32_t>(status)) :
        Json{{"state", "healthy"}, {"value", std::to_string(static_cast<std::uint32_t>(last))}, {"execution_instance", nullptr}});
    LONG missed = 0; status = task->get_NumberOfMissedRuns(&missed);
    retain("missed_runs", FAILED(status) ? failure("get_NumberOfMissedRuns", static_cast<std::uint32_t>(status)) :
        Json{{"state", "healthy"}, {"value", std::to_string(missed)}});
    Bstr sddl; status = task->GetSecurityDescriptor(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sddl.value);
    retain("owner_group_dacl_sddl", FAILED(status) ? failure("GetSecurityDescriptor/no SACL", static_cast<std::uint32_t>(status)) : bstr(sddl.value, pager.limits.field_bytes));
    return row;
}
}
Json tasks(Pager& pager) {
    constexpr const char* scope = "local caller-visible folders/tasks including TASK_ENUM_HIDDEN; full XML and selected getter/SDDL reports; no task execution/lifetime/effective access; silently inaccessible objects unknown";
    Apartment apartment;
    Com<ITaskService> service; HRESULT status = apartment.result;
    if (SUCCEEDED(status)) status = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&service.value));
    Variant empty;
    if (SUCCEEDED(status)) status = service.value->Connect(empty.value, empty.value, empty.value, empty.value);
    Com<ITaskFolder> root; Bstr root_path(L"\\");
    if (SUCCEEDED(status)) status = service.value->GetFolder(root_path.value, &root.value);
    if (FAILED(status) || !root.value) {
        ++pager.failures; pager.add({{"entry_kind", "source_error"}, {"query", failure("local TaskScheduler connect/root", static_cast<std::uint32_t>(status))}});
        auto result = pager.finish(scope, false); result["state"] = "unavailable"; return result;
    }
    std::deque<Com<ITaskFolder>> folders; folders.push_back(std::move(root));
    bool complete = true; std::size_t discovered = 1;
    while (!folders.empty() && pager.active()) {
        auto folder = std::move(folders.front()); folders.pop_front(); Bstr path;
        status = folder.value->get_Path(&path.value);
        auto folder_name = FAILED(status) ? failure("folder/get_Path", static_cast<std::uint32_t>(status)) : bstr(path.value, pager.limits.field_bytes);
        pager.field(folder_name);
        Json partition{{"folder", folder_name}, {"tasks_enumeration_complete", false}, {"subfolders_enumeration_complete", false}};
        Com<IRegisteredTaskCollection> collection; LONG count = 0;
        status = folder.value->GetTasks(TASK_ENUM_HIDDEN, &collection.value);
        if (SUCCEEDED(status) && collection.value) status = collection.value->get_Count(&count);
        if (FAILED(status) || !collection.value || count < 0) {
            ++pager.failures; complete = false; partition["tasks_error"] = failure("GetTasks(TASK_ENUM_HIDDEN)/Count", static_cast<std::uint32_t>(status));
        } else {
            partition["reported_task_count"] = std::to_string(count);
            LONG read = 0;
            for (LONG index = 1; index <= count && pager.active(); ++index) {
                Json row;
                {
                    Com<IRegisteredTask> task; Variant key; key.value.vt = VT_I4; key.value.lVal = index;
                    status = collection.value->get_Item(key.value, &task.value);
                    if (FAILED(status) || !task.value) { ++pager.failures; complete = false;
                        row = {{"entry_kind", "task_query_error"}, {"query", failure("tasks/get_Item", static_cast<std::uint32_t>(status))}};
                    } else row = task_row(task.value, pager);
                }
                row["folder"] = folder_name; row["collection_index"] = std::to_string(index);
                if (!pager.add(std::move(row))) break;
                ++read;
            }
            partition["tasks_enumeration_complete"] = read == count;
            if (read != count) complete = false;
        }
        Com<ITaskFolderCollection> children; count = 0;
        if (pager.active()) {
            status = folder.value->GetFolders(0, &children.value);
            if (SUCCEEDED(status) && children.value) status = children.value->get_Count(&count);
            if (FAILED(status) || !children.value || count < 0) {
                ++pager.failures; complete = false; partition["subfolders_error"] = failure("GetFolders(0)/Count", static_cast<std::uint32_t>(status));
            } else {
                LONG read = 0;
                for (LONG index = 1; index <= count && pager.active(); ++index) {
                    if (discovered >= 1024) { complete = false; partition["folder_bound_exceeded"] = true; break; }
                    Com<ITaskFolder> child; Variant key; key.value.vt = VT_I4; key.value.lVal = index;
                    status = children.value->get_Item(key.value, &child.value);
                    if (FAILED(status) || !child.value) { ++pager.failures; complete = false; }
                    else { folders.push_back(std::move(child)); ++discovered; }
                    ++read;
                }
                partition["subfolders_enumeration_complete"] = read == count;
                if (read != count) complete = false;
            }
        }
        // Partition details stream as rows, avoiding an unbounded manifest.
        partition["entry_kind"] = "task_folder_scan";
        if (!pager.add(std::move(partition))) break;
    }
    if (!folders.empty()) complete = false;
    pager.partitions.push_back({{"source", "TaskScheduler"}, {"folders_discovered", std::to_string(discovered)},
        {"folder_limit", "1024"}, {"remaining_discovered_folders", std::to_string(folders.size())}});
    return pager.finish(scope, complete);
}
}

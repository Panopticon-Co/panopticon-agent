#include "persistence_native.hpp"
#include <wbemidl.h>

namespace panopticon::officer::state::native_persistence {
namespace {
Json subscription_row(IWbemClassObject* object, Pager& pager) {
    Json row{{"entry_kind", "wmi_permanent_subscription_object"}, {"state", "degraded"}, {"fields", Json::object()},
        {"source", "local WMI caller-visible query"}, {"process_entity_id", nullptr},
        {"consistency", "held WMI object report; object/reference lifetime and creator identity unverified"}};
    Bstr mof; auto status = object->GetObjectText(0, &mof.value);
    row["object_mof"] = FAILED(status) ? failure("IWbemClassObject/GetObjectText", static_cast<std::uint32_t>(status)) : bstr(mof.value, pager.limits.field_bytes);
    pager.field(row["object_mof"]);
    // Closed selected property names; complete bounded MOF retains derived and
    // third-party consumer properties without activating a consumer or reference.
    constexpr const wchar_t* names[]{L"__CLASS", L"__PATH", L"__RELPATH", L"Name", L"CreatorSID", L"Query", L"QueryLanguage",
        L"EventNamespace", L"Filter", L"Consumer", L"ScriptText", L"ScriptingEngine", L"CommandLineTemplate", L"ExecutablePath",
        L"WorkingDirectory", L"RunInteractively", L"MachineName", L"MaintainSecurityContext", L"DeliverSynchronously"};
    std::size_t copied = 0;
    for (const auto* name : names) {
        Variant value; CIMTYPE type = 0;
        status = object->Get(name, 0, &value.value, &type, nullptr);
        Json fact;
        if (status == WBEM_E_NOT_FOUND) fact = {{"state", "healthy"}, {"present", false}, {"value", nullptr}};
        else if (FAILED(status)) fact = failure("IWbemClassObject/Get", static_cast<std::uint32_t>(status));
        else {
            const auto remaining = copied >= pager.limits.field_bytes ? 0 : pager.limits.field_bytes - copied;
            fact = detail::persistence_variant(&value.value, remaining);
            fact["present"] = true; fact["reported_cim_type"] = std::to_string(type);
            if (value.value.vt == VT_BSTR && value.value.bstrVal && !fact.value("bound_exceeded", false)) copied += SysStringByteLen(value.value.bstrVal);
        }
        fact["query_hresult"] = std::to_string(static_cast<std::uint32_t>(status));
        if (std::wstring_view{name} == L"CreatorSID") fact["scope"] = "reported security bytes; not an authenticated actor or process";
        pager.field(fact); row["fields"][text(name, std::wcslen(name)).get<std::string>()] = std::move(fact);
    }
    row["references_resolved"] = false;
    return row;
}
}
Json wmi(Pager& pager) {
    constexpr const char* scope = "local root\\subscription and root\\cimv2 __EventFilter/__EventConsumer subclasses/__FilterToConsumerBinding; bounded MOF and selected typed reports; other namespaces/unloaded providers unobserved; no execution/reference dereference";
    Apartment apartment; Com<IWbemLocator> locator; auto status = apartment.result;
    if (SUCCEEDED(status)) status = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator.value));
    if (FAILED(status) || !locator.value) {
        ++pager.failures; pager.add({{"entry_kind", "source_error"}, {"query", failure("WMI apartment/locator", static_cast<std::uint32_t>(status))}});
        auto result = pager.finish(scope, false); result["state"] = "unavailable"; return result;
    }
    bool complete = true; std::size_t completed_queries = 0;
    for (const auto* ns : {L"ROOT\\subscription", L"ROOT\\cimv2"}) {
        if (!pager.active()) { complete = false; break; }
        Com<IWbemServices> services; Bstr namespace_name(ns);
        status = locator.value->ConnectServer(namespace_name.value, nullptr, nullptr, nullptr, WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &services.value);
        if (SUCCEEDED(status) && services.value) status = CoSetProxyBlanket(services.value, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        if (FAILED(status) || !services.value) {
            ++pager.failures; complete = false;
            Json partition{{"namespace", text(ns, std::wcslen(ns))}, {"enumeration_complete", false},
                {"query", failure("WMI local ConnectServer/proxy", static_cast<std::uint32_t>(status))}};
            pager.partitions.push_back(partition); partition["entry_kind"] = "wmi_namespace_error"; pager.add(std::move(partition)); continue;
        }
        for (const auto* class_name : {L"__EventFilter", L"__EventConsumer", L"__FilterToConsumerBinding"}) {
            if (!pager.active()) { complete = false; break; }
            Json partition{{"namespace", text(ns, std::wcslen(ns))}, {"class", text(class_name, std::wcslen(class_name))},
                {"enumeration_complete", false}, {"returned_objects", "0"}, {"timeout_polls", "0"}};
            std::wstring statement = L"SELECT * FROM "; statement += class_name;
            Bstr language(L"WQL"), query(statement.c_str()); Com<IEnumWbemClassObject> enumeration;
            status = services.value->ExecQuery(language.value, query.value, WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY, nullptr, &enumeration.value);
            if (SUCCEEDED(status) && enumeration.value) status = CoSetProxyBlanket(enumeration.value, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
            std::size_t count = 0, timeouts = 0;
            if (FAILED(status) || !enumeration.value) {
                ++pager.failures; complete = false;
                partition["query"] = failure("WMI ExecQuery/enumerator proxy", static_cast<std::uint32_t>(status));
            } else while (pager.active()) {
                ULONG returned = 0; Json row;
                {
                    Com<IWbemClassObject> object;
                    status = enumeration.value->Next(1000, 1, &object.value, &returned);
                    if (FAILED(status) || returned > 1 || (returned && !object.value)) {
                        ++pager.failures; partition["query"] = failure("WMI Next(1000,1)/output", static_cast<std::uint32_t>(status)); break;
                    }
                    if (returned) row = subscription_row(object.value, pager);
                }
                // WBEM_S_FALSE can include a final object. Retain it before EOF.
                if (returned) {
                    row["namespace"] = partition["namespace"]; row["query_class"] = partition["class"];
                    if (!pager.add(std::move(row))) break;
                    ++count;
                }
                if (status == WBEM_S_FALSE) { partition["enumeration_complete"] = true; ++completed_queries; break; }
                if (status == WBEM_S_TIMEDOUT) { ++timeouts; continue; }
                if (status != WBEM_S_NO_ERROR || !returned) {
                    ++pager.failures; partition["query"] = failure("WMI Next/no_progress_or_unknown_status", static_cast<std::uint32_t>(status)); break;
                }
            }
            partition["returned_objects"] = std::to_string(count); partition["timeout_polls"] = std::to_string(timeouts);
            if (!partition["enumeration_complete"].get<bool>()) complete = false;
            pager.partitions.push_back(partition); partition["entry_kind"] = "wmi_class_scan";
            if (!pager.add(std::move(partition))) break;
        }
    }
    auto result = pager.finish(scope, complete);
    result["completed_query_count"] = std::to_string(completed_queries);
    if (!completed_queries && pager.failures) result["state"] = "unavailable";
    return result;
}
}

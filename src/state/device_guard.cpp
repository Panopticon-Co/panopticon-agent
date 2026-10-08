#include "panopticon/officer/state/device_guard.hpp"
#include "panopticon/officer/state/defender_status.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <string>
namespace panopticon::officer::state {
namespace {
using Json=nlohmann::json;
template<class T> struct Com { T* value=nullptr; ~Com(){if(value)value->Release();} };
struct Text { BSTR value; explicit Text(const wchar_t* s):value(SysAllocString(s)){} ~Text(){SysFreeString(value);} };
struct Variant { VARIANT value; Variant(){VariantInit(&value);} ~Variant(){VariantClear(&value);} };
struct Property {const wchar_t* name; const char* key; CIMTYPE type;};
constexpr Property properties[]{
    {L"__RELPATH","__RELPATH",CIM_STRING},{L"InstanceIdentifier","InstanceIdentifier",CIM_STRING},{L"Version","Version",CIM_STRING},
    {L"VirtualizationBasedSecurityStatus","VirtualizationBasedSecurityStatus",CIM_UINT32},
    {L"CodeIntegrityPolicyEnforcementStatus","CodeIntegrityPolicyEnforcementStatus",CIM_UINT32},
    {L"UsermodeCodeIntegrityPolicyEnforcementStatus","UsermodeCodeIntegrityPolicyEnforcementStatus",CIM_UINT32},
    {L"AvailableSecurityProperties","AvailableSecurityProperties",CIM_UINT32|CIM_FLAG_ARRAY},
    {L"RequiredSecurityProperties","RequiredSecurityProperties",CIM_UINT32|CIM_FLAG_ARRAY},
    {L"SecurityServicesConfigured","SecurityServicesConfigured",CIM_UINT32|CIM_FLAG_ARRAY},
    {L"SecurityServicesRunning","SecurityServicesRunning",CIM_UINT32|CIM_FLAG_ARRAY}};
}
Json detail::decode_device_guard_property(std::uint32_t status,const void* borrowed,std::uint32_t expected,std::uint32_t reported,std::size_t& copied) {
    Json result{{"state","unavailable"},{"error_domain","HRESULT"},{"hresult_code",std::to_string(status)},
        {"value",nullptr},{"protection_verified",false},{"policy_authority_verified",false}};
    if(static_cast<HRESULT>(status)!=S_OK){result["reason"]=static_cast<HRESULT>(status)<0?"property_query_failed":"informational_query_result_uninterpreted";return result;}
    if(expected!=(CIM_UINT32|CIM_FLAG_ARRAY)){result.update(decode_defender_property(borrowed,expected,reported,copied));return result;}
    result["state"]="degraded";result["expected_cim_type"]=std::to_string(expected);result["reported_cim_type"]=std::to_string(reported);
    if(!borrowed){result["validation_error"]="missing_variant";return result;}
    const auto& value=*static_cast<const VARIANT*>(borrowed);result["variant_type"]=std::to_string(value.vt);
    if(reported!=expected){result["validation_error"]="cim_type_mismatch";return result;}
    if(value.vt!=(VT_ARRAY|VT_I4)&&value.vt!=(VT_ARRAY|VT_UI4)){result["validation_error"]="array_variant_uninterpreted";return result;}
    if(!value.parray){result["validation_error"]="null_safearray";return result;}
    const auto dimensions=SafeArrayGetDim(value.parray);result["dimensions"]=dimensions;
    if(dimensions!=1){result["validation_error"]="array_dimension_bound";return result;}
    VARTYPE elementType=VT_EMPTY;auto hr=SafeArrayGetVartype(value.parray,&elementType);
    result["element_type_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));result["element_type"]=std::to_string(elementType);
    if(hr!=S_OK||elementType!=(value.vt&VT_TYPEMASK)||SafeArrayGetElemsize(value.parray)!=sizeof(ULONG)){result["validation_error"]="array_element_type_mismatch";return result;}
    LONG lower=0,upper=-1;hr=SafeArrayGetLBound(value.parray,1,&lower);
    if(hr==S_OK)hr=SafeArrayGetUBound(value.parray,1,&upper);
    result["bounds_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));
    if(hr!=S_OK){result["validation_error"]="array_bounds_failed";return result;}
    result["lower_bound"]=std::to_string(lower);result["upper_bound"]=std::to_string(upper);
    const auto count=static_cast<std::int64_t>(upper)-static_cast<std::int64_t>(lower)+1;
    if(count<0||count>64||copied>32768||static_cast<std::uint64_t>(count)*sizeof(ULONG)>32768-copied){result["validation_error"]="array_copy_bound";return result;}
    auto values=Json::array(); auto carriers=Json::array();
    for(std::int64_t offset=0;offset<count;++offset){LONG index=static_cast<LONG>(static_cast<std::int64_t>(lower)+offset);ULONG item=0;
        hr=SafeArrayGetElement(value.parray,&index,&item);
        if(hr!=S_OK){result["element_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));result["validation_error"]="array_element_query_failed";return result;}
        copied+=sizeof(item);values.push_back(std::to_string(item));
        carriers.push_back(elementType==VT_I4?std::to_string(static_cast<LONG>(item)):std::to_string(item));
    }
    result["state"]="healthy";result["value"]=std::move(values);result["raw_element_carriers"]=std::move(carriers);
    result["enum_values_interpreted"]=false;return result;
}
Json collect_device_guard_state(){
    const auto begun=GetTickCount64();
    Json result{{"format","device_guard_state_v1"},{"state","unavailable"},{"namespace","Root\\Microsoft\\Windows\\DeviceGuard"},
        {"query","SELECT * FROM Win32_DeviceGuard"},{"entries",Json::array()},{"inventory_complete",false},{"protection_verified",false},
        {"policy_authority_verified",false},{"enumeration_completed",false},{"consistency","non_atomic"},{"row_limit","8"},
        {"array_element_limit","64"},{"row_copy_byte_limit","32768"},{"encoded_entries_byte_limit","655360"},
        {"native_allocation_bounded",false},{"collection_deadline_enforced",false},{"connect_max_wait_ms","120000"},
        {"collection_started_uptime_ms",std::to_string(begun)},
        {"scope","selected caller-visible local Win32_DeviceGuard provider reports; no attestation, effective policy authority, hypervisor identity or complete virtualization inventory"}};
    const auto finish=[&](){result["collection_completed_uptime_ms"]=std::to_string(GetTickCount64());return result;};
    const auto step=[&](const char* name,HRESULT hr){result["native_steps"].push_back({{"source",name},{"error_domain","HRESULT"},{"hresult_code",std::to_string(static_cast<std::uint32_t>(hr))}});return SUCCEEDED(hr);};
    const auto init=CoInitializeEx(nullptr,COINIT_MULTITHREADED);if(!step("CoInitializeEx",init))return finish();
    struct Apartment{~Apartment(){CoUninitialize();}} apartment;
    Com<IWbemLocator> locator;if(!step("CoCreateInstance/WbemLocator",CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,reinterpret_cast<void**>(&locator.value)))||!locator.value)return finish();
    Text space{L"\\\\.\\root\\Microsoft\\Windows\\DeviceGuard"},language{L"WQL"},query{L"SELECT * FROM Win32_DeviceGuard"};
    if(!space.value||!language.value||!query.value){result["validation_error"]="bstr_allocation_failed";return finish();}
    Com<IWbemServices> services;if(!step("IWbemLocator::ConnectServer",locator.value->ConnectServer(space.value,nullptr,nullptr,nullptr,WBEM_FLAG_CONNECT_USE_MAX_WAIT,nullptr,nullptr,&services.value))||!services.value)return finish();
    const auto blanket=[&](IUnknown* proxy){return step("CoSetProxyBlanket",CoSetProxyBlanket(proxy,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE));};
    if(!blanket(services.value))return finish();
    Com<IEnumWbemClassObject> rows;if(!step("IWbemServices::ExecQuery",services.value->ExecQuery(language.value,query.value,WBEM_FLAG_RETURN_IMMEDIATELY|WBEM_FLAG_FORWARD_ONLY,nullptr,&rows.value))||!rows.value||!blanket(rows.value))return finish();
    std::size_t encoded=2;unsigned failures=0,unknown=0;
    for(unsigned index=0;index<=8;++index){Com<IWbemClassObject> object;ULONG fetched=0;const auto hr=rows.value->Next(1000,1,&object.value,&fetched);step("IEnumWbemClassObject::Next",hr);
        if(hr==WBEM_S_FALSE&&fetched==0&&!object.value){result["enumeration_completed"]=true;result["state"]="degraded";break;}
        if(FAILED(hr)||((hr!=S_OK&&hr!=WBEM_S_FALSE)||fetched!=1||!object.value)){result["enumeration_incomplete"]=true;break;}
        if(index==8){result["row_bound_exceeded"]=true;break;}
        Json row{{"enumeration_index",std::to_string(index)},{"fields",Json::object()},{"device_reference",nullptr}};std::size_t copied=0;
        for(const auto& property:properties){Variant value;CIMTYPE type=0;const auto started=GetTickCount64();const auto queried=object.value->Get(property.name,0,&value.value,&type,nullptr);
            auto field=detail::decode_device_guard_property(static_cast<std::uint32_t>(queried),&value.value,property.type,type,copied);
            field["source"]="IWbemClassObject::Get/Win32_DeviceGuard";field["query_started_uptime_ms"]=std::to_string(started);field["query_completed_uptime_ms"]=std::to_string(GetTickCount64());
            if(FAILED(queried))++failures;if(field["state"]!="healthy")++unknown;
            const auto cleared=VariantClear(&value.value);field["variant_clear_hresult_code"]=std::to_string(static_cast<std::uint32_t>(cleared));if(FAILED(cleared))field["state"]="degraded";
            row["fields"][property.key]=std::move(field);
        }
        const auto bytes=row.dump().size();if(bytes+1>655360-encoded){result["encoded_bound_exceeded"]=true;break;}encoded+=bytes+1;
        result["entries"].push_back(std::move(row));result["state"]="degraded";
        if(hr==WBEM_S_FALSE){result["enumeration_completed"]=true;break;}
    }
    result["failed_getters"]=std::to_string(failures);result["uninterpreted_getters"]=std::to_string(unknown);
    result["collection_completed_uptime_ms"]=std::to_string(GetTickCount64());return finish();
}
}

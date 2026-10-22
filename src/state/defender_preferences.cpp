#include "panopticon/officer/state/defender_preferences.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <algorithm>
#include <array>
#include <bit>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <string>
#include <utility>

namespace panopticon::officer::state {
namespace {
using Json=nlohmann::json;
template<class T> struct Com { T* p=nullptr; ~Com(){if(p)p->Release();} Com()=default; Com(const Com&)=delete; };
struct Bstr { BSTR p=nullptr; explicit Bstr(const wchar_t* s):p(SysAllocString(s)){} ~Bstr(){SysFreeString(p);} };
struct Variant { VARIANT v; Variant(){VariantInit(&v);} ~Variant(){VariantClear(&v);} };
struct Apartment { HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED); ~Apartment(){if(SUCCEEDED(hr))CoUninitialize();} };
struct Prop { const wchar_t* w; const char* key; };
// Explicit allowlist. Values are provider reports, not configuration inputs.
constexpr Prop props[]={
 {L"AttackSurfaceReductionRules_Ids","AttackSurfaceReductionRules_Ids"},{L"AttackSurfaceReductionRules_Actions","AttackSurfaceReductionRules_Actions"},
 {L"EnableControlledFolderAccess","EnableControlledFolderAccess"},{L"ControlledFolderAccessProtectedFolders","ControlledFolderAccessProtectedFolders"},{L"ControlledFolderAccessAllowedApplications","ControlledFolderAccessAllowedApplications"},
 {L"ExclusionPath","ExclusionPath"},{L"ExclusionExtension","ExclusionExtension"},{L"ExclusionProcess","ExclusionProcess"},
 {L"DisableRealtimeMonitoring","DisableRealtimeMonitoring"},{L"DisableBehaviorMonitoring","DisableBehaviorMonitoring"},{L"DisableIOAVProtection","DisableIOAVProtection"},{L"DisableScriptScanning","DisableScriptScanning"},
 {L"EnableNetworkProtection","EnableNetworkProtection"},{L"PUAProtection","PUAProtection"},{L"MAPSReporting","MAPSReporting"},{L"SubmitSamplesConsent","SubmitSamplesConsent"},
 {L"CloudBlockLevel","CloudBlockLevel"},{L"CloudExtendedTimeout","CloudExtendedTimeout"},{L"DisableBlockAtFirstSeen","DisableBlockAtFirstSeen"},
 {L"DisableArchiveScanning","DisableArchiveScanning"},{L"DisableRemovableDriveScanning","DisableRemovableDriveScanning"},{L"DisableEmailScanning","DisableEmailScanning"},{L"DisableScanningNetworkFiles","DisableScanningNetworkFiles"},
 {L"DisableCatchupQuickScan","DisableCatchupQuickScan"},{L"DisableCatchupFullScan","DisableCatchupFullScan"},{L"RealTimeScanDirection","RealTimeScanDirection"},
 {L"CheckForSignaturesBeforeRunningScan","CheckForSignaturesBeforeRunningScan"},{L"SignatureUpdateInterval","SignatureUpdateInterval"},{L"ScanScheduleDay","ScanScheduleDay"},{L"ScanScheduleTime","ScanScheduleTime"}
};
std::string utf8(BSTR s, UINT units, std::size_t max, bool& ok) {
 ok=false; if(!s || SysStringByteLen(s)>max || units>static_cast<UINT>(INT_MAX)) return {};
 if(!units){ok=true;return {};}
 int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,static_cast<int>(units),nullptr,0,nullptr,nullptr); if(n<=0)return {};
 std::string out(static_cast<std::size_t>(n),'\0'); if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s,static_cast<int>(units),out.data(),n,nullptr,nullptr)!=n)return {};
 ok=true; return out;
}
Json query_error(const char* source,HRESULT hr,const char* avail="query_failed") { return {{"state","unavailable"},{"source",source},{"error_domain","HRESULT"},{"hresult_code",std::to_string(static_cast<std::uint32_t>(hr))},{"property_availability",avail},{"value",nullptr}}; }
std::string byte_hex(const void* data,std::size_t bytes) {
 constexpr char digits[]="0123456789abcdef";const auto* p=static_cast<const unsigned char*>(data);std::string s;s.reserve(bytes*2);
 for(std::size_t i=0;i<bytes;++i){s+=digits[p[i]>>4];s+=digits[p[i]&15];}return s;
}
std::string bit_hex(std::uint64_t bits,std::size_t bytes) {
 std::array<unsigned char,8> raw{};for(std::size_t i=0;i<bytes;++i)raw[i]=static_cast<unsigned char>((bits>>(i*8))&0xff);return byte_hex(raw.data(),bytes);
}
Json bstr_raw(BSTR value,std::size_t limit,const char* reason) {
 const auto bytes=value?static_cast<std::size_t>(SysStringByteLen(value)):0;
 Json out{{"state","degraded"},{"value",nullptr},{"reported_bytes",std::to_string(bytes)},{"reported_utf16_units",std::to_string(value?SysStringLen(value):0)},{"validation_error",reason}};
 if(value&&bytes<=limit)out["raw_text"]={{"encoding","utf16le_hex"},{"bytes",byte_hex(value,bytes)}};
 else if(value)out["copy_bound_exceeded"]=true;
 return out;
}
}

Json detail::decode_defender_preference_variant(const void* borrowed,std::size_t limit) {
 Json r{{"state","degraded"},{"value",nullptr},{"variant_type",nullptr},{"raw_scalar",nullptr},{"protection_verified",false}};
 if(!borrowed){r["validation_error"]="missing_variant";return r;}
 const auto& v=*static_cast<const VARIANT*>(borrowed); r["variant_type"]=std::to_string(v.vt);
 if((v.vt&(VT_BYREF|VT_VECTOR))!=0){r["validation_error"]="byref_or_vector_variant_not_dereferenced";return r;}
 switch(v.vt){
 case VT_EMPTY:r["state"]="healthy";r["value"]={{"kind","empty"}};return r;
 case VT_NULL:r["state"]="healthy";r["value"]=nullptr;return r;
 case VT_BOOL:r["raw_scalar"]=std::to_string(v.boolVal);if(v.boolVal==VARIANT_TRUE||v.boolVal==VARIANT_FALSE){r["value"]=(v.boolVal==VARIANT_TRUE);r["state"]="healthy";}else r["validation_error"]="invalid_variant_bool";return r;
 case VT_I1:r["raw_scalar"]=std::to_string(v.cVal);r["value"]=std::to_string(v.cVal);r["state"]="healthy";return r;
 case VT_UI1:r["raw_scalar"]=std::to_string(v.bVal);r["value"]=std::to_string(v.bVal);r["state"]="healthy";return r;
 case VT_I2:r["raw_scalar"]=std::to_string(v.iVal);r["value"]=std::to_string(v.iVal);r["state"]="healthy";return r;
 case VT_UI2:r["raw_scalar"]=std::to_string(v.uiVal);r["value"]=std::to_string(v.uiVal);r["state"]="healthy";return r;
 case VT_I4:r["raw_scalar"]=std::to_string(v.lVal);r["value"]=std::to_string(v.lVal);r["state"]="healthy";return r;
 case VT_UI4:r["raw_scalar"]=std::to_string(v.ulVal);r["value"]=std::to_string(v.ulVal);r["state"]="healthy";return r;
 case VT_I8:r["raw_scalar"]=std::to_string(v.llVal);r["value"]=std::to_string(v.llVal);r["state"]="healthy";return r;
 case VT_UI8:r["raw_scalar"]=std::to_string(v.ullVal);r["value"]=std::to_string(v.ullVal);r["state"]="healthy";return r;
 case VT_R4:{std::uint32_t bits=0;std::memcpy(&bits,&v.fltVal,sizeof(bits));r["raw_bits_hex"]=bit_hex(bits,sizeof(bits));r["raw_bits_encoding"]="native_little_endian";r["validation_error"]="floating_value_not_interpreted";return r;}
 case VT_R8:case VT_DATE:{std::uint64_t bits=0;std::memcpy(&bits,&v.dblVal,sizeof(bits));r["raw_bits_hex"]=bit_hex(bits,sizeof(bits));r["raw_bits_encoding"]="native_little_endian";r["validation_error"]=v.vt==VT_DATE?"date_value_not_interpreted":"floating_value_not_interpreted";return r;}
 case VT_BSTR:{
   if(!v.bstrVal){r["validation_error"]="null_bstr";return r;} UINT bytes=SysStringByteLen(v.bstrVal), units=SysStringLen(v.bstrVal);r["reported_bytes"]=bytes;r["reported_utf16_units"]=units;
   if(bytes>limit){r["validation_error"]="bstr_copy_bound_exceeded";return r;}
   if(bytes%sizeof(wchar_t)){r["raw_text"]={{"encoding","utf16le_hex"},{"bytes",byte_hex(v.bstrVal,bytes)}};r["validation_error"]="odd_bstr_byte_length";return r;}
   bool ok=false;auto s=utf8(v.bstrVal,units,limit,ok);if(!ok){r["raw_text"]={{"encoding","utf16le_hex"},{"bytes",byte_hex(v.bstrVal,bytes)}};r["validation_error"]="utf8_conversion_failed";return r;}r["value"]=std::move(s);r["state"]="healthy";return r; }
 default: break;
 }
 if((v.vt&VT_ARRAY)==0 || v.vt!=(VT_ARRAY|(v.vt&VT_TYPEMASK))){r["validation_error"]="unsupported_variant_flags";return r;}
 if(!v.parray){r["validation_error"]="null_safearray";return r;}
 const auto dims=SafeArrayGetDim(v.parray);r["array_dimensions"]=dims;if(dims!=1){r["validation_error"]="array_dimension_uninterpreted";return r;}
 VARTYPE et=VT_EMPTY;HRESULT hr=SafeArrayGetVartype(v.parray,&et);if(FAILED(hr)){r["array_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));r["validation_error"]="array_type_query_failed";return r;}
 LONG lo=0,hi=-1;hr=SafeArrayGetLBound(v.parray,1,&lo);if(SUCCEEDED(hr))hr=SafeArrayGetUBound(v.parray,1,&hi);
 if(FAILED(hr)){r["array_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));r["validation_error"]="array_bounds_failed";return r;}
 const auto count=static_cast<std::int64_t>(hi)-lo+1;r["element_type"]=std::to_string(et);r["lower_bound"]=lo;r["upper_bound"]=hi;r["reported_element_count"]=std::to_string(count);
 if(count<0||static_cast<std::uint64_t>(count)>512){r["validation_error"]="array_element_bound";return r;}
 Json values=Json::array();std::size_t copied=0;bool supported=true;
 for(std::int64_t off=0;off<count;++off){LONG ix=static_cast<LONG>(static_cast<std::int64_t>(lo)+off);
   if(et==VT_BSTR&&(v.vt==(VT_ARRAY|VT_BSTR))){BSTR item=nullptr;hr=SafeArrayGetElement(v.parray,&ix,&item);if(FAILED(hr)){if(item)SysFreeString(item);r["array_element_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));supported=false;break;}const auto len=item?static_cast<std::size_t>(SysStringByteLen(item)):0;if(!item){values.push_back(nullptr);}else if(len>limit-copied){values.push_back({{"encoding","unavailable"},{"reported_bytes",std::to_string(len)},{"reason","array_string_copy_bound_exceeded"}});r["validation_error"]="array_string_copy_bound_exceeded";supported=false;SysFreeString(item);break;}else if(len%sizeof(wchar_t)){values.push_back({{"encoding","utf16le_hex"},{"bytes",byte_hex(item,len)}});r["validation_error"]="array_element_odd_bstr_byte_length";copied+=len;SysFreeString(item);supported=false;break;}else{bool ok=false;auto text=utf8(item,SysStringLen(item),limit-copied,ok);if(!ok){values.push_back({{"encoding","utf16le_hex"},{"bytes",byte_hex(item,len)}});r["validation_error"]="array_element_utf8_conversion_failed";copied+=len;SysFreeString(item);supported=false;break;}copied+=len;values.push_back(std::move(text));}if(item)SysFreeString(item);}
   else if(et==VT_I4&&(v.vt==(VT_ARRAY|VT_I4))){LONG item=0;hr=SafeArrayGetElement(v.parray,&ix,&item);if(FAILED(hr)){r["array_element_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));supported=false;break;}copied+=sizeof(item);values.push_back(std::to_string(item));}
   else if(et==VT_UI4&&(v.vt==(VT_ARRAY|VT_UI4))){ULONG item=0;hr=SafeArrayGetElement(v.parray,&ix,&item);if(FAILED(hr)){r["array_element_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));supported=false;break;}copied+=sizeof(item);values.push_back(std::to_string(item));}
   else if(et==VT_UI1&&(v.vt==(VT_ARRAY|VT_UI1))){BYTE item=0;hr=SafeArrayGetElement(v.parray,&ix,&item);if(FAILED(hr)){r["array_element_hresult"]=std::to_string(static_cast<std::uint32_t>(hr));supported=false;break;}copied+=sizeof(item);values.push_back(std::to_string(item));}
   else {supported=false;r["validation_error"]="array_element_type_uninterpreted";break;}
   if(copied>limit){supported=false;r["validation_error"]="array_copy_bound";break;}
 }
 r["array_copy_bytes"]=std::to_string(copied);r["array_semantics_interpreted"]=false;
 if(supported){r["value"]=std::move(values);r["state"]="healthy";}else if(!r.contains("validation_error"))r["validation_error"]="array_element_read_failed";
 return r;
}

Json collect_defender_preferences_pages(const std::function<bool(Json)>& consumer,DefenderPreferencesLimits limits,const std::function<bool()>& cancelled){
 if(!consumer||!limits.page_entries||limits.page_entries>4096||limits.encoded_bytes<4096||limits.encoded_bytes>512*1024||!limits.total_entries||limits.total_entries>65536||!limits.pages||limits.pages>1024||!limits.field_bytes||limits.field_bytes>128*1024||!limits.soft_budget_ms||limits.soft_budget_ms>300000)throw std::invalid_argument("invalid Defender preferences limits");
 const auto started=GetTickCount64();std::size_t pages=0,delivered=0,failures=0,copyRefusals=0;bool complete=false,bounded=false,refused=false,cancelledFlag=false,timed=false;
 Json partitions=Json::array();
 const auto manifest=[&](){return Json{{"format","defender_preferences_inventory_v1"},{"collector_version","1.0"},{"state",delivered?"degraded":"unavailable"},{"source","MSFT_MpPreference"},{"namespace","Root\\Microsoft\\Windows\\Defender"},{"inventory_complete",false},{"enumeration_complete",complete&&!bounded&&!refused&&!cancelledFlag&&!timed},{"query_failure_count",std::to_string(failures)},{"copy_refusal_count",std::to_string(copyRefusals)},{"pages_produced",std::to_string(pages)},{"entries_delivered",std::to_string(delivered)},{"partitions",std::move(partitions)},{"bound_exceeded",bounded||copyRefusals!=0},{"consumer_refused",refused},{"cancelled",cancelledFlag},{"soft_budget_exceeded",timed},{"soft_budget_ms",std::to_string(limits.soft_budget_ms)},{"collection_started_uptime_ms",std::to_string(started)},{"collection_completed_uptime_ms",std::to_string(GetTickCount64())},{"consistency","non_atomic; preferences reported by local WMI provider"},{"limits",{{"page_entries",limits.page_entries},{"page_encoded_bytes",limits.encoded_bytes},{"total_entries",limits.total_entries},{"pages",limits.pages},{"field_bytes",limits.field_bytes}}},{"resource_scope","application copies/pages are bounded; native COM/WMI allocations and calls have no hard time or memory bound"},{"protection_verified",false},{"policy_authority_verified",false},{"scope","selected caller-visible Defender preferences only; no effective enforcement, tamper-protection attestation, policy authority or configuration changes"}};};
 const auto active=[&](){if(cancelled&&cancelled()){cancelledFlag=true;return false;}if(GetTickCount64()-started>limits.soft_budget_ms){timed=true;return false;}return true;};
 if(!active())return manifest();
 Apartment apartment;if(FAILED(apartment.hr)) {++failures;partitions.push_back(query_error("CoInitializeEx",apartment.hr));return manifest();}
 Com<IWbemLocator> locator;HRESULT hr=CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,reinterpret_cast<void**>(&locator.p));
 if(FAILED(hr)||!locator.p){++failures;partitions.push_back(query_error("CoCreateInstance/WbemLocator",hr));return manifest();}
 std::wstring queryText=L"SELECT ";for(std::size_t i=0;i<std::size(props);++i){if(i)queryText+=L", ";queryText+=props[i].w;}queryText+=L" FROM MSFT_MpPreference";
 Bstr ns(L"\\\\.\\root\\Microsoft\\Windows\\Defender"),lang(L"WQL"),q(queryText.c_str());if(!ns.p||!lang.p||!q.p){++failures;partitions.push_back(query_error("SysAllocString",E_OUTOFMEMORY));return manifest();}
 Com<IWbemServices> svc;hr=locator.p->ConnectServer(ns.p,nullptr,nullptr,nullptr,WBEM_FLAG_CONNECT_USE_MAX_WAIT,nullptr,nullptr,&svc.p);if(FAILED(hr)||!svc.p){++failures;partitions.push_back(query_error("IWbemLocator::ConnectServer",hr));return manifest();}
 auto blanket=[](IUnknown* p){return CoSetProxyBlanket(p,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_PKT_PRIVACY,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);};
 hr=blanket(svc.p);if(FAILED(hr)){++failures;partitions.push_back(query_error("CoSetProxyBlanket/IWbemServices",hr));return manifest();}
 Com<IEnumWbemClassObject> en;hr=svc.p->ExecQuery(lang.p,q.p,WBEM_FLAG_RETURN_IMMEDIATELY|WBEM_FLAG_FORWARD_ONLY,nullptr,&en.p);if(FAILED(hr)||!en.p){++failures;partitions.push_back(query_error("IWbemServices::ExecQuery",hr));return manifest();}
 hr=blanket(en.p);if(FAILED(hr)){++failures;partitions.push_back(query_error("CoSetProxyBlanket/IEnumWbemClassObject",hr));return manifest();}
 Json rows=Json::array();std::size_t encoded=2;std::size_t index=0;
 for(;index<limits.total_entries;){if(!active())break;Com<IWbemClassObject> obj;ULONG fetched=0;const auto next=en.p->Next(1000,1,&obj.p,&fetched);
   if(next==WBEM_S_TIMEDOUT&&fetched==0&&!obj.p){timed=true;break;}
   if(next==WBEM_S_FALSE&&fetched==0&&!obj.p){complete=true;break;}
   const bool timedWithObject=next==WBEM_S_TIMEDOUT&&fetched==1&&obj.p;
   if(FAILED(next)||((next!=S_OK&&next!=WBEM_S_FALSE&&!timedWithObject)||fetched!=1||!obj.p)){++failures;partitions.push_back(query_error("IEnumWbemClassObject::Next",next,"enumeration_incomplete"));break;}
   Json row{{"enumeration_index",std::to_string(index)},{"source","IWbemClassObject::Get/MSFT_MpPreference"},{"fields",Json::object()},{"state","degraded"},{"protection_verified",false},{"configured_or_reported_preference_is_not_enforcement",true},{"next_hresult_code",std::to_string(static_cast<std::uint32_t>(next))},{"source_status",timedWithObject?"object_delivered_with_enumeration_timeout":"object_delivered"}};
   std::size_t rowCopied=0;
   for(const auto& p:props){if(!active())break;Variant v;CIMTYPE type=0;const auto get=obj.p->Get(p.w,0,&v.v,&type,nullptr);Json field;
     if(FAILED(get)){++failures;field=query_error("IWbemClassObject::Get",get,get==WBEM_E_NOT_FOUND?"not_exposed_by_object":"query_refused");}
     else {const auto allowance=rowCopied<limits.field_bytes?limits.field_bytes-rowCopied:0;field=detail::decode_defender_preference_variant(&v.v,allowance);field["source"]="IWbemClassObject::Get/MSFT_MpPreference";field["hresult_code"]=std::to_string(static_cast<std::uint32_t>(get));field["reported_cim_type"]=std::to_string(type);field["property_availability"]="reported";if(get!=S_OK&&field["state"]=="healthy")field["state"]="degraded";if(field["state"]!="healthy")++copyRefusals;
       if(field.contains("reported_bytes")){try{if(field["reported_bytes"].is_number())rowCopied+=field["reported_bytes"].get<std::size_t>();else if(field["reported_bytes"].is_string())rowCopied+=static_cast<std::size_t>(std::stoull(field["reported_bytes"].get<std::string>()));}catch(...) {rowCopied=limits.field_bytes;}}
       if(field.contains("array_copy_bytes")){try{rowCopied+=static_cast<std::size_t>(std::stoull(field["array_copy_bytes"].get<std::string>()));}catch(...) {rowCopied=limits.field_bytes;}}
       if(rowCopied>limits.field_bytes)rowCopied=limits.field_bytes;
     }
     const HRESULT clr=VariantClear(&v.v);field["variant_clear_hresult_code"]=std::to_string(static_cast<std::uint32_t>(clr));if(FAILED(clr))field["state"]="degraded";row["fields"][p.key]=std::move(field);
   }
   if(cancelledFlag||timed){row["property_capture_state"]="partial";row["source_status"]=cancelledFlag?"object_partial_cancelled":"object_partial_soft_timeout";}
   const auto originalBytes=row.dump().size();if(originalBytes+1024>limits.encoded_bytes){bounded=true;++copyRefusals;row={{"enumeration_index",std::to_string(index)},{"state","degraded"},{"reason","row_exceeds_page_encoded_byte_limit"},{"original_encoded_bytes",std::to_string(originalBytes)}};}
   auto bytes=row.dump().size();if(!rows.empty()&&(rows.size()>=limits.page_entries||encoded+bytes+1024>limits.encoded_bytes)){Json page{{"format","defender_preferences_page_v1"},{"source","MSFT_MpPreference"},{"page_index",std::to_string(pages)},{"entries",std::move(rows)},{"inventory_complete",false},{"consistency","non_atomic"},{"protection_verified",false}};if(pages>=limits.pages){bounded=true;break;}++pages;const auto n=page["entries"].size();if(!consumer(std::move(page))){refused=true;break;}delivered+=n;rows=Json::array();encoded=2;}
   encoded+=bytes+1;rows.push_back(std::move(row));++index;
   if(timedWithObject){timed=true;break;}if(cancelledFlag||timed)break;
   if(next==WBEM_S_FALSE){complete=true;break;}
 }
 if(index>=limits.total_entries&&!complete&&!cancelledFlag&&!timed)bounded=true;
 if(!rows.empty()&&!refused&&pages<limits.pages){Json page{{"format","defender_preferences_page_v1"},{"source","MSFT_MpPreference"},{"page_index",std::to_string(pages)},{"entries",std::move(rows)},{"inventory_complete",false},{"consistency","non_atomic"},{"protection_verified",false}};++pages;const auto n=page["entries"].size();if(consumer(std::move(page)))delivered+=n;else refused=true;}
 else if(!rows.empty()&&!refused)bounded=true;
 return manifest();
}
}

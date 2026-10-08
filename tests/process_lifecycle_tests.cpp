#include "panopticon/officer/collectors/sysmon_process_decoder.hpp"
#include "panopticon/officer/collectors/etw_process_collector.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/core/process_instance.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <evntcons.h>
#include <tdh.h>
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace panopticon::officer;
using Json=nlohmann::json;
void require(bool ok,const char* reason){if(!ok)throw std::runtime_error(reason);}
telemetry::RawProcessEvent native_fixture(std::uint16_t event_id=2, std::uint8_t version=0) {
    EVENT_RECORD record{}; record.EventHeader.ProviderId={0x22fb2cd6,0x0e7b,0x422b,{0xa0,0xc7,0x2f,0xad,0x1f,0xd0,0xe7,0x16}};
    record.EventHeader.EventDescriptor.Id=event_id; record.EventHeader.EventDescriptor.Version=version;
    record.EventHeader.EventDescriptor.Opcode=static_cast<UCHAR>(event_id); record.EventHeader.EventDescriptor.Task=event_id;
    record.EventHeader.Flags=EVENT_HEADER_FLAG_64_BIT_HEADER;
    ULONG needed=0;
    require(TdhGetEventInformation(&record,0,nullptr,nullptr,&needed)==ERROR_INSUFFICIENT_BUFFER && needed<2*1024*1024,"native process-stop metadata unavailable");
    std::vector<std::byte> metadata(needed);
    require(TdhGetEventInformation(&record,0,nullptr,reinterpret_cast<TRACE_EVENT_INFO*>(metadata.data()),&needed)==ERROR_SUCCESS,"native process-stop metadata query failed");
    const auto* info=reinterpret_cast<const TRACE_EVENT_INFO*>(metadata.data());
    require(info->TopLevelPropertyCount==info->PropertyCount && info->PropertyCount<=64,"fixture requires flat bounded native template");
    std::vector<std::byte> payload;
    const auto append=[&](auto value){const auto* first=reinterpret_cast<const std::byte*>(&value);payload.insert(payload.end(),first,first+sizeof(value));};
    bool pid=false,created=false,exited=false;
    for(ULONG i=0;i<info->TopLevelPropertyCount;++i) {
        const auto& property=info->EventPropertyInfoArray[i];
        require(!(property.Flags&PropertyStruct) && property.NameOffset<metadata.size(),"unsupported native template");
        const std::wstring name(reinterpret_cast<const wchar_t*>(metadata.data()+property.NameOffset));
        const auto type=property.nonStructType.InType;
        if(type==TDH_INTYPE_UINT32) {append(DWORD(name==L"ProcessID"?1234:name==L"ParentProcessID"?222:name==L"ExitCode"?7:name==L"Flags"?UINT32_MAX:0));pid|=name==L"ProcessID";}
        else if(type==TDH_INTYPE_UINT64 || type==TDH_INTYPE_FILETIME) {
            append(std::uint64_t(name==L"CreateTime"?133700000000000001ull:name==L"ExitTime"?133700000010000001ull:
                name==L"ProcessSequenceNumber"?UINT64_MAX:name==L"ParentProcessSequenceNumber"?UINT64_MAX-1:0));
            created|=name==L"CreateTime";exited|=name==L"ExitTime";
        } else if(type==TDH_INTYPE_UNICODESTRING) append(wchar_t(0));
        else if(type==TDH_INTYPE_ANSISTRING) append(char(0));
        else if(type==TDH_INTYPE_SID) {
            const unsigned char sid[]{1,1,0,0,0,0,0,16,0,32,0,0};
            const auto* begin=reinterpret_cast<const std::byte*>(sid);payload.insert(payload.end(),begin,begin+sizeof(sid));
        }
        else throw std::runtime_error("native stop fixture unsupported field type " + std::to_string(type));
    }
    require(pid && created && (event_id==1 || exited) && payload.size()<65536,"native template lacks identity clocks");
    record.UserData=payload.data();record.UserDataLength=static_cast<USHORT>(payload.size());std::string error;
    auto result=collectors::detail::decode_etw_process_record(&record,error);
    if(!result)throw std::runtime_error(error);
    require(result->terminated==(event_id==2) && result->pid==1234 && result->start_time_ticks==133700000000000001ull,"native TDH identity mismatch");
    if(event_id==2) require(result->termination_time_ticks==133700000010000001ull,"native TDH stop clock mismatch");
    require(result->native_fields && result->native_fields->event_id==event_id && result->native_fields->event_version==version,"native source template scope missing");
    const auto& fields=result->native_fields->fields;
    if((event_id==1 && version>=3) || (event_id==2 && version>=2)) {
        require(fields[0].state==telemetry::EtwUIntFieldState::copied && fields[0].value==UINT64_MAX && fields[0].reported_bytes==8,"native uint64 sequence lost precision");
    } else require(fields[0].state==telemetry::EtwUIntFieldState::absent && !fields[0].value,"older source invented sequence");
    if(event_id==1 && version>=3) require(fields[1].value==UINT64_MAX-1 && fields[3].value==UINT32_MAX,"native parent sequence/flags carrier changed");
    record.UserDataLength=1;
    require(!collectors::detail::decode_etw_process_record(&record,error),"truncated native payload accepted");
    return *result;
}
int main(int argc,char** argv){try {
    std::string error;
    const std::string xml="<Event><System><Provider Name='Microsoft-Windows-Sysmon'/><EventID>5</EventID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventRecordID>42</EventRecordID></System><EventData><Data Name='UtcTime'>2026-10-07 00:00:00.1234567</Data><Data Name='ProcessId'>1234</Data><Data Name='ProcessGuid'>{fixture-guid}</Data><Data Name='Image'>C:\\fixture.exe</Data></EventData></Event>";
    auto sysmon=collectors::SysmonProcessDecoder::decode_xml(xml,error);
    require(sysmon && sysmon->terminated && sysmon->termination_time && !sysmon->start_time_ticks,"Sysmon stop invented creation clock");
    auto duplicated=xml; duplicated.insert(duplicated.find("</EventData>"),"<Data Name='ProcessGuid'>{conflicting-guid}</Data>");
    require(!collectors::SysmonProcessDecoder::decode_xml(duplicated,error),"ambiguous termination GUID accepted");
    auto native=native_fixture();
    const auto sequenced_stop=native_fixture(2,2);
    const auto sequenced_birth=native_fixture(1,3);
    pipeline::NormalizationContext context{{"agent-1","1.0-dev"},{"host-1","LAB",{"Windows","26100"}}};
    const std::string boot="boot_"+std::string(64,'a');
    pipeline::EndpointRecordFactory factory{context,"device-1",std::string(64,'b'),boot,1};
    Json records=Json::array({factory.process_stop(native),factory.process_stop(*sysmon)});
    records.push_back(factory.process_stop(sequenced_stop));
    enrichment::EnrichedProcessEvent sequenced_enriched; sequenced_enriched.raw=sequenced_birth;
    const auto birth=pipeline::normalize_process_event(sequenced_enriched,context,error);
    require(birth.has_value(),"sequenced native birth normalization failed");
    records.push_back(factory.observation(telemetry::RawEvent{sequenced_birth},*birth));
    const auto& sequence_body=records.back()["data"]["source_facts"]["process"]["native_fields"];
    require(sequence_body["fields"]["ProcessSequenceNumber"]["value"]=="18446744073709551615" &&
        sequence_body["fields"]["ParentProcessSequenceNumber"]["value"]=="18446744073709551614" &&
        sequence_body["sequence_alias_promotion_performed"]==false && sequence_body["parent_instance_verified"]==false,
        "source sequence precision/scope changed during normalization");
    enrichment::EnrichedProcessEvent enriched; enriched.raw=*sysmon;
    require(!pipeline::normalize_process_event(enriched,context,error),"termination was normalized as a process birth");
    require(records[0]["subject"]["resolution"]=="native_exact" && records[1]["subject"]["resolution"]=="source_scoped","stop identity scope degraded or promoted incorrectly");
    require(records[0]["subject"]["entity_id"]!=records[1]["subject"]["entity_id"],"native and source stop aliases joined by PID");
    sysmon->process_guid.reset(); records.push_back(factory.process_stop(*sysmon));
    require(records.back()["subject"]["entity_id"].is_null(),"PID-only termination resolved an instance");
    core::ProcessInstanceStore store("host-1",boot);
    const auto old=store.observe(1234,100,std::nullopt,"etw:provider:");const auto replacement=store.observe(1234,101,std::nullopt,"etw:provider:");
    const auto first=*native.termination_time;store.terminate(old,first);store.terminate(old,first+std::chrono::seconds(1));
    for(const auto& row:store.snapshot()) {
        if(row["entity_id"]==*replacement.entity_id)require(row["terminated_at"].is_null(),"old stop tombstoned a reused PID");
        else require(row["terminated_at"]==pipeline::format_utc_timestamp(first),"duplicate late stop moved earliest tombstone");
    }
    factory.accepted_process_stop(native);
    if(argc==2 && std::string_view(argv[1])=="--emit-fixtures") std::cout<<records.dump()<<'\n';
    else std::cout<<"Synthetic TDH native-template and Sysmon stop identity/clock/PID reuse fixtures passed; live privileged ETW unverified\n";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

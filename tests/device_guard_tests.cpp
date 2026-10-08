#include "panopticon/officer/state/device_guard.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#include "panopticon/officer/health/state_freshness.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <iostream>
#include <stdexcept>
using Json=nlohmann::json;
namespace state=panopticon::officer::state;
void require(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
int main(int argc,char** argv){try{
    std::size_t copied=0;VARIANT value;VariantInit(&value);value.vt=VT_ARRAY|VT_I4;
    SAFEARRAYBOUND bound{3,-3};value.parray=SafeArrayCreate(VT_I4,1,&bound);require(value.parray!=nullptr,"fixture allocation");
    for(LONG i=-3;i<=-1;++i){LONG x=i==-1?-1:i+3;require(SafeArrayPutElement(value.parray,&i,&x)==S_OK,"fixture write");}
    const auto array=state::detail::decode_device_guard_property(S_OK,&value,CIM_UINT32|CIM_FLAG_ARRAY,CIM_UINT32|CIM_FLAG_ARRAY,copied);
    require(array["state"]=="healthy"&&array["value"]==Json::array({"0","1","4294967295"})&&array["raw_element_carriers"][2]=="-1"&&copied==12,"raw array carrier/order/lower bound preservation");
    require(!array["protection_verified"].get<bool>()&&!array["enum_values_interpreted"].get<bool>(),"array interpreted as enforcement");
    auto mismatch=state::detail::decode_device_guard_property(S_OK,&value,CIM_UINT32|CIM_FLAG_ARRAY,CIM_STRING,copied);
    require(mismatch["value"].is_null()&&mismatch["state"]=="degraded","type mismatch coerced");VariantClear(&value);
    bound={65,0};value.vt=VT_ARRAY|VT_UI4;value.parray=SafeArrayCreate(VT_UI4,1,&bound);
    const auto tooLarge=state::detail::decode_device_guard_property(S_OK,&value,CIM_UINT32|CIM_FLAG_ARRAY,CIM_UINT32|CIM_FLAG_ARRAY,copied);
    require(tooLarge["value"].is_null()&&tooLarge["validation_error"]=="array_copy_bound","unbounded array accepted");VariantClear(&value);
    value.vt=VT_BYREF|VT_ARRAY|VT_I4;value.pparray=nullptr;
    require(state::detail::decode_device_guard_property(S_OK,&value,CIM_UINT32|CIM_FLAG_ARRAY,CIM_UINT32|CIM_FLAG_ARRAY,copied)["value"].is_null(),"BYREF was followed");VariantInit(&value);
    require(state::detail::decode_device_guard_property(static_cast<std::uint32_t>(WBEM_E_ACCESS_DENIED),nullptr,CIM_UINT32,CIM_UINT32,copied)["state"]=="unavailable","denial became disabled state");
    value.vt=VT_I4;value.lVal=2;
    require(state::detail::decode_device_guard_property(S_OK,&value,CIM_UINT32,CIM_UINT32,copied)["value"]=="2","native scalar changed");
    Json health{{"device_guard_state",{{"state","degraded"},{"last_committed_record_id","fixture"},
        {"last_committed_capture_started_uptime_ms","100"},{"last_committed_uptime_ms","110"}}}};
    panopticon::officer::health::apply_state_capture_freshness(health,360101);
    require(health["device_guard_state"]["capture_freshness"]["state"]=="blind","stale Device Guard report remained current");
    const auto snapshot=state::collect_device_guard_state();require(snapshot["inventory_complete"]==false&&snapshot["protection_verified"]==false,"native snapshot overclaimed");
    panopticon::officer::pipeline::NormalizationContext context{{"agent-1","dev"},{"host-1","LAB",{"Windows","26100"}}};
    panopticon::officer::pipeline::EndpointRecordFactory factory{context,"device-1",std::string(64,'b'),"boot_"+std::string(64,'a'),1};
    if(argc==2&&std::string_view(argv[1])=="--emit-live")std::cout<<Json::array({factory.state("device_guard_state",snapshot)}).dump()<<'\n';
    else std::cout<<"Device Guard native provider and bounded variant fixtures passed; effective enforcement unverified\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}

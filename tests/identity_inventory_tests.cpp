#include "panopticon/officer/state/identity_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <ntsecapi.h>
#include <wtsapi32.h>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
using namespace panopticon::officer;
using Json = nlohmann::json;
void require(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
void decoders() {
    alignas(DWORD) std::array<std::byte, 128> bytes{};
    const wchar_t value[]{L'a',L'b',L'\0'}; std::memcpy(bytes.data()+16, value, sizeof(value));
    require(state::detail::identity_buffer_text(bytes, bytes.data()+16)["value"] == "ab", "bounded NetAPI text changed");
    require(state::detail::identity_buffer_text(bytes, bytes.data()+17)["state"] == "unavailable", "unaligned string accepted");
    require(state::detail::identity_buffer_text(bytes, bytes.data()+128)["state"] == "unavailable", "outside string read");
    require(state::detail::identity_buffer_text(std::span(bytes).first(20), bytes.data()+16)["state"] == "unavailable", "unterminated name read outside allocation");
    require(state::detail::identity_buffer_text(bytes, bytes.data()+16, 1)["bound_exceeded"] == true, "field copy cap ignored");
    bytes[32]=std::byte{1}; bytes[33]=std::byte{1}; bytes[39]=std::byte{5}; DWORD sub=18; std::memcpy(bytes.data()+40,&sub,4);
    require(state::detail::identity_buffer_sid(bytes, bytes.data()+32)["value"] == "S-1-5-18", "native SID bytes misrepresented");
    require(state::detail::identity_buffer_sid(std::span(bytes).first(40), bytes.data()+32)["state"] == "unavailable", "SID body overread");
    bytes[33]=std::byte{255}; require(state::detail::identity_buffer_sid(bytes, bytes.data()+32)["state"] == "unavailable", "SID count overread");
    wchar_t counted[]{L'a',L'\0',L'b'};
    LSA_UNICODE_STRING string{}; string.Buffer=counted; string.Length=6; string.MaximumLength=6;
    require(state::detail::identity_counted_text(&string,64)["value"] == std::string("a\0b",3), "counted native string treated as terminated");
    string.Length=5; require(state::detail::identity_counted_text(&string,64)["state"] == "unavailable", "odd LSA bytes decoded");
    string.Length=8; require(state::detail::identity_counted_text(&string,64)["state"] == "unavailable", "LSA maximum length ignored");
    string.Length=6; require(state::detail::identity_counted_text(&string,2)["bound_exceeded"] == true, "LSA copy cap ignored");
    string.Buffer=nullptr; require(state::detail::identity_counted_text(&string,64)["state"] == "unavailable", "null LSA text dereferenced");
    USHORT protocol=65535; std::memcpy(bytes.data(),&protocol,sizeof(protocol));
    require(state::detail::identity_wts_field(WTSClientProtocolType,std::span(bytes).first(2))["value"] == "65535", "unknown protocol coerced to RDP");
    require(state::detail::identity_wts_field(WTSClientProtocolType,std::span(bytes).first(1))["state"] == "unavailable", "WTS scalar overread");
    WTS_CLIENT_ADDRESS address{}; address.AddressFamily=999; address.Address[2]=0x80;
    const auto fact=state::detail::identity_wts_field(WTSClientAddress,{reinterpret_cast<const std::byte*>(&address),sizeof(address)});
    require(fact["value"]["reported_address_family"] == "999" && fact["value"]["interpreted_ip_address"].is_null(), "unknown family interpreted as an IP");
}
int main(int argc,char** argv) {
    try {
        decoders();
        Json records=Json::array(), reports=Json::array();
        pipeline::NormalizationContext context{{"agent-1","1.0-dev"},{"host-1","LAB",{"Windows","26100"}}};
        pipeline::EndpointRecordFactory factory{context,"device-1",std::string(64,'b'),std::nullopt,1};
        for(auto source:{state::IdentitySource::accounts,state::IdentitySource::groups,state::IdentitySource::logons,state::IdentitySource::terminal_sessions}) {
            const std::string category=state::identity_source_name(source);
            Json ids=Json::array(); std::size_t rows=0;
            const auto begin=factory.state(category+"_begin",{{"format","paged_"+category+"_begin_v1"},{"inventory_complete",false}}); records.push_back(begin);
            state::NativeInventoryLimits limits; limits.page_entries=2; limits.soft_budget_ms=15000;
            auto manifest=state::collect_identity_inventory_pages(source,[&](Json page){
                require(page.dump().size()<=limits.encoded_bytes && page["entries"].size()<=limits.page_entries,"native identity page exceeded limits");
                require(page.contains("identity_state_version") && !page.contains("persistence_state_version"),"OS state schema mislabeled as persistence");
                rows+=page["entries"].size(); page["capture_id"]=begin["record_id"];
                const auto record=factory.state(category+"_page",page); require(record["subject"].is_null(),"account or session invented a process actor");
                ids.push_back(record["record_id"]); records.push_back(record); return true;
            },limits);
            require(manifest["inventory_complete"] == false && manifest["entries_delivered"] == std::to_string(rows),"native identity census or accounting inflated");
            manifest["capture_id"]=begin["record_id"]; manifest["page_record_ids"]=ids; manifest["format"]="paged_"+category+"_v1";
            records.push_back(factory.state(category,manifest));
            reports.push_back({{"source",category},{"state",manifest["state"]},{"rows",rows},{"query_failures",manifest["query_failure_count"]},{"enumeration_complete",manifest["enumeration_complete"]}});
        }
        state::NativeInventoryLimits limits; limits.page_entries=1; std::size_t pages=0;
        const auto refused=state::collect_identity_inventory_pages(state::IdentitySource::accounts,[&](Json){++pages;return false;},limits);
        require(pages==1 && refused["consumer_refused"]==true && refused["entries_delivered"]=="0" && refused["enumeration_complete"]==false,"native account iterator advanced past refused page");
        const auto cancelled=state::collect_identity_inventory_pages(state::IdentitySource::groups,[](Json){return true;},{},[]{return true;});
        require(cancelled["cancelled"]==true && cancelled["enumeration_complete"]==false,"cancelled group capture became complete");
        std::cout << (argc==2 && std::string_view{argv[1]}=="--emit-live" ? records : reports).dump() << '\n'; return 0;
    }catch(const std::exception& error){std::cerr << error.what() << '\n'; return 1;}
}

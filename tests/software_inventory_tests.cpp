#include "panopticon/officer/state/software_inventory.hpp"
#include "panopticon/officer/pipeline/endpoint_record.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <stdexcept>
using Json = nlohmann::json;
using namespace panopticon::officer;
void require(bool ok, const char* reason) { if (!ok) throw std::runtime_error(reason); }
struct OwnedFixture {
    std::wstring path; HKEY key = nullptr;
    OwnedFixture() {
        path = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PanopticonInventoryTest-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
        DWORD disposition = 0;
        require(RegCreateKeyExW(HKEY_CURRENT_USER,path.c_str(),0,nullptr,0,KEY_SET_VALUE|KEY_WOW64_64KEY,nullptr,&key,&disposition)==ERROR_SUCCESS,"fixture create failed");
        require(disposition==REG_CREATED_NEW_KEY,"fixture collision");
        const wchar_t name[]=L"Panopticon read-only software fixture";
        require(RegSetValueExW(key,L"DisplayName",0,REG_SZ,reinterpret_cast<const BYTE*>(name),sizeof(name))==ERROR_SUCCESS,"fixture value failed");
        const BYTE malformed[]{0x61};
        require(RegSetValueExW(key,L"DisplayVersion",0,REG_SZ,malformed,sizeof(malformed))==ERROR_SUCCESS,"malformed fixture value failed");
    }
    ~OwnedFixture() { if(key) { RegCloseKey(key); RegDeleteKeyExW(HKEY_CURRENT_USER,path.c_str(),KEY_WOW64_64KEY,0); } }
};
int main(int argc,char** argv) {
    try {
        OwnedFixture owned;
        Json records=Json::array(), reports=Json::array(); bool found=false;
        pipeline::NormalizationContext context{{"agent-1","1.0-dev"},{"host-1","LAB",{"Windows","26100"}}};
        pipeline::EndpointRecordFactory factory{context,"device-1",std::string(64,'b'),std::nullopt,1};
        for (auto source:{state::SoftwareSource::msi,state::SoftwareSource::uninstall_registry}) {
            const std::string category=state::software_source_name(source); std::size_t rows=0;
            const auto begin=factory.state(category+"_begin",{{"inventory_complete",false}}); records.push_back(begin);
            Json ids=Json::array(); state::NativeInventoryLimits limits; limits.page_entries=4; limits.soft_budget_ms=15000;
            auto manifest=state::collect_software_inventory_pages(source,[&](Json page){
                require(page.dump().size()<=limits.encoded_bytes && page["entries"].size()<=limits.page_entries,"software page bounds exceeded");
                require(page.contains("software_state_version"),"software schema missing");
                for(const auto& row:page["entries"]) {
                    if(row.value("entry_kind","")=="msi_enumeration_error" && row["query"]["error_code"]!="234" && row["query"]["error_code"]!="0")
                        require(row["query"]["bound_exceeded"]==false,"failed MSI call's untouched capacity became copy loss");
                    for(const auto& field:row.value("fields",Json::object()))
                        if(field.contains("error_code") && field["error_code"]!="234" && field["error_code"]!="0")
                            require(field.value("bound_exceeded",false)==false,"failed property query's undefined size became copy loss");
                    if(row.value("entry_kind","")=="uninstall_registration" && row.contains("fields") && row["fields"].contains("DisplayName") &&
                        row["fields"]["DisplayName"].value("value",Json(nullptr))=="Panopticon read-only software fixture") {
                        found=true; require(row["installed_or_executable_verified"]==false,"registration promoted to installed file proof");
                        require(row["fields"]["DisplayVersion"]["state"]!="healthy","malformed registry text accepted");
                    }
                }
                rows+=page["entries"].size(); page["capture_id"]=begin["record_id"];
                const auto record=factory.state(category+"_page",page); require(record["subject"].is_null(),"inventory invented process actor");
                ids.push_back(record["record_id"]); records.push_back(record); return true;
            },limits);
            require(manifest["entries_delivered"]==std::to_string(rows) && manifest["inventory_complete"]==false,"software census/accounting inflated");
            manifest["capture_id"]=begin["record_id"]; manifest["page_record_ids"]=ids; manifest["format"]="paged_"+category+"_v1";
            records.push_back(factory.state(category,manifest)); reports.push_back({{"source",category},{"rows",rows},{"failures",manifest["query_failure_count"]}});
        }
        require(found,"owned registry software fixture not observed");
        state::NativeInventoryLimits limits; limits.page_entries=1; std::size_t pages=0;
        auto refused=state::collect_software_inventory_pages(state::SoftwareSource::uninstall_registry,[&](Json){++pages;return false;},limits);
        require(pages==1 && refused["consumer_refused"]==true && refused["entries_delivered"]=="0","refused software page advanced iterator");
        auto cancelled=state::collect_software_inventory_pages(state::SoftwareSource::msi,[](Json){return true;},{},[]{return true;});
        require(cancelled["cancelled"]==true && cancelled["enumeration_complete"]==false,"cancelled MSI census accepted");
        std::cout << (argc==2 && std::string_view(argv[1])=="--emit-live" ? records:reports).dump()<<'\n'; return 0;
    } catch(const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}

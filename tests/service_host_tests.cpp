#include "panopticon/officer/runtime/service_host.hpp"
#include <vector>
#include <iostream>
#include <stdexcept>
using panopticon::officer::runtime::ServiceStatusMachine;
void require(bool value,const char* reason){if(!value)throw std::runtime_error(reason);}
int main(){try {
    std::vector<SERVICE_STATUS> statuses;
    ServiceStatusMachine machine([&](const SERVICE_STATUS& status){statuses.push_back(status);return true;});
    require(machine.starting() && statuses.back().dwControlsAccepted==0,"start accepted controls before readiness");
    require(machine.interrogate() && statuses.back().dwCheckPoint==1,"interrogate invented progress");
    require(machine.progress() && statuses.back().dwCheckPoint==2,"real startup progress missing");
    require(machine.ready() && statuses.back().dwCurrentState==SERVICE_RUNNING && statuses.back().dwCheckPoint==0,"readiness invalid");
    require(!machine.progress(),"running status generated pending checkpoints");
    require(machine.stopping() && statuses.back().dwCurrentState==SERVICE_STOP_PENDING,"stop pending missing");
    const auto checkpoint=statuses.back().dwCheckPoint;
    require(machine.stopping() && statuses.back().dwCheckPoint==checkpoint,"duplicate stop renewed progress");
    require(!machine.ready(),"stop race returned to running");
    require(machine.progress() && statuses.back().dwCheckPoint==checkpoint+1,"drain progress missing");
    require(machine.stopped(7) && statuses.back().dwWin32ExitCode==ERROR_SERVICE_SPECIFIC_ERROR && statuses.back().dwServiceSpecificExitCode==7,"endpoint failure lost");
    const auto count=statuses.size();
    require(!machine.stopped(0) && !machine.interrogate() && !machine.progress() && !machine.stopping() && statuses.size()==count,"terminal status published twice");
    ServiceStatusMachine early([&](const SERVICE_STATUS& status){statuses.push_back(status);return true;});
    require(early.starting() && early.stopping() && !early.ready() && early.stopped(0),"startup interruption invalid");
    require(statuses.back().dwWin32ExitCode==0 && statuses.back().dwWaitHint==0 && statuses.back().dwControlsAccepted==0,"successful cleanup status invalid");
    ServiceStatusMachine failed([](const SERVICE_STATUS&){return false;});
    require(!failed.starting(),"SCM publication failure hidden");
    std::cout<<"Service transition, failure, stop race and real progress invariants passed; no SCM runtime qualification\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}

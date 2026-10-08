#include "panopticon/officer/runtime/service_host.hpp"
#include <atomic>
#include <iostream>
#include <memory>
#include <stdexcept>
namespace panopticon::officer::runtime {
ServiceStatusMachine::ServiceStatusMachine(Publish publish):publish_(std::move(publish)) {
    status_.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
    status_.dwCurrentState=SERVICE_START_PENDING;
}
bool ServiceStatusMachine::send() { return publish_ && publish_(status_); }
bool ServiceStatusMachine::starting() {
    std::scoped_lock lock(mutex_); if(terminal_ || status_.dwCurrentState!=SERVICE_START_PENDING) return false;
    status_.dwCheckPoint=1; status_.dwWaitHint=30000; return send();
}
bool ServiceStatusMachine::progress() {
    std::scoped_lock lock(mutex_); if(terminal_ || (status_.dwCurrentState!=SERVICE_START_PENDING && status_.dwCurrentState!=SERVICE_STOP_PENDING)) return false;
    if(status_.dwCheckPoint!=MAXDWORD) ++status_.dwCheckPoint;
    return send();
}
bool ServiceStatusMachine::ready() {
    std::scoped_lock lock(mutex_); if(terminal_ || status_.dwCurrentState!=SERVICE_START_PENDING) return false;
    status_.dwCurrentState=SERVICE_RUNNING; status_.dwControlsAccepted=SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
    status_.dwCheckPoint=0; status_.dwWaitHint=0; return send();
}
bool ServiceStatusMachine::stopping() {
    std::scoped_lock lock(mutex_); if(terminal_) return false;
    if(status_.dwCurrentState!=SERVICE_STOP_PENDING) {
        status_.dwCurrentState=SERVICE_STOP_PENDING; status_.dwControlsAccepted=0; status_.dwCheckPoint=1; status_.dwWaitHint=30000;
    }
    return send();
}
bool ServiceStatusMachine::stopped(DWORD endpoint_exit) {
    std::scoped_lock lock(mutex_); if(terminal_) return false;
    terminal_=true; status_.dwCurrentState=SERVICE_STOPPED; status_.dwControlsAccepted=0;
    status_.dwCheckPoint=0; status_.dwWaitHint=0;
    status_.dwWin32ExitCode=endpoint_exit ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR;
    status_.dwServiceSpecificExitCode=endpoint_exit; return send();
}
bool ServiceStatusMachine::interrogate() { std::scoped_lock lock(mutex_); return terminal_ ? false : send(); }
namespace {
constexpr wchar_t service_name[]=L"PanopticonOfficer";
struct Host {
    EndpointMain endpoint;
    SERVICE_STATUS_HANDLE status=nullptr;
    HANDLE stop=nullptr;
    std::atomic<int> result{0};
    std::atomic<DWORD> status_error{0};
    ServiceStatusMachine machine;
    explicit Host(EndpointMain run):endpoint(std::move(run)),machine([this](const SERVICE_STATUS& value){
        auto copy=value;
        if(SetServiceStatus(status,&copy)) return true;
        status_error.store(GetLastError()); if(stop) SetEvent(stop); return false;
    }) {}
    ~Host(){if(stop) CloseHandle(stop);}
};
Host* active=nullptr; // Valid until dispatcher has joined ServiceMain/control callbacks.
DWORD WINAPI control(DWORD code,DWORD,void*,void* context) {
    auto& host=*static_cast<Host*>(context);
    if(code==SERVICE_CONTROL_STOP || code==SERVICE_CONTROL_SHUTDOWN) {
        host.machine.stopping(); if(host.stop) SetEvent(host.stop); return NO_ERROR;
    }
    if(code==SERVICE_CONTROL_INTERROGATE) { host.machine.interrogate(); return NO_ERROR; }
    return ERROR_CALL_NOT_IMPLEMENTED;
}
void WINAPI service_main(DWORD,wchar_t**) {
    auto& host=*active;
    host.status=RegisterServiceCtrlHandlerExW(service_name,control,&host);
    if(!host.status) {host.result.store(static_cast<int>(GetLastError()));return;}
    if(!host.machine.starting()) {const auto error=host.status_error.load();host.result.store(static_cast<int>(error));host.machine.stopped(error);return;}
    host.stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    if(!host.stop) {const auto error=GetLastError();host.result.store(static_cast<int>(error));host.machine.stopped(error);return;}
    int result=0;
    try {
        result=host.endpoint(host.stop,[&]{host.machine.progress();},[&]{host.machine.ready();},[&]{host.machine.stopping();});
    } catch(...) { result=ERROR_EXCEPTION_IN_SERVICE; }
    if(!result && host.status_error.load()) result=static_cast<int>(host.status_error.load());
    host.result.store(result);
    // No endpoint work follows STOPPED; callbacks cannot re-publish it.
    host.machine.stopped(static_cast<DWORD>(result));
}
}
int run_service(const EndpointMain& endpoint) {
    Host host(endpoint); active=&host;
    SERVICE_TABLE_ENTRYW table[]{{const_cast<wchar_t*>(service_name),service_main},{nullptr,nullptr}};
    const bool connected=StartServiceCtrlDispatcherW(table)!=FALSE;
    const auto error=connected ? NO_ERROR : GetLastError(); active=nullptr;
    if(!connected) {std::cerr<<"SCM dispatch failed: "<<error<<'\n';return static_cast<int>(error);}
    return host.result.load();
}
}

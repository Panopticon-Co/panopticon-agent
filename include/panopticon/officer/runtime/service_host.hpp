#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <functional>
#include <mutex>
namespace panopticon::officer::runtime {
// A checkpoint is emitted only when the endpoint reports actual progress.
class ServiceStatusMachine {
public:
    using Publish = std::function<bool(const SERVICE_STATUS&)>;
    explicit ServiceStatusMachine(Publish publish);
    bool starting();
    bool progress();
    bool ready();
    bool stopping();
    bool stopped(DWORD endpoint_exit);
    bool interrogate();
private:
    bool send();
    std::mutex mutex_;
    SERVICE_STATUS status_{};
    Publish publish_;
    bool terminal_ = false;
};
using EndpointMain = std::function<int(HANDLE, const std::function<void()>&,
    const std::function<void()>&, const std::function<void()>&)>;
// SCM owns the dispatch lifetime. The endpoint receives a borrowed stop event;
// the service keeps its handle open through final cleanup/status publication.
int run_service(const EndpointMain& endpoint);
}

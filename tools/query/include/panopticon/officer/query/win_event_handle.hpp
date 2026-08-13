#pragma once

#include <windows.h>
#include <winevt.h>

#include <utility>

namespace panopticon::officer::query {

// Owns exactly one EVT_HANDLE. Copying is forbidden because two owners would
// otherwise both call EvtClose on the same Windows resource.
class WinEventHandle {
public:
    WinEventHandle() = default;
    explicit WinEventHandle(EVT_HANDLE handle) noexcept : handle_(handle) {}

    ~WinEventHandle() { reset(); }

    WinEventHandle(const WinEventHandle&) = delete;
    WinEventHandle& operator=(const WinEventHandle&) = delete;

    WinEventHandle(WinEventHandle&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}

    WinEventHandle& operator=(WinEventHandle&& other) noexcept {
        if (this != &other) {
            reset(std::exchange(other.handle_, nullptr));
        }
        return *this;
    }

    [[nodiscard]] EVT_HANDLE get() const noexcept { return handle_; }
    [[nodiscard]] explicit operator bool() const noexcept { return handle_ != nullptr; }

    void reset(EVT_HANDLE replacement = nullptr) noexcept {
        if (handle_ != nullptr) {
            EvtClose(handle_);
        }
        handle_ = replacement;
    }

private:
    EVT_HANDLE handle_{nullptr};
};

}  // namespace panopticon::officer::query

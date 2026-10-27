// officer-hook.dll -- Officer in-process API instrumentation.
//
// When injected into a monitored process, this DLL observes a small, fixed set
// of file-related Win32 APIs and reports each call to the agent's
// ApiHookCollector over the named pipe PANOPTICON_APIHOOK_PIPE_NAME, using the
// shared apihook_protocol.hpp wire contract.
//
// Mechanism: Import Address Table (IAT) hooking. For every loaded module, the
// thunk whose value equals a target API's resolved address is swapped to a
// detour and the original saved. This is deliberately chosen over inline
// trampoline patching because it cannot corrupt code or crash the host on an
// unexpected prologue. The honest cost is coverage: calls resolved dynamically
// (GetProcAddress) or issued via direct syscalls are NOT seen. This is an
// instrumentation sensor, not a security boundary.
//
// VM-gated: built and injected only on the validation VM. Not part of the agent
// CMake build.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>

// Include only the POD wire contract (enums/struct/macros); the user-mode std
// decoder declarations stay out of the DLL by not defining PANOPTICON_APIHOOK_USER.
#include "apihook_protocol.hpp"

#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------------------
// Pipe client: connect lazily, frame fixed-size records, count drops.
// ---------------------------------------------------------------------------
namespace {

HANDLE g_pipe = INVALID_HANDLE_VALUE;
CRITICAL_SECTION g_pipe_lock;
volatile LONG64 g_sequence = 0;
volatile LONG64 g_dropped = 0;
bool g_initialized = false;

bool ensure_pipe() {
    if (g_pipe != INVALID_HANDLE_VALUE) return true;
    HANDLE pipe = CreateFileW(PANOPTICON_APIHOOK_PIPE_NAME, GENERIC_WRITE, 0, nullptr,
                              OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) return false;
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
    g_pipe = pipe;
    return true;
}

std::uint64_t now_ticks() {
    FILETIME ft{};
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER v; v.LowPart = ft.dwLowDateTime; v.HighPart = ft.dwHighDateTime;
    return v.QuadPart;
}

std::uint64_t self_create_ticks() {
    FILETIME c{}, e{}, k{}, u{};
    if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) return 0;
    ULARGE_INTEGER v; v.LowPart = c.dwLowDateTime; v.HighPart = c.dwHighDateTime;
    return v.QuadPart;
}

void copy_units(unsigned short* dst, unsigned short cap, unsigned short* units,
                unsigned char* truncated, const wchar_t* text) {
    *units = 0; *truncated = 0;
    if (text == nullptr) return;
    unsigned short i = 0;
    for (; text[i] != L'\0'; ++i) {
        if (i >= cap) { *truncated = 1; break; }
        dst[i] = static_cast<unsigned short>(text[i]);
    }
    if (text[i] != L'\0' && i >= cap) *truncated = 1;
    *units = (i > cap) ? cap : i;
}

void emit(unsigned char op, unsigned char phase, const wchar_t* api,
          const wchar_t* path, const wchar_t* previous, DWORD win32_error) {
    PanopticonApiHookEvent e;
    std::memset(&e, 0, sizeof(e));
    e.version = PANOPTICON_APIHOOK_PROTOCOL_VERSION;
    e.record_bytes = sizeof(PanopticonApiHookEvent);
    e.operation = op;
    e.phase = phase;
    e.actor_pid = GetCurrentProcessId();
    e.actor_create = self_create_ticks();
    e.thread_id = GetCurrentThreadId();
    e.win32_error = (phase == PanopticonApiHookPhasePost) ? win32_error : 0;
    e.event_time = now_ticks();
    unsigned char dummy = 0;
    copy_units(e.api_name, 64, &e.api_name_units, &dummy, api);
    copy_units(e.path, PANOPTICON_APIHOOK_MAX_PATH, &e.path_units, &e.path_truncated, path);
    if (previous) copy_units(e.previous_path, PANOPTICON_APIHOOK_MAX_PATH, &e.previous_units, &e.previous_truncated, previous);

    EnterCriticalSection(&g_pipe_lock);
    if (!ensure_pipe()) {
        InterlockedIncrement64(&g_dropped);
        LeaveCriticalSection(&g_pipe_lock);
        return;
    }
    e.sequence = static_cast<std::uint64_t>(InterlockedIncrement64(&g_sequence));
    e.dropped_before = static_cast<std::uint64_t>(InterlockedCompareExchange64(&g_dropped, 0, 0));
    DWORD written = 0;
    if (!WriteFile(g_pipe, &e, sizeof(e), &written, nullptr) || written != sizeof(e)) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
        InterlockedIncrement64(&g_dropped);
    }
    LeaveCriticalSection(&g_pipe_lock);
}

// ---------------------------------------------------------------------------
// Detours (saved originals + replacements)
// ---------------------------------------------------------------------------
using CreateFileW_t = HANDLE (WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using WriteFile_t = BOOL (WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
using DeleteFileW_t = BOOL (WINAPI*)(LPCWSTR);
using MoveFileExW_t = BOOL (WINAPI*)(LPCWSTR, LPCWSTR, DWORD);

CreateFileW_t g_CreateFileW = nullptr;
WriteFile_t g_WriteFile = nullptr;
DeleteFileW_t g_DeleteFileW = nullptr;
MoveFileExW_t g_MoveFileExW = nullptr;

unsigned char create_op(DWORD disposition) {
    switch (disposition) {
        case CREATE_NEW: return PanopticonApiHookOpCreate;
        case CREATE_ALWAYS:
        case TRUNCATE_EXISTING: return PanopticonApiHookOpOverwrite;
        case OPEN_EXISTING:
        case OPEN_ALWAYS:
        default: return PanopticonApiHookOpOpen;
    }
}

HANDLE WINAPI Detour_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                 DWORD disposition, DWORD flags, HANDLE templ) {
    HANDLE result = g_CreateFileW(name, access, share, sa, disposition, flags, templ);
    DWORD err = GetLastError();
    emit(create_op(disposition), PanopticonApiHookPhasePost, L"CreateFileW", name, nullptr,
         result == INVALID_HANDLE_VALUE ? err : 0);
    SetLastError(err);
    return result;
}

BOOL WINAPI Detour_WriteFile(HANDLE file, LPCVOID buffer, DWORD bytes, LPDWORD written, LPOVERLAPPED ov) {
    // The handle's path is not cheaply available here; report the attempt with
    // the API only. The collector records an api_hook write attempt by actor.
    emit(PanopticonApiHookOpWrite, PanopticonApiHookPhasePre, L"WriteFile", nullptr, nullptr, 0);
    return g_WriteFile(file, buffer, bytes, written, ov);
}

BOOL WINAPI Detour_DeleteFileW(LPCWSTR name) {
    BOOL ok = g_DeleteFileW(name);
    DWORD err = GetLastError();
    emit(PanopticonApiHookOpDelete, PanopticonApiHookPhasePost, L"DeleteFileW", name, nullptr, ok ? 0 : err);
    SetLastError(err);
    return ok;
}

BOOL WINAPI Detour_MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags) {
    BOOL ok = g_MoveFileExW(from, to, flags);
    DWORD err = GetLastError();
    // Destination is the new path; source is the previous path.
    emit(PanopticonApiHookOpRename, PanopticonApiHookPhasePost, L"MoveFileExW", to, from, ok ? 0 : err);
    SetLastError(err);
    return ok;
}

// ---------------------------------------------------------------------------
// IAT patching
// ---------------------------------------------------------------------------
struct Target {
    const char* name;      // exported name in kernel32/kernelbase
    void* detour;
    void** original;       // where to store the resolved original
};

// Patch every module's IAT entry that currently points at `original_addr`.
void patch_all_modules(void* original_addr, void* detour) {
    HMODULE modules[1024];
    DWORD needed = 0;
    HMODULE self = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&patch_all_modules), &self);
    HANDLE proc = GetCurrentProcess();
    if (!EnumProcessModules(proc, modules, sizeof(modules), &needed)) return;
    const DWORD count = needed / sizeof(HMODULE);
    for (DWORD m = 0; m < count; ++m) {
        HMODULE mod = modules[m];
        if (mod == self) continue;  // never hook ourselves
        auto base = reinterpret_cast<unsigned char*>(mod);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0) continue;
        auto import = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
        for (; import->Name; ++import) {
            auto thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + import->FirstThunk);
            for (; thunk->u1.Function; ++thunk) {
                void** slot = reinterpret_cast<void**>(&thunk->u1.Function);
                if (*slot != original_addr) continue;
                DWORD old = 0;
                if (VirtualProtect(slot, sizeof(void*), PAGE_READWRITE, &old)) {
                    *slot = detour;
                    VirtualProtect(slot, sizeof(void*), old, &old);
                }
            }
        }
    }
}

bool install_hooks() {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE kbase = GetModuleHandleW(L"kernelbase.dll");
    auto resolve = [&](const char* name) -> void* {
        void* a = k32 ? reinterpret_cast<void*>(GetProcAddress(k32, name)) : nullptr;
        if (a) return a;
        return kbase ? reinterpret_cast<void*>(GetProcAddress(kbase, name)) : nullptr;
    };
    g_CreateFileW = reinterpret_cast<CreateFileW_t>(resolve("CreateFileW"));
    g_WriteFile = reinterpret_cast<WriteFile_t>(resolve("WriteFile"));
    g_DeleteFileW = reinterpret_cast<DeleteFileW_t>(resolve("DeleteFileW"));
    g_MoveFileExW = reinterpret_cast<MoveFileExW_t>(resolve("MoveFileExW"));
    if (!g_CreateFileW || !g_WriteFile || !g_DeleteFileW || !g_MoveFileExW) return false;

    patch_all_modules(reinterpret_cast<void*>(g_CreateFileW), reinterpret_cast<void*>(&Detour_CreateFileW));
    patch_all_modules(reinterpret_cast<void*>(g_WriteFile), reinterpret_cast<void*>(&Detour_WriteFile));
    patch_all_modules(reinterpret_cast<void*>(g_DeleteFileW), reinterpret_cast<void*>(&Detour_DeleteFileW));
    patch_all_modules(reinterpret_cast<void*>(g_MoveFileExW), reinterpret_cast<void*>(&Detour_MoveFileExW));
    return true;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(module);
            InitializeCriticalSection(&g_pipe_lock);
            g_initialized = install_hooks();
            break;
        case DLL_PROCESS_DETACH:
            if (g_initialized) {
                // Restore IAT entries by swapping detours back to originals.
                patch_all_modules(reinterpret_cast<void*>(&Detour_CreateFileW), reinterpret_cast<void*>(g_CreateFileW));
                patch_all_modules(reinterpret_cast<void*>(&Detour_WriteFile), reinterpret_cast<void*>(g_WriteFile));
                patch_all_modules(reinterpret_cast<void*>(&Detour_DeleteFileW), reinterpret_cast<void*>(g_DeleteFileW));
                patch_all_modules(reinterpret_cast<void*>(&Detour_MoveFileExW), reinterpret_cast<void*>(g_MoveFileExW));
            }
            if (g_pipe != INVALID_HANDLE_VALUE) CloseHandle(g_pipe);
            DeleteCriticalSection(&g_pipe_lock);
            break;
        default:
            break;
    }
    return TRUE;
}

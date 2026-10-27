// panopticon-fsmon.sys -- Panopticon Officer filesystem minifilter.
//
// A FltMgr minifilter that observes IRP-level file operations and forwards a
// bounded, fixed-size record per operation to the user-mode MinifilterCollector
// over a communication port. The wire contract is the shared header
// fsmon_protocol.hpp; this driver stamps PANOPTICON_FSMON_PROTOCOL_VERSION and
// the collector refuses any mismatch.
//
// Design constraints:
//  * Observe-only. No create is blocked, no data is altered. Pre callbacks emit
//    an attempt record; post callbacks emit the completion with NTSTATUS.
//  * Bounded memory. Records are drawn from an NPAGED lookaside list and held on
//    a spin-lock-protected queue capped at kMaxQueuedEvents; on overflow the
//    oldest-pending policy is NOT used -- the new event is dropped and a global
//    dropped counter is advanced so the collector sees an explicit gap.
//  * One subscriber. A single client (the Officer service, SYSTEM/Admin only via
//    the port security descriptor) connects at a time.
//  * Paths are captured from the normalized name when available and bounded to
//    PANOPTICON_FSMON_MAX_PATH UTF-16 units with an explicit truncation flag.
//
// This file is compiled only by the WDK (see panopticon-fsmon.vcxproj) and loaded
// test-signed on the validation VM. It is intentionally excluded from the agent's
// CMake build, which compiles only the user-mode half.

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define PANOPTICON_FSMON_KERNEL
#include "fsmon_protocol.hpp"

// ---------------------------------------------------------------------------
// Tunables and tags
// ---------------------------------------------------------------------------
#define FSMON_POOL_TAG 'nMsP'  // 'PsMn'
static const ULONG kMaxQueuedEvents = 4096;

// ---------------------------------------------------------------------------
// Global filter state
// ---------------------------------------------------------------------------
typedef struct _FSMON_GLOBALS {
    PFLT_FILTER Filter;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;           // single connected subscriber (or NULL)

    NPAGED_LOOKASIDE_LIST EventLookaside;

    KSPIN_LOCK QueueLock;
    LIST_ENTRY Queue;               // list of FSMON_QUEUED_EVENT
    ULONG QueueDepth;
    LONG64 Sequence;                // monotonic, assigned at enqueue
    LONG64 Dropped;                 // total events dropped (queue full / no client)

    KEVENT WorkAvailable;
    PETHREAD WorkerThread;
    BOOLEAN WorkerStop;
} FSMON_GLOBALS;

typedef struct _FSMON_QUEUED_EVENT {
    LIST_ENTRY Link;
    PanopticonFsMonEvent Event;
} FSMON_QUEUED_EVENT;

static FSMON_GLOBALS g = {0};

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
DRIVER_INITIALIZE DriverEntry;
NTSTATUS FsMonUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS FsMonInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                            DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS FsMonInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FsMonPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FsMonPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
FLT_PREOP_CALLBACK_STATUS FsMonPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_PREOP_CALLBACK_STATUS FsMonPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext);
FLT_POSTOP_CALLBACK_STATUS FsMonPostSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);

NTSTATUS FsMonConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID* ConnectionPortCookie);
VOID FsMonDisconnect(PVOID ConnectionCookie);
NTSTATUS FsMonMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength);
static VOID FsMonWorker(PVOID Context);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsMonUnload)
#pragma alloc_text(PAGE, FsMonInstanceSetup)
#pragma alloc_text(PAGE, FsMonInstanceQueryTeardown)
#endif

// ---------------------------------------------------------------------------
// Operation registration
// ---------------------------------------------------------------------------
static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,          0, FsMonPreCreate,         FsMonPostCreate },
    { IRP_MJ_WRITE,           0, FsMonPreWrite,          NULL },
    { IRP_MJ_SET_INFORMATION, 0, FsMonPreSetInformation, FsMonPostSetInformation },
    { IRP_MJ_OPERATION_END }
};

static const FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_CONTEXT_END }
};

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    Contexts,
    Callbacks,
    FsMonUnload,
    FsMonInstanceSetup,
    FsMonInstanceQueryTeardown,
    NULL,                   // InstanceTeardownStart
    NULL,                   // InstanceTeardownComplete
    NULL, NULL, NULL, NULL, NULL
};

// ---------------------------------------------------------------------------
// Time / identity helpers
// ---------------------------------------------------------------------------
static LONG64 FsMonNow(void) {
    LARGE_INTEGER t;
    KeQuerySystemTimePrecise(&t);
    return t.QuadPart;  // 100ns ticks since 1601 (FILETIME base)
}

// Actor process creation time as FILETIME ticks, 0 if unavailable. Uses the
// documented PsGetProcessCreateTimeQuadPart for the current process.
static LONG64 FsMonActorCreateTicks(void) {
    PEPROCESS process = PsGetCurrentProcess();
    LONG64 ticks = PsGetProcessCreateTimeQuadPart(process);
    return ticks;  // already 100ns since 1601
}

// ---------------------------------------------------------------------------
// Queue + enqueue
// ---------------------------------------------------------------------------
static VOID FsMonFillCommon(PanopticonFsMonEvent* e, UCHAR operation, UCHAR phase, NTSTATUS status) {
    e->version = PANOPTICON_FSMON_PROTOCOL_VERSION;
    e->record_bytes = sizeof(PanopticonFsMonEvent);
    e->operation = operation;
    e->phase = phase;
    e->path_truncated = 0;
    e->previous_truncated = 0;
    e->actor_pid = (unsigned int)(ULONG_PTR)PsGetCurrentProcessId();
    e->actor_create = (unsigned __int64)FsMonActorCreateTicks();
    e->actor_session = 0xFFFFFFFFu;  // session unknown at IRP time; collector tolerates
    e->thread_id = (unsigned int)(ULONG_PTR)PsGetCurrentThreadId();
    e->status = (phase == PanopticonFsMonPhasePost) ? (long)status : 0;
    e->event_time = (unsigned __int64)FsMonNow();
    e->path_units = 0;
    e->previous_units = 0;
}

// Copy a bounded UNICODE_STRING into a fixed unit buffer, setting *units and
// *truncated. Never writes past capacity.
static VOID FsMonCopyPath(const UNICODE_STRING* name, unsigned short* buffer,
                          unsigned short* units, unsigned char* truncated) {
    *units = 0;
    *truncated = 0;
    if (name == NULL || name->Buffer == NULL) return;
    USHORT available = (USHORT)(name->Length / sizeof(WCHAR));
    USHORT copy = available;
    if (copy > PANOPTICON_FSMON_MAX_PATH) {
        copy = PANOPTICON_FSMON_MAX_PATH;
        *truncated = 1;
    }
    for (USHORT i = 0; i < copy; ++i) buffer[i] = (unsigned short)name->Buffer[i];
    *units = (unsigned short)copy;
}

// Enqueue a filled event (common + path already set). Takes ownership semantics:
// copies into a lookaside record. On queue-full, drops and advances the counter.
static VOID FsMonEnqueue(const PanopticonFsMonEvent* source) {
    if (g.ClientPort == NULL) {
        // No subscriber: account as dropped so the eventual gap is explicit.
        InterlockedIncrement64(&g.Dropped);
        return;
    }
    FSMON_QUEUED_EVENT* node =
        (FSMON_QUEUED_EVENT*)ExAllocateFromNPagedLookasideList(&g.EventLookaside);
    if (node == NULL) {
        InterlockedIncrement64(&g.Dropped);
        return;
    }
    RtlCopyMemory(&node->Event, source, sizeof(PanopticonFsMonEvent));

    KIRQL irql;
    KeAcquireSpinLock(&g.QueueLock, &irql);
    if (g.QueueDepth >= kMaxQueuedEvents) {
        KeReleaseSpinLock(&g.QueueLock, irql);
        ExFreeToNPagedLookasideList(&g.EventLookaside, node);
        InterlockedIncrement64(&g.Dropped);
        return;
    }
    node->Event.sequence = (unsigned __int64)InterlockedIncrement64(&g.Sequence);
    node->Event.dropped_before = (unsigned __int64)InterlockedCompareExchange64(&g.Dropped, 0, 0);
    InsertTailList(&g.Queue, &node->Link);
    ++g.QueueDepth;
    KeReleaseSpinLock(&g.QueueLock, irql);

    KeSetEvent(&g.WorkAvailable, IO_NO_INCREMENT, FALSE);
}

// Build an event from the file name information and enqueue it.
static VOID FsMonEmit(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                      UCHAR operation, UCHAR phase, NTSTATUS status) {
    PanopticonFsMonEvent e;
    RtlZeroMemory(&e, sizeof(e));
    FsMonFillCommon(&e, operation, phase, status);

    PFLT_FILE_NAME_INFORMATION info = NULL;
    NTSTATUS nameStatus = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &info);
    if (NT_SUCCESS(nameStatus) && info != NULL) {
        FltParseFileNameInformation(info);
        FsMonCopyPath(&info->Name, e.path, &e.path_units, &e.path_truncated);
        FltReleaseFileNameInformation(info);
    }
    UNREFERENCED_PARAMETER(FltObjects);
    FsMonEnqueue(&e);
}

// ---------------------------------------------------------------------------
// Pre/post callbacks
// ---------------------------------------------------------------------------
FLT_PREOP_CALLBACK_STATUS FsMonPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    // Classify disposition from the create parameters to distinguish
    // open/create/overwrite. The post callback refines open vs create by the
    // information field (FILE_CREATED/FILE_OPENED).
    ULONG options = Data->Iopb->Parameters.Create.Options;
    ULONG disposition = (options >> 24) & 0x000000ff;
    UCHAR op = PanopticonFsMonOpOpen;
    if (disposition == FILE_SUPERSEDE || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF)
        op = PanopticonFsMonOpOverwrite;
    else if (disposition == FILE_CREATE)
        op = PanopticonFsMonOpCreate;
    // Carry the pre-classified op to the post callback (encoded as a pointer).
    *CompletionContext = (PVOID)(ULONG_PTR)op;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FsMonPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    UCHAR op = (UCHAR)(ULONG_PTR)CompletionContext;
    // Refine open/create using the actual information result.
    if (NT_SUCCESS(Data->IoStatus.Status)) {
        if (Data->IoStatus.Information == FILE_CREATED) op = PanopticonFsMonOpCreate;
        else if (Data->IoStatus.Information == FILE_OPENED && op == PanopticonFsMonOpOpen) op = PanopticonFsMonOpOpen;
    }
    FsMonEmit(Data, FltObjects, op, PanopticonFsMonPhasePost, Data->IoStatus.Status);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FsMonPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    // Writes are emitted as attempts (pre); a post callback on every write would
    // double volume for little added identity. The attempt carries the actor.
    FsMonEmit(Data, FltObjects, PanopticonFsMonOpWrite, PanopticonFsMonPhasePre, STATUS_SUCCESS);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FsMonPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(FltObjects);
    FILE_INFORMATION_CLASS fileClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    UCHAR op = PanopticonFsMonOpSetInformation;
    if (fileClass == FileRenameInformation || fileClass == FileRenameInformationEx)
        op = PanopticonFsMonOpRename;
    else if (fileClass == FileDispositionInformation || fileClass == FileDispositionInformationEx)
        op = PanopticonFsMonOpDelete;
    *CompletionContext = (PVOID)(ULONG_PTR)op;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS FsMonPostSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    if (Flags & FLTFL_POST_OPERATION_DRAINING) return FLT_POSTOP_FINISHED_PROCESSING;
    UCHAR op = (UCHAR)(ULONG_PTR)CompletionContext;

    PanopticonFsMonEvent e;
    RtlZeroMemory(&e, sizeof(e));
    FsMonFillCommon(&e, op, PanopticonFsMonPhasePost, Data->IoStatus.Status);

    // Current name (the source name for a rename).
    PFLT_FILE_NAME_INFORMATION info = NULL;
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &info)) && info) {
        FltParseFileNameInformation(info);
        // For a rename the pre-operation name is the previous path; the current
        // handle still resolves to it in the post callback for most filesystems.
        if (op == PanopticonFsMonOpRename)
            FsMonCopyPath(&info->Name, e.previous_path, &e.previous_units, &e.previous_truncated);
        else
            FsMonCopyPath(&info->Name, e.path, &e.path_units, &e.path_truncated);
        FltReleaseFileNameInformation(info);
    }

    // For a successful rename, resolve the destination from the target file.
    if (op == PanopticonFsMonOpRename && NT_SUCCESS(Data->IoStatus.Status)) {
        PFLT_FILE_NAME_INFORMATION dest = NULL;
        if (NT_SUCCESS(FltGetDestinationFileNameInformation(
                FltObjects->Instance, FltObjects->FileObject,
                Data->Iopb->Parameters.SetFileInformation.ParentOfTarget,
                Data->Iopb->Parameters.SetFileInformation.InfoBuffer,
                Data->Iopb->Parameters.SetFileInformation.Length,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &dest)) && dest) {
            FltParseFileNameInformation(dest);
            FsMonCopyPath(&dest->Name, e.path, &e.path_units, &e.path_truncated);
            FltReleaseFileNameInformation(dest);
        }
    }
    FsMonEnqueue(&e);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

// ---------------------------------------------------------------------------
// Worker: drain the queue to the connected client via FltSendMessage
// ---------------------------------------------------------------------------
static VOID FsMonWorker(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);
    for (;;) {
        KeWaitForSingleObject(&g.WorkAvailable, Executive, KernelMode, FALSE, NULL);
        if (g.WorkerStop) break;

        for (;;) {
            KIRQL irql;
            KeAcquireSpinLock(&g.QueueLock, &irql);
            if (IsListEmpty(&g.Queue)) { KeReleaseSpinLock(&g.QueueLock, irql); break; }
            PLIST_ENTRY link = RemoveHeadList(&g.Queue);
            --g.QueueDepth;
            KeReleaseSpinLock(&g.QueueLock, irql);

            FSMON_QUEUED_EVENT* node = CONTAINING_RECORD(link, FSMON_QUEUED_EVENT, Link);
            PFLT_PORT client = g.ClientPort;
            if (client != NULL) {
                LARGE_INTEGER timeout;
                timeout.QuadPart = -(5LL * 1000 * 1000 * 10);  // 5s, relative
                NTSTATUS sent = FltSendMessage(g.Filter, &client, &node->Event,
                                               sizeof(PanopticonFsMonEvent), NULL, NULL, &timeout);
                if (!NT_SUCCESS(sent)) InterlockedIncrement64(&g.Dropped);
            } else {
                InterlockedIncrement64(&g.Dropped);
            }
            ExFreeToNPagedLookasideList(&g.EventLookaside, node);
            if (g.WorkerStop) break;
        }
        if (g.WorkerStop) break;
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ---------------------------------------------------------------------------
// Port connect / disconnect / message
// ---------------------------------------------------------------------------
NTSTATUS FsMonConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext,
                      ULONG SizeOfContext, PVOID* ConnectionPortCookie) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    g.ClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID FsMonDisconnect(PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g.Filter, &g.ClientPort);
    g.ClientPort = NULL;
}

NTSTATUS FsMonMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                      PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength) {
    // No user->driver control messages are defined in protocol v1.
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(InputBuffer);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;
    return STATUS_INVALID_DEVICE_REQUEST;
}

// ---------------------------------------------------------------------------
// Instance callbacks
// ---------------------------------------------------------------------------
NTSTATUS FsMonInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                            DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    PAGED_CODE();
    // Attach to supported disk/network filesystems; skip raw volumes.
    if (VolumeFilesystemType == FLT_FSTYPE_RAW) return STATUS_FLT_DO_NOT_ATTACH;
    return STATUS_SUCCESS;
}

NTSTATUS FsMonInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Unload
// ---------------------------------------------------------------------------
NTSTATUS FsMonUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    // Stop the worker.
    g.WorkerStop = TRUE;
    KeSetEvent(&g.WorkAvailable, IO_NO_INCREMENT, FALSE);
    if (g.WorkerThread) {
        KeWaitForSingleObject(g.WorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(g.WorkerThread);
        g.WorkerThread = NULL;
    }

    if (g.ServerPort) { FltCloseCommunicationPort(g.ServerPort); g.ServerPort = NULL; }
    if (g.Filter) { FltUnregisterFilter(g.Filter); g.Filter = NULL; }

    // Drain any remaining queued records.
    while (!IsListEmpty(&g.Queue)) {
        PLIST_ENTRY link = RemoveHeadList(&g.Queue);
        FSMON_QUEUED_EVENT* node = CONTAINING_RECORD(link, FSMON_QUEUED_EVENT, Link);
        ExFreeToNPagedLookasideList(&g.EventLookaside, node);
    }
    ExDeleteNPagedLookasideList(&g.EventLookaside);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    RtlZeroMemory(&g, sizeof(g));
    KeInitializeSpinLock(&g.QueueLock);
    InitializeListHead(&g.Queue);
    KeInitializeEvent(&g.WorkAvailable, SynchronizationEvent, FALSE);
    ExInitializeNPagedLookasideList(&g.EventLookaside, NULL, NULL, 0,
                                    sizeof(FSMON_QUEUED_EVENT), FSMON_POOL_TAG, 0);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g.Filter);
    if (!NT_SUCCESS(status)) { ExDeleteNPagedLookasideList(&g.EventLookaside); return status; }

    // Communication port restricted to SYSTEM and Administrators.
    PSECURITY_DESCRIPTOR sd = NULL;
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (NT_SUCCESS(status)) {
        UNICODE_STRING portName;
        RtlInitUnicodeString(&portName, PANOPTICON_FSMON_PORT_NAME);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        status = FltCreateCommunicationPort(g.Filter, &g.ServerPort, &oa, NULL,
                                            FsMonConnect, FsMonDisconnect, FsMonMessage, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (!NT_SUCCESS(status)) { FltUnregisterFilter(g.Filter); ExDeleteNPagedLookasideList(&g.EventLookaside); return status; }

    // Worker thread to drain the queue.
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES ta;
    InitializeObjectAttributes(&ta, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, &ta, NULL, NULL, FsMonWorker, NULL);
    if (NT_SUCCESS(status)) {
        ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, (PVOID*)&g.WorkerThread, NULL);
        ZwClose(threadHandle);
    } else {
        FltCloseCommunicationPort(g.ServerPort);
        FltUnregisterFilter(g.Filter);
        ExDeleteNPagedLookasideList(&g.EventLookaside);
        return status;
    }

    status = FltStartFiltering(g.Filter);
    if (!NT_SUCCESS(status)) {
        g.WorkerStop = TRUE;
        KeSetEvent(&g.WorkAvailable, IO_NO_INCREMENT, FALSE);
        if (g.WorkerThread) { KeWaitForSingleObject(g.WorkerThread, Executive, KernelMode, FALSE, NULL); ObDereferenceObject(g.WorkerThread); }
        FltCloseCommunicationPort(g.ServerPort);
        FltUnregisterFilter(g.Filter);
        ExDeleteNPagedLookasideList(&g.EventLookaside);
        return status;
    }
    return STATUS_SUCCESS;
}

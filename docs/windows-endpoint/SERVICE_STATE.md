# Native service and driver state

The user-mode collector reads caller-visible SCM Win32 services and drivers with
EnumServicesStatusExW, then queries selected configuration through a separately
opened SERVICE_QUERY_CONFIG handle. Raw service status, reported PID, controls,
exit codes, checkpoint and wait hint remain descriptor facts. Neither the PID
nor the service name becomes a verified process or service instance. Deletion
and name reuse between enumeration and OpenServiceW remain explicitly unverified.
Configuration is a later, non-atomic query and can describe the next start rather
than the current running instance. Binary path/arguments are unparsed text;
accounts, driver objects and dependencies are not resolved identities.

SCM can silently omit services for which the caller lacks SERVICE_QUERY_STATUS.
Successful enumeration therefore means only caller-visible enumeration finished:
inventory_complete remains false and coverage remains degraded. Omitted names
and counts are unknown. Native failures retain exact Win32 status and null values;
validation refusals have a separate error domain. Missing configuration does not
erase an enumerated descriptor. Malformed UTF-16 is retained as original bytes.

Default bounds are 256 entries and 512 KiB encoded entry data per page, 65,536
entries and 4,096 pages per capture, a 256 KiB enumeration buffer and an 8 KiB
configuration buffer. Count, byte, page, consumer and non-advancing resume refusals
stop enumeration with explicit incomplete status. Query failures count later
configuration attempts, including queried but undelivered rows; they are not lost
event counts. Complete security semantics/SACL/labels, preferred NUMA node, lifecycle
continuity and complete configuration remain pending.

Service state version 1.1 independently queries eight QueryServiceConfig2W
levels on the same SERVICE_QUERY_CONFIG handle: description, failure actions,
delayed auto-start, non-crash failure-action flag, service SID type, required
privilege names, preshutdown timeout and launch protection. A base configuration
query failure does not suppress these independent queries. Each level uses a
fixed 8 KiB buffer, keeps its exact native error and query uptime window, and
validates structure/pointer/count bounds before reading variable data. Successful
native queries are distinguished from validation failures or unknown raw values.
Required-privilege null and empty lists remain separate configured facts; neither
means an empty effective privilege set. Failure command/resource strings are
retained without execution, resource loading, argument parsing or account lookup.
Unknown full-width SID/protection/action codes keep decimal raw values and null
symbols; no enum reads invent a known interpretation. Null action pointers retain
raw count/reset values without interpreting them as an active action array.

The manifest and committed health include per-level success, native failure,
uninterpreted/invalid and unattempted query counts, with explicit inclusion of
queried but undelivered rows. Query coverage is healthy only for successful,
interpretable queries across a finished caller-visible enumeration with no
unattempted objects or refusal. These narrow query capabilities never establish
full host coverage, descriptor/object identity, effective token privileges,
running PPL protection, or agent PPL/ELAM qualification. Description failures and
unknown actions can degrade one level while other levels remain query-healthy.

Version 1.2 adds a ninth optional query for service triggers. Trigger types and
actions keep full DWORD values and known SDK labels; subtype GUIDs are formatted
from bounded native structures without provider/device/domain/session lookup.
Trigger-specific data retains exact raw hex bytes, including unknown data types.
One-byte levels and eight-byte keywords have bounded numeric decoding; UTF-16
strings retain NUL-separated segments and malformed original code units. No
configuration string is executed, expanded or used as a verified actor/target.
Native zero-count pointers are unused; nonzero counts, array alignment, GUIDs and
payload pointers are checked before access. Reserved non-null pointers are
reported without dereference.

The decoder limits one result to 128 triggers, 256 aggregate data items, 1,024
bytes per payload, 32 KiB of aggregate copied payload and 256 decoded text
segments. Repeated/overlapping references are charged each time to prevent
output amplification. Bounds and validation refusals preserve declared counts
and available scalar/raw payload facts with explicit degraded status. Text
decoding refusal retains original payload bytes. These are collection bounds,
not claims that the remaining configured set is empty. The installed Windows
SDK 10.0.26100 names types 7 and 30; their detailed semantics remain unqualified
and they keep uninterpreted status even when a SDK label is available. Observed
trigger firing, aggregate/system-state semantics, continuous trigger changes,
service-instance binding and complete policy interpretation remain pending.

Version 1.3 independently opens each valid enumerated name with READ_CONTROL
and queries owner/group/DACL through QueryServiceObjectSecurity using an 8 KiB
buffer. Failure to open that security object does not erase configuration facts.
The security/configuration/descriptor relationship remains unverified across
the separate name lookups. No privilege adjustment, service change, SACL access,
account lookup or effective-access decision is performed.

The decoder reads bounded self-relative headers and validates revision, offsets,
alignment, SID counts, ACL sizes and ACE boundaries before access. Owner/group
retain binary SIDs and raw authority/subauthority fields, with null account
references. DACL representations distinguish not-present, null and actual ACLs;
an empty ACL is an actual ACL with zero ACEs. ACEs keep raw type, flags and bytes
without interpreting conditional/object/callback forms or access semantics.
Detailed ACE output is limited to 256 entries while complete bounded ACL bytes
remain available. Validation refusals retain the original allocated buffer bytes
where bounded header/component decoding is possible. A selected-component prefix
extent is derived from checked offsets; it is not an API-reported success byte
count or a full-security-descriptor claim. SACL/label/effective access are
explicitly unqualified. Security query health remains degraded even when all
selected reads succeed. The manifest separately counts native query success and
failure, security-open refusals, unattempted names, validation failures and bounded
results, including queried but undelivered rows.

An independent worker starts after event subscriptions are attempted. It retains
a canonical begin record, ordered pages and a final manifest with exact page IDs.
Each record keeps stable bytes and identity across durable-admission retries.
Stdout follows journal acceptance. Five-minute refresh begins after a committed
manifest; health binds committed query status to its exact record ID and reports
pending acceptance and commit failures. Abrupt exit can leave an incomplete
capture; persistent capture resumption and automatic reconciliation are pending.

Manager retains these records independently of existing latest-category schemas.
Authenticated immutable record readback returns the original accepted body;
Detection keeps endpoint domain data without inventing process attribution.
Complete capture discovery/assembly for services, Console integration, change
subscriptions, registry reconciliation, loaded driver modules/signers, response
target verification, native fault injection, deadlines, fairness, OS/service
account qualification and resource/soak validation remain open. Kernel signing,
HLK, PPL and ELAM qualification are independent pending work.

Microsoft API references: [EnumServicesStatusExW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-enumservicesstatusexw),
[QueryServiceConfigW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw),
[QUERY_SERVICE_CONFIGW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw).
Additional references: [QueryServiceConfig2W](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2w),
[required privileges](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow),
[launch protection](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_launch_protected_info),
[failure actions](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw),
[documented action types](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-sc_action),
[trigger information](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger_info),
[trigger types](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger),
[trigger-specific data](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger_specific_data_item).
Selected security query: [QueryServiceObjectSecurity](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceobjectsecurity).

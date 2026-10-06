# Held-process primary token context

The native process query opens one primary token from its already retained
PROCESS_QUERY_LIMITED_INFORMATION process handle, using TOKEN_QUERY only.
[OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
can fail even when process metadata is readable. Refusal retains the immediately
captured Win32 status and null value; it never becomes an anonymous user,
unelevated process or caller-token fallback. No privilege, token or policy changes
occur. Account-name resolution is not performed.

[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
queries six selected classes independently on that same token handle:

- User: canonical SID text and raw SID attributes.
- Integrity: raw SID/attributes, a RID only for a single-subauthority mandatory
  label SID, and a known level only for an explicitly recognized RID.
- Elevation: raw DWORD and the documented nonzero elevation Boolean.
- Elevation type: raw enum and recognized default/full/limited label.
- Session ID: exact decimal DWORD, with no inferred session entity.
- Statistics: TokenId, AuthenticationId and ModifiedId LUID components/full-width
  values, raw token type, group count and privilege count.

Raw integer values remain decimal strings. LUIDs require native host/boot scope;
they do not become global token or logon identities. Multiple tokens may share
an AuthenticationId. Expiration and primary-token impersonation-level fields
are not interpreted, following the validity limits of
[TOKEN_STATISTICS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_statistics).
Group/privilege counts do not imply that their contents or effective permissions
were collected. A primary token does not establish a thread's impersonation token.

Each information buffer starts at the class's structure size, permits at most
two resizes and is capped at 64 KiB. A zero-size TokenElevation probe returned
Win32 24 on the actual host; starting with the structure size avoids that invalid
probe without suppressing other errors. Returned lengths, fixed structures and
SID pointers are checked before reads. SID revision, count, alignment and total
length must fit the returned buffer before native SID functions run. Null,
truncated, outside, unaligned and excessive-count SIDs are refused. Validation
and collection-bound errors use separate domains from native Win32 failures.
Unknown integrity/elevation-type values remain raw and degraded.
Elevation type and statistics token type are decoded as raw DWORDs without
loading unknown bit patterns into C++ enums. An integrity RID label such as
protected_process is a label observation, not proof of process PPL/signing.

Every field keeps its own state/source/error. The selected-token fact remains
degraded whenever some attributes are available, or unavailable when none are.
It always says inventory_complete=false and same_token_non_atomic_fields:
the token can change between queries. Manifest-bound health counts opened tokens,
failed opens, successful/failed field queries and uninterpreted fields; the process
query-not-attempted count also applies. Counts include queried rows that a later
bound/refusal may prevent from being delivered, rather than guaranteed retained
membership or lost events. Paged process state version 1.3 and single-prefix
version 1.2 introduced these facts; later versions preserve them. Manager retains
them without reinterpretation. See [current process state](PROCESS_STATE.md).

Native owned-process checks compare SID, session, elevation, LUID and counts with
independent API calls, verify invalid-handle status without caller fallback, and
exercise bounded SID validation and unknown integrity RID handling. Compiled
records pass schema/Manager/Detection preservation and actual agent crash/reopen
checks bind token summaries to retained pages and committed health.

Complete groups/privileges/restricted SIDs/capabilities/AppContainer/claims,
effective access, thread impersonation, token changes/reconciliation, correlated
logon/session entities, API fault/resize injection, native deadline/resource
qualification, protected/privileged targets and service/OS compatibility remain
open. No complete user/session or process lifecycle coverage is claimed.

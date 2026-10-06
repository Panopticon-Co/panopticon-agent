# Decoded source facts and normalization failure evidence

Canonical observations retain `data.source_facts`, representation
`decoded_source_facts_v1`, independently of legacy normalized aliases. It contains
every field currently present in the five RawEvent structures: process, network,
file, registry and image-load; exact signed nanosecond source time; decimal uint64
record/creation tokens; source kind/provider/channel; and nullable original values.
This is the decoded fact boundary, not original ETW bytes or rendered Event Log XML.
Fields which the adapter never decoded remain unavailable.

Empty strings, embedded NULs, false and null remain distinct. Valid UTF-8 stays
text without Unicode normalization. Invalid UTF-8 is an object with
`encoding=hex`, lowercase `bytes`, and decimal `byte_length`; consumers can
reconstruct those exact bytes. No replacement characters are introduced.
Validation uses the explicit byte length and `MB_ERR_INVALID_CHARS`, consistent
with the [Windows conversion API](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar).
Enum values preserve the underlying numeric value: source kinds ETW 0/Sysmon 1/
Event Log 2; direction inbound 0/outbound 1; protocol TCP 0/UDP 1/other 2; file
create 0/remove 1/rename 2; registry add-key 0/delete-key 1/set-value 2/rename-key 3.
Representation revisions must preserve or explicitly migrate these meanings.

Sysmon's GUID/PID-matched cache now attaches a separate candidate context, leaving
the event's decoded executable/user fields unchanged. Canonical `data.enrichment`
retains that candidate's originating provider/channel/record ID/start time,
GUID/PID and image/user facts, and whether it is applicable. Normalization uses
it only for an unresolved image after provider/channel/kind/GUID/PID agreement;
observed user fields take precedence. It cannot invent a native creation token.
Candidate cache residency is bounded and is not durable complete process state.

Normalizer refusal, normalization exceptions and canonical serialization errors
produce `kind=evidence`, `category=normalization_failure`. Agent provenance names
`Officer-Decoded-Facts`; source facts keep the original native source separately.
The evidence capture timestamp is current; original source time is preserved even
when it cannot be rendered as a UTC date. Exact native identity remains usable
when available. Invalid/oversized GUID or source scope cannot manufacture a source
alias; those original fields remain in facts while the subject stays unresolved
unless independently exact native identity exists. These candidates require later
reprocessing rather than arbitrary truncation to fit an envelope.

Failure evidence uses the same encrypted journal/protocol 2 path as observations.
The callback reports success only after durable acceptance. Journal refusal now
increments pipeline admission accounting and throws back to the collector, which
counts a sink failure for subsequent source supervision. Health separately exposes
normalization/serialization failures, committed failure evidence and observation
admission failures. These counters overlap by stage and must not be summed into a
unique lost-event count. Runtime counters reset on process restart.

This does not establish capture before all decoding/enrichment, nor guarantee
acceptance during disk exhaustion. Native decode/render failures still need raw
evidence retention. Allocation failure, source facts beyond the current 1 MiB
journal record limit, fault intent/reserve, collector isolation, stage checkpoint
recovery, privacy/configuration enforcement and enlarged-payload performance
qualification remain open. Registry value data is serialized only when it already
exists in the decoded structure; this feature does not enable new collection.
The new payload increases record size; earlier small-record throughput numbers
are not qualifications of this representation.

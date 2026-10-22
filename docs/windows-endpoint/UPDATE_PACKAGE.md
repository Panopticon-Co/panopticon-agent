# Windows update package verification and staging core

`deployment::UpdatePackageStore` is a source-level AJ foundation. It validates a
bounded, canonical, versioned JSON payload inside a signed envelope; verifies
ECDSA P-256 with one of at most eight caller-provisioned pinned SPKI keys; and
copies a bounded package to a pre-created fixed staging root while hashing the
same open source handle. The signed manifest binds product, monotonic
generation, version, architecture, byte count and SHA-256 package identity.
Issue/expiry checks, a 30-day maximum validity, five-minute future clock skew,
and x64/ARM64 architecture matching are enforced.

The stager rejects a lower generation and rejects a same-generation fork. An
identical already-staged generation is idempotent only after re-hashing its
staged file. A per-root interprocess lock serializes metadata transitions. The
package is promoted under a generation-and-digest-derived filename; the
high-water record and previous signed manifest/path are atomically replaced
with write-through metadata. If metadata replacement fails after content
promotion, the package is left as an orphan for safe retry/reconciliation and
the durable generation is not advanced. A rollback intent validates the
previous signed manifest and re-hashes the candidate before recording the
selection; it does not perform an installation or rollback.

## Trust and safety boundary

The staging root must already exist on a local fixed-volume path. The
constructor rejects relative/non-normalized paths and reparse-point components,
and validates the opened directory handle's owner and protected DACL. Only
SYSTEM, Administrators and the running service identity may receive write or
delete rights. Lock, state, temporary and staged file handles undergo the same
write/delete-principal check; temp-to-final rename preserves the validated file
object's security descriptor. The source package must be an ordinary
non-reparse file. The caller must provision the root with a restrictive
service-owned ACL and deliver publisher pins through an independently
authenticated installation channel. The core does not provision trust, change
ACLs, enroll devices, download packages,
install or execute anything, load plugins, run shell commands, or accept
arbitrary package actions. Callers remain responsible for authenticating the
command that requests staging and authorizing any rollback-intent operation.

The signed manifest format is `panopticon_signed_update_manifest_v1`; its
`payload` is exact canonical UTF-8 JSON and its signature is base64-encoded
64-byte IEEE P1363 `r || s`, over SHA-256 of
`PANOPTICON-WINDOWS-UPDATE-MANIFEST-V1\0` followed by those exact payload bytes.
The closed payload v1 fields are `schema_version`, `product`, `generation`,
`version`, `architecture`, `package_size`, `package_sha256`,
`issued_at_unix_ms`, and `expires_at_unix_ms`. Package size is capped at 512
MiB and manifest/payload sizes at 64 KiB.

## Remaining AJ work and evidence

No tests, build, or Windows runtime validation have been run for this slice.
Root ACL provisioning and runtime ACL qualification, version-compatibility policy, supported installer/MSI and service migration,
startup recovery, authorized install/rollback orchestration, result/audit
integration, recovery after power loss, package signature catalog validation,
and Windows compatibility/qualification remain unimplemented. This component
is verified only by source inspection and must be treated as unverified; AJ
remains partial. It does not qualify secure update or deployment.

## Publisher trust-bundle lifecycle primitive

`PublisherTrustStore` is an additional source-level primitive using the same
pre-created local fixed-volume, protected service-owned state root. The caller
must provide one to eight bootstrap ECDSA P-256 SPKI pins through an
independently authenticated provisioning boundary. No bootstrap key is bundled
or invented. A closed `panopticon_signed_publisher_trust_v1` envelope signs the
exact canonical UTF-8 payload over SHA-256 of
`PANOPTICON-WINDOWS-PUBLISHER-TRUST-V1\0` plus payload bytes. The bounded v1
payload contains product, generation, issue/expiry times, and up to eight
publisher entries with SPKI SHA-256 identity, activation, retirement and
revocation timestamps. DER keys are checked as importable ECDSA P-256.

Generation rollback is rejected; the same generation and same canonical
payload is idempotent, while a same-generation fork is rejected. Rotating
non-revoked keys require at least 24 hours of overlap. A bundle must have at
least one currently active, non-revoked key. State is written under the
interprocess root lock using flushed temporary content and atomic write-through
replacement; root and state file ACL/reparse checks are enforced. `snapshot()`
returns `unknown` when no state exists and `unavailable` for unreadable,
unauthenticated, expired or otherwise invalid state; unavailable snapshots
return no trusted keys. Consumers must check state and use only
`active_publishers` for new manifest verification.

`UpdatePackageStore(root, PublisherTrustStore&)` now obtains the authenticated
active publisher set from a fresh snapshot at the supplied staging time. It
fails closed when trust is unknown, unavailable, expired or has no active key.
The trust and staging roots must be the same protected directory so bundle
installation and package staging serialize under one interprocess lock. Each
new durable package high-water state retains the exact signed trust bundle
that authorized its manifest, and keeps the prior bundle with the previous
manifest. During later generation changes and rollback-intent verification,
the bootstrap signature and key validity interval are rechecked against those
historical bundles. Legacy state without this provenance is accepted only if
the current authenticated bundle can establish the old manifest's issue-time
key; otherwise the operation fails closed. Existing generation, fork, package
hash and staged-file checks remain in force.

The static-pin constructor remains as a deprecated compatibility API. It is
explicitly scoped to a fixed caller-provided pin set and cannot enforce key
activation or revocation. The caller must provision bootstrap pins and install
signed bundles through an authenticated lifecycle outside this component; no
bootstrap key or service/command integration is supplied. Trust-bundle
persistence/rotation/revocation and package provenance retention are implemented
only at source level; crash/power-loss recovery has not been built, tested, or
run on Windows. This is not yet an operational trust-root lifecycle or secure
update capability.

## Abandoned transaction temporary recovery

Each trust install, package stage, and rollback-intent transaction scans three
exact temporary-name families while holding the shared interprocess state lock.
Files left by a crashed process are opened with `FILE_FLAG_OPEN_REPARSE_POINT`,
checked as non-directory/non-reparse objects, checked against the service-root
write/delete ACL policy, and marked for deletion through the validated handle.
The scan is capped at 4,096 candidates and fails closed on unsafe objects,
sharing/access errors, or incomplete enumeration. It does not delete
content-addressed package files, infer that a staged package is committed, or
advance update/trust state. This is source-only recovery logic; crash injection,
concurrent scanner behavior, disk-full behavior, and Windows runtime validation
remain outstanding.

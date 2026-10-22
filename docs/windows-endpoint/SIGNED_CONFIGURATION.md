# Windows signed configuration foundation

`configuration::PolicyStore` is an isolated configuration core included in the Windows `officer-core` build target. It is not wired into startup, CLI options, service lifecycle, collectors, Manager, or deployment. That runtime integration is required before any existing collector can claim policy-controlled activation. No independent trust root is provisioned, so the safe boundary remains inactive and unconnected.

## Contract implemented here

The signed envelope has exactly four fields: `format` (`panopticon_signed_policy_v1`), `key_id`, `payload`, and `signature`. `payload` is an exact UTF-8 JSON string, not a reserialized object. The signature is the 64-byte IEEE P1363 `r || s` ECDSA P-256 signature over SHA-256 of `PANOPTICON-WINDOWS-CONFIG-V1\0` followed by the exact payload bytes. `key_id` is lowercase SHA-256 hex of the exact DER SubjectPublicKeyInfo. Windows Crypt32 imports the pinned DER public key and CNG verifies the signature; ambient certificate stores and certificate-chain discovery are not used.

Payload schema version 1 is closed and bounded. It requires a strictly positive generation, issue and expiry times, all nine named feature booleans, and exactly four integer limits. Lifetime is at most 30 days, issue time allows at most five minutes of clock skew, and each limit has fixed hard bounds in the implementation. Unknown top-level fields, feature names, and limit names are rejected. There are no command, script, arbitrary path, plugin, response-action, or registry-write fields.

`activate()` verifies the envelope and schema before it persists a desired policy. It rejects expired input, stale generations, same-generation forks, and weakening transitions. A policy may add collection features, increase sampling, shorten its interval, or raise resource ceilings; it cannot reverse those changes. It does not start collectors. New features stay `pending` until the integration starts the authorized collector and calls `confirm_effective()` with the actually running feature set. The feature remains `unsupported` when the caller says the platform/source cannot support it. A failed state commit means the caller must stop or withhold collection until it rereads a valid committed state. `confirm_effective()` may also remove a feature from the observed effective set after a collector stops or fails; the signed desired feature remains enabled and reports `pending` or `unsupported` until it is running again.

State is a single bounded record containing the desired signed envelope, current effective signed envelope, rollback envelope, highest accepted generation/digest, and runtime effective feature set. The temporary file is created beside the state file, fully written and flushed, then promoted with `ReplaceFileW` or first-created with `MoveFileExW(..., MOVEFILE_WRITE_THROUGH)`. Rollback uses the same atomic replacement and retains the high-water generation. Rollback is refused if it would weaken policy or deactivate a feature reported effective. On restart, policy expiry, malformed state, signature failure, or a generation/digest mismatch leaves collection unauthorized/effectively off.

## Trust and storage integration contract

The caller must supply one to eight pinned ECDSA P-256 SPKI DER keys. For rotation, supply the old and new pins concurrently in a trust set delivered by a separately authenticated installer/update mechanism, then retire the old pin in a later authenticated update. This component does not implement or claim that root of trust, trust-set signing, secure enrollment, key custody, private-key generation, rotation authorization, revocation, or recovery. Do not populate the trust set from the policy being verified or from an unauthenticated Manager response.

Build integration adds `src/configuration/policy.cpp` to `officer-core` and links the Windows `bcrypt` and `crypt32` libraries required by the CNG and Crypt32 verification calls. The target change is source-reviewed but was not built or tested in this wave.

The state-file parent must already exist and have a service-owned Windows ACL that denies untrusted users write/delete/rename access. The component deliberately does not choose an installation path, change ACLs, elevate privileges, seal keys in TPM/DPAPI, or defend the high-water record from a local administrator. File replacement is atomic on the same volume; power-loss behavior and filesystem-specific durability still require Windows VM fault qualification. The integrator must check the returned commit outcome and reread state after ambiguous I/O failures.

## Required endpoint integration

1. Install trust pins from the independently authenticated product installation/update path and create a protected state directory.
2. Before launching policy-gated collectors, load committed state and refuse startup when it is absent, invalid, expired, unsupported, or otherwise unauthorized. An absent policy means every feature is `unauthorized` and ineffective.
3. Authenticate/verify the remote transport separately. Pass only the exact signed envelope bytes to `activate()`; network TLS is not a substitute for the policy signature.
4. Apply only the fixed feature and limit fields. Reconcile collector starts/stops, then record observed effective state through `confirm_effective()`. Never map policy strings to shell commands, dynamic libraries, arbitrary paths, or response execution.
5. Expose desired state, effective state, unsupported/pending reasons, generation, digest, expiry, and storage/signature errors in health and audit records. Do not report policy enforcement merely because a collector is compiled or desired.
6. Gate rollback through a separately authorized local operator/control path. Remote policy cannot invoke rollback as an arbitrary command.

No tests or builds were run for this integration, as requested. The trust-root lifecycle, caller authorization, startup loading, actual collector reconciliation, Manager transport/contract, ACL setup, post-replacement durability qualification, migration of existing CLI controls, and real Windows/VM qualification remain unimplemented. The policy core is build-integrated but runtime-unintegrated and therefore does not currently control collection.

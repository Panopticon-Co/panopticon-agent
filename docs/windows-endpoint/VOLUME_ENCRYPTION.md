# Read-only BitLocker volume status

The independent `volume_encryption_worker` captures
`Win32_EncryptableVolume` from
`ROOT\CIMV2\Security\MicrosoftVolumeEncryption` every five minutes. It
retains a bounded set of caller-visible `DeviceID`, `DriveLetter`, and
`PersistentVolumeID` properties, then separately invokes only the documented
read methods `GetProtectionStatus`, `GetConversionStatus` and
`GetEncryptionMethod`. Each method record separates the COM/WMI call HRESULT
from the provider's `ReturnValue`, and retains each output-property HRESULT and
raw numeric value. Conversion precision is supplied as the documented value 0.
No encryption, protection, key-protector, locking, unlock, or other
state-changing method is called.

Microsoft documents the class and methods in the
[Win32_EncryptableVolume reference](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume),
[GetProtectionStatus](https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume),
[GetConversionStatus](https://learn.microsoft.com/en-us/windows/win32/secprov/getconversionstatus-win32-encryptablevolume), and
[GetEncryptionMethod](https://learn.microsoft.com/en-us/windows/win32/secprov/getencryptionmethod-win32-encryptablevolume).
The documented status and method enums are labeled; unknown values remain raw
and degraded. A protection status of `on` is a provider report, not an
independent proof that the disk is currently encrypted or that protection is
effective.

Bounds are 64 volume rows, 4 KiB per returned identifier string, 32 KiB per
encoded row, and 512 KiB for encoded entries. Enumeration timeout, row/byte
bound excess, method HRESULTs, provider return codes, output getter HRESULTs and
invalid values remain explicit. The capture is sequential and non-atomic. A row
is associated only with the identifiers returned by this provider; there is no
join to physical disk, partition, mount graph, hardware, or other volume
inventory. Identifiers may be sensitive. The collector does not query key
protectors, recovery passwords, TPM state, recovery-key escrow, encryption
policy provenance, or whether hardware encryption is trustworthy.

The worker writes one immutable state record and exposes committed query health
only after durable acceptance. It is independent from host inventory and other
WMI workers. Microsoft documents the class in the
`ROOT\CIMV2\Security\MicrosoftVolumeEncryption` namespace and states that
method access requires administrator privileges. WMI namespace ACLs, BitLocker
service/provider availability and volume lock state can cause partial or
unavailable results. Connect/query/method calls are synchronous; `Next` uses a
bounded one-second wait, but there is no hard deadline or cancellation for WMI
calls. A hung call can delay worker shutdown. COM and WMI native allocations
are not bounded by the copied-output limit.

The source is registered in the Windows `officer-core` target, but this wave did
not build or runtime-validate it. Privilege and service
coverage, locked/removable/data volumes, event-source availability, crash/replay,
method return/output variations, Windows editions, hardware encryption,
key-protector configuration, and escrow remain unverified. See [capability
matrix](CAPABILITY_MATRIX.md) and [validation ledger](VALIDATION.md).

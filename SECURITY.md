# Security Policy

Officer collects live Windows telemetry and executes response actions
(including process termination, file quarantine, and host network isolation)
when explicitly enabled by an operator. Please report suspected security
issues responsibly.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** Public
issues are visible to everyone, including anyone who might exploit the report
before a fix ships.

Instead, report privately through GitHub Security Advisories:

<https://github.com/Panopticon-Co/panopticon-agent/security/advisories/new>

Please include, where possible:

- A clear description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- The affected version/commit and target platform (`arm64-windows` /
  `x64-windows`).
- Any relevant logs or output (sanitized — do not include real telemetry,
  hostnames, credentials, or personal data; see "Privacy and safety" in
  [README.md](README.md)).

## Scope

This repository is the Windows endpoint agent ("Officer") component of the
Panopticon-Co capstone/research platform. In scope: the telemetry collectors,
normalization/serialization pipeline, delivery client, and the response
module (command parsing, gating, and the 7 closed-set Win32 actions). Issues
in sibling repositories (`panopticon-detection-engine`, `panopticon-manager`,
`panopticon-contracts`) should be reported to those repositories instead.

## Response expectations

Panopticon is a capstone/research project maintained on a best-effort basis.
There is no service-level agreement for response or fix times. We will
acknowledge reports as promptly as we reasonably can and keep the reporter
informed as the issue is investigated and, if applicable, fixed.

## Supported versions

This project does not yet maintain multiple release branches. Security fixes
are applied to the latest code on `main`.

# Contributing to Officer

Officer is the Windows endpoint agent for Panopticon, a cybersecurity/EDR
capstone platform. This guide covers how to build, test, and submit changes.
For the architecture and current status, start with [README.md](README.md).

## Prerequisites

- Windows 10/11 (arm64 or x64).
- Visual Studio 2022+ with the "Desktop development with C++" workload
  (provides the MSVC toolchain and Developer PowerShell).
- [CMake](https://cmake.org/) 3.20 or newer.
- [Ninja](https://ninja-build.org/) (used as the generator in the commands
  below and in CI).
- [vcpkg](https://github.com/microsoft/vcpkg), for `nlohmann-json` and
  `tinyxml2` (declared in `vcpkg.json`, pinned to the `builtin-baseline` in
  that file).
- Administrator/elevated PowerShell if you intend to run live ETW/Sysmon
  collection or exercise the response module's Win32 actions locally — build
  and unit tests do not require elevation.

## Clone

```powershell
git clone https://github.com/Panopticon-Co/panopticon-agent.git
cd panopticon-agent
```

Optionally, clone [panopticon-contracts](https://github.com/Panopticon-Co/panopticon-contracts)
as a sibling directory (`../panopticon-contracts`, next to this repo) if you
want `officer-response-tests` to also exercise the shared cross-repo response
contract fixtures. This is exactly what CI does (see
`.github/workflows/ci.yml`); the tests skip those cases gracefully if the
sibling checkout is absent.

## Build

From a Developer PowerShell matching your target architecture (Arm64 or x64
Developer PowerShell for Visual Studio, or any shell with `VCToolsInstallDir`
set for your target):

```powershell
cmake -S . -B build-officer-x64 -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE="<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows

cmake --build build-officer-x64
```

Substitute `arm64-windows` and a `build-officer-arm64` build directory for an
ARM64 build. Officer's CMake configuration is triplet-driven with no
architecture-specific source, so the same commands apply to either target.

## Test

```powershell
ctest --test-dir build-officer-x64 --output-on-failure
```

This runs the full suite defined in `CMakeLists.txt`: contract/serialization
tests (`officer-core-tests`), collector decoder tests
(`officer-collector-tests`), a CLI smoke test (`officer-agent --help`),
delivery tests (`officer-delivery-tests`), and response-module tests
(`officer-response-tests`). All fixtures used by these tests are sanitized
(see "Privacy and safety" in the README) — never add real captured telemetry.

There is no fuzzing or sanitizer configuration (ASan/UBSan) wired into the
build or CI today; if you add one, document it here and in CI rather than
leaving it undiscoverable.

## Continuous integration

Every push and pull request to `main` runs `.github/workflows/ci.yml` on
`windows-latest`: it checks out this repo and a sibling
`panopticon-contracts` checkout, bootstraps vcpkg, configures and builds for
`x64-windows`, and runs the full `ctest` suite. A PR should pass this
workflow before it is merged.

## Branch and commit workflow

- Create a feature branch off `main` for any non-trivial change; small,
  obvious fixes can go straight to a PR from a short-lived branch.
- Keep commits focused and single-purpose rather than large mixed commits.
  Follow the existing commit style visible in `git log`, e.g.:
  - `feat(response): implement Windows response module (7 closed actions)`
  - `test(response): add officer-response-tests`
  - `build: validate and document Windows x64 target`
  - `docs: explain Officer's role in Panopticon`
  - `fix: ...`, `chore: ...`, `ci: ...`
- Do not rewrite shared history (no force-push over commits others may have
  pulled) unless a maintainer explicitly asks for it.

## Pull requests

- Use the PR template (`.github/pull_request_template.md`) — it will be
  applied automatically.
- Describe what changed and why, not just what.
- Call out any change to the Panopticon event schema (`schema/event.schema.json`)
  or the Manager response command contract explicitly: these are the API
  boundary with other Panopticon repositories, and changes need a
  compatibility note plus updated tests on both sides where applicable.
- Note any security-relevant change (anything touching elevation, the
  response module's authorization/replay/target-checking logic, or file/path
  handling) in the PR's Security Impact section.
- Ensure `cmake --build` and `ctest` pass locally before requesting review;
  CI will also verify this.

## Scope boundaries

- Do not add a dependency on another Panopticon repository's source tree.
  The only integration surfaces are the build artifact
  (`officer-agent.exe`), the Panopticon event schema, and the Manager's HTTP
  command/result contract.
- Do not add a new response action outside the closed set of 7
  (`KILL_PROCESS`, `COLLECT_PROCESS_INFO`, `COLLECT_NETWORK_CONNECTIONS`,
  `COLLECT_FILE`, `QUARANTINE_FILE`, `ISOLATE_HOST`,
  `RELEASE_HOST_ISOLATION`) without first discussing it — this set is a
  deliberate, reviewed security boundary shared with the Manager and
  `panopticon-linux-agent`.
- Do not commit raw XML, NDJSON, EVTX files, or real captured telemetry —
  see "Privacy and safety" in the README.

## Reporting security issues

Do not open a public issue for a suspected vulnerability. See
[SECURITY.md](SECURITY.md) for private reporting instructions.

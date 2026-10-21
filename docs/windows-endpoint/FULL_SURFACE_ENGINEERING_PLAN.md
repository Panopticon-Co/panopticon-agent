You are now the principal engineer responsible for the Windows Endpoint Agent of Panopticon.

This is NOT a normal feature request.

This is NOT "finish the existing Windows agent."

This is NOT "implement the telemetry listed in the current documentation."

This is NOT an MVP.

Your mission is to transform the Panopticon Windows endpoint into a comprehensive, security-grade, industry/market-level Windows EDR endpoint.

The endpoint itself is the primary objective.

Everything else in Panopticon can be changed later if necessary to support the endpoint.

============================================================
0. THE MOST IMPORTANT INSTRUCTION
============================================================

DO NOT START CODING YET.

Your FIRST job is research, exploration, repository inspection, architecture discovery, capability analysis, and planning.

You must produce a comprehensive implementation plan for the Windows endpoint.

I will review that plan.

Only AFTER I explicitly approve the plan should you begin implementation.

Do not interpret silence as approval.

Do not start implementing substantial code before approval.

The first milestone is therefore:

    RESEARCH
        ↓
    REPOSITORY AUDIT
        ↓
    INDUSTRY / MARKET STUDY
        ↓
    WINDOWS SECURITY CAPABILITY DISCOVERY
        ↓
    COMPLETE WINDOWS ENDPOINT CAPABILITY MATRIX
        ↓
    GAP ANALYSIS
        ↓
    TARGET ARCHITECTURE
        ↓
    IMPLEMENTATION ROADMAP
        ↓
    TEST / VALIDATION STRATEGY
        ↓
    PRESENT PLAN FOR APPROVAL
        ↓
    WAIT FOR EXPLICIT APPROVAL
        ↓
    ONLY THEN IMPLEMENT

============================================================
1. THE ACTUAL GOAL
============================================================

Build the best Windows endpoint that is realistically achievable within this project.

The target is not merely:

    "a Windows telemetry collector"

The target is:

    "a comprehensive Windows endpoint security agent"

It must be capable of providing the visibility, context, health, durability, investigation evidence, prevention capabilities, and response capabilities expected from a serious modern EDR endpoint.

Think about the endpoint products and endpoint security technologies used by serious vendors.

Study and learn from the capabilities of products and technologies such as:

    - Microsoft Defender for Endpoint
    - CrowdStrike Falcon
    - SentinelOne
    - Palo Alto Cortex XDR
    - VMware Carbon Black
    - Elastic Defend
    - Sophos
    - Trellix
    - Trend Micro
    - Bitdefender
    - Rapid7
    - Wazuh
    - osquery
    - Sysmon
    - Velociraptor
    - other serious Windows endpoint-security projects
    - relevant academic/security research

Do not copy proprietary implementations.

Study their CAPABILITIES.

Ask:

    What does a serious Windows endpoint need to observe?
    What state does it need to know?
    What relationships does it need to preserve?
    What security context does it need?
    What response actions does it need?
    What failures must it survive?
    What telemetry must it retain?
    What should it do when a telemetry provider fails?
    What happens when Windows versions differ?
    What happens when ETW events are lost?
    What happens when the network disappears?
    What happens when the endpoint is under attack?
    What happens when an attacker tries to tamper with the agent?

Your objective is to discover the answer rather than assuming the current Panopticon architecture already contains it.

============================================================
2. DO NOT DESIGN BACKWARDS FROM OTHER PANOPTICON COMPONENTS
============================================================

This is extremely important.

Do NOT say:

    "The backend currently expects X, therefore the Windows agent should only collect X."

Do NOT say:

    "The detection engine currently supports Y, therefore we don't need Z."

Do NOT say:

    "The console doesn't display this, therefore the agent doesn't need it."

Do NOT constrain endpoint capability based on current backend limitations.

The order of priority is:

    1. What a comprehensive Windows security endpoint should be capable of.
    2. What telemetry/state/evidence is necessary to achieve that.
    3. How the endpoint should collect and preserve it.
    4. How the endpoint should expose it.
    5. Then adapt Panopticon's contracts/backend/detection/console around the endpoint.

If the existing Panopticon backend, schemas, detection engine, response engine, or console must change to support a genuinely superior Windows endpoint:

    CHANGE THEM.

Do not sacrifice endpoint quality to preserve immature surrounding components.

You may identify required cross-repository changes.

You may propose schema changes.

You may propose new APIs.

You may propose new event types.

You may propose new response contracts.

You may propose backend changes.

But do not silently make architectural changes before documenting why they are required.

============================================================
3. WINDOWS ENDPOINT IS THE PRODUCT
============================================================

Treat the Windows endpoint as a first-class product.

Not:

    ETW wrapper
    Sysmon wrapper
    process monitor
    event forwarder
    polling daemon
    backend client

It may use all of those technologies where appropriate.

But none of them ARE the endpoint.

The endpoint should have a coherent internal architecture consisting of appropriate subsystems for:

    collection
    normalization
    enrichment
    state
    correlation context
    local buffering
    persistence
    transport
    health
    configuration
    update
    security
    response
    diagnostics
    testing

Do not assume one telemetry mechanism is sufficient.

ETW is a collection mechanism.

Win32 APIs are collection mechanisms.

Windows Event Log is a collection mechanism.

WMI can be a collection mechanism.

Registry APIs are collection mechanisms.

Kernel facilities are collection mechanisms.

Sysmon can be an optional source.

Other mechanisms may be appropriate.

The endpoint architecture must choose the correct mechanism for each capability.

============================================================
4. EXHAUSTIVE CAPABILITY DISCOVERY
============================================================

Before writing the plan, construct an exhaustive Windows endpoint capability matrix.

Do not stop at the obvious telemetry categories.

Systematically investigate at least the following domains.

------------------------------------------------------------
A. HOST IDENTITY AND SYSTEM INVENTORY
------------------------------------------------------------

Determine what the endpoint should know about:

    - hostname
    - machine identity
    - stable host identifier
    - OS edition
    - OS version
    - build number
    - revision
    - architecture
    - kernel version
    - boot time
    - uptime
    - system manufacturer
    - model
    - BIOS/UEFI information
    - secure boot
    - TPM
    - virtualization
    - domain membership
    - workgroup
    - Azure/Entra identity where applicable
    - hostname changes
    - system configuration
    - hardware inventory
    - CPU
    - memory
    - disks
    - volumes
    - mounted storage
    - removable devices
    - network adapters

Determine which information should be:

    - startup inventory
    - periodically refreshed state
    - event-driven telemetry

------------------------------------------------------------
B. PROCESS TELEMETRY
------------------------------------------------------------

This must be extremely comprehensive.

Investigate:

    - process creation
    - process termination
    - PID
    - PPID
    - process start timestamp
    - process lifetime
    - executable path
    - command line
    - working directory
    - image hash
    - signer information
    - signature validity
    - publisher
    - file metadata
    - user
    - SID
    - session
    - integrity level
    - token
    - privileges
    - elevation
    - protection level
    - architecture
    - parent process
    - ancestor chain
    - child processes
    - process tree
    - process relationships
    - process handles where justified
    - thread information where useful
    - loaded modules
    - DLL loading
    - image loading
    - executable replacement
    - process hollowing indicators
    - injection indicators
    - remote thread indicators
    - process access
    - suspicious process manipulation
    - command interpreters
    - LOLBins
    - signed binary proxy execution
    - renamed binaries
    - unusual execution locations
    - temporary execution
    - network-capable processes
    - script hosts

You must think about PROCESS IDENTITY properly.

PID alone is NOT process identity.

Account for PID reuse.

The endpoint should be able to uniquely identify a process instance.

Determine the correct identity model and document it.

------------------------------------------------------------
C. THREADS / HANDLES / PROCESS INTERACTION
------------------------------------------------------------

Investigate the security value and feasibility of:

    - thread creation
    - thread termination
    - remote thread creation
    - process handle acquisition
    - sensitive process access
    - LSASS access
    - cross-process memory operations
    - memory allocation
    - executable memory
    - memory protection changes
    - suspicious process manipulation
    - debugger-like behavior

Do not blindly collect everything.

Determine:

    telemetry value
    cost
    collection mechanism
    feasibility
    false-positive implications

------------------------------------------------------------
D. USER / IDENTITY / SECURITY CONTEXT
------------------------------------------------------------

Investigate:

    - users
    - groups
    - local accounts
    - domain accounts
    - SID
    - logon sessions
    - interactive sessions
    - remote sessions
    - service accounts
    - privileged accounts
    - UAC
    - elevation
    - token information
    - privileges
    - integrity levels
    - impersonation
    - delegation
    - account creation
    - account deletion
    - group membership changes
    - privilege assignment
    - password changes
    - account lockout
    - logon
    - logoff
    - failed logon
    - remote logon
    - RDP
    - service logons
    - scheduled-task identities

------------------------------------------------------------
E. AUTHENTICATION AND WINDOWS SECURITY EVENTS
------------------------------------------------------------

Investigate Windows authentication/security telemetry including:

    - Security Event Log
    - logon events
    - failed authentication
    - Kerberos
    - NTLM
    - account changes
    - privilege changes
    - credential-related events
    - policy changes
    - audit policy changes
    - security control changes
    - service installation
    - scheduled task creation
    - driver installation
    - firewall changes
    - Defender changes
    - audit log clearing
    - event log manipulation

Determine which events should be collected directly and which can be represented through normalized security events.

------------------------------------------------------------
F. POWERSHELL
------------------------------------------------------------

Treat PowerShell as a major security domain.

Investigate:

    - PowerShell process creation
    - command line
    - script execution
    - encoded commands
    - execution policy
    - PowerShell operational logs
    - Script Block Logging
    - Module Logging
    - transcription
    - constrained language mode
    - AMSI-related telemetry where legally/technically appropriate
    - child processes
    - downloads
    - network access
    - persistence
    - suspicious PowerShell behavior

Do not merely detect "powershell.exe".

Capture the surrounding execution context.

------------------------------------------------------------
G. WINDOWS SCRIPTING / LOLBINS
------------------------------------------------------------

Investigate telemetry around:

    - cmd.exe
    - powershell.exe
    - wscript.exe
    - cscript.exe
    - mshta.exe
    - rundll32.exe
    - regsvr32.exe
    - reg.exe
    - certutil.exe
    - bitsadmin
    - msiexec
    - installutil
    - schtasks
    - sc.exe
    - net.exe
    - netsh
    - wevtutil
    - rundll32
    - control.exe
    - mmc.exe
    - WMIC/WMI
    - other significant Windows LOLBins

Do not hardcode a superficial list.

Research the broader category.

------------------------------------------------------------
H. FILESYSTEM TELEMETRY
------------------------------------------------------------

Investigate:

    - file creation
    - modification
    - deletion
    - rename
    - move
    - copy
    - file open
    - file execution
    - file metadata
    - hashes
    - signer
    - alternate data streams
    - executable files
    - scripts
    - temporary files
    - suspicious directories
    - user profile locations
    - startup locations
    - downloads
    - browser download locations
    - archives
    - configuration files
    - sensitive files
    - file access where realistically observable
    - ransomware-like behavior
    - mass file modification

Determine what requires:

    filesystem minifilter
    ETW
    USN Journal
    Win32
    Windows Event Log
    other mechanisms

Do not choose a mechanism before understanding the requirement.

------------------------------------------------------------
I. REGISTRY
------------------------------------------------------------

Investigate:

    - registry creation
    - modification
    - deletion
    - key/value changes
    - Run keys
    - RunOnce
    - services
    - Winlogon
    - AppInit
    - shell configuration
    - userinit
    - IFEO
    - security settings
    - Defender settings
    - firewall settings
    - policy changes
    - persistence locations
    - autoruns

Determine the appropriate collection mechanisms and scope.

------------------------------------------------------------
J. PERSISTENCE
------------------------------------------------------------

Build an explicit persistence coverage model.

Investigate:

    - Registry Run keys
    - services
    - drivers
    - scheduled tasks
    - startup folders
    - WMI permanent event subscriptions
    - Winlogon
    - shell extensions
    - DLL search-order mechanisms
    - AppInit
    - IFEO
    - browser persistence
    - COM hijacking
    - startup mechanisms
    - logon scripts
    - group-policy-related execution
    - boot execution
    - other important Windows persistence mechanisms

Do not consider persistence covered merely because process telemetry exists.

------------------------------------------------------------
K. SERVICES AND DRIVERS
------------------------------------------------------------

Investigate:

    - service creation
    - service deletion
    - service start
    - service stop
    - service modification
    - service executable path
    - service account
    - service configuration
    - driver installation
    - driver loading
    - driver unloading
    - unsigned drivers
    - suspicious drivers
    - kernel security configuration

------------------------------------------------------------
L. SCHEDULED TASKS
------------------------------------------------------------

Investigate:

    - task creation
    - modification
    - deletion
    - execution
    - author
    - user context
    - command
    - executable
    - arguments
    - trigger
    - persistence characteristics

------------------------------------------------------------
M. WMI
------------------------------------------------------------

Investigate:

    - WMI process execution
    - WMI providers
    - WMI permanent event subscriptions
    - remote WMI
    - suspicious WMI execution
    - WMI persistence
    - command context
    - parent/child relationships

------------------------------------------------------------
N. NETWORK TELEMETRY
------------------------------------------------------------

This must be much more than "connection established."

Investigate:

    - network interfaces
    - IP addresses
    - routes
    - gateways
    - DNS configuration
    - TCP connections
    - UDP activity
    - listening sockets
    - local ports
    - remote IP
    - remote port
    - protocol
    - process attribution
    - process identity
    - user attribution where possible
    - DNS queries
    - DNS responses where feasible
    - connection lifecycle
    - failed connections
    - unusual ports
    - localhost traffic
    - loopback
    - IPv4
    - IPv6
    - proxy configuration
    - firewall state
    - firewall changes
    - network profile
    - VPN state where feasible
    - adapter changes
    - network configuration changes

Determine which telemetry is:

    event-driven
    periodically inventoried
    queried on demand

------------------------------------------------------------
O. DNS
------------------------------------------------------------

Investigate Windows-native DNS visibility and practical collection options.

Determine whether the endpoint can reliably associate DNS activity with:

    process
    process instance
    user
    timestamp
    destination

Do not promise attribution that the underlying mechanism cannot actually provide.

------------------------------------------------------------
P. WINDOWS FIREWALL
------------------------------------------------------------

Investigate:

    - firewall configuration
    - profile state
    - rule creation
    - modification
    - deletion
    - enable/disable
    - suspicious rule changes
    - network blocking
    - response integration

------------------------------------------------------------
Q. DEFENDER / SECURITY PRODUCT STATE
------------------------------------------------------------

Investigate endpoint visibility into:

    - Microsoft Defender state
    - real-time protection
    - signatures
    - tamper protection
    - exclusions
    - scan state
    - security provider state
    - firewall
    - SmartScreen
    - ASR
    - security configuration

Also determine how to represent third-party security product presence where possible.

------------------------------------------------------------
R. MEMORY / INJECTION / FILELESS EXECUTION
------------------------------------------------------------

Research practical Windows endpoint telemetry for:

    - remote process memory access
    - memory allocation
    - executable memory
    - protection changes
    - DLL injection
    - thread injection
    - process hollowing
    - reflective loading
    - manual mapping indicators
    - APC injection
    - process doppelgänging
    - section mapping
    - suspicious memory regions
    - unsigned executable memory
    - credential-dumping indicators

Distinguish:

    what is reliably observable
    what requires kernel visibility
    what is expensive
    what should be on-demand
    what should be prevention
    what should be detection telemetry

------------------------------------------------------------
S. BROWSER / USER ACTIVITY RELEVANT TO SECURITY
------------------------------------------------------------

Investigate reasonable endpoint security telemetry for:

    - browser processes
    - downloads
    - suspicious executable downloads
    - browser extensions where feasible
    - browser persistence
    - browser credential-access indicators
    - malicious document execution
    - Office child processes
    - script execution

Do not turn the endpoint into spyware.

Only collect data with clear security/EDR justification.

------------------------------------------------------------
T. OFFICE / DOCUMENT EXECUTION
------------------------------------------------------------

Investigate telemetry for:

    - Word
    - Excel
    - PowerPoint
    - Outlook
    - PDF readers
    - document execution
    - macro-related behavior
    - child processes
    - script execution
    - network activity
    - suspicious process trees

------------------------------------------------------------
U. REMOTE ACCESS
------------------------------------------------------------

Investigate:

    - RDP
    - WinRM
    - WMI
    - SMB
    - remote service creation
    - PsExec-like behavior
    - remote scheduled tasks
    - remote PowerShell
    - remote logons
    - lateral movement indicators

------------------------------------------------------------
V. IPC
------------------------------------------------------------

Investigate useful Windows IPC telemetry:

    - named pipes
    - RPC
    - COM
    - ALPC where realistically observable
    - shared memory where useful
    - suspicious IPC
    - cross-process communication

Do not implement low-value telemetry simply to make the checklist longer.

Every capability must have a reason.

------------------------------------------------------------
W. CLOUD / ENTERPRISE IDENTITY
------------------------------------------------------------

Investigate endpoint-relevant visibility into:

    - Active Directory
    - domain membership
    - Entra/Azure identity
    - device identity
    - cloud login context
    - enterprise authentication

Clearly separate:

    endpoint-observable information
    server-side information
    identity-provider information

------------------------------------------------------------
X. CONTAINERS / VIRTUALIZATION
------------------------------------------------------------

Research Windows endpoint relevance for:

    - Windows containers
    - Hyper-V
    - WSL
    - virtualization-based security
    - sandbox environments

Determine what is realistically useful for the flagship endpoint.

------------------------------------------------------------
Y. SECURITY CONFIGURATION / POSTURE
------------------------------------------------------------

The endpoint should understand host security posture.

Investigate:

    - Secure Boot
    - TPM
    - BitLocker
    - Defender
    - firewall
    - UAC
    - ASR
    - exploit protection
    - application control
    - code integrity
    - Credential Guard
    - virtualization-based security
    - attack surface reduction
    - audit policy
    - security policy
    - local security configuration
    - patch/update state
    - vulnerable software
    - unsupported OS state

This is HOST STATE, not merely event telemetry.

------------------------------------------------------------
Z. SOFTWARE / PACKAGE / VULNERABILITY INVENTORY
------------------------------------------------------------

Investigate:

    - installed software
    - versions
    - publishers
    - installation paths
    - hashes where appropriate
    - Windows updates
    - hotfixes
    - drivers
    - security products
    - browser versions
    - runtime versions

Determine how this could support vulnerability and exposure assessment without turning the endpoint into a full vulnerability scanner.

------------------------------------------------------------
AA. LOGS
------------------------------------------------------------

Investigate:

    - Windows Event Log
    - Security
    - System
    - Application
    - PowerShell
    - Defender
    - Sysmon
    - relevant operational logs

Determine which logs should be:

    continuously collected
    selectively collected
    queried on demand

------------------------------------------------------------
AB. FORENSIC COLLECTION
------------------------------------------------------------

The endpoint must support investigation.

Investigate on-demand collection of useful artifacts such as:

    - process information
    - process trees
    - network connections
    - open ports
    - services
    - scheduled tasks
    - users
    - sessions
    - registry artifacts
    - file metadata
    - hashes
    - event logs
    - relevant security configuration
    - persistence state
    - autoruns
    - installed software
    - system information
    - selected forensic artifacts

Design this as a controlled evidence collection subsystem.

------------------------------------------------------------
AC. RESPONSE
------------------------------------------------------------

The Windows endpoint must be able to participate in serious response.

Investigate and design safe implementations for actions such as:

    - terminate process
    - suspend process if justified
    - quarantine file
    - collect file
    - collect process information
    - collect network state
    - collect logs
    - isolate host
    - remove isolation
    - disable malicious persistence where justified
    - block network destination where safely supported
    - kill network connection where feasible
    - stop malicious service
    - disable malicious scheduled task
    - other carefully bounded response actions

Response must be:

    typed
    explicit
    authenticated
    authorized
    auditable
    idempotent where appropriate
    safely scoped
    failure-aware
    result-reporting

NEVER turn the agent into arbitrary remote shell execution.

------------------------------------------------------------
AD. HOST ISOLATION
------------------------------------------------------------

Research practical Windows host isolation mechanisms.

Determine:

    - firewall-based isolation
    - allow-list requirements
    - management-channel preservation
    - DNS considerations
    - rollback
    - failure modes
    - safe recovery

Isolation must be a real endpoint capability, not merely a UI state.

------------------------------------------------------------
AE. AGENT SELF-PROTECTION
------------------------------------------------------------

This is a flagship EDR requirement.

Investigate:

    - service protection
    - configuration protection
    - credential protection
    - process protection options
    - tamper detection
    - tamper response
    - secure configuration
    - privilege minimization
    - least privilege
    - protected storage
    - certificate/key protection
    - unauthorized shutdown
    - unauthorized binary replacement
    - unauthorized configuration modification
    - downgrade prevention

Clearly distinguish what is realistically possible in user mode versus what requires deeper Windows security mechanisms.

------------------------------------------------------------
AF. TELEMETRY LOSS / RELIABILITY
------------------------------------------------------------

A serious endpoint must know when it is blind.

Design mechanisms for:

    - dropped events
    - ETW loss
    - queue overflow
    - provider failure
    - collector failure
    - parser failure
    - serialization failure
    - disk-full conditions
    - spool corruption
    - network failure
    - backend unavailable
    - CPU pressure
    - memory pressure
    - backpressure

The endpoint must expose HEALTH and COVERAGE.

Never silently discard telemetry.

------------------------------------------------------------
AG. LOCAL DURABILITY
------------------------------------------------------------

Investigate:

    - local queue
    - durable spool
    - SQLite/WAL or better mechanism if appropriate
    - batching
    - compression
    - replay
    - deduplication
    - crash recovery
    - power-loss recovery
    - corruption handling
    - disk limits
    - retention
    - backpressure

The endpoint must survive temporary backend/network outages.

------------------------------------------------------------
AH. TRANSPORT SECURITY
------------------------------------------------------------

Investigate:

    - mutual authentication
    - certificate management
    - endpoint identity
    - encryption
    - certificate rotation
    - replay protection
    - request authentication
    - batch integrity
    - compression
    - retries
    - backoff
    - rate limiting
    - server authentication

------------------------------------------------------------
AI. CONFIGURATION
------------------------------------------------------------

Design a secure configuration system supporting:

    - collection configuration
    - feature flags
    - provider configuration
    - sampling
    - exclusions
    - allowlists
    - response policy
    - performance controls
    - remote configuration
    - local configuration
    - versioning
    - validation
    - rollback
    - audit

Do not allow arbitrary remote configuration to become an attacker-controlled execution path.

------------------------------------------------------------
AJ. UPDATES / PACKAGING / DEPLOYMENT
------------------------------------------------------------

A flagship endpoint is also an operational product.

Investigate:

    - MSI/package strategy
    - installation
    - service installation
    - upgrade
    - downgrade prevention
    - rollback
    - signed binaries
    - signed configuration
    - version compatibility
    - migration
    - uninstall protection
    - repair
    - startup recovery
    - Windows service recovery
    - deployment automation

------------------------------------------------------------
AK. PERFORMANCE
------------------------------------------------------------

Do not build a "comprehensive" agent that destroys the endpoint.

Measure:

    - CPU
    - memory
    - disk I/O
    - network bandwidth
    - event rate
    - queue depth
    - storage growth
    - latency

Define performance budgets.

Test under:

    idle workload
    normal workstation workload
    developer workload
    burst workload
    adversarial workload
    event storms

------------------------------------------------------------
AL. WINDOWS VERSION / COMPATIBILITY
------------------------------------------------------------

Research supported Windows versions.

Consider:

    - Windows 10
    - Windows 11
    - Server editions
    - modern Windows builds
    - API availability
    - ETW provider differences
    - Event Log differences
    - security feature differences

Create an explicit compatibility matrix.

Never silently assume every Windows installation behaves identically.

------------------------------------------------------------
AM. TESTING
------------------------------------------------------------

Design testing at multiple levels:

    - unit tests
    - component tests
    - collector tests
    - parser tests
    - schema tests
    - integration tests
    - Windows VM tests
    - end-to-end tests
    - performance tests
    - stress tests
    - crash/recovery tests
    - network outage tests
    - disk-full tests
    - event-loss tests
    - upgrade tests
    - rollback tests
    - security tests
    - tamper tests
    - response tests
    - attack simulation

Build benign attack simulations for important Windows attack techniques.

The endpoint must demonstrate actual observable evidence.

------------------------------------------------------------
AN. DETECTION ENABLEMENT
------------------------------------------------------------

The endpoint should provide high-quality evidence to the Detection Engine.

Do NOT move detection logic into the endpoint merely because it is convenient.

The endpoint should expose:

    context
    relationships
    identity
    timestamps
    hashes
    ancestry
    security context
    network attribution
    file attribution
    persistence context
    relevant security state

The Detection Engine can then determine maliciousness.

If the existing detection engine cannot consume the telemetry needed by the flagship Windows endpoint:

    identify the gap
    propose the contract change
    document the required integration

Do not cripple the endpoint to fit the current detection engine.

============================================================
5. EVENT QUALITY IS AS IMPORTANT AS EVENT QUANTITY
============================================================

Do not create thousands of shallow events.

A flagship endpoint needs high-quality security semantics.

Every event should have a clear answer to:

    What happened?
    When did it happen?
    On which host?
    Which process caused it?
    Which process instance?
    Which user?
    Which executable?
    Which file?
    Which network endpoint?
    What was the security context?
    What was the parent/ancestor?
    What entity relationships exist?
    What confidence/coverage limitations exist?

Where applicable preserve:

    event timestamp
    collection timestamp
    host identity
    process identity
    user identity
    entity identity
    source/provider
    sequence/order information
    correlation context
    hashes
    paths
    command line
    network context

Do not invent information that the underlying Windows mechanism cannot reliably provide.

============================================================
6. MULTIPLE COLLECTION MECHANISMS
============================================================

Do not force everything through one provider.

For every major capability determine:

    primary mechanism
    secondary mechanism
    fallback
    minimum supported Windows version
    performance characteristics
    failure behavior
    coverage limitations

For example, investigate combinations of:

    ETW
    Windows Event Log
    Win32 APIs
    NT APIs where justified
    WMI
    Registry APIs
    filesystem facilities
    USN Journal
    Windows Filtering Platform
    service APIs
    Task Scheduler APIs
    security APIs
    performance counters
    Sysmon integration
    other appropriate Windows facilities

Do not use privileged/low-level mechanisms simply because they sound advanced.

Use them when they materially improve security capability.

============================================================
7. HOST STATE IS FIRST-CLASS
============================================================

Do not build only an event stream.

The endpoint must maintain an understanding of current host state.

At minimum investigate state models for:

    processes
    users
    sessions
    services
    scheduled tasks
    installed software
    network interfaces
    routes
    sockets
    security controls
    persistence
    drivers
    Defender
    firewall
    system configuration
    agent health

The endpoint should be able to answer:

    "What is happening?"

and:

    "What currently exists on this machine?"

Both are necessary.

============================================================
8. RESPONSE IS PART OF THE ENDPOINT
============================================================

Do not treat response as a backend-only feature.

The Windows endpoint must have a secure response subsystem.

But response actions must remain controlled.

No arbitrary:

    cmd.exe /c ...
    powershell ...
    shell command

as a generic response primitive.

Prefer explicit typed actions.

Each response action needs:

    validation
    authorization context
    target identity
    execution
    timeout
    result
    error
    audit context
    rollback where possible
    idempotency semantics where appropriate

For process termination, never trust PID alone.

Verify process identity.

============================================================
9. CONCURRENT DEVELOPMENT — VERY IMPORTANT
============================================================

Claude may also be actively working on the Linux endpoint on this SAME LAPTOP.

This means you must assume that another AI coding agent may be modifying Panopticon repositories while you work.

DO NOT assume you are the only process touching the workspace.

Before making changes:

    - inspect git status
    - inspect current branch
    - inspect uncommitted changes
    - inspect recently modified files
    - understand repository state
    - identify whether another agent appears to be working

Do NOT:

    - git reset --hard
    - git clean -fd
    - delete uncommitted work
    - overwrite unrelated modifications
    - revert another agent's changes
    - force checkout another branch
    - rewrite history
    - force push
    - blindly regenerate files
    - "clean up" changes that you did not author

If you discover modifications that appear to belong to Claude or another contributor:

    preserve them.

If a file needs modification and contains concurrent changes:

    inspect carefully
    make the smallest safe change
    preserve unrelated work

Do not use destructive synchronization commands simply to make the workspace clean.

If concurrent work creates a genuine conflict:

    stop at the conflict
    document it
    explain exactly what conflicts
    ask for direction if the conflict cannot be safely resolved

Do not destroy another agent's work to continue.

============================================================
10. REPOSITORY BOUNDARIES
============================================================

You own the Windows endpoint.

You do NOT own:

    - Sokhi's Detection Engine
    - Claude's Linux endpoint
    - Rishi's lab validation work
    - the entire Panopticon architecture

However, the Windows endpoint has priority.

If another component must change to support the endpoint:

    identify it
    document it
    propose it
    implement it when appropriate
    coordinate carefully

Do not redesign other subsystems gratuitously.

============================================================
11. EXISTING CODE IS EVIDENCE, NOT TRUTH
============================================================

The existing Windows agent may contain useful work.

Audit it.

Classify components as:

    KEEP
    HARDEN
    REFACTOR
    REPLACE
    REMOVE
    MISSING

Do not preserve weak designs merely because they already exist.

Do not rewrite good implementations merely because they are old.

Make engineering decisions based on evidence.

============================================================
12. PLAN PHASE — YOUR FIRST DELIVERABLE
============================================================

Before implementation, produce a serious engineering plan.

The plan MUST contain:

------------------------------------------------------------
1. EXECUTIVE SUMMARY
------------------------------------------------------------

What will the flagship Windows endpoint become?

------------------------------------------------------------
2. INDUSTRY CAPABILITY RESEARCH
------------------------------------------------------------

Summarize what major Windows EDRs provide.

Do not merely list product names.

Extract capabilities.

------------------------------------------------------------
3. COMPLETE WINDOWS ENDPOINT CAPABILITY MATRIX
------------------------------------------------------------

For every major capability:

    capability
    security purpose
    telemetry/state required
    collection mechanism
    fallback
    expected event/state model
    performance cost
    reliability concerns
    Windows compatibility
    implementation difficulty
    testing method
    detection value
    response value

------------------------------------------------------------
4. CURRENT PANOPTICON WINDOWS AGENT AUDIT
------------------------------------------------------------

For every capability:

    existing
    partial
    weak
    missing
    unknown

------------------------------------------------------------
5. GAP ANALYSIS
------------------------------------------------------------

Show exactly what is missing between:

    current Panopticon

and:

    target flagship endpoint.

------------------------------------------------------------
6. TARGET ARCHITECTURE
------------------------------------------------------------

Design the complete internal Windows endpoint architecture.

Include:

    processes/services
    modules
    collectors
    normalization
    enrichment
    state
    queues
    storage
    transport
    response
    configuration
    health
    diagnostics
    security
    update
    testing

------------------------------------------------------------
7. DATA MODEL
------------------------------------------------------------

Describe the endpoint's required entities and relationships.

Especially:

    host
    process
    process instance
    user
    session
    file
    registry key
    service
    scheduled task
    socket
    IP
    DNS
    executable
    module
    driver
    persistence mechanism
    security control
    response action

------------------------------------------------------------
8. TELEMETRY SOURCE MATRIX
------------------------------------------------------------

For each telemetry class:

    source
    mechanism
    event
    fields
    reliability
    fallback
    limitations

------------------------------------------------------------
9. HOST STATE MODEL
------------------------------------------------------------

Define how the endpoint maintains current state.

------------------------------------------------------------
10. RESPONSE MODEL
------------------------------------------------------------

Define endpoint-side response capabilities.

------------------------------------------------------------
11. SECURITY / SELF-PROTECTION MODEL
------------------------------------------------------------

Define how the agent protects itself.

------------------------------------------------------------
12. DURABILITY / OFFLINE MODEL
------------------------------------------------------------

Define what happens when Manager/network/storage is unavailable.

------------------------------------------------------------
13. PERFORMANCE MODEL
------------------------------------------------------------

Define realistic performance budgets and measurements.

------------------------------------------------------------
14. COMPATIBILITY MATRIX
------------------------------------------------------------

Windows versions, editions and security configurations.

------------------------------------------------------------
15. TESTING STRATEGY
------------------------------------------------------------

Unit → component → VM → E2E → attack simulation → stress → chaos.

------------------------------------------------------------
16. IMPLEMENTATION PHASES
------------------------------------------------------------

Break the work into logical engineering phases.

Do NOT create fake phases simply to make the project look organized.

Each phase must produce real capability.

------------------------------------------------------------
17. DEPENDENCIES ON OTHER PANOPTICON COMPONENTS
------------------------------------------------------------

Clearly identify:

    required schema changes
    Manager changes
    Detection Engine integration
    Console changes
    response control-plane changes
    deployment changes

But do not let those dependencies dictate endpoint capability.

------------------------------------------------------------
18. DEFINITION OF DONE
------------------------------------------------------------

Define objectively what must be true before you can declare the Windows endpoint complete.

============================================================
13. AFTER I APPROVE THE PLAN
============================================================

Once I explicitly approve the plan:

BEGIN IMPLEMENTATION.

At that point, do not repeatedly ask me:

    "Should I implement this?"
    "Should I continue?"
    "Should I fix this?"
    "Should I add tests?"

You are expected to continue autonomously through the approved roadmap.

The workflow becomes:

    inspect
    implement
    test
    measure
    discover gaps
    improve
    test again
    integrate
    validate
    document
    repeat

Do not stop merely because the original checklist is implemented.

============================================================
14. ITERATION LOOP
============================================================

After every major implementation stage:

    1. Run tests.
    2. Inspect failures.
    3. Inspect telemetry quality.
    4. Inspect performance.
    5. Inspect reliability.
    6. Compare implementation against the capability matrix.
    7. Identify newly discovered gaps.
    8. Research those gaps.
    9. Implement improvements.
    10. Repeat.

The capability matrix is a living engineering artifact.

If implementation reveals a missing capability:

    add it to the matrix
    research it
    determine whether it belongs
    implement it if required
    test it

Do not artificially constrain yourself to the first implementation plan.

============================================================
15. SECURITY VALIDATION
============================================================

Do not validate only with happy-path tests.

Create controlled, benign simulations of relevant Windows attacker behavior.

Examples may include:

    process injection indicators
    suspicious PowerShell
    LOLBin execution
    persistence creation
    service creation
    scheduled task persistence
    suspicious registry modification
    credential-access-like behavior
    lateral movement-like behavior
    malicious file behavior
    network callbacks
    Defender tampering attempts
    event log manipulation
    process tree abuse

For each scenario ask:

    Did the endpoint observe it?
    Was the correct process identified?
    Was the correct user identified?
    Was the process instance correct?
    Was the relevant file identified?
    Was network activity attributed?
    Was context preserved?
    Were events lost?
    Did the endpoint remain healthy?
    Could the Detection Engine consume the evidence?
    Could response safely act on the correct entity?

============================================================
16. PERFORMANCE AND TELEMETRY QUALITY
============================================================

A flagship endpoint must be measurable.

Create benchmarks for:

    CPU
    RAM
    disk
    network
    event throughput
    queue latency
    event loss
    startup time
    recovery time
    response latency

Measure:

    idle
    normal
    high activity
    event storm
    attack simulation

Do not make performance claims without measurement.

============================================================
17. FAILURE ENGINEERING
============================================================

Intentionally test:

    backend unavailable
    network unavailable
    certificate failure
    disk full
    queue full
    event storm
    process crash
    collector crash
    service restart
    machine reboot
    power-loss-like recovery where practical
    corrupted spool
    invalid configuration
    invalid command
    duplicate command
    replayed command
    partial response failure

The endpoint should recover predictably.

============================================================
18. DOCUMENTATION MUST MATCH REALITY
============================================================

Update documentation as implementation evolves.

Documentation must describe:

    actual capabilities
    limitations
    supported Windows versions
    installation
    configuration
    telemetry
    response
    troubleshooting
    health
    performance
    security
    architecture
    testing

Never document a feature merely because the code structure suggests it exists.

============================================================
19. NO FAKE COMPLETION
============================================================

Do NOT declare the endpoint complete because:

    it compiles
    unit tests pass
    telemetry reaches Manager
    process creation works
    one attack demo works
    the dashboard displays events
    the original TODO list is empty

Completion requires the full capability assessment.

============================================================
20. FINAL COMPLETION AUDIT
============================================================

Before declaring the Windows endpoint complete, perform a final independent audit.

Ask:

    What can a serious Windows EDR observe that we cannot?

    What Windows host state do we not understand?

    What attacker behavior would currently be invisible?

    Which telemetry sources can silently fail?

    Which important events can be lost?

    Which process relationships are ambiguous?

    Where do we rely on PID alone?

    What persistence mechanisms are uncovered?

    What authentication activity is missing?

    What network activity is unattributed?

    What security posture information is missing?

    What response actions are missing?

    What endpoint self-protection is missing?

    What happens if the endpoint is offline for 24 hours?

    What happens during an event storm?

    What happens if the collector crashes?

    What happens if an attacker tries to kill or tamper with the agent?

    What happens across different Windows versions?

    What happens when ETW or another provider is unavailable?

    What evidence would an incident responder wish they had?

    What does Microsoft Defender / CrowdStrike / SentinelOne / Cortex / Elastic provide that we still do not?

Then close the gaps that are realistically required.

============================================================
21. "DONE" MEANS DONE
============================================================

Your mission does NOT end when the initial implementation is finished.

Your mission ends when:

    - the Windows capability matrix is comprehensively covered
    - major security telemetry domains are implemented or explicitly justified
    - host state is first-class
    - process identity is correct
    - telemetry relationships are preserved
    - collection mechanisms have appropriate fallbacks
    - telemetry loss is measurable
    - local durability works
    - offline operation works
    - transport is secure
    - configuration is secure
    - response is real and safe
    - forensic collection works
    - host isolation is implemented where feasible
    - agent health is observable
    - self-protection is implemented to the realistic level of the architecture
    - performance has been measured
    - Windows compatibility has been evaluated
    - installation and upgrade paths work
    - failure/recovery behavior is tested
    - security/attack simulations have been executed
    - endpoint output can support serious detection engineering
    - Manager integration works
    - response integration works
    - E2E validation works
    - documentation matches reality
    - there are no unexplained major capability gaps
    - all deliberately unsupported capabilities are explicitly documented with reasons
    - final industry/market gap analysis has been completed

If important gaps remain:

    DO NOT CALL IT COMPLETE.

============================================================
22. FINAL MINDSET
============================================================

Think like the principal engineer of an endpoint-security company.

Do not think:

    "What is the smallest code change that satisfies the ticket?"

Think:

    "If this were our flagship Windows EDR endpoint, what would an experienced detection engineer, incident responder, malware analyst, DFIR investigator, SOC analyst, and endpoint engineer expect this machine to know?"

Then build that.

Do not optimize for:

    smallest diff
    fastest implementation
    easiest architecture
    current backend limitations
    demo-only behavior
    superficial feature count

Optimize for:

    security visibility
    correctness
    evidence quality
    reliability
    durability
    performance
    response safety
    maintainability
    compatibility
    operational resilience
    real-world usefulness

The endpoint is the foundation of Panopticon.

Build it accordingly.

============================================================
23. FIRST ACTION
============================================================

RIGHT NOW:

DO NOT CODE.

Perform:

    1. repository reconnaissance
    2. current Windows agent audit
    3. architecture/documentation audit
    4. industry capability research
    5. Windows security telemetry research
    6. capability matrix creation
    7. gap analysis
    8. target architecture design
    9. implementation roadmap
    10. testing and validation strategy

Then present the COMPLETE PLAN TO ME FOR APPROVAL.

Wait for my explicit approval.

ONLY AFTER APPROVAL:

begin implementation.

Once implementation begins, continue iterating until the endpoint meets the completion criteria above.

Do not stop at MVP.

Do not stop at "good enough."

Do not stop merely because the original code works.

Build the flagship Windows endpoint.
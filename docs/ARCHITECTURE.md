# Architecture

## Overview

```
┌────────────────────────── user session ──────────────────────────┐
│  NetGuard.Desktop (WPF, asInvoker)                               │
│   ├─ NetGuardClient ──┐  request/response                        │
│   └─ EventPump ───────┤  long-poll (WaitForEvents)               │
└───────────────────────┼──────────────────────────────────────────┘
                        │  \\.\pipe\NetGuardEnterprise.Control.v1
                        │  (ACL: local authenticated users; network denied;
                        │   client verifies server owner = SYSTEM/Administrators)
┌───────────────────────┼──────── NetGuard.Service (LocalSystem) ──┐
│  PipeServer → identify caller from token → RequestDispatcher     │
│     │  (permission per command: Read / Modify / Administer)      │
│     ├─ PolicyService ── validate, audit, mutate ─┐               │
│     ├─ QueryService / DiagnosticReportBuilder    │               │
│     └─ ConfigurationPorter (import/export)       ▼               │
│  EnforcementScheduler ─► EnforcementEngine (reconcile & verify)  │
│     ▲        ▲        ▲          │                               │
│     │        │        │          ├─► IFirewallManager (COM)      │
│  ProcessTracker  FirewallChange  ├─► IPolicyStore / IAuditLog    │
│  (WMI/ETW)       Watcher (log)   └─► EventBroker (UI events)     │
│  BlockedConnectionObserver (WFP 5157)  OrganizationPolicyLoader  │
└──────────────────────────────────────────────────────────────────┘
          │                                   │
   Windows Defender Firewall          %ProgramData%\NetGuard (SQLite, logs)
```

Each layer has one job:

| Layer | Project | Depends on |
|---|---|---|
| Domain | `NetGuard.Domain` | — |
| Contracts | `NetGuard.Contracts` | Domain |
| Application services | `NetGuard.Core` | Contracts, Domain |
| Persistence | `NetGuard.Persistence.Sqlite` | Core |
| OS integration | `NetGuard.Platform.Windows` | Core |
| Transport | `NetGuard.Ipc` | Contracts |
| Hosts | `NetGuard.Service`, `NetGuard.Desktop` | everything above / Contracts + Ipc |

The desktop app references only Contracts and Ipc. It has no access to the database, the firewall, or the policy logic, and every decision is made by the service.

## Enforcement model

### Desired state, then reconcile

Every enforcement action is a **reconciliation**. `RulePlanner` turns each application's *effective* policy into the exact set of rules that should exist. The effective policy is the application's own policy, or an enabled profile's policy, adjusted for exceptions, running state, and enablement. `EnforcementEngine` then:

1. reads the firewall's current state and rules;
2. collapses duplicate NetGuard rules left by an interrupted update;
3. creates missing rules and replaces rules that differ from the plan. Replacement is **make-before-break**: the new rule exists before the old one is removed, so a restricted program is never unblocked during an update;
4. removes NetGuard rules that are no longer needed. Rules whose application is unknown (*orphans*) are **kept** unless an administrator asks to remove them, so database loss can never unblock anything;
5. **reads everything back** and derives each application's state from what Windows actually reports.

Reconciliation is idempotent and serialized. The scheduler coalesces bursts of triggers into one run.

| Trigger | Source |
|---|---|
| Policy change | Any `PolicyService` mutation, import, or organization policy update (synchronous: the caller gets the verified result) |
| Process launch / exit | `ProcessTracker` |
| Firewall changed | `FirewallChangeWatcher`, which subscribes to the Windows Firewall operational log and detects tampering within seconds |
| Integrity check | Timer (default 5 minutes, configurable) |
| Exception expiry | Timer set to the next expiry |
| Startup | Service start, after reboot, crash, or update |

### Rule ownership

A rule belongs to NetGuard only when **both** of these hold:

- it is in the group `NetGuard Enterprise`;
- its description carries a well-formed key, `[ngkey:<appId>.<exeId>.<suffix>]`.

Rule names are deterministic. The firewall manager refuses to remove or rename any rule that fails this test, including a third-party rule that happens to share a name. `FirewallRuleSpec` can only describe an **enabled, outbound, block** rule scoped to one program path. The service is structurally unable to create allow rules or inbound rules.

### Policies as rules

| Policy | Rules per executable |
|---|---|
| Block | 1 rule: protocol Any, remote `*`. This covers IPv4, IPv6, TCP, UDP, ICMP, and raw protocols. |
| Custom | Up to 5 block rules that together cover the complement of the allow-list: all protocols to non-allowed destinations; TCP and UDP to allowed destinations on non-allowed ports; ICMPv4 and ICMPv6 to allowed destinations unless ICMP is allowed. The complement is computed exactly with 128-bit range arithmetic. |
| Allow | No rules. The existing system policy applies, and conflicts are reported. |

Windows Firewall evaluates block rules before allow rules, so these rules take effect regardless of allow rules created by others.

### Retention

* **Persistent** (default): rules exist before launch and after exit. There is no launch race, and rules survive reboots inside the firewall itself.
* **While running**: rules are created when the process is detected and removed after the last instance exits, after a configurable grace period that absorbs crash-and-restart cycles. The process may make network attempts in the short interval before detection; see [LIMITATIONS.md](LIMITATIONS.md).

### State model

`Enforced` is shown only when every planned rule was read back, matches the plan, and the firewall is on for every active network profile the policy targets, with local rules honored.

| State | Meaning |
|---|---|
| Enforced | Rules verified and in effect on the current network |
| Inactive | Rules verified, but the policy targets other network profiles |
| Degraded | Rules verified, but the firewall is off for the current profile, Group Policy overrides local rules, or another rule conflicts |
| Failed | Rules could not be created, verified, or removed (the reason is shown) |
| Standby | While-running policy and the application is not running |
| Suspended | A time-limited exception is active |
| Disabled | Management disabled; NetGuard's rules removed |
| NotRequired | Allow policy, no conflicts |
| Unsupported | Packaged (MSIX) application |
| Pending | Not yet verified, or waiting for the firewall to confirm removal |

## Process monitoring

`WmiProcessMonitor` combines two sources and de-duplicates them by (PID, start time):

* **ETW, the primary source.** A real-time session on the `Microsoft-Windows-Kernel-Process` provider (via TraceEvent) delivers process-start events. It is flushed every 500 ms, so a launch is reported within about 0.1–0.5 s, measured at 117–306 ms end to end. This source requires administrative rights; the LocalSystem service has them.
* **WMI instance-creation events, the safety net.** WMI polls the process table every 5 s while ETW is active, or every 1 s when ETW is unavailable (for example, a non-elevated diagnostic run).

The WMI wrapper `Win32_ProcessStartTrace` is deliberately not used. On Windows 11 build 26200 it accepts a subscription but delivers no events, even when elevated; this was verified on a test machine. Diagnostics shows how many events each source has delivered.

Exit is detected by waiting on a process handle (`RegisterWaitForSingleObject`). The handle pins the process object, so PID reuse cannot confuse tracking.

`ProcessTracker` processes events on a single consumer:

* **Matching** uses the canonical final path (symlinks, junctions, and 8.3 names resolved), never the file name. A copy of an executable elsewhere is not "the application".
* **Launch**: register the instance, reconcile synchronously (this creates while-running rules and re-verifies persistent ones), notify, and verify identity: SHA-256 plus Authenticode signer compared with the recorded identity.
* **Child processes** of a managed instance:
  - inside the application's own (specific) install directory, they are added automatically when enabled;
  - anything else is only *observed*, because a path-scoped rule on a shared program such as `powershell.exe` would affect everyone.
* **Relocation** after an update: a same-named executable with a valid signature from the same signer and the same product is followed automatically when enabled. Anything else is reported for review.
* **Already-running** processes are found by a snapshot at startup and whenever policies change.

## Persistence

SQLite (WAL mode, foreign keys enforced) holds applications, executables, profiles, temporary exceptions, enforcement status, settings, and the audit log. Every multi-statement change is a transaction.

* **Migrations** are ordered and append-only. The database is backed up with `VACUUM INTO` before migrating.
* **Integrity check** (`PRAGMA quick_check`) runs at startup. A corrupt database is moved aside (never deleted) and the newest backup is restored. Any firewall rules whose owners were lost become orphans, which are kept.
* **Backups** are taken daily, before every import, and on demand. The last 20 are kept.
* **Optimistic concurrency**: every application row has a revision, and stale updates are rejected.

## Communication

`PipeServer` and `PipeClient` exchange length-prefixed UTF-8 JSON: requests up to 4 MB, responses up to 8 MB. Unknown JSON members in imports are rejected, and enum values must be names. Each connection identifies its caller once, from the client's token at identification level, on a dedicated short-lived thread. Every request is then authorized against `CommandPermissions`. The UI receives live updates by long-polling `WaitForEvents`, so there is no busy polling; a broken long-poll connection is how the UI learns the service stopped.

## Startup and recovery

1. Harden `%ProgramData%\NetGuard` permissions, open the database, run the integrity check, recover if needed, and migrate.
2. Start process monitoring *before* the initial snapshot so no launch falls between them.
3. Run the startup reconcile, which re-creates or repairs every rule and records an audit summary.
4. Start optional subsystems: firewall change watcher, blocked-connection observer, and organization policy. Their failure is logged and audited but never stops enforcement.
5. Start the control pipe.

If the service crashes, persistent rules remain in the firewall. Service Control Manager recovery restarts the service after 10 s, configured by the MSI.

## Organization policy (extension point)

`OrganizationPolicyLoader` applies `%ProgramData%\NetGuard\Policies\organization-policy.json`, a policy document with `"scope": "organization"`. The folder is writable only by SYSTEM and Administrators, so Group Policy, Intune, or any other device-management tool can deliver it. Organization applications and profiles are read-only in the UI, and local imports cannot override them. Removing the file retires them.

This is the seam for centralized distribution. A future `IPolicySource`, such as an HTTPS policy service with mutual TLS, can feed `ConfigurationPorter.ImportAsync(..., PolicySource.Organization, ...)` the same way. Role-based access maps onto the existing permission tiers and the `NetGuard Operators` group.

## Requirements traceability

| Requirement | Implementation | Verified by |
|---|---|---|
| A. Discovery (registry, running, browse, helpers, duplicates) | `WindowsApplicationDiscovery`, `ScanDirectory`, Discovery page | `DiscoveryTests`, manual M2 |
| B. Allow / Block / Custom / Restore | `RulePlanner`, `PolicyService.RestoreApplicationAsync` | `RulePlannerTests`, `PolicyServiceTests` |
| B. Conflicts and effective policy | `ConflictDetector`, `StatusEvaluator`, Firewall page | `EnforcementEngineTests` (Allow conflicts, Degraded) |
| C. Event-driven launch detection, canonical match, identity | `WmiProcessMonitor`, `ProcessTracker` | `ProcessTrackerTests`, `ProcessMonitorTests` |
| C. Verify, no duplicates, rapid restart, concurrency | `EnforcementEngine` read-back, idempotent reconcile, grace period | `EnforcementEngineTests`, `ProcessTrackerTests` |
| D. Persistence, startup, exceptions | Retention modes, startup reconcile, `TemporaryException` | `PolicyServiceTests` (exception expiry), manual M5 |
| E/F. Dashboard and management UI | `NetGuard.Desktop` | Manual M1–M3 |
| G. Notifications (only observed events) | `EventBroker`, `TrayService`, `BlockedConnectionObserver` (WFP 5157) | `EventBrokerTests`, manual M9 |
| 4. Owned rules only, never reset or disable | `OwnedRules`, `WindowsFirewallManager`, COM placeholders | `OwnedRulesTests`, `ThirdPartyRules_*`, `FirewallWriteTests` |
| 5. Least privilege, IPC security, TOCTOU, audit | See [SECURITY.md](SECURITY.md) | `AuthorizationTests`, `PipeImpersonationTests`, `ExecutableInspectorTests` |
| 6. Profiles, export/import, versioning | `PolicyProfile`, `ConfigurationPorter`, JSON Schema | `ConfigurationTests` |
| 7. Audit, search, export, retention, diagnostics | `SqliteStore`, `AuditExporter`, `DiagnosticReportBuilder` | `SqliteStoreTests`, `AuditExportTests`, `RedactionTests` |
| 9. Recovery, drift, backups | Startup reconcile, `FirewallChangeWatcher`, `SqliteStore.Recover` | `DeletedRule_IsRestored…`, `CorruptDatabase_…` |

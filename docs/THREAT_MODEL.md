# Threat model

Method: STRIDE per trust boundary. Scope: NetGuard Enterprise 1.0 on a single Windows endpoint.

## Assets

| Asset | Why it matters |
|---|---|
| Firewall configuration | Integrity of restrictions; availability of every other application's networking |
| Policy database and organization policy | They define what gets restricted |
| Audit log | Accountability and investigations |
| Service process (LocalSystem) | Highest privilege on the machine |
| User trust in displayed status | Users act on "Enforced" |

## Actors

* **Standard user**: may view status. Must not change policies, or use the service to restrict other users' programs (denial of service) or to gain privileges.
* **Operator** (member of NetGuard Operators): may manage application policies.
* **Administrator**: full control of the machine, and therefore of NetGuard. This is out of scope as an adversary.
* **Malware running as a standard user**: tries to impersonate the service, escape restrictions, or tamper with state.
* **A restricted application**: tries to reach the network anyway.

## Trust boundaries

1. Desktop UI (user) ↔ service (SYSTEM) over the named pipe.
2. Service ↔ Windows Defender Firewall (COM/RPC).
3. Service ↔ file system: executables to inspect, and the data directory.
4. Device management ↔ organization policy folder.
5. Restricted application ↔ network.

## STRIDE analysis

| # | Threat | Boundary | Mitigation | Residual risk |
|---|---|---|---|---|
| S1 | Malware creates `\\.\pipe\NetGuardEnterprise.Control.v1` first to capture UI requests | 1 | The service uses `FirstPipeInstance` and logs a critical error if the name is taken. The client verifies that the pipe owner is SYSTEM or Administrators. | None known |
| S2 | Caller claims to be an administrator in the request body | 1 | Identity comes only from the pipe client's token. The request has no identity fields. | None |
| S3 | A different binary placed at the managed path impersonates the app | 3 | Rules are path-scoped, so impersonation gains nothing: the path stays blocked. Identity changes are detected and audited. | None |
| S4 | A lookalike binary named like a managed app is auto-trusted | 3 | Matching is by canonical path only. Auto-follow requires a valid signature from the same signer plus a matching product. | A compromised signing key of the same publisher |
| T1 | A user edits or deletes NetGuard rules | 2 | Requires admin. The firewall change watcher and integrity timer detect it, the rules are restored, and the drift is audited and notified. | Brief window until detection (seconds; at most the integrity interval if the event log is unavailable) |
| T2 | A user edits the database or logs | 3 | The data directory DACL allows SYSTEM and Administrators only. | Administrators |
| T3 | A path is swapped (symlink) between check and use | 3 | The file is opened while denying writers; the canonical path, hash, and signature all come from the same handle; rules use the final path. | Junction retargeting after enrollment changes which file the path refers to. The rule still applies to the path; the new file's launch is observed and reported. |
| T4 | A malicious import document | 1 | Administer permission required; strict schema; semantic validation; dry-run preview; backup first; all-or-nothing transaction. | None known |
| R1 | Denial of having made a change | 1 | Every mutation and every denial is audited with the token-derived account name. | Administrators can delete audit data |
| I1 | A standard user reads paths of other users' programs | 1 | Read access is configurable off. Discovery and inspection require Modify. Reports redact by default. | Status pages show managed paths to readers when Read is enabled |
| I2 | Diagnostics leak personal data | — | Redaction on by default; no browsing, credential, or file-content collection. | Executable paths outside user profiles |
| D1 | A standard user blocks other users' applications or Windows components | 1 | Modify requires Operator or elevated Administrator. Protected deny-list. System components need an explicit flag and Administer. | Operators can restrict any non-protected program machine-wide (by design) |
| D2 | Request flooding | 1 | Per-connection rate limit, connection cap (16), size limits, timeouts. | Local resource exhaustion by many processes |
| D3 | Service crash leaves the system unprotected | — | Persistent rules live in the firewall; SCM restart; startup reconcile. | While-running policies created during downtime are not applied |
| D4 | DB corruption unblocks applications | 3 | Orphaned rules are kept; DB restored from backup. | None |
| E1 | Elevation through the service, such as creating allow rules or running code | 1 | The command set contains no arbitrary rule creation, no allow rules, no process launch, and no file writes outside the data directory. Inputs are strictly validated. | Bugs; mitigated by tests and code review |
| E2 | A leaked impersonation token causes privileged work in the wrong context | 1 | Identification runs on a dedicated thread that reverts and exits; regression-tested. | None known |
| N1 | A restricted app communicates through another process | 5 | Child processes in its folder are auto-restricted; others are observed and reported. | Inherent to path-based filtering. See LIMITATIONS.md. |
| N2 | A restricted app uses connections opened before the rule existed | 5 | Persistent mode avoids the gap; the UI advises a restart. | Documented |

## Out of scope

* An administrator who wants to disable NetGuard. They can, and Windows treats them as the machine owner.
* Kernel-level attackers, or malware running as SYSTEM.
* Applications that are themselves network services (inbound), and packaged MSIX applications. These are reported as Unsupported.

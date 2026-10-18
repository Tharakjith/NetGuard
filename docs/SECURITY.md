# Security

## Principles

* **Least privilege.** Only the service runs privileged. The desktop interface runs `asInvoker` and never needs administrator rights to display status.
* **Restrict, never open.** The service can only create *outbound block* rules scoped to one program path. It has no code path that creates allow rules, inbound rules, or service-scoped rules, or that disables the firewall, changes default actions, restores defaults, or toggles rule groups. Those COM methods are declared only as unnamed vtable placeholders in `FirewallComInterop.cs`.
* **Own what you touch.** Rules are modified only when they carry NetGuard's group and a well-formed ownership key. A rule with a matching name but a different owner causes the operation to fail rather than be removed.
* **Fail closed and say so.** Missing verification never shows as "Enforced". Orphaned rules are kept. A failed removal keeps the application record, so its rules stay tracked. A service crash leaves persistent rules in place.
* **Transparency.** There are no hidden components. The service, the Start menu entry, and optional tray autostart (per user, opt-in, visible in Task Manager) are all standard and visible. Nothing evades or interferes with security software.

## Privilege model

| Component | Account | Why |
|---|---|---|
| `NetGuard.Service` | LocalSystem | Firewall rule management (`INetFwPolicy2`), the ETW kernel process session, and reading the Security log (optional) all require administrative rights. The service exposes only the narrow command set below. |
| `NetGuard.Desktop` | Interactive user (asInvoker) | Display and request changes; never trusted for decisions. |
| MSI custom action `cleanup-rules` | LocalSystem (deferred, no impersonation) | Removes NetGuard-owned rules on uninstall only. |

## Authorization

The caller's identity comes from the pipe client's Windows token, read with identification-level impersonation. It never comes from request content. Impersonation runs on a dedicated short-lived thread that reverts and exits, so a client token can never remain on a thread that later performs service work. This is covered by a regression test, `PipeImpersonationTests`.

| Permission | Who | Commands |
|---|---|---|
| Read | Any local authenticated user (configurable off), Operators, elevated Administrators | Status, applications, firewall overview, logs, diagnostics, events |
| Modify | Members of the local group **NetGuard Operators**, elevated Administrators | Add, update, enable or disable, restore, or remove applications; temporary exceptions; profiles; discovery and inspection; re-verify; export |
| Administer | Elevated Administrators only | Service settings, configuration import, orphaned-rule clean-up, database backup |

Under UAC, a non-elevated administrator token has the Administrators group as deny-only, so it gets Read only. The UI offers **Restart as administrator**. Members of NetGuard Operators can manage policies without elevation; administrators control that group's membership.

Additional rules:

* **Organization-sourced** applications and profiles cannot be changed or removed through the pipe, even by administrators. They change only through the organization policy file.
* Restricting an executable **inside the Windows directory** requires an explicit `AllowSystemComponent` flag *and* Administer permission.
* A **deny-list** of core components (svchost, lsass, csrss, Defender binaries, NetGuard itself, and others) can never be restricted, because doing so would break networking or security.
* Every denied request is audited, rate-limited to one record per caller and command per minute.

## IPC hardening

* **Pipe ACL**: Deny NETWORK; allow SYSTEM and the service identity full control; allow Administrators and Authenticated Users read/write *without* `CreateNewInstance`.
* **Pipe-squatting defense**: the first instance is created with `FirstPipeInstance`, so the service fails loudly if the name is taken. The client refuses a server whose pipe owner is not SYSTEM or Administrators, which a standard user cannot fake.
* **Input limits**: 4 MB requests and 8 MB responses with length-prefixed framing; a JSON max depth of 32; strict enum parsing; unknown members rejected for imports; and a per-connection token-bucket rate limit (burst 60, then 20/s).
* **Timeouts**: 2-minute request timeout and 10-minute idle disconnect.
* **No retry of sent requests**: the client retries only if a stale connection failed *before* the request was written, so a command can never be executed twice.

## Input validation and path safety

* Paths must be absolute local drive paths to an `.exe`. They are rejected if they contain UNC or device prefixes, `..` segments, alternate data streams, environment variables, or wildcard characters, or if they are longer than 1024 characters.
* **TOCTOU protection**: the service never trusts the client's view of a file. It opens the file itself while denying writers, takes the canonical path *from the open handle* (`GetFinalPathNameByHandle`), and computes the SHA-256 and verifies the Authenticode signature while still holding that handle (`WinVerifyTrust` receives the same handle).
* Rules target the canonical path. Process matching uses canonical paths, never file names, so a renamed or copied binary elsewhere is not treated as the managed application.
* Identity changes at a managed path (a different hash and a different or missing signer) raise a warning and an audit record. The path-based restriction stays in force.
* Signature verification uses cached revocation data only, so verification never needs the network.
* Custom allow-lists accept only IP literals, CIDR blocks, and ranges (no keywords or host names), up to 200 entries.

## Data protection

* `%ProgramData%\NetGuard` (database, logs, backups, organization policy) has a protected DACL: SYSTEM and Administrators full control, no inherited access, and no access for standard users. Both the MSI (`util:PermissionEx`) and the service at startup apply it.
* The audit log stores account names, executable paths, and policy details. It never stores passwords, tokens, file contents, or browsing data. Message and detail fields have size limits.
* Diagnostic reports redact user names, user-profile path segments, and the computer name by default.
* CSV exports neutralize spreadsheet formula injection.

## Signing and supply chain

* Release binaries and the MSI must be Authenticode-signed with SHA-256 and an RFC 3161 timestamp (`scripts/sign.ps1`). The script signs only NetGuard's own files and verifies each signature.
* Package versions are pinned centrally in `Directory.Packages.props`. Builds are deterministic, and warnings are errors.
* **About & Security** in the UI shows whether the running binary is signed.
* `build-installer.ps1` writes a SHA-256 checksum next to the MSI for distribution verification.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainers' security contact rather than in a public issue tracker. Include the version, reproduction steps, and a diagnostic report (redacted).

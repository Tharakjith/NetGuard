# NetGuard Enterprise

Per-application network control for Windows 10 and 11, built on Windows Defender Firewall.

Choose an application, such as a design tool or a development tool, and set its policy to **Block** (no outbound network access), **Custom** (only listed destinations and ports), or **Allow**. A background Windows service enforces the policy automatically. It creates narrowly scoped outbound block rules for that application's executables, verifies them by reading them back from the firewall, and repairs them if something changes them. Every other application, and Windows itself, keeps its normal connectivity.

NetGuard performs legitimate application-level network isolation with supported Windows interfaces. It does not bypass licensing, activation, DRM or security controls. It never disables Windows Defender Firewall or any other security feature.

## Contents

| Path | What it is |
|---|---|
| `src/NetGuard.Domain` | Entities, policy model, IPv4/IPv6 address and port set arithmetic, validation |
| `src/NetGuard.Contracts` | IPC envelope, commands, DTOs, JSON options shared by the service and the UI |
| `src/NetGuard.Core` | Rule planner, reconciliation engine, process tracker, policy service, queries, import/export, diagnostics, authorization |
| `src/NetGuard.Persistence.Sqlite` | SQLite storage with migrations, backups, corruption recovery and the audit log |
| `src/NetGuard.Platform.Windows` | Windows Defender Firewall (COM), process monitoring (WMI/ETW), executable identity (Authenticode, SHA-256), discovery, event-log watchers |
| `src/NetGuard.Logging` | Structured JSON-lines file logging with retention |
| `src/NetGuard.Ipc` | Named-pipe transport: framing, ACLs, caller identity, server verification |
| `src/NetGuard.Service` | The Windows service host (LocalSystem) and request dispatcher |
| `src/NetGuard.Desktop` | WPF desktop interface (light and dark themes) |
| `tests/NetGuard.Tests.Unit` | Unit tests over the full core using in-memory fakes at the OS boundary |
| `tests/NetGuard.Tests.Integration` | Tests against real SQLite, firewall, processes, pipes and file signatures; gated firewall-write and traffic tests |
| `tools/NetGuard.NetProbe`, `tools/NetGuard.TestServer` | Controlled test application and test server for end-to-end traffic verification |
| `installer/` | WiX v5 MSI project |
| `scripts/` | Build, test, publish, sign, installer and developer install scripts |
| `schemas/` | JSON Schema for policy export/import |
| `docs/` | Architecture, security, threat model, limitations, testing and deployment |

## Prerequisites

* Windows 10 (1809 or later) or Windows 11, x64.
* .NET 9 SDK (9.0.200 or later) to build. Installed systems need no separate .NET runtime because the MSI ships self-contained binaries.
* Visual Studio 2022 17.12+ (optional), with the .NET desktop development workload.
* To build a signed release: the Windows SDK signing tools (`signtool.exe`) and an Authenticode code-signing certificate.
* Administrator rights to install the service or run the tests that change the firewall.

## Quick start (development)

```powershell
./scripts/build.ps1                          # restore, build (Release), run unit + integration tests
./scripts/install-dev.ps1                    # elevated: register the locally built service
src\NetGuard.Desktop\bin\Release\net9.0-windows\NetGuard.Desktop.exe
```

You can also run the service in a console for diagnostics. From an elevated prompt, run `NetGuard.Service.exe --data-dir C:\Temp\ng`. If the console isn't elevated, NetGuard runs anyway but reports every enforcement as **Failed** rather than pretending.

To work on the UI against a non-elevated console service, use a **Debug** build and start the desktop app with `--dev-trust-current-user`. Release builds do not contain this switch.

## Using it

1. Open **NetGuard Enterprise** from the Start menu. Viewing status is allowed by default for all users. Changing policies requires an elevated administrator (**Restart as administrator** in the banner) or membership in the local **NetGuard Operators** group.
2. Use **Application Discovery** → **Scan**, or **Managed Applications** → **Add application…**, to pick an executable. NetGuard resolves the real path, records its hash and signature, and offers to include helper executables from the same folder.
3. Choose **Block internet access**, a **Custom allow-list**, or **Allow**. Then choose whether the rules exist **always** (recommended) or **only while the application runs**, and which network profiles they apply to.
4. The status column shows a restriction as **Enforced (verified)** only after the rules were read back from the firewall and the firewall is active on the current network. Other states, such as Degraded, Inactive, Failed, Standby, and Exception active, each come with a plain-language explanation.

The window is optional. Closing it, logging off, or rebooting does not change enforcement, because persistent rules live in Windows Defender Firewall itself and the service re-verifies them at startup.

## Build, test, publish, install

| Task | Command |
|---|---|
| Build and test | `./scripts/build.ps1` |
| Publish self-contained binaries | `./scripts/publish.ps1 -Version 1.0.0` |
| Signed release MSI | `./scripts/build-installer.ps1 -Version 1.0.0 -Thumbprint <cert thumbprint>` |
| Unsigned internal MSI | `./scripts/build-installer.ps1 -Version 1.0.0 -Unsigned` |
| Silent install | `msiexec /i NetGuardEnterprise-1.0.0-x64.msi /qn /l*v install.log` |
| Silent uninstall (removes NetGuard's rules) | `msiexec /x NetGuardEnterprise-1.0.0-x64.msi /qn` |
| Uninstall but keep rules | `msiexec /x … /qn KEEPRULES=1` |

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for signing, Intune/Group Policy deployment and organization policy, and [docs/TESTING.md](docs/TESTING.md) for the test strategy and manual scenarios.

## Data locations

| Location | Contents | Access |
|---|---|---|
| `%ProgramData%\NetGuard\data\netguard.db` | Policies, state, audit log (SQLite) | SYSTEM, Administrators |
| `%ProgramData%\NetGuard\data\backups\` | Automatic and manual database backups (last 20) | SYSTEM, Administrators |
| `%ProgramData%\NetGuard\logs\` | Service logs, JSON lines, configurable retention | SYSTEM, Administrators |
| `%ProgramData%\NetGuard\Policies\organization-policy.json` | Organization policy (read-only in the UI) | SYSTEM, Administrators |
| `%LOCALAPPDATA%\NetGuard\desktop-preferences.json` | Theme and notification preferences | The user |
| Windows Event Log → Application, source "NetGuard Enterprise" | Warnings and errors | Standard |

## Troubleshooting

| Symptom | What to check |
|---|---|
| Banner says the service is not reachable | `Get-Service NetGuardService`. The service restarts automatically after failures. If it stopped, check the Application event log and `%ProgramData%\NetGuard\logs`. |
| An application shows **Failed** | Open it in **Managed Applications** to read the exact error. "Access denied" means the service is not running as LocalSystem. "Firewall service is stopped" means `mpssvc` is not running; NetGuard never starts or changes it. |
| **Degraded** | The rules exist, but something may stop them working. The firewall may be off for the current profile, Group Policy may not merge local rules, or another rule may conflict. The details pane and **Firewall Policies** page list the reasons. |
| **Inactive on this network** | The policy targets other network profiles than the current one, for example Public only. |
| The application still connects | Check **Diagnostics → Observations** for helper processes, and read [docs/LIMITATIONS.md](docs/LIMITATIONS.md). Updaters, browsers, and Windows services often carry traffic for an application. Connections opened before the rule existed may persist until the app restarts. |
| Orphaned rules on the Firewall page | These are left over from a restored or reset configuration. NetGuard keeps them so nothing becomes unblocked unexpectedly. An administrator can remove them there. |
| Remove every NetGuard rule manually | Elevated prompt: `"C:\Program Files\NetGuard Enterprise\Service\NetGuard.Service.exe" cleanup-rules`. This removes only rules carrying NetGuard's ownership marker. Use `list-rules` to preview. |
| Collect information for support | **Diagnostics → Generate**. Redaction of user names, profile paths, and the computer name is on by default. |

## Documentation

* [Architecture](docs/ARCHITECTURE.md): components, data flow, reconciliation, startup and recovery, and a requirements traceability table.
* [Security](docs/SECURITY.md): privilege model, authorization, IPC hardening, data protection, and signing.
* [Threat model](docs/THREAT_MODEL.md): assets, trust boundaries, STRIDE analysis, and residual risks.
* [Limitations](docs/LIMITATIONS.md): what executable-based filtering can and cannot do.
* [Testing](docs/TESTING.md): automated suites and manual end-to-end scenarios.
* [Deployment](docs/DEPLOYMENT.md): building, signing, installing, organization policy, and upgrades.

# Testing

Two kinds of evidence are kept separate throughout:

* **Configuration verification**: the intended rules exist in Windows Defender Firewall, match the plan, and the firewall is active. The service does this automatically on every reconcile, and the automated tests check it.
* **End-to-end traffic verification**: a restricted program actually cannot connect while others can. This needs a second machine, because Windows Firewall does not filter loopback.

## Automated suites

```powershell
./scripts/build.ps1            # runs both suites
dotnet test tests/NetGuard.Tests.Unit
dotnet test tests/NetGuard.Tests.Integration
```

| Suite | What it covers | Needs |
|---|---|---|
| `NetGuard.Tests.Unit` (142 tests) | Address and port arithmetic; rule planning; ownership markers; the reconcile engine (verification, drift repair, make-before-break, duplicates, orphans, failure states, Degraded, Inactive, conflicts); the process tracker (launch, exit, while-running, concurrency, children, relocation, identity changes, impersonation by file name); the policy service (protected components, authorization boundaries, concurrency, organization policy, safe removal, exceptions, profiles); configuration import/export (round trip, replace, schema rejection); authorization matrix; CSV injection; redaction; event long-poll; framing; the logger | Nothing |
| `NetGuard.Tests.Integration` | Real firewall COM reads (interop layout validated against late-bound COM); SQLite store (migrations, concurrency, uniqueness, audit queries, backups, **corruption recovery**); executable inspector (Authenticode, SHA-256, 8.3 and `..` canonicalization, non-PE rejection); discovery; live process monitoring (launch and exit of a real process); named-pipe impersonation regression | Windows |
| Integration, firewall-write (gated) | Create, verify, rename, and remove real rules; custom-policy rules accepted by Windows; refusal to remove a foreign rule; unrelated rules unchanged | Elevated prompt + `NETGUARD_FIREWALL_WRITE_TESTS=1` |
| Integration, traffic (gated) | A blocked copy of NetProbe cannot connect, while an identical copy at another path can; access is restored after rule removal | The above + `NETGUARD_E2E_TARGET=host:port` (a TestServer on another machine) |

Running the gated tests:

```powershell
# On the test server machine (or VM):
NetGuard.TestServer.exe --port 5099          # allow inbound TCP/UDP 5099 on that machine

# On the machine under test, elevated:
$env:NETGUARD_FIREWALL_WRITE_TESTS = '1'
$env:NETGUARD_E2E_TARGET = '192.0.2.10:5099'
dotnet test tests/NetGuard.Tests.Integration
```

These tests create rules only for paths under `C:\NetGuardTest\` or a temporary folder, and remove them in `finally` blocks.

## Manual test scenarios

Use a disposable VM. Install the MSI, open the desktop app elevated, and keep **Activity Logs** open. `NetProbe` is the controlled test application. Copy it to `C:\Probe\A\` and `C:\Probe\B\`. `TestServer` runs on a second host (`SERVER:5099`). A browser stands in for "everything else".

| # | Scenario | Steps | Expected result |
|---|---|---|---|
| M1 | Block one app while the browser keeps working | Manage `C:\Probe\A\NetGuard.NetProbe.exe` with **Block**. Run `A\NetProbe SERVER 5099` and `B\NetProbe SERVER 5099`, then browse to any website. | A fails (exit 1), B succeeds, and the browser works. A shows **Enforced (verified)**. |
| M2 | Allow one app while another stays blocked | Also manage B with **Allow**. | B still connects; A is still blocked. B shows **Not required (allowed)**. |
| M3 | Policy for an already-running app | Start `A\NetProbe SERVER 5099 --timeout 60000` against a TestServer that delays its response. Apply Block, then run A again. | The new attempt fails. The UI notes that existing connections may persist until restart. |
| M4 | Newly launched app | While-running policy on A. Check **Firewall Policies** (no rule), launch A, check again, exit, wait for the grace period. | The rule appears on launch (status Enforced) and disappears after exit (status Standby). Audit shows both. |
| M5 | Persist across reboot | Block A (persistent). Reboot, and do *not* sign in for the first attempt (use a scheduled task or a remote session to run A). | Blocked before any user signs in. After the service starts, the audit shows "Startup verification" with 0 re-created. |
| M6 | Service restart | `Restart-Service NetGuardService` while A is running. | A stays blocked throughout. The UI shows the service-stopped notification, then reconnects. The startup reconcile is audited. |
| M7 | Update / path change | Sign NetProbe with a test certificate, manage it, then copy it to `C:\Probe\A2\` and run it from there. Repeat with an unsigned copy. | Signed copy: the policy follows automatically (notification + audit). Unsigned copy: observation and notification only; not restricted. |
| M8 | IPv4 and IPv6 | Run `A\NetProbe SERVER 5099 --ipv4` and `--ipv6` (server dual-stack). Repeat with a Custom policy allowing only the server's IPv4 address. | Block: both fail. Custom: IPv4 to the server succeeds; IPv6 and other destinations fail. |
| M9 | Standard user vs administrator | Sign in as a standard user and open NetGuard. Try **Add application**. Then add the user to *NetGuard Operators*, sign out and back in, and retry. | Standard user: read-only banner, actions disabled, and a direct pipe request returns Unauthorized (audited). Operator: can manage applications; cannot change service settings. |
| M10 | Firewall conflicts and org restrictions | (a) Turn the firewall off for the Private profile. (b) Use `gpedit` to set "Apply local firewall rules: No". (c) Create an admin block rule for B while B is set to Allow. (d) Connect a VPN and repeat M1. | (a) and (b): **Degraded**, with the reason. (c): B is **Degraded**, and the conflict is listed on the Firewall page. (d): Same results as M1. If not, the VPN's WFP filters take precedence; record this. |
| M11 | Recover from failed operations | `Stop-Service mpssvc` (test VM only), then change a policy; start mpssvc again. | While stopped: **Failed**, "firewall service is stopped", and nothing claims enforcement. After it starts: the next integrity check or a change event restores **Enforced**. |
| M12 | Remove without touching unrelated rules | Export `Get-NetFirewallRule \| Select Name` to a file, then remove A from management. Export again and compare. | Only NetGuard rules for A disappear. `cleanup-rules` on uninstall removes only NetGuard-owned rules. |
| M13 | Unauthorized modification attempts | As a standard user: (a) send `AddApplication` to the pipe with a small script; (b) edit `%ProgramData%\NetGuard\data\netguard.db`; (c) delete a NetGuard rule as an admin with `Remove-NetFirewallRule`. | (a) Unauthorized + audit record. (b) Access denied. (c) The rule is restored within seconds; IntegrityDrift is audited and notified. |
| M14 | Exit does not remove a persistent restriction | Block A (persistent). Launch A, exit it, then check rules and status. | The rule remains; the status stays **Enforced**. |

Record the result of every manual run (date, Windows build, VPN/endpoint products present, pass/fail, and a redacted diagnostic report) in the release checklist.

## Performance and idle-cost checks

* Idle CPU: with no launches, the service should show ~0% CPU in Performance Monitor (`Process(NetGuard.Service)\% Processor Time`). Monitoring is event-driven. The only timers are the integrity check (default 5 min), exception expiry, and daily maintenance.
* Memory: the working set is typically 60â€“90 MB, mainly the .NET runtime and SQLite.
* Reconcile cost: one full reconcile reads all firewall rules (about 700 on a typical client) in under a second. The read-only integration test asserts that enumeration completes in under 10 s.
* Launch-time cost: process events are matched by path dictionary lookup; files are hashed only for managed or name-matching executables (cached by size + timestamp).

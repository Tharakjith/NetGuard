# Deployment

## Build a release

```powershell
./scripts/build-installer.ps1 -Version 1.2.0 -Thumbprint <code-signing certificate thumbprint>
```

The script:

1. builds the solution in Release and runs all automated tests;
2. publishes the service and desktop app as self-contained `win-x64` builds into `artifacts\publish`;
3. signs every `NetGuard.*.exe`/`.dll` with SHA-256 and an RFC 3161 timestamp, and verifies each signature;
4. builds `artifacts\installer\NetGuardEnterprise-1.2.0-x64.msi` with WiX v5;
5. signs the MSI and writes `…msi.sha256`.

`-Unsigned` produces an internal test build and prints a warning. Never distribute unsigned builds: About & Security shows the signature state, and many enterprise application-control policies (WDAC/AppLocker) will block unsigned binaries.

### Signing certificate handling

* Keep the private key in a hardware token, HSM, or a cloud signing service. `signtool` accepts certificates from the Windows certificate store by thumbprint, including HSM-backed keys.
* A PFX can be used with `scripts/sign.ps1 -PfxPath … -PfxPassword (Read-Host -AsSecureString)`. Never commit PFX files; `.gitignore` excludes them.
* In CI, run the signing step in a protected job that has access to the signing identity.

## Install

| Scenario | Command |
|---|---|
| Interactive | Double-click the MSI (requires administrator) |
| Silent | `msiexec /i NetGuardEnterprise-1.2.0-x64.msi /qn /l*v "%TEMP%\netguard-install.log"` |
| Intune (Win32 app or LOB MSI) | Install command as above. Detection: MSI product code, or the service `NetGuardService` exists. |
| Configuration Manager / Group Policy software installation | Standard per-machine MSI, no transforms needed |

What the MSI does:

* Installs to `C:\Program Files\NetGuard Enterprise\{Service,Desktop,Docs}`.
* Registers `NetGuardService` (LocalSystem, automatic start, restart on failure after 10 s, failure count reset daily).
* Creates `%ProgramData%\NetGuard` and `…\Policies` with a protected DACL (SYSTEM and Administrators only).
* Adds a Start menu shortcut. Nothing is configured to start in user sessions; each user can opt in from Settings.
* At first start, the service creates the local group **NetGuard Operators** (empty).

## Organization policy

Deploy a policy document (exported from a reference machine and edited if needed) as:

```
%ProgramData%\NetGuard\Policies\organization-policy.json
```

with `"scope": "organization"`. Options:

* **Group Policy Preferences → Files**: copy from a read-only share; action *Replace*.
* **Intune**: a Win32 app or remediation script that writes the file.
* **Configuration Manager**: a package or compliance remediation.

The service watches the folder and applies changes within seconds. Organization policies are validated with the same rules as interactive imports. An invalid file is rejected as a whole, and the rejection is audited ("Organization policy file was rejected"). The previous organization policy stays in effect. Organization-managed applications and profiles are read-only in the UI and cannot be overridden by local imports. Deleting the file retires all organization-managed applications and removes their rules.

Validate a document before deploying it: open it in an editor that understands JSON Schema (`schemas/netguard-policy.v1.schema.json`), and use **Settings → Import configuration** on a test machine. The preview step lists every change and makes none.

## Granting management rights

```powershell
Add-LocalGroupMember -Group 'NetGuard Operators' -Member 'CONTOSO\Desktop Support'
```

Members can manage application policies without elevation after signing in again. Service settings, imports, and orphaned-rule clean-up remain administrator-only. To make NetGuard status visible only to operators and administrators, clear **Settings → Standard users may view status**.

## Optional: observe blocked connection attempts

```
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
```

This enables Security event 5157. NetGuard then shows "*application* tried to connect" notifications backed by those events (rate-limited to one per application per 10 minutes). Weigh the Security log volume on busy machines.

## Upgrade

Install the newer MSI over the old one. The major upgrade keeps the database and settings. **It does not remove firewall rules**: the clean-up action runs only on a real uninstall, so restrictions stay in force throughout the upgrade. On first start, the new service migrates the database (backing it up first) and re-verifies every rule.

Downgrades are blocked by the MSI. If a newer database is found by an older service, the service refuses to start rather than corrupt it.

## Uninstall

* `msiexec /x {ProductCode} /qn` stops the service, removes only NetGuard-owned rules, and then removes the files.
* Add `KEEPRULES=1` to keep the rules, for example when replacing NetGuard with Group Policy-deployed rules.
* `%ProgramData%\NetGuard` (database, logs, backups) is left in place for audit retention. Delete it manually when it is no longer needed.

## Backup and restore

* Automatic database backups are kept in `%ProgramData%\NetGuard\data\backups` (daily, before imports and migrations, and on demand from Settings; the last 20 are kept).
* Policy-level backup: **Settings → Export configuration** produces a portable JSON document.
* Restore a policy export: **Settings → Import configuration** → Replace. Restore a database: stop the service, copy a backup over `netguard.db`, and start the service.

## Production readiness checklist

- [ ] All automated suites pass, including the gated firewall-write and traffic tests on a clean VM of each supported Windows build.
- [ ] Manual scenarios M1–M14 (TESTING.md) are recorded for the release.
- [ ] Binaries and MSI are signed; signatures verified on a clean machine; checksum published.
- [ ] Upgrade from the previous release tested: rules stay in place, the database migrates, and the backup exists.
- [ ] Uninstall tested: only NetGuard-owned rules removed; `KEEPRULES=1` honored.
- [ ] Organization policy deployment tested with the target management tool.
- [ ] Tested alongside the organization's endpoint security product and VPN client.
- [ ] Security review of changes to `NetGuard.Ipc`, `RequestDispatcher`, `WindowsFirewallManager` and `ExecutablePathRules`.

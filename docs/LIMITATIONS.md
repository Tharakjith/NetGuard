# What executable-based filtering can and cannot do

NetGuard restricts programs with Windows Defender Firewall rules that match an **executable path**. This is reliable for the traffic a program sends itself. It cannot control traffic that the program asks *another* process to send. NetGuard never promises complete isolation when it cannot enforce it. Instead, it reports what it observes so administrators can close gaps deliberately.

## Traffic that is not covered by an application's rules

| Path | Why | What NetGuard does |
|---|---|---|
| **DNS resolution** | Name lookups are performed by the DNS Client service (`svchost.exe`). | A blocked application can resolve names but cannot connect to the results. DNS tunnelling via the system resolver is theoretically possible. If that matters, combine NetGuard with DNS filtering. |
| **Helper executables** (updaters, crash reporters, license helpers) | They are separate programs with their own paths. | Helpers started from the application's own folder are restricted automatically, when enabled. Helpers elsewhere are listed under Diagnostics → Observations. You can also add them manually, or use **Find helpers in the same folder** when adding an application. |
| **Shared Windows services** (BITS, Windows Update, WinHTTP auto-proxy, Delivery Optimization) | They run inside `svchost.exe` on behalf of many programs. | Never restricted (protected list), because doing so would break Windows. Downloads an application hands to BITS are not blocked. |
| **Other programs it launches** (default browser, PowerShell, cmd) | Restricting a shared program by path would affect every user of it. | Observed and reported, never restricted automatically. |
| **Local proxies** | If an application sends traffic through a proxy process on the same machine, the proxy is what connects out. | Restrict the proxy itself, or enforce the policy at the proxy. |
| **Loopback** (`127.0.0.1`, `::1`) | Windows Firewall does not filter loopback traffic. | Local inter-process communication is unaffected. Tests must use a remote server. |
| **Packaged (MSIX / Microsoft Store) apps** | Windows filters them by package identity, not path. | Reported as **Unsupported**; never shown as enforced. |

## Timing

* **Connections opened before a rule existed** may continue until they close; Windows does not always terminate established flows when a rule is added. Restart the application for a clean state.
* **While-running retention** creates rules after process creation is observed. Detection is event-driven and the rule follows within tens to hundreds of milliseconds, but the first connection attempts can happen before it. Use **persistent** retention (the default) when this matters; persistent rules exist before launch.
* **Detection latency.** As LocalSystem, launches are reported through ETW kernel events within about 0.1–0.5 s. Without administrative rights (diagnostic runs only), WMI polls every second, and a process that lives for less than a second can be missed. Diagnostics shows which sources are active and how many events each delivered.

## Environment

| Condition | Effect | How it is shown |
|---|---|---|
| Firewall turned off for the current profile | Rules exist but are not enforced | **Degraded**, with the profile named |
| Group Policy disables local rule merging (`LocalPolicyModifyState = GroupPolicyOverride`) | Locally created rules may be ignored | **Degraded**. Deploy restrictions through Group Policy, or allow local merging. |
| Third-party firewall replaces Windows Defender Firewall | Windows Firewall rules may not apply | Registered firewall products are listed on the Firewall page; the firewall shows as off |
| Windows Defender Firewall service stopped | Nothing can be enforced or verified | **Failed** for every restricted application |
| Policy targets profiles other than the current network | Not restricting right now (by design) | **Inactive on this network** |
| VPN clients | Usually not relevant: rules match the program regardless of interface. Some VPNs install their own WFP filters, which can override Windows Firewall rules. | Validate with the end-to-end test (TESTING.md, M10). |

## Detecting blocked attempts

Notifications that an application *tried* to connect are based only on Windows Filtering Platform audit event 5157. This event exists only when the **Filtering Platform Connection** failure audit policy is enabled. NetGuard never changes audit policy itself. To enable it (administrator, can be noisy on busy machines):

```
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
```

Without it, NetGuard reports blocks as configured and verified, but does not claim to have observed attempts.

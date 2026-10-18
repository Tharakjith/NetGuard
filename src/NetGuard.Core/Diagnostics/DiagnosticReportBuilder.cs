using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Monitoring;
using NetGuard.Core.Queries;
using NetGuard.Core.Security;
using NetGuard.Domain;

namespace NetGuard.Core.Diagnostics;

/// <summary>
/// Replaces personal identifiers in diagnostic output: user-profile path segments, account names and the computer
/// name. Applied to every string placed in a redacted report.
/// </summary>
public sealed partial class Redactor
{
    private readonly bool _enabled;
    private readonly string _machineName;
    private readonly Dictionary<string, string> _accounts = new(StringComparer.OrdinalIgnoreCase);

    public Redactor(bool enabled, string machineName)
    {
        _enabled = enabled;
        _machineName = machineName;
    }

    public string? Text(string? value)
    {
        if (!_enabled || string.IsNullOrEmpty(value))
        {
            return value;
        }

        var result = UserProfilePath().Replace(value, m => m.Groups["prefix"].Value + "<user>");
        if (_machineName.Length > 0)
        {
            result = result.Replace(_machineName, "<computer>", StringComparison.OrdinalIgnoreCase);
        }

        return result;
    }

    public string Account(string? account)
    {
        if (!_enabled || string.IsNullOrEmpty(account) || account is "system")
        {
            return account ?? string.Empty;
        }

        if (!_accounts.TryGetValue(account, out var alias))
        {
            alias = $"<account-{_accounts.Count + 1}>";
            _accounts[account] = alias;
        }

        return alias;
    }

    [GeneratedRegex(@"(?<prefix>[A-Za-z]:\\Users\\)[^\\""\r\n,;]+", RegexOptions.CultureInvariant)]
    private static partial Regex UserProfilePath();
}

public sealed class DiagnosticReportBuilder
{
    private readonly QueryService _queries;
    private readonly IPolicyStore _store;
    private readonly IAuditLog _audit;
    private readonly ObservationLog _observations;
    private readonly AuditWriter _auditWriter;
    private readonly IClock _clock;

    public DiagnosticReportBuilder(QueryService queries, IPolicyStore store, IAuditLog audit, ObservationLog observations, AuditWriter auditWriter, IClock clock)
    {
        _queries = queries;
        _store = store;
        _audit = audit;
        _observations = observations;
        _auditWriter = auditWriter;
        _clock = clock;
    }

    public async Task<ExportResultDto> BuildAsync(DiagnosticsRequest request, ActorContext actor, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var r = new Redactor(request.Redact, Environment.MachineName);
        var service = await _queries.GetServiceInfoAsync(actor, cancellationToken).ConfigureAwait(false);
        var firewall = await _queries.GetFirewallOverviewAsync(cancellationToken).ConfigureAwait(false);
        var applications = await _queries.ListApplicationsAsync(cancellationToken).ConfigureAwait(false);
        var details = await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false);
        var profiles = await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false);
        var settings = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
        var problems = await _audit.QueryAsync(new AuditQuery { Outcomes = [AuditOutcome.Failure, AuditOutcome.Warning, AuditOutcome.Denied], Take = 100 }, cancellationToken).ConfigureAwait(false);

        var report = new
        {
            report = new
            {
                generatedAtUtc = now,
                redacted = request.Redact,
                generatedBy = r.Account(actor.Name),
            },
            environment = new
            {
                product = "NetGuard Enterprise",
                version = service.Version,
                os = RuntimeInformation.OSDescription,
                osVersion = Environment.OSVersion.VersionString,
                architecture = RuntimeInformation.OSArchitecture.ToString(),
                runtime = RuntimeInformation.FrameworkDescription,
                computer = request.Redact ? "<computer>" : Environment.MachineName,
            },
            service = new
            {
                service.StartedAt,
                service.MonitoringMode,
                service.BlockedConnectionAuditingAvailable,
                service.LastReconcileAt,
                lastReconcileError = r.Text(service.LastReconcileError),
                dataDirectory = r.Text(service.DataDirectory),
            },
            firewall = new
            {
                firewall.Status.Available,
                firewall.Status.Error,
                currentProfiles = firewall.Status.CurrentProfiles.ToString(),
                profiles = firewall.Status.Profiles,
                firewall.Status.LocalPolicyModifyState,
                firewall.Status.RegisteredFirewallProducts,
                firewall.Status.TotalRuleCount,
                firewall.Status.OwnedRuleCount,
                firewall.Status.Issues,
                ownedRules = firewall.OwnedRules.Select(rule => RedactRule(rule, r)),
                orphanedRules = firewall.OrphanedRules.Select(rule => RedactRule(rule, r)),
                conflicts = firewall.Conflicts.Select(c => new { c.ApplicationName, executablePath = r.Text(c.ExecutablePath), c.RuleName, c.Explanation }),
            },
            applications = applications.Select(a =>
            {
                var application = details.First(d => d.Id == a.Id);
                return new
                {
                    a.Id,
                    a.DisplayName,
                    a.Publisher,
                    a.IsEnabled,
                    source = a.Source.ToString(),
                    a.IsRunning,
                    policy = PolicyServiceDescribe(a.Policy),
                    effectivePolicy = PolicyServiceDescribe(a.EffectivePolicy),
                    a.ProfileName,
                    enforcement = new
                    {
                        state = a.Enforcement.State.ToString(),
                        message = r.Text(a.Enforcement.Message),
                        warnings = a.Enforcement.Warnings.Select(r.Text),
                        a.Enforcement.ExpectedRuleCount,
                        a.Enforcement.VerifiedRuleCount,
                        a.Enforcement.LastVerifiedAt,
                    },
                    executables = application.Executables.Select(e => new
                    {
                        path = r.Text(e.Path),
                        e.IsPrimary,
                        origin = e.Origin.ToString(),
                        e.FileVersion,
                        signature = e.SignatureStatus.ToString(),
                        e.SignerSubject,
                        sha256 = e.Sha256,
                    }),
                };
            }),
            profiles = profiles.Select(p => new { p.Id, p.Name, p.IsEnabled, p.IsBuiltIn, source = p.Source.ToString(), policy = PolicyServiceDescribe(p.Policy) }),
            settings,
            observations = _observations.GetAll().Select(o => new { o.Timestamp, kind = o.Kind.ToString(), o.ApplicationName, executablePath = r.Text(o.ExecutablePath), detail = r.Text(o.Detail), o.Count }),
            recentProblems = problems.Items.Select(e => new
            {
                e.Timestamp,
                type = e.Type.ToString(),
                outcome = e.Outcome.ToString(),
                actor = r.Account(e.Actor),
                e.ApplicationName,
                executablePath = r.Text(e.ExecutablePath),
                message = r.Text(e.Message),
            }),
            knownLimitations = KnownLimitations,
        };

        var json = JsonSerializer.Serialize(report, NetGuardJson.Indented);
        await _auditWriter.WriteAsync(AuditEventType.DiagnosticsGenerated, AuditOutcome.Info,
            $"Diagnostic report generated ({(request.Redact ? "redacted" : "not redacted")}).", actor.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
        return new ExportResultDto
        {
            SuggestedFileName = $"netguard-diagnostics-{now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture)}.json",
            ContentType = "application/json",
            Content = json,
        };
    }

    public static readonly IReadOnlyList<string> KnownLimitations =
    [
        "Rules are scoped to executable paths. Traffic that an application delegates to another process (Windows services such as BITS or the DNS Client, a browser, an update service, or a helper outside its install directory) is controlled by that process's rules, not the application's.",
        "DNS name resolution is performed by the DNS Client service (svchost.exe), so a blocked application can still resolve names; it cannot connect to the results.",
        "Windows Firewall does not filter loopback (127.0.0.1/::1) traffic. Local inter-process communication is unaffected.",
        "Connections that were already established before a rule was created may continue until they close. Restart the application for a guaranteed clean state.",
        "While-running retention creates rules after the process is detected; a process can attempt connections in the short interval before. Use persistent retention when this matters.",
        "Packaged (Microsoft Store/MSIX) applications are filtered by package identity and cannot be controlled with program-path rules.",
        "If Group Policy disables local rule merging, or the firewall is turned off or replaced by a third-party firewall, NetGuard rules exist but are not enforced. NetGuard reports this as Degraded.",
    ];

    private static object RedactRule(FirewallRuleDto rule, Redactor r) => new
    {
        rule.Name,
        applicationPath = r.Text(rule.ApplicationPath),
        rule.Direction,
        rule.Action,
        rule.Enabled,
        rule.Protocol,
        rule.RemoteAddresses,
        rule.RemotePorts,
        profiles = rule.Profiles.ToString(),
        rule.ApplicationName,
    };

    private static string PolicyServiceDescribe(ApplicationPolicy policy) => Policies.PolicyService.DescribePolicy(policy);
}

using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Enforcement;
using NetGuard.Core.Firewall;
using NetGuard.Core.Monitoring;
using NetGuard.Core.Planning;
using NetGuard.Core.Security;
using NetGuard.Domain;

namespace NetGuard.Core.Queries;

/// <summary>Static facts about the running service, supplied by the host.</summary>
public sealed class ServiceRuntimeInfo
{
    public string Version { get; init; } = "0.0.0";

    public DateTimeOffset StartedAt { get; init; }

    public string DataDirectory { get; init; } = string.Empty;

    public Func<string> MonitoringMode { get; init; } = () => "Unknown";

    public Func<bool> BlockedConnectionAuditing { get; init; } = () => false;
}

/// <summary>Read-only views for the desktop interface. Firewall data is always read fresh, never cached.</summary>
public sealed class QueryService
{
    private static readonly AuditEventType[] PolicyChangeTypes =
    [
        AuditEventType.ApplicationAdded, AuditEventType.ApplicationUpdated, AuditEventType.ApplicationRemoved,
        AuditEventType.PolicyChanged, AuditEventType.ProfileChanged, AuditEventType.TemporaryExceptionGranted,
        AuditEventType.TemporaryExceptionEnded, AuditEventType.ConfigurationImported, AuditEventType.ConfigurationChanged,
    ];

    private readonly IPolicyStore _store;
    private readonly IAuditLog _audit;
    private readonly IFirewallManager _firewall;
    private readonly IRuntimeState _runtime;
    private readonly ObservationLog _observations;
    private readonly EnforcementEngine _engine;
    private readonly ServiceRuntimeInfo _info;

    public QueryService(
        IPolicyStore store,
        IAuditLog audit,
        IFirewallManager firewall,
        IRuntimeState runtime,
        ObservationLog observations,
        EnforcementEngine engine,
        ServiceRuntimeInfo info)
    {
        _store = store;
        _audit = audit;
        _firewall = firewall;
        _runtime = runtime;
        _observations = observations;
        _engine = engine;
        _info = info;
    }

    public async Task<ServiceInfoDto> GetServiceInfoAsync(ActorContext actor, CancellationToken cancellationToken)
    {
        var settings = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
        var (state, rules) = ReadFirewall();
        return new ServiceInfoDto
        {
            Version = _info.Version,
            ProtocolVersion = IpcConstants.ProtocolVersion,
            StartedAt = _info.StartedAt,
            MonitoringMode = _info.MonitoringMode(),
            BlockedConnectionAuditingAvailable = _info.BlockedConnectionAuditing(),
            DataDirectory = actor.Has(Permission.Modify, settings) ? _info.DataDirectory : string.Empty,
            Caller = actor.ToDto(settings),
            Firewall = ToDto(state, rules),
            LastReconcileAt = _engine.LastRunAt,
            LastReconcileError = _engine.LastError,
        };
    }

    public async Task<IReadOnlyList<ApplicationSummaryDto>> ListApplicationsAsync(CancellationToken cancellationToken)
    {
        var applications = await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false);
        var profiles = (await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(p => p.Id);
        var statuses = (await _store.GetStatusesAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(s => s.ApplicationId);
        var exceptions = (await _store.GetExceptionsAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(e => e.ApplicationId);
        return applications
            .Select(a => Summarize(a, profiles, statuses.GetValueOrDefault(a.Id), exceptions.GetValueOrDefault(a.Id)))
            .OrderBy(a => a.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    public async Task<DashboardDto> GetDashboardAsync(ActorContext actor, CancellationToken cancellationToken)
    {
        var applications = await ListApplicationsAsync(cancellationToken).ConfigureAwait(false);
        var service = await GetServiceInfoAsync(actor, cancellationToken).ConfigureAwait(false);
        var changes = await _audit.QueryAsync(new AuditQuery { Types = PolicyChangeTypes, Take = 10 }, cancellationToken).ConfigureAwait(false);
        var failures = await _audit.QueryAsync(new AuditQuery { Outcomes = [AuditOutcome.Failure], Take = 10 }, cancellationToken).ConfigureAwait(false);

        bool Restricting(ApplicationSummaryDto a, PolicyMode mode) => a.IsEnabled && a.EffectivePolicy.Mode == mode;
        return new DashboardDto
        {
            ManagedCount = applications.Count,
            RunningCount = applications.Count(a => a.IsRunning),
            BlockedCount = applications.Count(a => Restricting(a, PolicyMode.Block)),
            CustomCount = applications.Count(a => Restricting(a, PolicyMode.Custom)),
            AllowedCount = applications.Count(a => !a.IsEnabled || a.EffectivePolicy.Mode == PolicyMode.Allow),
            ErrorCount = applications.Count(a => a.Enforcement.State is EnforcementState.Failed or EnforcementState.Degraded),
            EnforcedCount = applications.Count(a => a.Enforcement.State == EnforcementState.Enforced),
            Service = service,
            Applications = applications,
            RecentPolicyChanges = changes.Items,
            RecentFailures = failures.Items,
        };
    }

    public async Task<ApplicationDetailDto> GetApplicationAsync(Guid id, CancellationToken cancellationToken)
    {
        var application = await _store.GetApplicationAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new NotFoundException("Application not found.");
        var profiles = (await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(p => p.Id);
        var status = (await _store.GetStatusesAsync(cancellationToken).ConfigureAwait(false)).FirstOrDefault(s => s.ApplicationId == id);
        var exception = (await _store.GetExceptionsAsync(cancellationToken).ConfigureAwait(false)).FirstOrDefault(e => e.ApplicationId == id);
        var summary = Summarize(application, profiles, status, exception);

        var (state, rules) = ReadFirewall();
        var owned = rules.Where(r => OwnedRules.GetApplicationId(r) == id).Select(r => ToDto(r, application)).ToList();
        var profile = application.ProfileId is { } pid ? profiles.GetValueOrDefault(pid) : null;
        var plan = RulePlanner.Plan(application, profile, new ApplicationRuntime(_runtime.IsRunning(id), exception));
        var conflicts = state.Available ? ConflictDetector.Find(plan, rules.Where(r => !OwnedRules.IsOwned(r)).ToList(), state) : [];

        return new ApplicationDetailDto
        {
            Application = application,
            Summary = summary,
            Exception = exception,
            RunningProcesses = _runtime.GetInstances(id)
                .Select(i => new RunningProcessDto { ProcessId = i.ProcessId, ExecutablePath = i.ExecutablePath, StartedAt = i.StartTime })
                .ToList(),
            Rules = owned,
            Conflicts = conflicts,
            Observations = _observations.GetAll(id),
        };
    }

    public async Task<FirewallOverviewDto> GetFirewallOverviewAsync(CancellationToken cancellationToken)
    {
        var applications = (await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(a => a.Id);
        var profiles = (await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(p => p.Id);
        var exceptions = (await _store.GetExceptionsAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(e => e.ApplicationId);
        var (state, rules) = ReadFirewall();

        var owned = new List<FirewallRuleDto>();
        var orphaned = new List<FirewallRuleDto>();
        foreach (var rule in rules.Where(OwnedRules.IsOwned))
        {
            var appId = OwnedRules.GetApplicationId(rule)!.Value;
            if (applications.TryGetValue(appId, out var application))
            {
                owned.Add(ToDto(rule, application));
            }
            else
            {
                orphaned.Add(ToDto(rule, null));
            }
        }

        var thirdParty = rules.Where(r => !OwnedRules.IsOwned(r)).ToList();
        var conflicts = state.Available
            ? applications.Values.SelectMany(a => ConflictDetector.Find(
                RulePlanner.Plan(a, a.ProfileId is { } pid ? profiles.GetValueOrDefault(pid) : null, new ApplicationRuntime(_runtime.IsRunning(a.Id), exceptions.GetValueOrDefault(a.Id))),
                thirdParty,
                state)).ToList()
            : [];

        return new FirewallOverviewDto
        {
            Status = ToDto(state, rules),
            OwnedRules = owned.OrderBy(r => r.ApplicationName).ThenBy(r => r.Name).ToList(),
            OrphanedRules = orphaned,
            Conflicts = conflicts,
        };
    }

    public static ApplicationSummaryDto Summarize(
        ManagedApplication application,
        IReadOnlyDictionary<Guid, PolicyProfile> profiles,
        EnforcementStatus? status,
        TemporaryException? exception,
        IRuntimeState? runtime = null)
    {
        var profile = application.ProfileId is { } pid ? profiles.GetValueOrDefault(pid) : null;
        return new ApplicationSummaryDto
        {
            Id = application.Id,
            DisplayName = application.DisplayName,
            Publisher = application.Publisher,
            PrimaryPath = application.PrimaryExecutable?.Path,
            ExecutableCount = application.Executables.Count,
            IsEnabled = application.IsEnabled,
            Source = application.Source,
            Policy = application.Policy,
            EffectivePolicy = application.GetEffectivePolicy(profile),
            ProfileName = profile?.Name,
            ProfileOverridesPolicy = profile is { IsEnabled: true },
            Enforcement = status ?? new EnforcementStatus { ApplicationId = application.Id, State = EnforcementState.Pending, Message = "Waiting for the first verification." },
            ExceptionExpiresAt = exception?.ExpiresAt,
            SignatureStatus = application.PrimaryExecutable?.SignatureStatus ?? SignatureStatus.Unknown,
            CreatedAt = application.CreatedAt,
            ModifiedAt = application.ModifiedAt,
            Revision = application.Revision,
            IsRunning = runtime?.IsRunning(application.Id) ?? false,
            RunningInstances = runtime?.GetInstances(application.Id).Count ?? 0,
        };
    }

    private ApplicationSummaryDto Summarize(
        ManagedApplication application,
        IReadOnlyDictionary<Guid, PolicyProfile> profiles,
        EnforcementStatus? status,
        TemporaryException? exception) => Summarize(application, profiles, status, exception, _runtime);

    private (FirewallState State, IReadOnlyList<FirewallRule> Rules) ReadFirewall()
    {
        try
        {
            var state = _firewall.GetState();
            return (state, state.Available ? _firewall.GetRules() : []);
        }
        catch (Exception ex)
        {
            return (FirewallState.Unavailable(ex.Message), []);
        }
    }

    public static FirewallStatusDto ToDto(FirewallState state, IReadOnlyList<FirewallRule> rules)
    {
        var issues = new List<string>();
        if (!state.Available)
        {
            issues.Add(state.Error ?? "Windows Defender Firewall is not available.");
        }
        else
        {
            foreach (var profile in state.Profiles.Where(p => !p.Enabled))
            {
                issues.Add(state.CurrentProfiles.HasFlag(profile.Profile)
                    ? $"The firewall is turned off for the {profile.Profile} profile, which is the current network. Restrictions are not enforced."
                    : $"The firewall is turned off for the {profile.Profile} profile. Restrictions will not apply when connected to such a network.");
            }

            if (state.LocalPolicy == LocalPolicyState.GroupPolicyOverride)
            {
                issues.Add("Group Policy overrides the local firewall policy. Rules created by NetGuard may be ignored.");
            }
        }

        return new FirewallStatusDto
        {
            Available = state.Available,
            Error = state.Error,
            CurrentProfiles = state.CurrentProfiles,
            Profiles = state.Profiles.Select(p => new FirewallProfileDto
            {
                Profile = p.Profile,
                Enabled = p.Enabled,
                IsCurrent = state.CurrentProfiles.HasFlag(p.Profile),
                DefaultInboundBlocked = p.DefaultInboundBlock,
                DefaultOutboundBlocked = p.DefaultOutboundBlock,
            }).ToList(),
            LocalPolicyModifyState = state.LocalPolicy.ToString(),
            RegisteredFirewallProducts = state.RegisteredProducts,
            TotalRuleCount = rules.Count,
            OwnedRuleCount = rules.Count(OwnedRules.IsOwned),
            Issues = issues,
        };
    }

    public static FirewallRuleDto ToDto(FirewallRule rule, ManagedApplication? application) => new()
    {
        Name = rule.Name,
        Description = rule.Description,
        ApplicationPath = rule.ApplicationName,
        Direction = rule.Direction.ToString(),
        Action = rule.Action.ToString(),
        Enabled = rule.Enabled,
        Protocol = FirewallProtocols.Describe(rule.Protocol),
        RemoteAddresses = string.IsNullOrEmpty(rule.RemoteAddresses) ? "*" : rule.RemoteAddresses,
        RemotePorts = string.IsNullOrEmpty(rule.RemotePorts) ? "*" : rule.RemotePorts,
        Profiles = rule.NormalizedProfiles,
        Grouping = rule.Grouping,
        IsOwned = OwnedRules.IsOwned(rule),
        ApplicationId = OwnedRules.GetApplicationId(rule),
        ApplicationName = application?.DisplayName,
    };
}

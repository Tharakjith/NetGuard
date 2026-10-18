using System.Diagnostics;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Events;
using NetGuard.Core.Firewall;
using NetGuard.Core.Monitoring;
using NetGuard.Core.Planning;
using NetGuard.Domain;

namespace NetGuard.Core.Enforcement;

public enum ReconcileTrigger
{
    Startup,
    PolicyChange,
    ProcessLaunch,
    ProcessExit,
    IntegrityCheck,
    FirewallChanged,
    ExceptionExpiry,
    Manual,
}

public sealed record ReconcileOptions(ReconcileTrigger Trigger, string Reason, string Actor = "system", bool RemoveOrphans = false);

public sealed record ReconcileReport
{
    public int RulesAdded { get; init; }

    public int RulesUpdated { get; init; }

    public int RulesRemoved { get; init; }

    public int Failures { get; init; }

    public int OrphanedRules { get; init; }

    public bool DriftDetected { get; init; }

    public IReadOnlyList<string> Errors { get; init; } = [];

    public IReadOnlyDictionary<Guid, EnforcementStatus> Statuses { get; init; } = new Dictionary<Guid, EnforcementStatus>();

    public DateTimeOffset? NextExceptionExpiry { get; init; }

    public TimeSpan Duration { get; init; }

    public ReconcileResultDto ToDto() => new()
    {
        RulesAdded = RulesAdded,
        RulesUpdated = RulesUpdated,
        RulesRemoved = RulesRemoved,
        Failures = Failures,
        OrphanedRules = OrphanedRules,
        DurationMs = (long)Duration.TotalMilliseconds,
        Errors = Errors,
    };
}

/// <summary>
/// Converges Windows Defender Firewall to the configured policies. Every run: plan desired rules, read actual rules,
/// add/replace/remove only NetGuard-owned rules, read back to verify, then derive each application's state from the
/// verified configuration and the firewall's environment. Runs are serialized.
/// </summary>
public sealed class EnforcementEngine
{
    private readonly IPolicyStore _store;
    private readonly IFirewallManager _firewall;
    private readonly IRuntimeState _runtime;
    private readonly AuditWriter _audit;
    private readonly EventBroker _events;
    private readonly IClock _clock;
    private readonly ILogger<EnforcementEngine> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public EnforcementEngine(
        IPolicyStore store,
        IFirewallManager firewall,
        IRuntimeState runtime,
        AuditWriter audit,
        EventBroker events,
        IClock clock,
        ILogger<EnforcementEngine> logger)
    {
        _store = store;
        _firewall = firewall;
        _runtime = runtime;
        _audit = audit;
        _events = events;
        _clock = clock;
        _logger = logger;
    }

    public DateTimeOffset? LastRunAt { get; private set; }

    public string? LastError { get; private set; }

    public async Task<ReconcileReport> ReconcileAsync(ReconcileOptions options, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await ReconcileCoreAsync(options, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<ReconcileReport> ReconcileCoreAsync(ReconcileOptions options, CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var now = _clock.UtcNow;
        var applications = await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false);
        var profiles = (await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(p => p.Id);
        var exceptions = await ExpireExceptionsAsync(applications, now, cancellationToken).ConfigureAwait(false);
        var previous = (await _store.GetStatusesAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(s => s.ApplicationId);

        var plans = applications
            .Select(app => RulePlanner.Plan(
                app,
                app.ProfileId is { } profileId ? profiles.GetValueOrDefault(profileId) : null,
                new ApplicationRuntime(_runtime.IsRunning(app.Id), exceptions.GetValueOrDefault(app.Id))))
            .ToList();

        FirewallState state;
        IReadOnlyList<FirewallRule> rules;
        try
        {
            state = _firewall.GetState();
            if (!state.Available)
            {
                throw new FirewallUnavailableException(state.Error ?? "Windows Defender Firewall is not available.");
            }

            rules = _firewall.GetRules();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return await HandleFirewallUnavailableAsync(options, plans, previous, ex, exceptions, stopwatch, cancellationToken).ConfigureAwait(false);
        }

        var desired = plans.SelectMany(p => p.Rules).ToDictionary(r => r.Key, StringComparer.Ordinal);
        var knownApplications = applications.ToDictionary(a => a.Id);
        var errorsByApp = new Dictionary<Guid, List<RuleError>>();
        var errors = new List<string>();
        int added = 0, updated = 0, removed = 0, orphaned = 0;
        var driftApps = new HashSet<Guid>();
        var mutated = false;

        void RecordError(Guid appId, string action, string ruleName, string cause)
        {
            errors.Add($"Could not {action} rule '{ruleName}': {cause}");
            if (!errorsByApp.TryGetValue(appId, out var list))
            {
                errorsByApp[appId] = list = [];
            }

            list.Add(new RuleError(action, ruleName, cause));
        }

        // Step 1: collapse duplicate owned rules that share a key (left behind by an interrupted update).
        if (RemoveDuplicates(rules, desired, RecordError))
        {
            rules = _firewall.GetRules();
            mutated = true;
        }

        var current = OwnedByKey(rules);

        // Step 2: create or replace rules that are missing or differ.
        foreach (var spec in desired.Values)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var application = knownApplications[spec.ApplicationId];
            try
            {
                if (current.TryGetValue(spec.Key, out var existing))
                {
                    var difference = RuleMatcher.Explain(existing, spec);
                    if (difference is null)
                    {
                        continue;
                    }

                    ReplaceRule(existing, spec);
                    updated++;
                    mutated = true;
                    if (WasVerified(previous, spec.ApplicationId))
                    {
                        driftApps.Add(spec.ApplicationId);
                    }

                    await _audit.WriteAsync(AuditEventType.EnforcementApplied, AuditOutcome.Success,
                        $"Firewall rule corrected ({difference}): {spec.Name}", options.Actor, application, spec.ApplicationPath,
                        new { spec.Name, reason = options.Reason, difference }, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    _firewall.AddRule(spec);
                    added++;
                    mutated = true;
                    if (WasVerified(previous, spec.ApplicationId) && options.Trigger is not ReconcileTrigger.PolicyChange)
                    {
                        driftApps.Add(spec.ApplicationId);
                    }

                    await _audit.WriteAsync(AuditEventType.EnforcementApplied, AuditOutcome.Success,
                        $"Firewall rule created: {spec.Name}", options.Actor, application, spec.ApplicationPath,
                        new { spec.Name, spec.Protocol, spec.RemoteAddresses, spec.RemotePorts, profiles = spec.Profiles.ToString(), reason = options.Reason },
                        cancellationToken).ConfigureAwait(false);
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                var message = $"Could not apply rule '{spec.Name}': {ex.Message}";
                RecordError(spec.ApplicationId, "apply", spec.Name, ex.Message);
                _logger.LogError(ex, "Failed to apply firewall rule {RuleName}", spec.Name);
                await _audit.WriteAsync(AuditEventType.EnforcementFailed, AuditOutcome.Failure, message, options.Actor, application,
                    spec.ApplicationPath, new { spec.Name, error = ex.Message, hresult = ex.HResult }, cancellationToken).ConfigureAwait(false);
            }
        }

        // Step 3: remove owned rules that are no longer desired. Rules for unknown applications are orphans:
        // they are kept (fail closed) unless an administrator explicitly asked for clean-up.
        foreach (var (key, rule) in current)
        {
            if (desired.ContainsKey(key))
            {
                continue;
            }

            OwnedRules.TryParseKey(key, out var appId, out _, out _);
            knownApplications.TryGetValue(appId, out var application);
            if (application is null)
            {
                orphaned++;
                if (!options.RemoveOrphans)
                {
                    continue;
                }
            }

            try
            {
                _firewall.RemoveOwnedRule(rule.Name);
                removed++;
                mutated = true;
                if (application is null)
                {
                    orphaned--;
                }

                var why = application is null
                    ? "orphaned rule removed by administrator request"
                    : $"no longer required ({plans.First(p => p.Application.Id == appId).Disposition})";
                await _audit.WriteAsync(AuditEventType.RuleRemoved, AuditOutcome.Success, $"Firewall rule removed, {why}: {rule.Name}",
                    options.Actor, application, rule.ApplicationName, new { rule.Name, reason = options.Reason }, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                var message = $"Could not remove rule '{rule.Name}': {ex.Message}";
                RecordError(appId, "remove", rule.Name, ex.Message);
                _logger.LogError(ex, "Failed to remove firewall rule {RuleName}", rule.Name);
                await _audit.WriteAsync(AuditEventType.EnforcementFailed, AuditOutcome.Failure, message, options.Actor, application,
                    rule.ApplicationName, new { rule.Name, error = ex.Message }, cancellationToken).ConfigureAwait(false);
            }
        }

        // Step 4: verify by reading the configuration back from the firewall.
        if (mutated)
        {
            try
            {
                rules = _firewall.GetRules();
                state = _firewall.GetState();
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return await HandleFirewallUnavailableAsync(options, plans, previous, ex, exceptions, stopwatch, cancellationToken).ConfigureAwait(false);
            }
        }

        current = OwnedByKey(rules);
        var thirdParty = rules.Where(r => !OwnedRules.IsOwned(r)).ToList();
        var statuses = new Dictionary<Guid, EnforcementStatus>();
        foreach (var plan in plans)
        {
            var conflicts = ConflictDetector.Find(plan, thirdParty, state);
            statuses[plan.Application.Id] = StatusEvaluator.Evaluate(
                plan,
                state,
                current,
                Summarize(errorsByApp.GetValueOrDefault(plan.Application.Id)),
                conflicts,
                _runtime.GetWarnings(plan.Application.Id),
                exceptions.GetValueOrDefault(plan.Application.Id),
                previous.GetValueOrDefault(plan.Application.Id),
                now);
        }

        await PersistAndAnnounceAsync(options, plans, previous, statuses, driftApps, mutated, cancellationToken).ConfigureAwait(false);

        LastRunAt = now;
        LastError = errors.Count > 0 ? errors[0] : null;
        var report = new ReconcileReport
        {
            RulesAdded = added,
            RulesUpdated = updated,
            RulesRemoved = removed,
            Failures = errors.Count,
            OrphanedRules = orphaned,
            DriftDetected = driftApps.Count > 0,
            Errors = errors,
            Statuses = statuses,
            NextExceptionExpiry = exceptions.Values.Select(e => (DateTimeOffset?)e.ExpiresAt).Min(),
            Duration = stopwatch.Elapsed,
        };

        _logger.LogInformation(
            "Reconcile ({Trigger}: {Reason}) added={Added} updated={Updated} removed={Removed} failures={Failures} orphaned={Orphaned} in {Elapsed} ms",
            options.Trigger, options.Reason, added, updated, removed, errors.Count, orphaned, stopwatch.ElapsedMilliseconds);
        return report;
    }

    private sealed record RuleError(string Action, string RuleName, string Cause);

    /// <summary>
    /// Collapses failures with the same action and cause into one sentence, so the status reads
    /// "Could not apply 4 rules: Access denied…" instead of repeating the cause once per rule.
    /// The audit log keeps one detailed record per rule.
    /// </summary>
    private static IReadOnlyList<string> Summarize(List<RuleError>? errors) =>
        errors is null
            ? []
            : errors
                .GroupBy(e => (e.Action, e.Cause))
                .Select(g => g.Count() == 1
                    ? $"Could not {g.Key.Action} rule '{g.First().RuleName}': {g.Key.Cause}"
                    : $"Could not {g.Key.Action} {g.Count()} rules: {g.Key.Cause}")
                .ToList();

    private bool RemoveDuplicates(IReadOnlyList<FirewallRule> rules, IReadOnlyDictionary<string, FirewallRuleSpec> desired, Action<Guid, string, string, string> recordError)
    {
        var changed = false;
        var groups = rules
            .Where(OwnedRules.IsOwned)
            .GroupBy(r => OwnedRules.TryGetKey(r.Description)!, StringComparer.Ordinal)
            .Where(g => g.Count() > 1);

        foreach (var group in groups)
        {
            desired.TryGetValue(group.Key, out var spec);
            var keep = group.FirstOrDefault(r => spec is not null && RuleMatcher.Matches(r, spec)) ?? group.First();
            foreach (var name in group.Where(r => !ReferenceEquals(r, keep)).Select(r => r.Name).Distinct(StringComparer.Ordinal))
            {
                try
                {
                    // Removing by name also removes 'keep' when it shares the name; the next step re-creates it.
                    _firewall.RemoveOwnedRule(name);
                    changed = true;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    OwnedRules.TryParseKey(group.Key, out var appId, out _, out _);
                    recordError(appId, "remove duplicate", name, ex.Message);
                }
            }
        }

        return changed;
    }

    /// <summary>Make-before-break: the replacement exists before the old rule is removed, so the program is never unblocked.</summary>
    private void ReplaceRule(FirewallRule existing, FirewallRuleSpec spec)
    {
        if (!string.Equals(existing.Name, spec.Name, StringComparison.Ordinal))
        {
            _firewall.AddRule(spec);
            _firewall.RemoveOwnedRule(existing.Name);
            return;
        }

        var temporaryName = spec.Name + " (updating)";
        _firewall.AddRule(spec with { Name = temporaryName });
        _firewall.RemoveOwnedRule(existing.Name);
        _firewall.RenameOwnedRule(temporaryName, spec.Name);
    }

    private static Dictionary<string, FirewallRule> OwnedByKey(IEnumerable<FirewallRule> rules)
    {
        var result = new Dictionary<string, FirewallRule>(StringComparer.Ordinal);
        foreach (var rule in rules)
        {
            var key = OwnedRules.IsOwned(rule) ? OwnedRules.TryGetKey(rule.Description) : null;
            if (key is not null)
            {
                result.TryAdd(key, rule);
            }
        }

        return result;
    }

    private static bool WasVerified(IReadOnlyDictionary<Guid, EnforcementStatus> previous, Guid applicationId) =>
        previous.TryGetValue(applicationId, out var status) &&
        status.State is EnforcementState.Enforced or EnforcementState.Inactive or EnforcementState.Degraded &&
        status.VerifiedRuleCount > 0;

    private async Task<Dictionary<Guid, TemporaryException>> ExpireExceptionsAsync(
        IReadOnlyList<ManagedApplication> applications,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var active = new Dictionary<Guid, TemporaryException>();
        foreach (var exception in await _store.GetExceptionsAsync(cancellationToken).ConfigureAwait(false))
        {
            var application = applications.FirstOrDefault(a => a.Id == exception.ApplicationId);
            if (exception.IsActive(now) && application is not null)
            {
                active[exception.ApplicationId] = exception;
                continue;
            }

            await _store.DeleteExceptionAsync(exception.ApplicationId, cancellationToken).ConfigureAwait(false);
            if (application is not null)
            {
                await _audit.WriteAsync(AuditEventType.TemporaryExceptionEnded, AuditOutcome.Info,
                    "Temporary exception expired; restriction is being re-applied.", "system", application,
                    details: new { exception.GrantedBy, exception.ExpiresAt }, cancellationToken: cancellationToken).ConfigureAwait(false);
                _events.Notify(NotificationKind.TemporaryExceptionEnded, $"{application.DisplayName}: exception ended",
                    "The temporary network exception expired and the restriction is being re-applied.", application.Id);
            }
        }

        return active;
    }

    private async Task<ReconcileReport> HandleFirewallUnavailableAsync(
        ReconcileOptions options,
        IReadOnlyList<ApplicationPlan> plans,
        IReadOnlyDictionary<Guid, EnforcementStatus> previous,
        Exception exception,
        IReadOnlyDictionary<Guid, TemporaryException> exceptions,
        Stopwatch stopwatch,
        CancellationToken cancellationToken)
    {
        var message = exception is FirewallUnavailableException
            ? exception.Message
            : $"Windows Defender Firewall could not be queried: {exception.Message}";
        _logger.LogError(exception, "Firewall unavailable during reconcile ({Reason})", options.Reason);

        var now = _clock.UtcNow;
        var statuses = plans.ToDictionary(
            p => p.Application.Id,
            p => StatusEvaluator.Unverifiable(p, message, previous.GetValueOrDefault(p.Application.Id), now));

        await PersistAndAnnounceAsync(options, plans, previous, statuses, new HashSet<Guid>(), false, cancellationToken).ConfigureAwait(false);
        LastRunAt = now;
        LastError = message;
        return new ReconcileReport
        {
            Failures = 1,
            Errors = [message],
            Statuses = statuses,
            NextExceptionExpiry = exceptions.Values.Select(e => (DateTimeOffset?)e.ExpiresAt).Min(),
            Duration = stopwatch.Elapsed,
        };
    }

    private async Task PersistAndAnnounceAsync(
        ReconcileOptions options,
        IReadOnlyList<ApplicationPlan> plans,
        IReadOnlyDictionary<Guid, EnforcementStatus> previous,
        IReadOnlyDictionary<Guid, EnforcementStatus> statuses,
        IReadOnlySet<Guid> driftApps,
        bool mutated,
        CancellationToken cancellationToken)
    {
        await _store.SaveStatusesAsync(statuses.Values.ToList(), cancellationToken).ConfigureAwait(false);

        var changed = mutated;
        foreach (var plan in plans)
        {
            var application = plan.Application;
            var status = statuses[application.Id];
            var before = previous.GetValueOrDefault(application.Id);

            if (driftApps.Contains(application.Id))
            {
                await _audit.WriteAsync(AuditEventType.IntegrityDrift, AuditOutcome.Warning,
                    "NetGuard rules for this application were missing or modified outside NetGuard and have been restored.",
                    "system", application, details: new { trigger = options.Trigger.ToString() }, cancellationToken: cancellationToken).ConfigureAwait(false);
                _events.Notify(NotificationKind.EnforcementFailed, $"{application.DisplayName}: rules restored",
                    "Firewall rules for this application were changed outside NetGuard and have been restored.", application.Id);
            }

            if (before is not null && before.State == status.State && before.Message == status.Message)
            {
                continue;
            }

            changed = true;
            switch (status.State)
            {
                case EnforcementState.Enforced:
                    await _audit.WriteAsync(AuditEventType.EnforcementVerified, AuditOutcome.Success, status.Message, options.Actor, application,
                        details: new { status.VerifiedRuleCount, trigger = options.Trigger.ToString() }, cancellationToken: cancellationToken).ConfigureAwait(false);
                    if (options.Trigger == ReconcileTrigger.PolicyChange)
                    {
                        _events.Notify(NotificationKind.PolicyApplied, $"{application.DisplayName}: policy applied", status.Message, application.Id);
                    }

                    break;

                case EnforcementState.Failed:
                    await _audit.WriteAsync(AuditEventType.EnforcementFailed, AuditOutcome.Failure, status.Message, options.Actor, application,
                        details: new { status.ExpectedRuleCount, status.VerifiedRuleCount, status.Warnings }, cancellationToken: cancellationToken).ConfigureAwait(false);
                    _events.Notify(NotificationKind.EnforcementFailed, $"{application.DisplayName}: enforcement failed", status.Message, application.Id);
                    break;

                case EnforcementState.Degraded:
                    await _audit.WriteAsync(AuditEventType.EnforcementVerified, AuditOutcome.Warning, status.Message, options.Actor, application,
                        details: new { status.Warnings }, cancellationToken: cancellationToken).ConfigureAwait(false);
                    _events.Notify(NotificationKind.EnforcementFailed, $"{application.DisplayName}: restriction may not be effective", status.Message, application.Id);
                    break;

                default:
                    if (options.Trigger == ReconcileTrigger.PolicyChange)
                    {
                        _events.Notify(NotificationKind.PolicyApplied, $"{application.DisplayName}: policy updated", status.Message, application.Id);
                    }

                    break;
            }
        }

        if (changed)
        {
            _events.PublishStateChanged();
        }
    }
}

using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Firewall;
using NetGuard.Core.Planning;
using NetGuard.Domain;

namespace NetGuard.Core.Enforcement;

/// <summary>Finds rules outside NetGuard's control that may override or undermine a managed application's policy.</summary>
public static class ConflictDetector
{
    public static IReadOnlyList<RuleConflictDto> Find(ApplicationPlan plan, IReadOnlyList<FirewallRule> thirdPartyRules, FirewallState state)
    {
        var application = plan.Application;
        if (!application.IsEnabled || plan.Disposition is PlanDisposition.Unsupported)
        {
            return [];
        }

        var mode = plan.EffectivePolicy.Mode;
        var conflicts = new List<RuleConflictDto>();
        foreach (var executable in application.Executables)
        {
            var relevant = thirdPartyRules
                .Where(r => r.Enabled && r.Direction == FirewallDirection.Outbound && RuleMatcher.PathEquals(r.ApplicationName, executable.Path))
                .ToList();

            if (mode is PolicyMode.Allow or PolicyMode.Custom)
            {
                foreach (var rule in relevant.Where(r => r.Action == FirewallAction.Block))
                {
                    conflicts.Add(new RuleConflictDto
                    {
                        ApplicationId = application.Id,
                        ApplicationName = application.DisplayName,
                        ExecutablePath = executable.Path,
                        RuleName = rule.Name,
                        Explanation = "This block rule was not created by NetGuard. Windows applies block rules before allow rules, so it restricts this program regardless of the NetGuard policy. NetGuard does not modify rules it does not own.",
                    });
                }
            }

            if (mode == PolicyMode.Allow && state.Available)
            {
                var hasAllowRule = relevant.Any(r => r.Action == FirewallAction.Allow);
                foreach (var profile in state.Profiles.Where(p => p.Enabled && p.DefaultOutboundBlock && state.CurrentProfiles.HasFlag(p.Profile)))
                {
                    if (!hasAllowRule)
                    {
                        conflicts.Add(new RuleConflictDto
                        {
                            ApplicationId = application.Id,
                            ApplicationName = application.DisplayName,
                            ExecutablePath = executable.Path,
                            RuleName = $"Default outbound action ({profile.Profile})",
                            Explanation = $"Outbound connections are blocked by default on the {profile.Profile} profile and no allow rule exists for this program. NetGuard never creates allow rules, so an administrator must add one.",
                        });
                    }
                }
            }
        }

        return conflicts;
    }
}

/// <summary>Derives an application's enforcement state strictly from verified firewall configuration.</summary>
public static class StatusEvaluator
{
    public static EnforcementStatus Evaluate(
        ApplicationPlan plan,
        FirewallState state,
        IReadOnlyDictionary<string, FirewallRule> ownedRulesByKey,
        IReadOnlyList<string> errors,
        IReadOnlyList<RuleConflictDto> conflicts,
        IReadOnlyList<string> runtimeWarnings,
        TemporaryException? activeException,
        EnforcementStatus? previous,
        DateTimeOffset now)
    {
        var application = plan.Application;
        var leftover = ownedRulesByKey
            .Where(kv => OwnedRules.TryParseKey(kv.Key, out var appId, out _, out _) && appId == application.Id &&
                         plan.Rules.All(r => r.Key != kv.Key))
            .Select(kv => kv.Value.Name)
            .ToList();

        var warnings = new List<string>(runtimeWarnings);
        warnings.AddRange(plan.Notes);
        warnings.AddRange(conflicts.Select(c => $"{c.RuleName}: {c.Explanation}"));

        EnforcementStatus Status(EnforcementState value, string message, int expected = 0, int verified = 0) => new()
        {
            ApplicationId = application.Id,
            State = value,
            Message = message,
            Warnings = warnings,
            ExpectedRuleCount = expected,
            VerifiedRuleCount = verified,
            EvaluatedAt = now,
            LastVerifiedAt = value is EnforcementState.Enforced or EnforcementState.Inactive or EnforcementState.Degraded
                ? now
                : previous?.LastVerifiedAt,
        };

        // Any rule that should have been removed but still exists is a failure for non-enforcing dispositions.
        if (plan.Disposition != PlanDisposition.RulesRequired && leftover.Count > 0)
        {
            var detail = errors.Count > 0 ? " " + string.Join(" ", errors) : string.Empty;
            return Status(EnforcementState.Failed, $"{leftover.Count} NetGuard rule(s) could not be removed.{detail}");
        }

        switch (plan.Disposition)
        {
            case PlanDisposition.Disabled:
                return Status(EnforcementState.Disabled, "Management is disabled. NetGuard rules for this application were removed; the original firewall configuration applies.");

            case PlanDisposition.Unsupported:
                return Status(EnforcementState.Unsupported, "This application cannot be controlled with program-path firewall rules (packaged/MSIX application).");

            case PlanDisposition.Suspended:
                return Status(EnforcementState.Suspended,
                    $"Temporary exception granted by {activeException?.GrantedBy ?? "an administrator"} until {activeException?.ExpiresAt.ToLocalTime():g}. The restriction is re-applied automatically when it expires.");

            case PlanDisposition.Standby:
                return Status(EnforcementState.Standby, "While-running policy: rules are created when the application starts and removed after it exits.");

            case PlanDisposition.NotRequired:
                return conflicts.Count > 0
                    ? Status(EnforcementState.Degraded, "Allow policy: NetGuard creates no rules, but other firewall configuration restricts this application.")
                    : Status(EnforcementState.NotRequired, "Allow policy: NetGuard creates no rules; the existing system firewall policy applies.");
        }

        var expected = plan.Rules.Count;
        var verified = plan.Rules.Count(spec => ownedRulesByKey.TryGetValue(spec.Key, out var actual) && RuleMatcher.Matches(actual, spec));
        if (verified < expected)
        {
            var detail = errors.Count > 0 ? string.Join(" ", errors) : "Rules were not found when read back from the firewall.";
            return Status(EnforcementState.Failed, $"Verified {verified} of {expected} required rule(s). {detail}", expected, verified);
        }

        var targeted = plan.EffectivePolicy.Profiles;
        var active = targeted & state.CurrentProfiles;
        if (active == NetworkProfiles.None)
        {
            return Status(EnforcementState.Inactive,
                $"Rules verified. This policy applies on {Describe(targeted)} networks; the current network profile is {Describe(state.CurrentProfiles)}, so connections are not restricted right now.",
                expected, verified);
        }

        var issues = new List<string>();
        foreach (var profile in Enum.GetValues<NetworkProfiles>().Where(p => p is NetworkProfiles.Domain or NetworkProfiles.Private or NetworkProfiles.Public && active.HasFlag(p)))
        {
            if (state.GetProfile(profile) is { Enabled: false })
            {
                issues.Add($"Windows Defender Firewall is turned off for the {profile} profile, so rules are not enforced on the current network.");
            }
        }

        if (state.LocalPolicy == LocalPolicyState.GroupPolicyOverride)
        {
            issues.Add("Group Policy overrides the local firewall policy; locally created rules may be ignored. Ask an administrator to allow local rule merging or deploy the rules through Group Policy.");
        }

        if (plan.EffectivePolicy.Mode == PolicyMode.Custom && conflicts.Count > 0)
        {
            issues.Add("Other block rules further restrict this application beyond the custom allow-list.");
        }

        if (issues.Count > 0)
        {
            warnings.InsertRange(0, issues);
            return Status(EnforcementState.Degraded, "Rules are verified but may not take effect: " + issues[0], expected, verified);
        }

        var what = plan.EffectivePolicy.Mode == PolicyMode.Block
            ? "Outbound connections are blocked"
            : "Outbound connections are limited to the custom allow-list";
        var executables = plan.Rules.Select(r => r.ExecutableId).Distinct().Count();
        return Status(EnforcementState.Enforced,
            $"{what} for {executables} executable(s) on {Describe(targeted)} networks. Rules verified in Windows Defender Firewall.",
            expected, verified);
    }

    /// <summary>Status when the firewall cannot be queried: nothing can be verified, so nothing is reported as enforced.</summary>
    public static EnforcementStatus Unverifiable(ApplicationPlan plan, string error, EnforcementStatus? previous, DateTimeOffset now)
    {
        var (state, message) = plan.Disposition switch
        {
            PlanDisposition.RulesRequired => (EnforcementState.Failed, $"Cannot apply or verify rules: {error}"),
            PlanDisposition.NotRequired => (EnforcementState.NotRequired, "Allow policy: NetGuard creates no rules."),
            PlanDisposition.Unsupported => (EnforcementState.Unsupported, "This application cannot be controlled with program-path firewall rules."),
            _ => (EnforcementState.Pending, $"Waiting for Windows Defender Firewall to confirm rule removal: {error}"),
        };

        return new EnforcementStatus
        {
            ApplicationId = plan.Application.Id,
            State = state,
            Message = message,
            Warnings = plan.Notes,
            ExpectedRuleCount = plan.Rules.Count,
            EvaluatedAt = now,
            LastVerifiedAt = previous?.LastVerifiedAt,
        };
    }

    public static string Describe(NetworkProfiles profiles) => profiles switch
    {
        NetworkProfiles.All => "all",
        NetworkProfiles.None => "no",
        _ => string.Join(", ", Enum.GetValues<NetworkProfiles>().Where(p => p is NetworkProfiles.Domain or NetworkProfiles.Private or NetworkProfiles.Public && profiles.HasFlag(p))),
    };
}

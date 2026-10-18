using NetGuard.Core.Abstractions;
using NetGuard.Core.Enforcement;
using NetGuard.Core.Firewall;
using NetGuard.Domain;
using NetGuard.Tests.Unit.Fakes;
using Xunit;

namespace NetGuard.Tests.Unit;

public sealed class EnforcementEngineTests
{
    [Fact]
    public async Task Block_CreatesVerifiedRule_AndReportsEnforced()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);

        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
        var status = await h.StatusAsync(id);
        Assert.Equal(EnforcementState.Enforced, status.State);
        Assert.Equal(1, status.VerifiedRuleCount);
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.EnforcementApplied && e.ApplicationId == id);
    }

    [Fact]
    public async Task OtherApplications_AreNeverAffected()
    {
        await using var h = await Harness.StartAsync();
        await h.AddAsync(Harness.AppPath);

        Assert.Equal(0, h.OwnedRulesFor(Harness.OtherPath));
        Assert.All(h.Firewall.Rules, r => Assert.Equal(Harness.AppPath, r.ApplicationName));
    }

    [Fact]
    public async Task Reconcile_IsIdempotent_NoDuplicateRules()
    {
        await using var h = await Harness.StartAsync();
        await h.AddAsync(Harness.AppPath);
        var mutations = h.Firewall.MutationCount;

        for (var i = 0; i < 5; i++)
        {
            await h.ReconcileAsync(ReconcileTrigger.IntegrityCheck);
        }

        Assert.Equal(mutations, h.Firewall.MutationCount);
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task DeletedRule_IsRestored_AndDriftIsAudited()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);

        h.Firewall.External(rules => rules.Clear());
        var report = await h.ReconcileAsync(ReconcileTrigger.FirewallChanged);

        Assert.True(report.DriftDetected);
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
        Assert.Equal(EnforcementState.Enforced, (await h.StatusAsync(id)).State);
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.IntegrityDrift && e.ApplicationId == id);
    }

    [Fact]
    public async Task TamperedRule_IsCorrected_WithoutEverUnblocking()
    {
        await using var h = await Harness.StartAsync();
        await h.AddAsync(Harness.AppPath);

        // Someone narrows the rule so it no longer blocks everything.
        h.Firewall.External(rules => rules[0] = rules[0] with { RemoteAddresses = "10.0.0.0/8" });
        h.Firewall.History.Clear();
        await h.ReconcileAsync(ReconcileTrigger.FirewallChanged);

        Assert.NotEmpty(h.Firewall.History);
        Assert.All(h.Firewall.History, snapshot =>
            Assert.Contains(snapshot, r => r.ApplicationName == Harness.AppPath && r.RemoteAddresses == "*" && r.Enabled && r.Action == FirewallAction.Block));
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task DuplicateOwnedRules_AreCollapsed()
    {
        await using var h = await Harness.StartAsync();
        await h.AddAsync(Harness.AppPath);
        h.Firewall.External(rules => rules.Add(rules[0] with { Name = rules[0].Name + " (updating)" }));

        await h.ReconcileAsync();

        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task ThirdPartyRules_AreNeverModifiedOrRemoved()
    {
        await using var h = await Harness.StartAsync();
        var thirdParty = FakeFirewall.ThirdPartyRule("Contoso block", Harness.OtherPath);
        h.Firewall.External(rules => rules.Add(thirdParty));
        var id = await h.AddAsync(Harness.AppPath);

        await h.Policies.RemoveApplicationAsync(new Contracts.ApplicationIdRequest { Id = id }, Harness.Admin, h.Token);
        await h.ReconcileAsync(removeOrphans: true);

        Assert.Equal([thirdParty], h.Firewall.Rules);
    }

    [Fact]
    public async Task ThirdPartyRuleWithSameName_IsNotRemoved()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        var owned = h.Firewall.Rules.Single();
        h.Firewall.External(rules => rules.Add(FakeFirewall.ThirdPartyRule(owned.Name, Harness.OtherPath)));

        await h.Policies.SetEnabledAsync(new Contracts.SetEnabledRequest { Id = id, Enabled = false }, Harness.Admin, h.Token);

        Assert.Contains(h.Firewall.Rules, r => r.Grouping == "Contoso Security");
        Assert.Equal(EnforcementState.Failed, (await h.StatusAsync(id)).State);
    }

    [Fact]
    public async Task OrphanedRules_AreKept_UntilAdministratorCleansUp()
    {
        await using var h = await Harness.StartAsync();
        var key = OwnedRules.BuildKey(Guid.NewGuid(), Guid.NewGuid(), "block-all");
        var orphan = new FirewallRule
        {
            Name = "NetGuard - Old", Description = OwnedRules.BuildDescription("Old", key), Grouping = OwnedRules.Grouping,
            ApplicationName = @"C:\Old\old.exe", Direction = FirewallDirection.Outbound, Action = FirewallAction.Block, Enabled = true,
        };
        h.Firewall.External(rules => rules.Add(orphan));

        var report = await h.ReconcileAsync(ReconcileTrigger.Startup);
        Assert.Equal(1, report.OrphanedRules);
        Assert.Contains(orphan, h.Firewall.Rules);

        var cleanup = await h.ReconcileAsync(removeOrphans: true);
        Assert.Equal(1, cleanup.RulesRemoved);
        Assert.DoesNotContain(h.Firewall.Rules, r => r.Name == orphan.Name);
    }

    [Fact]
    public async Task FailedRuleCreation_IsReportedAsFailed_NeverEnforced()
    {
        await using var h = await Harness.StartAsync(x => x.Firewall.FailAdd = _ => true);
        var id = await h.AddAsync(Harness.AppPath);

        var status = await h.StatusAsync(id);
        Assert.Equal(EnforcementState.Failed, status.State);
        Assert.Contains("Simulated failure", status.Message);
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.EnforcementFailed);
    }

    [Fact]
    public async Task RepeatedFailuresWithSameCause_AreSummarizedOnce()
    {
        await using var h = await Harness.StartAsync(x => x.Firewall.FailAdd = _ => true);
        var id = await h.AddAsync(Harness.AppPath, new ApplicationPolicy
        {
            Mode = PolicyMode.Custom,
            Custom = new CustomNetworkPolicy { AllowedRemoteAddresses = ["203.0.113.10"], AllowedTcpPorts = "443" },
        });

        var status = await h.StatusAsync(id);
        Assert.Equal(EnforcementState.Failed, status.State);
        Assert.Contains("Could not apply 4 rules: Simulated failure creating the rule.", status.Message);
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(status.Message, "Simulated failure"));

        // The audit log still has one detailed record per rule.
        Assert.Equal(4, h.Store.Audit.Count(e => e.Type == AuditEventType.EnforcementFailed && e.Message.StartsWith("Could not apply rule '")));
    }

    [Fact]
    public async Task RecoveryAfterFailure_ReappliesOnNextReconcile()
    {
        await using var h = await Harness.StartAsync(x => x.Firewall.FailAdd = _ => true);
        var id = await h.AddAsync(Harness.AppPath);
        h.Firewall.FailAdd = null;

        await h.ReconcileAsync(ReconcileTrigger.IntegrityCheck);

        Assert.Equal(EnforcementState.Enforced, (await h.StatusAsync(id)).State);
    }

    [Fact]
    public async Task FirewallUnavailable_IsFailed_AndNothingClaimsEnforcement()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        h.Firewall.Unavailable = true;

        await h.ReconcileAsync();

        var status = await h.StatusAsync(id);
        Assert.Equal(EnforcementState.Failed, status.State);
        Assert.Contains("stopped", status.Message);
    }

    [Fact]
    public async Task FirewallOffOnCurrentProfile_IsDegraded()
    {
        await using var h = await Harness.StartAsync();
        h.Firewall.State = h.Firewall.State with
        {
            Profiles = h.Firewall.State.Profiles.Select(p => p.Profile == NetworkProfiles.Private ? p with { Enabled = false } : p).ToList(),
        };
        var id = await h.AddAsync(Harness.AppPath);

        var status = await h.StatusAsync(id);
        Assert.Equal(EnforcementState.Degraded, status.State);
        Assert.Contains("turned off", status.Message);
    }

    [Fact]
    public async Task GroupPolicyOverride_IsDegraded()
    {
        await using var h = await Harness.StartAsync();
        h.Firewall.State = h.Firewall.State with { LocalPolicy = LocalPolicyState.GroupPolicyOverride };
        var id = await h.AddAsync(Harness.AppPath);

        Assert.Equal(EnforcementState.Degraded, (await h.StatusAsync(id)).State);
    }

    [Fact]
    public async Task PolicyForOtherNetworkProfile_IsInactive()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath, ApplicationPolicy.BlockAll with { Profiles = NetworkProfiles.Public });

        var status = await h.StatusAsync(id);
        Assert.Equal(EnforcementState.Inactive, status.State);
        Assert.Equal(1, status.VerifiedRuleCount);
    }

    [Fact]
    public async Task AllowPolicy_WithThirdPartyBlock_IsDegradedConflict()
    {
        await using var h = await Harness.StartAsync();
        h.Firewall.External(rules => rules.Add(FakeFirewall.ThirdPartyRule("Admin block", Harness.AppPath)));
        var id = await h.AddAsync(Harness.AppPath, ApplicationPolicy.AllowAll);

        var status = await h.StatusAsync(id);
        Assert.Equal(EnforcementState.Degraded, status.State);
        Assert.Contains(status.Warnings, w => w.Contains("Admin block"));
        Assert.Equal(0, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task AllowPolicy_WithDefaultOutboundBlock_ReportsConflict()
    {
        await using var h = await Harness.StartAsync();
        h.Firewall.State = h.Firewall.State with
        {
            Profiles = h.Firewall.State.Profiles.Select(p => p with { DefaultOutboundBlock = true }).ToList(),
        };
        var id = await h.AddAsync(Harness.AppPath, ApplicationPolicy.AllowAll);

        Assert.Equal(EnforcementState.Degraded, (await h.StatusAsync(id)).State);
    }

    [Fact]
    public async Task ChangingPolicy_ReplacesRules()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        var app = await h.Store.GetApplicationAsync(id);

        await h.Policies.UpdateApplicationAsync(new Contracts.UpdateApplicationRequest
        {
            Id = id,
            ExpectedRevision = app!.Revision,
            Policy = new ApplicationPolicy { Mode = PolicyMode.Custom, Custom = new CustomNetworkPolicy { AllowedRemoteAddresses = ["203.0.113.10"], AllowedTcpPorts = "443" } },
        }, Harness.Admin, h.Token);

        Assert.Equal(4, h.OwnedRulesFor(Harness.AppPath));
        Assert.DoesNotContain(h.Firewall.Rules, r => r.Name.Contains("block-all"));
        Assert.Equal(EnforcementState.Enforced, (await h.StatusAsync(id)).State);
    }
}

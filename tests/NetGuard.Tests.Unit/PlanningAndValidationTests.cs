using NetGuard.Core.Abstractions;
using NetGuard.Core.Firewall;
using NetGuard.Core.Planning;
using NetGuard.Domain;
using NetGuard.Domain.Networking;
using Xunit;

namespace NetGuard.Tests.Unit;

public sealed class RulePlannerTests
{
    private static ManagedApplication App(ApplicationPolicy policy, params string[] paths) => new()
    {
        DisplayName = "Contoso",
        Executables = paths.Select((p, i) => new ManagedExecutable { Path = p, IsPrimary = i == 0 }).ToList(),
        Policy = policy,
    };

    private static readonly ApplicationRuntime Stopped = new(false, null);

    [Fact]
    public void Block_ProducesOneAnyProtocolRulePerExecutable_CoveringIPv4AndIPv6()
    {
        var app = App(ApplicationPolicy.BlockAll, @"C:\A\a.exe", @"C:\A\b.exe");
        var plan = RulePlanner.Plan(app, null, Stopped);

        Assert.Equal(PlanDisposition.RulesRequired, plan.Disposition);
        Assert.Equal(2, plan.Rules.Count);
        Assert.All(plan.Rules, r =>
        {
            Assert.Equal(FirewallProtocols.Any, r.Protocol);
            Assert.Equal("*", r.RemoteAddresses);
            Assert.Equal(NetworkProfiles.All, r.Profiles);
            Assert.Contains("[ngkey:", r.Description);
        });
    }

    [Fact]
    public void Plan_IsDeterministic()
    {
        var app = App(ApplicationPolicy.BlockAll, @"C:\A\a.exe");
        Assert.Equal(RulePlanner.Plan(app, null, Stopped).Rules, RulePlanner.Plan(app, null, Stopped).Rules);
    }

    [Fact]
    public void Custom_BlocksComplementOfAllowList()
    {
        var policy = new ApplicationPolicy
        {
            Mode = PolicyMode.Custom,
            Custom = new CustomNetworkPolicy { AllowedRemoteAddresses = ["203.0.113.0/24"], AllowedTcpPorts = "443", AllowedUdpPorts = "" },
        };
        var rules = RulePlanner.Plan(App(policy, @"C:\A\a.exe"), null, Stopped).Rules.ToDictionary(r => r.Key.Split('.')[2]);

        Assert.Equal(FirewallProtocols.Any, rules["block-other-dest"].Protocol);
        Assert.True(AddressSet.TryParseFirewallString(rules["block-other-dest"].RemoteAddresses, out var other, out _));
        Assert.Equal(AddressSet.Parse(["203.0.113.0/24"]).Complement(), other);

        Assert.Equal(FirewallProtocols.Tcp, rules["block-tcp"].Protocol);
        Assert.Equal("1-442,444-65535", rules["block-tcp"].RemotePorts);
        Assert.Equal(FirewallProtocols.Udp, rules["block-udp"].Protocol);
        Assert.Equal("*", rules["block-udp"].RemotePorts);
        Assert.Equal(FirewallProtocols.Icmpv4, rules["block-icmp4"].Protocol);
        Assert.False(rules.ContainsKey("block-icmp6"), "No IPv6 destinations are allowed, so no ICMPv6 rule is needed (IPv6 is covered by block-other-dest).");
    }

    [Fact]
    public void Custom_AllPortsAndIcmp_ProducesOnlyDestinationRule()
    {
        var policy = new ApplicationPolicy
        {
            Mode = PolicyMode.Custom,
            Custom = new CustomNetworkPolicy { AllowLocalNetwork = true, AllowedTcpPorts = "*", AllowedUdpPorts = "*", AllowIcmp = true },
        };
        var plan = RulePlanner.Plan(App(policy, @"C:\A\a.exe"), null, Stopped);
        Assert.Single(plan.Rules);
        Assert.EndsWith("block-other-dest", plan.Rules[0].Key);
    }

    [Theory]
    [InlineData(false, false, true, PlanDisposition.Disabled)]
    [InlineData(true, true, false, PlanDisposition.Suspended)]
    public void Disposition_RespectsEnabledAndExceptions(bool enabled, bool exception, bool running, PlanDisposition expected)
    {
        var app = App(ApplicationPolicy.BlockAll, @"C:\A\a.exe") with { IsEnabled = enabled };
        var runtime = new ApplicationRuntime(running, exception ? new TemporaryException { ApplicationId = app.Id, GrantedAt = DateTimeOffset.UtcNow, ExpiresAt = DateTimeOffset.UtcNow.AddHours(1), GrantedBy = "x" } : null);
        var plan = RulePlanner.Plan(app, null, runtime);
        Assert.Equal(expected, plan.Disposition);
        Assert.Empty(plan.Rules);
    }

    [Fact]
    public void WhileRunning_IsStandbyUntilLaunched()
    {
        var app = App(ApplicationPolicy.BlockAll with { Retention = RetentionMode.WhileRunning }, @"C:\A\a.exe");
        Assert.Equal(PlanDisposition.Standby, RulePlanner.Plan(app, null, Stopped).Disposition);
        Assert.Equal(PlanDisposition.RulesRequired, RulePlanner.Plan(app, null, new ApplicationRuntime(true, null)).Disposition);
    }

    [Fact]
    public void EnabledProfile_OverridesApplicationPolicy()
    {
        var profile = new PolicyProfile { Name = "Offline", Policy = ApplicationPolicy.BlockAll, IsEnabled = true };
        var app = App(ApplicationPolicy.AllowAll, @"C:\A\a.exe") with { ProfileId = profile.Id };

        Assert.Equal(PlanDisposition.RulesRequired, RulePlanner.Plan(app, profile, Stopped).Disposition);
        Assert.Equal(PlanDisposition.NotRequired, RulePlanner.Plan(app, profile with { IsEnabled = false }, Stopped).Disposition);
    }

    [Fact]
    public void PackagedApplications_AreUnsupported()
    {
        var app = App(ApplicationPolicy.BlockAll, @"C:\Program Files\WindowsApps\Contoso_1.0_x64__abc\app.exe");
        var plan = RulePlanner.Plan(app, null, Stopped);
        Assert.Equal(PlanDisposition.Unsupported, plan.Disposition);
        Assert.NotEmpty(plan.Notes);
    }
}

public sealed class OwnedRulesTests
{
    [Fact]
    public void RuleIsOwned_OnlyWithGroupAndWellFormedMarker()
    {
        var key = OwnedRules.BuildKey(Guid.NewGuid(), Guid.NewGuid(), "block-all");
        var owned = new FirewallRule { Name = "x", Grouping = OwnedRules.Grouping, Description = OwnedRules.BuildDescription("App", key) };

        Assert.True(OwnedRules.IsOwned(owned));
        Assert.False(OwnedRules.IsOwned(owned with { Grouping = "Other" }), "A marker outside the NetGuard group is not ownership.");
        Assert.False(OwnedRules.IsOwned(owned with { Description = "Managed by NetGuard [ngkey:not-a-key]" }));
        Assert.False(OwnedRules.IsOwned(owned with { Description = null }));
    }

    [Fact]
    public void DisplayNameCannotInjectMarker()
    {
        var key = OwnedRules.BuildKey(Guid.NewGuid(), Guid.NewGuid(), "block-all");
        var forged = OwnedRules.BuildKey(Guid.NewGuid(), Guid.NewGuid(), "block-all");
        var description = OwnedRules.BuildDescription($"Evil [ngkey:{forged}]", key);
        Assert.Equal(key, OwnedRules.TryGetKey(description));
    }

    [Fact]
    public void Matcher_DetectsTampering()
    {
        var spec = RulePlanner.Plan(new ManagedApplication { DisplayName = "A", Executables = [new ManagedExecutable { Path = @"C:\A\a.exe" }] }, null, new ApplicationRuntime(false, null)).Rules[0];
        var rule = new FirewallRule
        {
            Name = spec.Name, Description = spec.Description, ApplicationName = spec.ApplicationPath, Grouping = OwnedRules.Grouping,
            Direction = FirewallDirection.Outbound, Action = FirewallAction.Block, Enabled = true, Protocol = spec.Protocol,
            RemoteAddresses = "*", RemotePorts = "*", LocalAddresses = "*", LocalPorts = "*", Profiles = 0x7FFFFFFF, InterfaceTypes = "All",
        };

        Assert.Null(RuleMatcher.Explain(rule, spec));
        Assert.NotNull(RuleMatcher.Explain(rule with { Enabled = false }, spec));
        Assert.NotNull(RuleMatcher.Explain(rule with { Action = FirewallAction.Allow }, spec));
        Assert.NotNull(RuleMatcher.Explain(rule with { ApplicationName = @"C:\A\other.exe" }, spec));
        Assert.NotNull(RuleMatcher.Explain(rule with { RemoteAddresses = "10.0.0.0/8" }, spec));
        Assert.NotNull(RuleMatcher.Explain(rule with { LocalPorts = "80" }, spec));
        Assert.NotNull(RuleMatcher.Explain(rule with { Profiles = 4 }, spec));
        Assert.Null(RuleMatcher.Explain(rule with { ApplicationName = @"c:\a\A.EXE" }, spec));
    }
}

public sealed class ValidationTests
{
    [Theory]
    [InlineData(@"C:\Program Files\App\app.exe", true)]
    [InlineData(@"D:\Tools\x.EXE", true)]
    [InlineData(@"\\server\share\app.exe", false)]
    [InlineData(@"\\?\C:\app.exe", false)]
    [InlineData(@"app.exe", false)]
    [InlineData(@"C:\App\..\Windows\notepad.exe", false)]
    [InlineData(@"C:\App\app.exe:stream", false)]
    [InlineData(@"%ProgramFiles%\App\app.exe", false)]
    [InlineData(@"C:\App\app.dll", false)]
    [InlineData(@"C:\App\a*.exe", false)]
    [InlineData("", false)]
    public void ExecutablePathSyntax(string path, bool valid) =>
        Assert.Equal(valid, ExecutablePathRules.ValidateSyntax(path) is null);

    [Theory]
    [InlineData(@"C:\Windows\System32\svchost.exe", true)]
    [InlineData(@"C:\Windows\System32\lsass.exe", true)]
    [InlineData(@"C:\Program Files\NetGuard Enterprise\Service\NetGuard.Service.exe", true)]
    [InlineData(@"C:\Tools\svchost.exe", false)]
    [InlineData(@"C:\Windows\System32\curl.exe", false)]
    public void ProtectedComponents(string path, bool isProtected) =>
        Assert.Equal(isProtected, ExecutablePathRules.GetProtectionReason(path, @"C:\Windows", @"C:\Program Files\NetGuard Enterprise") is not null);

    [Fact]
    public void CustomPolicy_RejectsDegenerateAllowLists()
    {
        Assert.NotEmpty(PolicyValidator.Validate(new CustomNetworkPolicy { AllowedRemoteAddresses = [], AllowedTcpPorts = "443" }));
        Assert.NotEmpty(PolicyValidator.Validate(new CustomNetworkPolicy { AllowedRemoteAddresses = ["1.2.3.4"], AllowedTcpPorts = "", AllowedUdpPorts = "" }));
        Assert.NotEmpty(PolicyValidator.Validate(new CustomNetworkPolicy { AllowedRemoteAddresses = ["*"], AllowedTcpPorts = "*", AllowedUdpPorts = "*", AllowIcmp = true }));
        Assert.NotEmpty(PolicyValidator.Validate(new CustomNetworkPolicy { AllowedRemoteAddresses = ["intranet"], AllowedTcpPorts = "443" }));
        Assert.Empty(PolicyValidator.Validate(new CustomNetworkPolicy { AllowedRemoteAddresses = ["1.2.3.4"], AllowedTcpPorts = "443" }));
    }

    [Fact]
    public void CustomPolicy_HasValueEqualityOverAddressList()
    {
        var a = new CustomNetworkPolicy { AllowedRemoteAddresses = ["10.0.0.0/8"], AllowedTcpPorts = "443" };
        var b = new CustomNetworkPolicy { AllowedRemoteAddresses = new List<string> { "10.0.0.0/8" }, AllowedTcpPorts = "443" };
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
        Assert.Equal(new ApplicationPolicy { Mode = PolicyMode.Custom, Custom = a }, new ApplicationPolicy { Mode = PolicyMode.Custom, Custom = b });
        Assert.NotEqual(a, b with { AllowedRemoteAddresses = ["10.0.0.0/16"] });
    }

    [Fact]
    public void Policy_RequiresAtLeastOneProfile()
    {
        Assert.NotEmpty(PolicyValidator.Validate(ApplicationPolicy.BlockAll with { Profiles = NetworkProfiles.None }));
        Assert.NotEmpty(PolicyValidator.Validate(ApplicationPolicy.BlockAll with { Profiles = (NetworkProfiles)64 }));
    }

    [Fact]
    public void Settings_AreRangeChecked()
    {
        Assert.Throws<DomainValidationException>(() => new ServiceSettings { AuditRetentionDays = 1 }.Validate());
        Assert.Throws<DomainValidationException>(() => new ServiceSettings { IntegrityCheckIntervalMinutes = 0 }.Validate());
        new ServiceSettings().Validate();
    }
}

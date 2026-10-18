using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using NetGuard.Core.Firewall;
using NetGuard.Domain;
using NetGuard.Platform.Windows.Firewall;
using Xunit;

namespace NetGuard.Tests.Integration;

/// <summary>
/// Read-only checks against the real Windows Defender Firewall. Safe on any Windows machine and without elevation:
/// they never create, modify or delete rules. They validate the hand-written COM interop layout.
/// </summary>
[Collection(WindowsFirewallCollection.Name)]
public sealed class FirewallReadOnlyTests
{
    private readonly WindowsFirewallManager _firewall = new(NullLogger<WindowsFirewallManager>.Instance);

    [Fact]
    public void State_IsAvailable_AndReportsAllThreeProfiles()
    {
        var state = _firewall.GetState();

        Assert.True(state.Available, state.Error);
        Assert.Equal(3, state.Profiles.Count);
        Assert.NotEqual(NetworkProfiles.None, state.CurrentProfiles);
    }

    [Fact]
    public void Rules_EnumerateSameCountAsComApi_WithReadableProperties()
    {
        var stopwatch = Stopwatch.StartNew();
        var rules = _firewall.GetRules();
        stopwatch.Stop();

        var expected = CountRulesViaLateBinding();
        Assert.Equal(expected, rules.Count);
        Assert.All(rules, r => Assert.False(string.IsNullOrEmpty(r.Name)));
        Assert.Contains(rules, r => r.Direction == Core.Abstractions.FirewallDirection.Inbound);
        Assert.Contains(rules, r => r.Direction == Core.Abstractions.FirewallDirection.Outbound);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(10), $"Enumeration took {stopwatch.Elapsed}.");
    }

    [Fact]
    public void Rules_ProgramPathsAndProtocolsLookPlausible()
    {
        var rules = _firewall.GetRules();

        // Built-in Windows rules include program-scoped TCP/UDP rules; if the vtable were misaligned these values
        // would be garbage or the calls would fail.
        Assert.Contains(rules, r => r.ApplicationName?.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) == true);
        Assert.Contains(rules, r => r.Protocol == Core.Abstractions.FirewallProtocols.Tcp);
        Assert.Contains(rules, r => r.Protocol == Core.Abstractions.FirewallProtocols.Udp);
        Assert.All(rules, r => Assert.InRange(r.Protocol, 0, 256));
    }

    [Fact]
    public void NoThirdPartyRuleIsMistakenForOwned()
    {
        var rules = _firewall.GetRules();
        Assert.All(rules.Where(OwnedRules.IsOwned), r => Assert.Equal(OwnedRules.Grouping, r.Grouping));
    }

    private static int CountRulesViaLateBinding()
    {
        // Independent path: late-bound IDispatch call, not our vtable declarations.
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        dynamic policy = Activator.CreateInstance(type)!;
        return (int)policy.Rules.Count;
    }
}

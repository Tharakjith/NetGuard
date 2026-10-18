using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Firewall;
using NetGuard.Core.Planning;
using NetGuard.Domain;
using NetGuard.Platform.Windows.Firewall;
using Xunit;

namespace NetGuard.Tests.Integration;

/// <summary>
/// Runs only on an elevated test machine with NETGUARD_FIREWALL_WRITE_TESTS=1. These tests create and delete real
/// firewall rules (only NetGuard-owned rules for paths that do not exist), and verify unrelated rules are untouched.
/// </summary>
public sealed class FirewallWriteFactAttribute : FactAttribute
{
    public FirewallWriteFactAttribute()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            Skip = "Requires an elevated process.";
        }
        else if (Environment.GetEnvironmentVariable("NETGUARD_FIREWALL_WRITE_TESTS") != "1")
        {
            Skip = "Set NETGUARD_FIREWALL_WRITE_TESTS=1 to run tests that modify Windows Defender Firewall.";
        }
    }
}

/// <summary>
/// End-to-end traffic verification. Requires FirewallWrite prerequisites plus NETGUARD_E2E_TARGET=host:port pointing
/// at a NetGuard.TestServer on ANOTHER machine (Windows Firewall never filters loopback, so a local server proves nothing).
/// </summary>
public sealed class TrafficFactAttribute : FactAttribute
{
    public TrafficFactAttribute()
    {
        Skip = new FirewallWriteFactAttribute().Skip;
        if (Skip is null && string.IsNullOrEmpty(Environment.GetEnvironmentVariable("NETGUARD_E2E_TARGET")))
        {
            Skip = "Set NETGUARD_E2E_TARGET=host:port (a TestServer on another machine).";
        }
    }
}

[Collection(WindowsFirewallCollection.Name)]
public sealed class FirewallWriteTests
{
    private readonly WindowsFirewallManager _firewall = new(NullLogger<WindowsFirewallManager>.Instance);

    private static FirewallRuleSpec Spec(string path, ApplicationPolicy? policy = null) =>
        RulePlanner.Plan(
            new ManagedApplication { DisplayName = "NetGuard integration test", Executables = [new ManagedExecutable { Path = path }], Policy = policy ?? ApplicationPolicy.BlockAll },
            null,
            new ApplicationRuntime(false, null)).Rules[0];

    [FirewallWriteFact]
    public void CreateVerifyRenameRemove_OnlyTouchesOwnedRule()
    {
        var before = _firewall.GetRules().Where(r => !OwnedRules.IsOwned(r)).Select(r => r.Name).OrderBy(n => n).ToList();
        var spec = Spec($@"C:\NetGuardTest\{Guid.NewGuid():N}\probe.exe");
        try
        {
            _firewall.AddRule(spec);
            var created = _firewall.GetRules().Single(r => r.Name == spec.Name);
            Assert.Null(RuleMatcher.Explain(created, spec));

            _firewall.RenameOwnedRule(spec.Name, spec.Name + " renamed");
            Assert.Contains(_firewall.GetRules(), r => r.Name == spec.Name + " renamed");
            _firewall.RemoveOwnedRule(spec.Name + " renamed");
        }
        finally
        {
            _firewall.RemoveOwnedRule(spec.Name);
            _firewall.RemoveOwnedRule(spec.Name + " renamed");
        }

        var after = _firewall.GetRules().Where(r => !OwnedRules.IsOwned(r)).Select(r => r.Name).OrderBy(n => n).ToList();
        Assert.Equal(before, after);
    }

    [FirewallWriteFact]
    public void CustomPolicyRules_AreAcceptedByWindowsAndVerify()
    {
        var policy = new ApplicationPolicy
        {
            Mode = PolicyMode.Custom,
            Custom = new CustomNetworkPolicy { AllowedRemoteAddresses = ["203.0.113.0/24", "2001:db8::/32"], AllowedTcpPorts = "443", AllowedUdpPorts = "53" },
        };
        var app = new ManagedApplication { DisplayName = "NetGuard integration test", Executables = [new ManagedExecutable { Path = $@"C:\NetGuardTest\{Guid.NewGuid():N}\c.exe" }], Policy = policy };
        var specs = RulePlanner.Plan(app, null, new ApplicationRuntime(false, null)).Rules;
        try
        {
            foreach (var spec in specs)
            {
                _firewall.AddRule(spec);
            }

            var rules = _firewall.GetRules();
            Assert.All(specs, spec => Assert.Null(RuleMatcher.Explain(rules.Single(r => r.Name == spec.Name), spec)));
        }
        finally
        {
            foreach (var spec in specs)
            {
                _firewall.RemoveOwnedRule(spec.Name);
            }
        }
    }

    [FirewallWriteFact]
    public void RefusesToRemoveRuleItDoesNotOwn()
    {
        var name = "NetGuard integration foreign rule " + Guid.NewGuid().ToString("N");
        var type = Type.GetTypeFromProgID("HNetCfg.FWRule")!;
        dynamic foreign = Activator.CreateInstance(type)!;
        foreign.Name = name;
        foreign.ApplicationName = @"C:\NetGuardTest\foreign.exe";
        foreign.Direction = 2;
        foreign.Action = 0;
        foreign.Grouping = "Someone Else";
        foreign.Enabled = false;
        dynamic policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2")!)!;
        policy.Rules.Add(foreign);
        try
        {
            Assert.Throws<FirewallOperationException>(() => _firewall.RemoveOwnedRule(name));
            Assert.Contains(_firewall.GetRules(), r => r.Name == name);
        }
        finally
        {
            policy.Rules.Remove(name);
        }
    }

    [TrafficFact]
    public async Task BlockedProgramCannotConnect_WhileAnotherProgramCan()
    {
        var target = Environment.GetEnvironmentVariable("NETGUARD_E2E_TARGET")!;
        var probe = Path.Combine(AppContext.BaseDirectory, "NetGuard.NetProbe.exe");
        Assert.True(File.Exists(probe), "Build tools/NetGuard.NetProbe first; it is copied next to the tests.");

        // Two copies at different paths: one is blocked, the other must stay unaffected.
        var dir = Path.Combine(Path.GetTempPath(), "ng-e2e-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        foreach (var file in Directory.GetFiles(AppContext.BaseDirectory, "NetGuard.NetProbe*"))
        {
            File.Copy(file, Path.Combine(dir, Path.GetFileName(file)));
        }

        var blockedProbe = Path.Combine(dir, "NetGuard.NetProbe.exe");
        var spec = Spec(blockedProbe);
        Assert.Equal(0, await RunAsync(blockedProbe, target));
        try
        {
            _firewall.AddRule(spec);
            Assert.NotEqual(0, await RunAsync(blockedProbe, target));
            Assert.Equal(0, await RunAsync(probe, target));
        }
        finally
        {
            _firewall.RemoveOwnedRule(spec.Name);
        }

        Assert.Equal(0, await RunAsync(blockedProbe, target));
    }

    private static async Task<int> RunAsync(string exe, string target)
    {
        var (host, port) = (target[..target.LastIndexOf(':')], target[(target.LastIndexOf(':') + 1)..]);
        using var process = Process.Start(new ProcessStartInfo(exe, $"{host} {port} --timeout 3000") { UseShellExecute = false, CreateNoWindow = true })!;
        await process.WaitForExitAsync();
        return process.ExitCode;
    }
}

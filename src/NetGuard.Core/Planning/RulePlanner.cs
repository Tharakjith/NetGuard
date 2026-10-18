using NetGuard.Core.Abstractions;
using NetGuard.Core.Firewall;
using NetGuard.Domain;
using NetGuard.Domain.Networking;

namespace NetGuard.Core.Planning;

public sealed record ApplicationRuntime(bool IsRunning, TemporaryException? ActiveException);

public enum PlanDisposition
{
    RulesRequired,
    NotRequired,
    Standby,
    Suspended,
    Disabled,
    Unsupported,
}

public sealed record ApplicationPlan(
    ManagedApplication Application,
    ApplicationPolicy EffectivePolicy,
    PolicyProfile? Profile,
    PlanDisposition Disposition,
    IReadOnlyList<FirewallRuleSpec> Rules,
    IReadOnlyList<string> Notes);

/// <summary>
/// Translates an application's effective policy into the exact set of block rules that must exist.
/// Pure and deterministic: the same inputs always produce the same rule names, keys and properties.
/// </summary>
public static class RulePlanner
{
    public static ApplicationPlan Plan(ManagedApplication application, PolicyProfile? profile, ApplicationRuntime runtime)
    {
        var effective = application.GetEffectivePolicy(profile);
        var notes = new List<string>();

        if (!application.IsEnabled)
        {
            return new ApplicationPlan(application, effective, profile, PlanDisposition.Disabled, [], notes);
        }

        if (!effective.RequiresRules)
        {
            return new ApplicationPlan(application, effective, profile, PlanDisposition.NotRequired, [], notes);
        }

        if (runtime.ActiveException is not null)
        {
            return new ApplicationPlan(application, effective, profile, PlanDisposition.Suspended, [], notes);
        }

        if (effective.Retention == RetentionMode.WhileRunning && !runtime.IsRunning)
        {
            return new ApplicationPlan(application, effective, profile, PlanDisposition.Standby, [], notes);
        }

        var supported = new List<ManagedExecutable>();
        foreach (var executable in application.Executables)
        {
            if (ExecutablePathRules.IsPackagedApplication(executable.Path))
            {
                notes.Add($"{executable.FileName} is a packaged (Microsoft Store/MSIX) executable. Packaged apps are filtered by package identity, so a program-path rule cannot control it.");
            }
            else
            {
                supported.Add(executable);
            }
        }

        if (supported.Count == 0)
        {
            return new ApplicationPlan(application, effective, profile, PlanDisposition.Unsupported, [], notes);
        }

        var rules = new List<FirewallRuleSpec>();
        foreach (var executable in supported)
        {
            rules.AddRange(effective.Mode == PolicyMode.Block
                ? BuildBlockRules(application, executable, effective)
                : BuildCustomRules(application, executable, effective));
        }

        return new ApplicationPlan(application, effective, profile, PlanDisposition.RulesRequired, rules, notes);
    }

    private static IEnumerable<FirewallRuleSpec> BuildBlockRules(ManagedApplication application, ManagedExecutable executable, ApplicationPolicy policy)
    {
        // A single rule with protocol "Any" and remote "*" covers IPv4 and IPv6, TCP, UDP, ICMP and raw protocols.
        yield return Create(application, executable, policy, "block-all", FirewallProtocols.Any, "*", "*");
    }

    private static IEnumerable<FirewallRuleSpec> BuildCustomRules(ManagedApplication application, ManagedExecutable executable, ApplicationPolicy policy)
    {
        var custom = policy.Custom ?? throw new InvalidOperationException("Custom policy without allow-list.");
        var allowed = AddressSet.Parse(custom.AllowedRemoteAddresses);
        if (custom.AllowLocalNetwork)
        {
            allowed = allowed.Union(AddressSet.LocalNetwork);
        }

        var tcp = PortSet.Parse(custom.AllowedTcpPorts);
        var udp = PortSet.Parse(custom.AllowedUdpPorts);
        var allowedText = allowed.IsAny ? "*" : allowed.ToFirewallString();

        // Windows Firewall evaluates block rules before allow rules, so "allow only X" is expressed as
        // block rules covering the complement of X. NetGuard never creates allow rules.

        // 1. Every protocol to every destination outside the allow-list.
        if (!allowed.IsAny)
        {
            yield return Create(application, executable, policy, "block-other-dest", FirewallProtocols.Any, allowed.Complement().ToFirewallString(), "*");
        }

        // 2. TCP/UDP to allowed destinations on ports outside the allowed set.
        if (!tcp.IsAll)
        {
            yield return Create(application, executable, policy, "block-tcp", FirewallProtocols.Tcp, allowedText, tcp.IsEmpty ? "*" : tcp.Complement().ToFirewallString());
        }

        if (!udp.IsAll)
        {
            yield return Create(application, executable, policy, "block-udp", FirewallProtocols.Udp, allowedText, udp.IsEmpty ? "*" : udp.Complement().ToFirewallString());
        }

        // 3. ICMP to allowed destinations, one rule per address family.
        if (!custom.AllowIcmp)
        {
            if (allowed.HasIPv4)
            {
                yield return Create(application, executable, policy, "block-icmp4", FirewallProtocols.Icmpv4, allowed.IsAllIPv4 ? "*" : allowed.OnlyIPv4().ToFirewallString(), "*");
            }

            if (allowed.HasIPv6)
            {
                yield return Create(application, executable, policy, "block-icmp6", FirewallProtocols.Icmpv6, allowed.IsAllIPv6 ? "*" : allowed.OnlyIPv6().ToFirewallString(), "*");
            }
        }
    }

    private static FirewallRuleSpec Create(
        ManagedApplication application,
        ManagedExecutable executable,
        ApplicationPolicy policy,
        string suffix,
        int protocol,
        string remoteAddresses,
        string remotePorts)
    {
        var key = OwnedRules.BuildKey(application.Id, executable.Id, suffix);
        return new FirewallRuleSpec
        {
            Key = key,
            Name = OwnedRules.BuildName(application.DisplayName, executable.FileName, suffix, application.Id, executable.Id),
            Description = OwnedRules.BuildDescription(application.DisplayName, key),
            ApplicationPath = executable.Path,
            Protocol = protocol,
            RemoteAddresses = remoteAddresses,
            RemotePorts = protocol is FirewallProtocols.Tcp or FirewallProtocols.Udp ? remotePorts : "*",
            Profiles = policy.Profiles,
            ApplicationId = application.Id,
            ExecutableId = executable.Id,
        };
    }
}

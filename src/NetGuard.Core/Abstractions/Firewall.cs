using NetGuard.Domain;

namespace NetGuard.Core.Abstractions;

public enum FirewallDirection
{
    Inbound = 1,
    Outbound = 2,
}

public enum FirewallAction
{
    Block = 0,
    Allow = 1,
}

public static class FirewallProtocols
{
    public const int Any = 256;
    public const int Icmpv4 = 1;
    public const int Tcp = 6;
    public const int Udp = 17;
    public const int Icmpv6 = 58;

    public static string Describe(int protocol) => protocol switch
    {
        Any => "Any",
        Icmpv4 => "ICMPv4",
        Tcp => "TCP",
        Udp => "UDP",
        Icmpv6 => "ICMPv6",
        _ => protocol.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };
}

/// <summary>
/// A rule NetGuard wants to exist. By construction this type can only describe an enabled, outbound, BLOCK rule
/// scoped to a single program: the service is unable to create allow rules or inbound rules.
/// </summary>
public sealed record FirewallRuleSpec
{
    public required string Key { get; init; }

    public required string Name { get; init; }

    public required string Description { get; init; }

    public required string ApplicationPath { get; init; }

    public int Protocol { get; init; } = FirewallProtocols.Any;

    public string RemoteAddresses { get; init; } = "*";

    public string RemotePorts { get; init; } = "*";

    public NetworkProfiles Profiles { get; init; } = NetworkProfiles.All;

    public Guid ApplicationId { get; init; }

    public Guid ExecutableId { get; init; }
}

/// <summary>A snapshot of any firewall rule as read from Windows Defender Firewall.</summary>
public sealed record FirewallRule
{
    public string Name { get; init; } = string.Empty;

    public string? Description { get; init; }

    public string? ApplicationName { get; init; }

    public string? ServiceName { get; init; }

    public string? Grouping { get; init; }

    public FirewallDirection Direction { get; init; }

    public FirewallAction Action { get; init; }

    public bool Enabled { get; init; }

    public int Protocol { get; init; } = FirewallProtocols.Any;

    public string? RemoteAddresses { get; init; }

    public string? RemotePorts { get; init; }

    public string? LocalAddresses { get; init; }

    public string? LocalPorts { get; init; }

    /// <summary>Raw NET_FW_PROFILE_TYPE2 bitmask (0x7FFFFFFF means all profiles).</summary>
    public int Profiles { get; init; }

    public string? InterfaceTypes { get; init; }

    public NetworkProfiles NormalizedProfiles => Profiles == 0x7FFFFFFF ? NetworkProfiles.All : (NetworkProfiles)(Profiles & (int)NetworkProfiles.All);
}

public sealed record FirewallProfileState(NetworkProfiles Profile, bool Enabled, bool DefaultOutboundBlock, bool DefaultInboundBlock);

public enum LocalPolicyState
{
    Unknown = 0,
    Ok = 1,

    /// <summary>Group Policy settings override local firewall policy; locally created rules may not apply.</summary>
    GroupPolicyOverride = 2,
    InboundBlocked = 3,
}

public sealed record FirewallState
{
    public bool Available { get; init; }

    public string? Error { get; init; }

    public NetworkProfiles CurrentProfiles { get; init; }

    public IReadOnlyList<FirewallProfileState> Profiles { get; init; } = [];

    public LocalPolicyState LocalPolicy { get; init; }

    /// <summary>Firewall products registered with Windows Security Center (may include third-party firewalls).</summary>
    public IReadOnlyList<string> RegisteredProducts { get; init; } = [];

    public FirewallProfileState? GetProfile(NetworkProfiles profile) => Profiles.FirstOrDefault(p => p.Profile == profile);

    public static FirewallState Unavailable(string error) => new() { Available = false, Error = error };
}

/// <summary>Windows Defender Firewall access. Implementations must never modify rules they do not own.</summary>
public interface IFirewallManager
{
    FirewallState GetState();

    IReadOnlyList<FirewallRule> GetRules();

    void AddRule(FirewallRuleSpec spec);

    /// <summary>Removes the rule with this name. Throws if any rule with this name is not owned by NetGuard.</summary>
    void RemoveOwnedRule(string name);

    /// <summary>Renames an owned rule. Throws if the rule is not owned by NetGuard.</summary>
    void RenameOwnedRule(string currentName, string newName);
}

public sealed class FirewallUnavailableException : Exception
{
    public FirewallUnavailableException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

public sealed class FirewallOperationException : Exception
{
    public FirewallOperationException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

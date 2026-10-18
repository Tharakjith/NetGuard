namespace NetGuard.Domain;

/// <summary>
/// Destination allow-list for <see cref="PolicyMode.Custom"/>. A connection is permitted only when its remote
/// address is allowed AND its protocol/port is allowed. Everything else is blocked.
/// </summary>
public sealed record CustomNetworkPolicy
{
    /// <summary>IP addresses, CIDR blocks or ranges (IPv4 or IPv6). "*" allows every address.</summary>
    public IReadOnlyList<string> AllowedRemoteAddresses { get; init; } = [];

    /// <summary>Also allow loopback, RFC 1918, link-local and local multicast destinations.</summary>
    public bool AllowLocalNetwork { get; init; }

    /// <summary>"*" for all TCP ports, "" for none, or a list such as "443,8443".</summary>
    public string AllowedTcpPorts { get; init; } = "443";

    /// <summary>"*" for all UDP ports, "" for none, or a list such as "53,123".</summary>
    public string AllowedUdpPorts { get; init; } = string.Empty;

    /// <summary>Allow ICMPv4/ICMPv6 to the allowed destinations.</summary>
    public bool AllowIcmp { get; init; }

    /// <summary>Value equality including the address list contents (records compare collections by reference).</summary>
    public bool Equals(CustomNetworkPolicy? other) =>
        other is not null &&
        AllowedRemoteAddresses.SequenceEqual(other.AllowedRemoteAddresses, StringComparer.OrdinalIgnoreCase) &&
        AllowLocalNetwork == other.AllowLocalNetwork &&
        AllowedTcpPorts == other.AllowedTcpPorts &&
        AllowedUdpPorts == other.AllowedUdpPorts &&
        AllowIcmp == other.AllowIcmp;

    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach (var address in AllowedRemoteAddresses)
        {
            hash.Add(address, StringComparer.OrdinalIgnoreCase);
        }

        hash.Add(AllowLocalNetwork);
        hash.Add(AllowedTcpPorts);
        hash.Add(AllowedUdpPorts);
        hash.Add(AllowIcmp);
        return hash.ToHashCode();
    }
}

public sealed record ApplicationPolicy
{
    public PolicyMode Mode { get; init; } = PolicyMode.Block;

    public RetentionMode Retention { get; init; } = RetentionMode.Persistent;

    /// <summary>Network profiles on which the restriction applies.</summary>
    public NetworkProfiles Profiles { get; init; } = NetworkProfiles.All;

    /// <summary>Required when <see cref="Mode"/> is <see cref="PolicyMode.Custom"/>.</summary>
    public CustomNetworkPolicy? Custom { get; init; }

    public static ApplicationPolicy AllowAll { get; } = new() { Mode = PolicyMode.Allow };

    public static ApplicationPolicy BlockAll { get; } = new() { Mode = PolicyMode.Block };

    public bool RequiresRules => Mode is PolicyMode.Block or PolicyMode.Custom;
}

/// <summary>
/// A named policy template that applications can be assigned to. While a profile is enabled, its policy
/// overrides the policy of every member application (for example "Offline Work" blocks all members).
/// </summary>
public sealed record PolicyProfile
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public required string Name { get; init; }

    public string Description { get; init; } = string.Empty;

    public bool IsBuiltIn { get; init; }

    public bool IsEnabled { get; init; }

    public PolicySource Source { get; init; } = PolicySource.User;

    public ApplicationPolicy Policy { get; init; } = ApplicationPolicy.BlockAll;

    public DateTimeOffset ModifiedAt { get; init; }

    public string ModifiedBy { get; init; } = string.Empty;

    public static IReadOnlyList<PolicyProfile> CreateBuiltIns(DateTimeOffset now) =>
    [
        new()
        {
            Id = new Guid("8f0c5b8e-6a3e-4f0a-9d7d-0d1a2b3c4d01"),
            Name = "Development Tools",
            Description = "Development tools that should only reach package registries over HTTPS. Edit the allow-list before enabling.",
            IsBuiltIn = true,
            Policy = new ApplicationPolicy
            {
                Mode = PolicyMode.Custom,
                Custom = new CustomNetworkPolicy { AllowLocalNetwork = true, AllowedRemoteAddresses = [], AllowedTcpPorts = "443" },
            },
            ModifiedAt = now,
            ModifiedBy = "system",
        },
        new()
        {
            Id = new Guid("8f0c5b8e-6a3e-4f0a-9d7d-0d1a2b3c4d02"),
            Name = "Offline Work",
            Description = "Blocks all outbound connections for member applications while enabled.",
            IsBuiltIn = true,
            Policy = ApplicationPolicy.BlockAll,
            ModifiedAt = now,
            ModifiedBy = "system",
        },
        new()
        {
            Id = new Guid("8f0c5b8e-6a3e-4f0a-9d7d-0d1a2b3c4d03"),
            Name = "Privacy Restrictions",
            Description = "Allows local network access only (for example printers and file shares); blocks internet destinations.",
            IsBuiltIn = true,
            Policy = new ApplicationPolicy
            {
                Mode = PolicyMode.Custom,
                Custom = new CustomNetworkPolicy { AllowLocalNetwork = true, AllowedTcpPorts = "*", AllowedUdpPorts = "*", AllowIcmp = true },
            },
            ModifiedAt = now,
            ModifiedBy = "system",
        },
        new()
        {
            Id = new Guid("8f0c5b8e-6a3e-4f0a-9d7d-0d1a2b3c4d04"),
            Name = "Custom Application Policies",
            Description = "A starting point for organization-specific rules. Edit the policy before enabling.",
            IsBuiltIn = true,
            Policy = ApplicationPolicy.BlockAll,
            ModifiedAt = now,
            ModifiedBy = "system",
        },
    ];
}

/// <summary>A time-limited suspension of an application's restriction, granted explicitly by an authorized user.</summary>
public sealed record TemporaryException
{
    public required Guid ApplicationId { get; init; }

    public required DateTimeOffset GrantedAt { get; init; }

    public required DateTimeOffset ExpiresAt { get; init; }

    public required string GrantedBy { get; init; }

    public string Reason { get; init; } = string.Empty;

    public bool IsActive(DateTimeOffset now) => now < ExpiresAt;

    public static readonly TimeSpan MaximumDuration = TimeSpan.FromHours(24);
}

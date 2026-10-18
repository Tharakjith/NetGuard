using System.Text.Json.Serialization;
using NetGuard.Domain;

namespace NetGuard.Core.Configuration;

/// <summary>
/// Exchange format for policy export/import (schemas/netguard-policy.v1.schema.json). Deliberately separate from the
/// domain model so the file format stays stable when internal types change.
/// </summary>
public sealed record PolicyDocument
{
    public const int CurrentSchemaVersion = 1;
    public const string SchemaId = "https://schemas.netguard.local/policy/v1.json";

    [JsonPropertyName("$schema")]
    public string? Schema { get; init; }

    public required int SchemaVersion { get; init; }

    public string? Product { get; init; }

    public DateTimeOffset? ExportedAt { get; init; }

    public string? ExportedBy { get; init; }

    /// <summary>"user" or "organization".</summary>
    public string Scope { get; init; } = "user";

    public IReadOnlyList<ProfileEntry> Profiles { get; init; } = [];

    public IReadOnlyList<ApplicationEntry> Applications { get; init; } = [];

    public SettingsEntry? Settings { get; init; }
}

public sealed record ProfileEntry
{
    public required Guid Id { get; init; }

    public required string Name { get; init; }

    public string Description { get; init; } = string.Empty;

    public bool Enabled { get; init; }

    public required PolicyEntry Policy { get; init; }
}

public sealed record ApplicationEntry
{
    public Guid? Id { get; init; }

    public required string DisplayName { get; init; }

    public string? Publisher { get; init; }

    public bool Enabled { get; init; } = true;

    public Guid? ProfileId { get; init; }

    public bool IncludeChildProcesses { get; init; } = true;

    public bool FollowSignedUpdates { get; init; } = true;

    /// <summary>Must be true to manage an executable inside the Windows directory.</summary>
    public bool AllowSystemComponent { get; init; }

    public required PolicyEntry Policy { get; init; }

    public required IReadOnlyList<ExecutableEntry> Executables { get; init; }
}

public sealed record ExecutableEntry
{
    public required string Path { get; init; }

    public bool Primary { get; init; }

    public string? Sha256 { get; init; }

    public string? SignerSubject { get; init; }
}

public sealed record PolicyEntry
{
    public required PolicyMode Mode { get; init; }

    public RetentionMode Retention { get; init; } = RetentionMode.Persistent;

    /// <summary>Any of "Domain", "Private", "Public".</summary>
    public IReadOnlyList<string> NetworkProfiles { get; init; } = ["Domain", "Private", "Public"];

    public CustomEntry? Custom { get; init; }

    public static PolicyEntry From(ApplicationPolicy policy) => new()
    {
        Mode = policy.Mode,
        Retention = policy.Retention,
        NetworkProfiles = Enum.GetValues<NetworkProfiles>()
            .Where(p => p is Domain.NetworkProfiles.Domain or Domain.NetworkProfiles.Private or Domain.NetworkProfiles.Public && policy.Profiles.HasFlag(p))
            .Select(p => p.ToString())
            .ToList(),
        Custom = policy.Custom is null ? null : new CustomEntry
        {
            AllowedRemoteAddresses = policy.Custom.AllowedRemoteAddresses,
            AllowLocalNetwork = policy.Custom.AllowLocalNetwork,
            AllowedTcpPorts = policy.Custom.AllowedTcpPorts,
            AllowedUdpPorts = policy.Custom.AllowedUdpPorts,
            AllowIcmp = policy.Custom.AllowIcmp,
        },
    };

    public ApplicationPolicy ToDomain(List<string> errors, string path)
    {
        var profiles = Domain.NetworkProfiles.None;
        foreach (var name in NetworkProfiles)
        {
            if (Enum.TryParse<NetworkProfiles>(name, ignoreCase: true, out var parsed) &&
                parsed is Domain.NetworkProfiles.Domain or Domain.NetworkProfiles.Private or Domain.NetworkProfiles.Public)
            {
                profiles |= parsed;
            }
            else
            {
                errors.Add($"{path}.networkProfiles: '{name}' is not one of Domain, Private, Public.");
            }
        }

        var policy = new ApplicationPolicy
        {
            Mode = Mode,
            Retention = Retention,
            Profiles = profiles,
            Custom = Custom is null ? null : new CustomNetworkPolicy
            {
                AllowedRemoteAddresses = Custom.AllowedRemoteAddresses,
                AllowLocalNetwork = Custom.AllowLocalNetwork,
                AllowedTcpPorts = Custom.AllowedTcpPorts,
                AllowedUdpPorts = Custom.AllowedUdpPorts,
                AllowIcmp = Custom.AllowIcmp,
            },
        };
        errors.AddRange(PolicyValidator.Validate(policy).Select(e => $"{path}: {e}"));
        return policy;
    }
}

public sealed record CustomEntry
{
    public IReadOnlyList<string> AllowedRemoteAddresses { get; init; } = [];

    public bool AllowLocalNetwork { get; init; }

    public string AllowedTcpPorts { get; init; } = string.Empty;

    public string AllowedUdpPorts { get; init; } = string.Empty;

    public bool AllowIcmp { get; init; }
}

public sealed record SettingsEntry
{
    public int AuditRetentionDays { get; init; } = 180;

    public int LogRetentionDays { get; init; } = 30;

    public int IntegrityCheckIntervalMinutes { get; init; } = 5;

    public int WhileRunningGraceSeconds { get; init; } = 5;

    public bool AllowStandardUserRead { get; init; } = true;

    public bool ObserveBlockedConnections { get; init; } = true;

    public RetentionMode DefaultRetention { get; init; } = RetentionMode.Persistent;

    public int MaxTemporaryExceptionMinutes { get; init; } = 1440;

    public static SettingsEntry From(ServiceSettings s) => new()
    {
        AuditRetentionDays = s.AuditRetentionDays,
        LogRetentionDays = s.LogRetentionDays,
        IntegrityCheckIntervalMinutes = s.IntegrityCheckIntervalMinutes,
        WhileRunningGraceSeconds = s.WhileRunningGraceSeconds,
        AllowStandardUserRead = s.AllowStandardUserRead,
        ObserveBlockedConnections = s.ObserveBlockedConnections,
        DefaultRetention = s.DefaultRetention,
        MaxTemporaryExceptionMinutes = s.MaxTemporaryExceptionMinutes,
    };

    public ServiceSettings ToDomain() => new()
    {
        AuditRetentionDays = AuditRetentionDays,
        LogRetentionDays = LogRetentionDays,
        IntegrityCheckIntervalMinutes = IntegrityCheckIntervalMinutes,
        WhileRunningGraceSeconds = WhileRunningGraceSeconds,
        AllowStandardUserRead = AllowStandardUserRead,
        ObserveBlockedConnections = ObserveBlockedConnections,
        DefaultRetention = DefaultRetention,
        MaxTemporaryExceptionMinutes = MaxTemporaryExceptionMinutes,
    };
}

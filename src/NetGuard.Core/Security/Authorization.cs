using NetGuard.Contracts;
using NetGuard.Domain;

namespace NetGuard.Core.Security;

/// <summary>Identity of the caller as established by the transport (named pipe client token), never by the request body.</summary>
public sealed record ActorContext
{
    public required string Name { get; init; }

    public string? Sid { get; init; }

    /// <summary>The token has the Administrators group enabled (i.e. the client process is elevated).</summary>
    public bool IsElevatedAdministrator { get; init; }

    /// <summary>The token contains the "NetGuard Operators" local group.</summary>
    public bool IsOperator { get; init; }

    public bool IsSystem { get; init; }

    public static ActorContext System { get; } = new() { Name = "system", Sid = "S-1-5-18", IsSystem = true, IsElevatedAdministrator = true };

    public bool Has(Permission permission, ServiceSettings settings) => permission switch
    {
        Permission.Read => IsSystem || IsElevatedAdministrator || IsOperator || settings.AllowStandardUserRead,
        Permission.Modify => IsSystem || IsElevatedAdministrator || IsOperator,
        Permission.Administer => IsSystem || IsElevatedAdministrator,
        _ => false,
    };

    public CallerDto ToDto(ServiceSettings settings) => new()
    {
        Name = Name,
        IsElevatedAdministrator = IsElevatedAdministrator,
        IsOperator = IsOperator,
        CanRead = Has(Permission.Read, settings),
        CanModify = Has(Permission.Modify, settings),
        CanAdminister = Has(Permission.Administer, settings),
    };
}

/// <summary>The single source of truth mapping each IPC command to its required permission.</summary>
public static class CommandPermissions
{
    private static readonly IReadOnlyDictionary<string, Permission> Map = new Dictionary<string, Permission>(StringComparer.Ordinal)
    {
        [Commands.GetServiceInfo] = Permission.Read,
        [Commands.GetDashboard] = Permission.Read,
        [Commands.ListApplications] = Permission.Read,
        [Commands.GetApplication] = Permission.Read,
        [Commands.ListProfiles] = Permission.Read,
        [Commands.GetFirewallOverview] = Permission.Read,
        [Commands.QueryAudit] = Permission.Read,
        [Commands.ExportAudit] = Permission.Read,
        [Commands.GenerateDiagnostics] = Permission.Read,
        [Commands.GetSettings] = Permission.Read,
        [Commands.WaitForEvents] = Permission.Read,
        [Commands.GetObservations] = Permission.Read,

        [Commands.AddApplication] = Permission.Modify,
        [Commands.UpdateApplication] = Permission.Modify,
        [Commands.SetApplicationEnabled] = Permission.Modify,
        [Commands.RestoreApplication] = Permission.Modify,
        [Commands.RemoveApplication] = Permission.Modify,
        [Commands.GrantTemporaryException] = Permission.Modify,
        [Commands.RevokeTemporaryException] = Permission.Modify,
        [Commands.InspectExecutable] = Permission.Modify,
        [Commands.ScanInstallDirectory] = Permission.Modify,
        [Commands.DiscoverApplications] = Permission.Modify,
        [Commands.SaveProfile] = Permission.Modify,
        [Commands.DeleteProfile] = Permission.Modify,
        [Commands.SetProfileEnabled] = Permission.Modify,
        [Commands.Reconcile] = Permission.Modify,
        [Commands.ExportConfiguration] = Permission.Modify,

        [Commands.CleanupOrphanedRules] = Permission.Administer,
        [Commands.UpdateSettings] = Permission.Administer,
        [Commands.ImportConfiguration] = Permission.Administer,
        [Commands.CreateBackup] = Permission.Administer,
    };

    public static IReadOnlyCollection<string> All => Map.Keys.ToList();

    public static bool TryGet(string command, out Permission permission) => Map.TryGetValue(command, out permission);
}

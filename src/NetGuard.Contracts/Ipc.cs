using System.Text.Json;

namespace NetGuard.Contracts;

public static class IpcConstants
{
    /// <summary>Local named pipe served by NetGuard.Service. The pipe ACL denies network access.</summary>
    public const string PipeName = "NetGuardEnterprise.Control.v1";

    public const int ProtocolVersion = 1;

    /// <summary>Upper bound for a single framed message in either direction.</summary>
    public const int MaxMessageBytes = 8 * 1024 * 1024;

    /// <summary>Upper bound for a single request from a client (requests are small; imports are the largest).</summary>
    public const int MaxRequestBytes = 4 * 1024 * 1024;

    public const string ServiceName = "NetGuardService";

    public const string OperatorsGroupName = "NetGuard Operators";
}

public sealed record IpcRequest
{
    public int ProtocolVersion { get; init; } = IpcConstants.ProtocolVersion;

    public Guid RequestId { get; init; } = Guid.NewGuid();

    public required string Command { get; init; }

    public JsonElement? Payload { get; init; }
}

public sealed record IpcResponse
{
    public Guid RequestId { get; init; }

    public bool Success { get; init; }

    public string? ErrorCode { get; init; }

    public string? ErrorMessage { get; init; }

    public IReadOnlyList<string>? ValidationErrors { get; init; }

    public JsonElement? Payload { get; init; }

    public static IpcResponse Ok(Guid requestId, JsonElement? payload) => new() { RequestId = requestId, Success = true, Payload = payload };

    public static IpcResponse Fail(Guid requestId, string code, string message, IReadOnlyList<string>? validationErrors = null) =>
        new() { RequestId = requestId, Success = false, ErrorCode = code, ErrorMessage = message, ValidationErrors = validationErrors };
}

public static class IpcErrorCodes
{
    public const string BadRequest = "BadRequest";
    public const string UnknownCommand = "UnknownCommand";
    public const string ProtocolMismatch = "ProtocolMismatch";
    public const string Unauthorized = "Unauthorized";
    public const string ValidationFailed = "ValidationFailed";
    public const string NotFound = "NotFound";
    public const string Conflict = "Conflict";
    public const string OrganizationManaged = "OrganizationManaged";
    public const string FirewallUnavailable = "FirewallUnavailable";
    public const string RateLimited = "RateLimited";
    public const string Timeout = "Timeout";
    public const string InternalError = "InternalError";
}

/// <summary>Command names. Each command has exactly one required permission defined by the service.</summary>
public static class Commands
{
    public const string GetServiceInfo = "GetServiceInfo";
    public const string GetDashboard = "GetDashboard";
    public const string ListApplications = "ListApplications";
    public const string GetApplication = "GetApplication";
    public const string AddApplication = "AddApplication";
    public const string UpdateApplication = "UpdateApplication";
    public const string SetApplicationEnabled = "SetApplicationEnabled";
    public const string RestoreApplication = "RestoreApplication";
    public const string RemoveApplication = "RemoveApplication";
    public const string GrantTemporaryException = "GrantTemporaryException";
    public const string RevokeTemporaryException = "RevokeTemporaryException";
    public const string InspectExecutable = "InspectExecutable";
    public const string ScanInstallDirectory = "ScanInstallDirectory";
    public const string DiscoverApplications = "DiscoverApplications";
    public const string ListProfiles = "ListProfiles";
    public const string SaveProfile = "SaveProfile";
    public const string DeleteProfile = "DeleteProfile";
    public const string SetProfileEnabled = "SetProfileEnabled";
    public const string GetFirewallOverview = "GetFirewallOverview";
    public const string Reconcile = "Reconcile";
    public const string CleanupOrphanedRules = "CleanupOrphanedRules";
    public const string QueryAudit = "QueryAudit";
    public const string ExportAudit = "ExportAudit";
    public const string GenerateDiagnostics = "GenerateDiagnostics";
    public const string GetSettings = "GetSettings";
    public const string UpdateSettings = "UpdateSettings";
    public const string ExportConfiguration = "ExportConfiguration";
    public const string ImportConfiguration = "ImportConfiguration";
    public const string CreateBackup = "CreateBackup";
    public const string WaitForEvents = "WaitForEvents";
    public const string GetObservations = "GetObservations";
}

public enum Permission
{
    /// <summary>View status, applications and logs.</summary>
    Read = 0,

    /// <summary>Change application policies. Elevated administrators or members of "NetGuard Operators".</summary>
    Modify = 1,

    /// <summary>Change service settings, import organization policy, clean up rules. Elevated administrators only.</summary>
    Administer = 2,
}

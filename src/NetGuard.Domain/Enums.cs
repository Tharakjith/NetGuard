namespace NetGuard.Domain;

/// <summary>The network policy an administrator assigns to a managed application.</summary>
public enum PolicyMode
{
    /// <summary>NetGuard creates no rules; the existing system firewall policy applies.</summary>
    Allow = 0,

    /// <summary>All outbound IPv4 and IPv6 connections from the application's executables are blocked.</summary>
    Block = 1,

    /// <summary>Outbound connections are blocked except to the configured destinations, protocols and ports.</summary>
    Custom = 2,
}

/// <summary>Controls when the firewall rules for a restricted application exist.</summary>
public enum RetentionMode
{
    /// <summary>Rules exist at all times, including before launch and after exit. Recommended: no launch race.</summary>
    Persistent = 0,

    /// <summary>
    /// Rules are created when the application is detected starting and removed after the last instance exits.
    /// There is an unavoidable window between process creation and rule creation; see docs/LIMITATIONS.md.
    /// </summary>
    WhileRunning = 1,
}

/// <summary>Windows Firewall network profiles. Values match NET_FW_PROFILE_TYPE2.</summary>
[Flags]
public enum NetworkProfiles
{
    None = 0,
    Domain = 1,
    Private = 2,
    Public = 4,
    All = Domain | Private | Public,
}

/// <summary>Who owns a policy. Organization policies are read-only to the desktop interface.</summary>
public enum PolicySource
{
    User = 0,
    Organization = 1,
}

/// <summary>Verified enforcement state of an application. Only <see cref="Enforced"/> means "verified and active now".</summary>
public enum EnforcementState
{
    /// <summary>Not evaluated yet (for example immediately after service start).</summary>
    Unknown = 0,

    /// <summary>The policy is Allow and requires no NetGuard rules.</summary>
    NotRequired = 1,

    /// <summary>WhileRunning policy and the application is not running, so no rules exist by design.</summary>
    Standby = 2,

    /// <summary>Enforcement has been requested and has not been verified yet.</summary>
    Pending = 3,

    /// <summary>Rules were read back from the firewall, match the policy, and the firewall is active on the current network.</summary>
    Enforced = 4,

    /// <summary>Rules are verified but the policy does not target the currently connected network profile(s).</summary>
    Inactive = 5,

    /// <summary>Rules are verified but something may prevent them from taking effect (firewall off, Group Policy, conflicts).</summary>
    Degraded = 6,

    /// <summary>Rules could not be created or verified.</summary>
    Failed = 7,

    /// <summary>A time-limited exception is active; restriction rules are intentionally removed.</summary>
    Suspended = 8,

    /// <summary>Management for this application has been disabled; NetGuard rules were removed.</summary>
    Disabled = 9,

    /// <summary>The executable cannot be controlled by path-based rules (for example packaged/MSIX applications).</summary>
    Unsupported = 10,
}

public enum SignatureStatus
{
    Unknown = 0,

    /// <summary>The file has no embedded Authenticode signature (it may still be catalog-signed).</summary>
    NotSigned = 1,

    /// <summary>Embedded signature verified and chains to a trusted root.</summary>
    Valid = 2,

    /// <summary>Signature present but the file was modified or the signature is malformed.</summary>
    Invalid = 3,

    /// <summary>Signature present but the certificate is not trusted, expired or revoked.</summary>
    Untrusted = 4,

    /// <summary>Verification could not be completed.</summary>
    Error = 5,
}

public enum ExecutableOrigin
{
    UserSelected = 0,
    Discovery = 1,
    InstallDirectory = 2,
    ChildProcess = 3,
    LocationChange = 4,
    Import = 5,
}

public enum AuditOutcome
{
    Info = 0,
    Success = 1,
    Warning = 2,
    Failure = 3,
    Denied = 4,
}

public enum AuditEventType
{
    ServiceStarted = 0,
    ServiceStopped = 1,
    ApplicationDiscovery = 2,
    ApplicationAdded = 3,
    ApplicationUpdated = 4,
    ApplicationRemoved = 5,
    PolicyChanged = 6,
    EnforcementApplied = 7,
    EnforcementVerified = 8,
    EnforcementFailed = 9,
    RuleRemoved = 10,
    IntegrityDrift = 11,
    ProcessStarted = 12,
    ProcessExited = 13,
    IdentityChanged = 14,
    ExecutableLocationChanged = 15,
    ChildProcessObserved = 16,
    TemporaryExceptionGranted = 17,
    TemporaryExceptionEnded = 18,
    AuthorizationDenied = 19,
    ConfigurationChanged = 20,
    ConfigurationImported = 21,
    ConfigurationExported = 22,
    ProfileChanged = 23,
    Recovery = 24,
    Error = 25,
    BlockedConnectionObserved = 26,
    BackupCreated = 27,
    DiagnosticsGenerated = 28,
}

/// <summary>Kinds of user-facing notifications the service can raise.</summary>
public enum NotificationKind
{
    PolicyApplied = 0,
    ApplicationBlocked = 1,
    EnforcementFailed = 2,
    ExecutableLocationChanged = 3,
    ServiceStopped = 4,
    BlockedConnectionObserved = 5,
    TemporaryExceptionEnded = 6,
    IdentityChanged = 7,
}

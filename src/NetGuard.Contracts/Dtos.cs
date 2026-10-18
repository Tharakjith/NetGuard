using NetGuard.Domain;

namespace NetGuard.Contracts;

// ---------------------------------------------------------------- service / caller

public sealed record CallerDto
{
    public string Name { get; init; } = string.Empty;

    public bool IsElevatedAdministrator { get; init; }

    public bool IsOperator { get; init; }

    public bool CanRead { get; init; }

    public bool CanModify { get; init; }

    public bool CanAdminister { get; init; }
}

public sealed record ServiceInfoDto
{
    public string Version { get; init; } = string.Empty;

    public int ProtocolVersion { get; init; }

    public DateTimeOffset StartedAt { get; init; }

    public string MonitoringMode { get; init; } = string.Empty;

    public bool BlockedConnectionAuditingAvailable { get; init; }

    public string DataDirectory { get; init; } = string.Empty;

    public CallerDto Caller { get; init; } = new();

    public FirewallStatusDto Firewall { get; init; } = new();

    public DateTimeOffset? LastReconcileAt { get; init; }

    public string? LastReconcileError { get; init; }
}

// ---------------------------------------------------------------- firewall

public sealed record FirewallProfileDto
{
    public NetworkProfiles Profile { get; init; }

    public bool Enabled { get; init; }

    public bool IsCurrent { get; init; }

    public bool DefaultOutboundBlocked { get; init; }

    public bool DefaultInboundBlocked { get; init; }
}

public sealed record FirewallStatusDto
{
    public bool Available { get; init; }

    public string? Error { get; init; }

    public NetworkProfiles CurrentProfiles { get; init; }

    public IReadOnlyList<FirewallProfileDto> Profiles { get; init; } = [];

    /// <summary>"Ok", "GroupPolicyOverride" (local rules may be ignored) or "InboundBlocked".</summary>
    public string LocalPolicyModifyState { get; init; } = "Unknown";

    public IReadOnlyList<string> RegisteredFirewallProducts { get; init; } = [];

    public int TotalRuleCount { get; init; }

    public int OwnedRuleCount { get; init; }

    /// <summary>Plain-language problems that may stop rules from taking effect.</summary>
    public IReadOnlyList<string> Issues { get; init; } = [];
}

public sealed record FirewallRuleDto
{
    public string Name { get; init; } = string.Empty;

    public string? Description { get; init; }

    public string? ApplicationPath { get; init; }

    public string Direction { get; init; } = string.Empty;

    public string Action { get; init; } = string.Empty;

    public bool Enabled { get; init; }

    public string Protocol { get; init; } = string.Empty;

    public string RemoteAddresses { get; init; } = "*";

    public string RemotePorts { get; init; } = "*";

    public NetworkProfiles Profiles { get; init; }

    public string? Grouping { get; init; }

    public bool IsOwned { get; init; }

    public Guid? ApplicationId { get; init; }

    public string? ApplicationName { get; init; }
}

public sealed record RuleConflictDto
{
    public Guid ApplicationId { get; init; }

    public string ApplicationName { get; init; } = string.Empty;

    public string ExecutablePath { get; init; } = string.Empty;

    public string RuleName { get; init; } = string.Empty;

    public string Explanation { get; init; } = string.Empty;
}

public sealed record FirewallOverviewDto
{
    public FirewallStatusDto Status { get; init; } = new();

    public IReadOnlyList<FirewallRuleDto> OwnedRules { get; init; } = [];

    /// <summary>Rules carrying NetGuard's marker that no managed application claims. Kept until an administrator removes them.</summary>
    public IReadOnlyList<FirewallRuleDto> OrphanedRules { get; init; } = [];

    public IReadOnlyList<RuleConflictDto> Conflicts { get; init; } = [];
}

public sealed record ReconcileResultDto
{
    public int RulesAdded { get; init; }

    public int RulesUpdated { get; init; }

    public int RulesRemoved { get; init; }

    public int Failures { get; init; }

    public int OrphanedRules { get; init; }

    public long DurationMs { get; init; }

    public IReadOnlyList<string> Errors { get; init; } = [];
}

// ---------------------------------------------------------------- applications

public sealed record RunningProcessDto
{
    public int ProcessId { get; init; }

    public string ExecutablePath { get; init; } = string.Empty;

    public DateTimeOffset StartedAt { get; init; }
}

public sealed record ApplicationSummaryDto
{
    public Guid Id { get; init; }

    public string DisplayName { get; init; } = string.Empty;

    public string? Publisher { get; init; }

    public string? PrimaryPath { get; init; }

    public int ExecutableCount { get; init; }

    public bool IsRunning { get; init; }

    public int RunningInstances { get; init; }

    public bool IsEnabled { get; init; }

    public PolicySource Source { get; init; }

    public ApplicationPolicy Policy { get; init; } = ApplicationPolicy.AllowAll;

    public ApplicationPolicy EffectivePolicy { get; init; } = ApplicationPolicy.AllowAll;

    public string? ProfileName { get; init; }

    public bool ProfileOverridesPolicy { get; init; }

    public EnforcementStatus Enforcement { get; init; } = new() { ApplicationId = Guid.Empty };

    public DateTimeOffset? ExceptionExpiresAt { get; init; }

    public SignatureStatus SignatureStatus { get; init; }

    public DateTimeOffset CreatedAt { get; init; }

    public DateTimeOffset ModifiedAt { get; init; }

    public long Revision { get; init; }
}

public sealed record ApplicationDetailDto
{
    public ManagedApplication Application { get; init; } = null!;

    public ApplicationSummaryDto Summary { get; init; } = new();

    public TemporaryException? Exception { get; init; }

    public IReadOnlyList<RunningProcessDto> RunningProcesses { get; init; } = [];

    public IReadOnlyList<FirewallRuleDto> Rules { get; init; } = [];

    public IReadOnlyList<RuleConflictDto> Conflicts { get; init; } = [];

    public IReadOnlyList<ObservationDto> Observations { get; init; } = [];
}

public sealed record AddApplicationRequest
{
    public string? DisplayName { get; init; }

    /// <summary>The first path is the primary executable.</summary>
    public IReadOnlyList<string> ExecutablePaths { get; init; } = [];

    public ApplicationPolicy Policy { get; init; } = ApplicationPolicy.BlockAll;

    public Guid? ProfileId { get; init; }

    public bool IncludeChildProcesses { get; init; } = true;

    public bool FollowSignedUpdates { get; init; } = true;

    /// <summary>Required (with Administer permission) to manage an executable inside the Windows directory.</summary>
    public bool AllowSystemComponent { get; init; }
}

public sealed record UpdateApplicationRequest
{
    public Guid Id { get; init; }

    public long ExpectedRevision { get; init; }

    public string? DisplayName { get; init; }

    public ApplicationPolicy? Policy { get; init; }

    public Guid? ProfileId { get; init; }

    /// <summary>Set to true to clear the profile assignment (ProfileId null otherwise means "unchanged").</summary>
    public bool ClearProfile { get; init; }

    public bool? IncludeChildProcesses { get; init; }

    public bool? FollowSignedUpdates { get; init; }

    public IReadOnlyList<string> AddExecutablePaths { get; init; } = [];

    public IReadOnlyList<Guid> RemoveExecutableIds { get; init; } = [];

    public bool AllowSystemComponent { get; init; }
}

public sealed record ApplicationIdRequest
{
    public Guid Id { get; init; }

    public long? ExpectedRevision { get; init; }
}

public sealed record SetEnabledRequest
{
    public Guid Id { get; init; }

    public bool Enabled { get; init; }

    public long? ExpectedRevision { get; init; }
}

public sealed record TemporaryExceptionRequest
{
    public Guid Id { get; init; }

    public int DurationMinutes { get; init; }

    public string Reason { get; init; } = string.Empty;
}

// ---------------------------------------------------------------- discovery

public sealed record InspectExecutableRequest
{
    public string Path { get; init; } = string.Empty;
}

public sealed record ExecutableInspectionDto
{
    public string RequestedPath { get; init; } = string.Empty;

    public string CanonicalPath { get; init; } = string.Empty;

    public bool Exists { get; init; }

    public long FileSize { get; init; }

    public string? Sha256 { get; init; }

    public string? FileVersion { get; init; }

    public string? ProductName { get; init; }

    public string? FileDescription { get; init; }

    public string? CompanyName { get; init; }

    public string? OriginalFileName { get; init; }

    public SignatureStatus SignatureStatus { get; init; }

    public string? SignerSubject { get; init; }

    public string? SignerThumbprint { get; init; }

    public bool IsSystemComponent { get; init; }

    public bool IsPackagedApplication { get; init; }

    public string? ProtectionReason { get; init; }

    public Guid? ManagedByApplicationId { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = [];
}

public sealed record ScanDirectoryRequest
{
    public string Directory { get; init; } = string.Empty;
}

public sealed record RelatedExecutableDto
{
    public string Path { get; init; } = string.Empty;

    public string? ProductName { get; init; }

    public string? CompanyName { get; init; }

    public long FileSize { get; init; }

    public bool IsManaged { get; init; }
}

public sealed record DiscoveryRequest
{
    public bool IncludeSystemComponents { get; init; }

    public bool IncludeRunningProcesses { get; init; } = true;
}

public sealed record DiscoveredExecutableDto
{
    public string Path { get; init; } = string.Empty;

    public bool IsRunning { get; init; }

    public Guid? ManagedByApplicationId { get; init; }
}

public sealed record DiscoveredApplicationDto
{
    public string Name { get; init; } = string.Empty;

    public string? Publisher { get; init; }

    public string? Version { get; init; }

    public string? InstallLocation { get; init; }

    public IReadOnlyList<DiscoveredExecutableDto> Executables { get; init; } = [];

    /// <summary>Where the entry came from: "Uninstall registry", "App Paths", "Running process".</summary>
    public IReadOnlyList<string> Sources { get; init; } = [];

    public bool IsRunning { get; init; }

    public bool IsManaged { get; init; }

    public bool IsSystemComponent { get; init; }

    /// <summary>Set when another entry with the same name/publisher exists (for example per-user and per-machine installs).</summary>
    public bool IsPossibleDuplicate { get; init; }
}

// ---------------------------------------------------------------- profiles

public sealed record ProfileDto
{
    public PolicyProfile Profile { get; init; } = null!;

    public int MemberCount { get; init; }

    public IReadOnlyList<string> MemberNames { get; init; } = [];
}

public sealed record SaveProfileRequest
{
    public PolicyProfile Profile { get; init; } = null!;
}

public sealed record ProfileIdRequest
{
    public Guid Id { get; init; }
}

public sealed record SetProfileEnabledRequest
{
    public Guid Id { get; init; }

    public bool Enabled { get; init; }
}

// ---------------------------------------------------------------- audit / diagnostics / config

public sealed record AuditPageDto
{
    public IReadOnlyList<AuditEvent> Items { get; init; } = [];

    public int TotalCount { get; init; }
}

public enum ExportFormat
{
    Json = 0,
    Csv = 1,
}

public sealed record AuditExportRequest
{
    public AuditQuery Query { get; init; } = new();

    public ExportFormat Format { get; init; }
}

public sealed record ExportResultDto
{
    public string SuggestedFileName { get; init; } = string.Empty;

    public string ContentType { get; init; } = "application/json";

    public string Content { get; init; } = string.Empty;
}

public sealed record DiagnosticsRequest
{
    /// <summary>Replace user-profile paths, user names and the machine name with placeholders.</summary>
    public bool Redact { get; init; } = true;
}

public sealed record ConfigurationExportRequest
{
    public bool IncludeSettings { get; init; } = true;

    public bool IncludeOrganizationPolicies { get; init; }
}

public enum ImportMode
{
    /// <summary>Add new items and update matching ones; leave others untouched.</summary>
    Merge = 0,

    /// <summary>Make the user-scoped configuration match the document exactly (removes unlisted user applications).</summary>
    Replace = 1,
}

public sealed record ConfigurationImportRequest
{
    public string Json { get; init; } = string.Empty;

    public ImportMode Mode { get; init; }

    public bool DryRun { get; init; } = true;
}

public sealed record ImportResultDto
{
    public bool Applied { get; init; }

    public int SchemaVersion { get; init; }

    public IReadOnlyList<string> AddedApplications { get; init; } = [];

    public IReadOnlyList<string> UpdatedApplications { get; init; } = [];

    public IReadOnlyList<string> RemovedApplications { get; init; } = [];

    public IReadOnlyList<string> AddedProfiles { get; init; } = [];

    public IReadOnlyList<string> UpdatedProfiles { get; init; } = [];

    public bool SettingsChanged { get; init; }

    public IReadOnlyList<string> Warnings { get; init; } = [];

    public IReadOnlyList<string> Errors { get; init; } = [];
}

public sealed record BackupResultDto
{
    public string Path { get; init; } = string.Empty;

    public long SizeBytes { get; init; }
}

// ---------------------------------------------------------------- dashboard

public sealed record DashboardDto
{
    public int ManagedCount { get; init; }

    public int RunningCount { get; init; }

    public int BlockedCount { get; init; }

    public int AllowedCount { get; init; }

    public int CustomCount { get; init; }

    public int ErrorCount { get; init; }

    public int EnforcedCount { get; init; }

    public ServiceInfoDto Service { get; init; } = new();

    public IReadOnlyList<ApplicationSummaryDto> Applications { get; init; } = [];

    public IReadOnlyList<AuditEvent> RecentPolicyChanges { get; init; } = [];

    public IReadOnlyList<AuditEvent> RecentFailures { get; init; } = [];
}

// ---------------------------------------------------------------- events / observations

public enum ServiceEventKind
{
    /// <summary>Application list, policy or enforcement state changed; clients should refresh.</summary>
    StateChanged = 0,

    /// <summary>A user-facing notification. Clients decide whether to show it based on user preferences.</summary>
    Notification = 1,

    /// <summary>The service is stopping.</summary>
    ServiceStopping = 2,
}

public sealed record ServiceEventDto
{
    public long Sequence { get; init; }

    public DateTimeOffset Timestamp { get; init; }

    public ServiceEventKind Kind { get; init; }

    public NotificationKind? Notification { get; init; }

    public Guid? ApplicationId { get; init; }

    public string Title { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;
}

public sealed record WaitForEventsRequest
{
    public long AfterSequence { get; init; }

    public int TimeoutSeconds { get; init; } = 20;
}

public sealed record EventBatchDto
{
    public long LatestSequence { get; init; }

    /// <summary>True when events were dropped from the buffer; the client should perform a full refresh.</summary>
    public bool Gap { get; init; }

    public IReadOnlyList<ServiceEventDto> Events { get; init; } = [];
}

public enum ObservationKind
{
    ChildProcess = 0,
    LocationChange = 1,
    IdentityChange = 2,
    BlockedConnection = 3,
}

public sealed record ObservationDto
{
    public DateTimeOffset Timestamp { get; init; }

    public ObservationKind Kind { get; init; }

    public Guid? ApplicationId { get; init; }

    public string? ApplicationName { get; init; }

    public string ExecutablePath { get; init; } = string.Empty;

    public string Detail { get; init; } = string.Empty;

    public int Count { get; init; } = 1;
}

using NetGuard.Domain;

namespace NetGuard.Core.Abstractions;

/// <summary>Persistent configuration and state. Implementations must be safe for concurrent use.</summary>
public interface IPolicyStore
{
    Task<IReadOnlyList<ManagedApplication>> GetApplicationsAsync(CancellationToken cancellationToken = default);

    Task<ManagedApplication?> GetApplicationAsync(Guid id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Inserts or updates an application. When <paramref name="expectedRevision"/> is set and does not match the
    /// stored revision a <see cref="ConcurrencyException"/> is thrown. Returns the stored record with its new revision.
    /// </summary>
    Task<ManagedApplication> SaveApplicationAsync(ManagedApplication application, long? expectedRevision, CancellationToken cancellationToken = default);

    Task DeleteApplicationAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<PolicyProfile>> GetProfilesAsync(CancellationToken cancellationToken = default);

    Task SaveProfileAsync(PolicyProfile profile, CancellationToken cancellationToken = default);

    Task DeleteProfileAsync(Guid id, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<TemporaryException>> GetExceptionsAsync(CancellationToken cancellationToken = default);

    Task SaveExceptionAsync(TemporaryException exception, CancellationToken cancellationToken = default);

    Task DeleteExceptionAsync(Guid applicationId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<EnforcementStatus>> GetStatusesAsync(CancellationToken cancellationToken = default);

    Task SaveStatusesAsync(IReadOnlyCollection<EnforcementStatus> statuses, CancellationToken cancellationToken = default);

    Task<ServiceSettings> GetSettingsAsync(CancellationToken cancellationToken = default);

    Task SaveSettingsAsync(ServiceSettings settings, CancellationToken cancellationToken = default);

    /// <summary>Applies an import atomically: either every change is stored or none is.</summary>
    Task ApplyImportAsync(ImportChangeSet changes, CancellationToken cancellationToken = default);

    /// <summary>Creates a consistent copy of the database and returns its path.</summary>
    Task<string> CreateBackupAsync(string reason, CancellationToken cancellationToken = default);
}

public sealed record ImportChangeSet
{
    public IReadOnlyList<ManagedApplication> UpsertApplications { get; init; } = [];

    public IReadOnlyList<Guid> DeleteApplications { get; init; } = [];

    public IReadOnlyList<PolicyProfile> UpsertProfiles { get; init; } = [];

    public ServiceSettings? Settings { get; init; }
}

public sealed record AuditPage(IReadOnlyList<AuditEvent> Items, int TotalCount);

public interface IAuditLog
{
    Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default);

    Task<AuditPage> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default);

    Task<int> PurgeOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default);
}

public sealed class ConcurrencyException : Exception
{
    public ConcurrencyException(string message)
        : base(message)
    {
    }
}

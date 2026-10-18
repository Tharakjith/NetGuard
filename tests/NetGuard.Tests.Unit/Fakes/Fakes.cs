using NetGuard.Contracts;
using NetGuard.Core;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;

namespace NetGuard.Tests.Unit.Fakes;

public sealed class FakeClock : IClock
{
    public DateTimeOffset UtcNow { get; set; } = new(2026, 10, 1, 12, 0, 0, TimeSpan.Zero);

    public void Advance(TimeSpan by) => UtcNow += by;
}

/// <summary>Thread-safe in-memory store with the same concurrency and uniqueness semantics as the SQLite store.</summary>
public sealed class InMemoryStore : IPolicyStore, IAuditLog
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, ManagedApplication> _apps = new();
    private readonly Dictionary<Guid, PolicyProfile> _profiles = new();
    private readonly Dictionary<Guid, TemporaryException> _exceptions = new();
    private readonly Dictionary<Guid, EnforcementStatus> _statuses = new();
    private readonly List<AuditEvent> _audit = [];
    private ServiceSettings _settings = new();

    public InMemoryStore(IClock clock)
    {
        foreach (var profile in PolicyProfile.CreateBuiltIns(clock.UtcNow))
        {
            _profiles[profile.Id] = profile;
        }
    }

    public IReadOnlyList<AuditEvent> Audit
    {
        get
        {
            lock (_gate)
            {
                return _audit.ToList();
            }
        }
    }

    public int BackupCount { get; private set; }

    public Task<IReadOnlyList<ManagedApplication>> GetApplicationsAsync(CancellationToken cancellationToken = default) =>
        Locked<IReadOnlyList<ManagedApplication>>(() => _apps.Values.OrderBy(a => a.DisplayName).ToList());

    public Task<ManagedApplication?> GetApplicationAsync(Guid id, CancellationToken cancellationToken = default) =>
        Locked(() => _apps.GetValueOrDefault(id));

    public Task<ManagedApplication> SaveApplicationAsync(ManagedApplication application, long? expectedRevision, CancellationToken cancellationToken = default) =>
        Locked(() => Upsert(application, expectedRevision));

    private ManagedApplication Upsert(ManagedApplication application, long? expectedRevision)
    {
        if (_apps.TryGetValue(application.Id, out var existing))
        {
            if (expectedRevision is not null && expectedRevision != existing.Revision)
            {
                throw new ConcurrencyException("changed");
            }
        }
        else if (expectedRevision is > 0)
        {
            throw new ConcurrencyException("missing");
        }

        foreach (var exe in application.Executables)
        {
            if (_apps.Values.Any(a => a.Id != application.Id && a.Executables.Any(e => string.Equals(e.Path, exe.Path, StringComparison.OrdinalIgnoreCase))))
            {
                throw new ConflictException($"{exe.Path} is already managed by another application.");
            }
        }

        var saved = application with { Revision = (existing?.Revision ?? 0) + 1 };
        _apps[application.Id] = saved;
        return saved;
    }

    public Task DeleteApplicationAsync(Guid id, CancellationToken cancellationToken = default) => Locked(() =>
    {
        _apps.Remove(id);
        _statuses.Remove(id);
        _exceptions.Remove(id);
        return true;
    });

    public Task<IReadOnlyList<PolicyProfile>> GetProfilesAsync(CancellationToken cancellationToken = default) =>
        Locked<IReadOnlyList<PolicyProfile>>(() => _profiles.Values.ToList());

    public Task SaveProfileAsync(PolicyProfile profile, CancellationToken cancellationToken = default) => Locked(() => _profiles[profile.Id] = profile);

    public Task DeleteProfileAsync(Guid id, CancellationToken cancellationToken = default) => Locked(() => _profiles.Remove(id));

    public Task<IReadOnlyList<TemporaryException>> GetExceptionsAsync(CancellationToken cancellationToken = default) =>
        Locked<IReadOnlyList<TemporaryException>>(() => _exceptions.Values.ToList());

    public Task SaveExceptionAsync(TemporaryException exception, CancellationToken cancellationToken = default) =>
        Locked(() => _exceptions[exception.ApplicationId] = exception);

    public Task DeleteExceptionAsync(Guid applicationId, CancellationToken cancellationToken = default) => Locked(() => _exceptions.Remove(applicationId));

    public Task<IReadOnlyList<EnforcementStatus>> GetStatusesAsync(CancellationToken cancellationToken = default) =>
        Locked<IReadOnlyList<EnforcementStatus>>(() => _statuses.Values.ToList());

    public Task SaveStatusesAsync(IReadOnlyCollection<EnforcementStatus> statuses, CancellationToken cancellationToken = default) => Locked(() =>
    {
        _statuses.Clear();
        foreach (var status in statuses)
        {
            _statuses[status.ApplicationId] = status;
        }

        return true;
    });

    public Task<ServiceSettings> GetSettingsAsync(CancellationToken cancellationToken = default) => Locked(() => _settings);

    public Task SaveSettingsAsync(ServiceSettings settings, CancellationToken cancellationToken = default) => Locked(() => _settings = settings);

    public Task ApplyImportAsync(ImportChangeSet changes, CancellationToken cancellationToken = default) => Locked(() =>
    {
        foreach (var profile in changes.UpsertProfiles)
        {
            _profiles[profile.Id] = profile;
        }

        foreach (var id in changes.DeleteApplications)
        {
            _apps.Remove(id);
        }

        foreach (var app in changes.UpsertApplications)
        {
            _apps.Remove(app.Id);
        }

        foreach (var app in changes.UpsertApplications)
        {
            Upsert(app, null);
        }

        if (changes.Settings is not null)
        {
            _settings = changes.Settings;
        }

        return true;
    });

    public Task<string> CreateBackupAsync(string reason, CancellationToken cancellationToken = default) => Locked(() =>
    {
        BackupCount++;
        return Path.GetTempFileName();
    });

    public Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default) => Locked(() =>
    {
        var stored = auditEvent with { Id = _audit.Count + 1 };
        _audit.Add(stored);
        return stored.Id;
    });

    public Task<AuditPage> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default) => Locked(() =>
    {
        var items = _audit.AsEnumerable().Reverse()
            .Where(e => query.Types is null || query.Types.Contains(e.Type))
            .Where(e => query.Outcomes is null || query.Outcomes.Contains(e.Outcome))
            .Where(e => query.ApplicationId is null || e.ApplicationId == query.ApplicationId)
            .ToList();
        return new AuditPage(items.Skip(query.Skip).Take(query.Take).ToList(), items.Count);
    });

    public Task<int> PurgeOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default) =>
        Locked(() => _audit.RemoveAll(e => e.Timestamp < cutoff));

    private Task<T> Locked<T>(Func<T> action)
    {
        lock (_gate)
        {
            return Task.FromResult(action());
        }
    }
}

/// <summary>Executable inspector over a virtual file table.</summary>
public sealed class FakeInspector : IExecutableInspector
{
    public Dictionary<string, ExecutableInspection> Files { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Alias (symlink / short name) to canonical path.</summary>
    public Dictionary<string, string> Aliases { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string WindowsDirectory => @"C:\Windows";

    public string? ProductDirectory => @"C:\Program Files\NetGuard Enterprise";

    public ExecutableInspection AddFile(string path, string? signer = "CN=Contoso Ltd, O=Contoso Ltd", string? product = "Contoso App", string sha = "AA", string version = "1.0.0.0")
    {
        var inspection = new ExecutableInspection
        {
            RequestedPath = path,
            CanonicalPath = path,
            Exists = true,
            FileSize = 1000,
            Sha256 = sha,
            ProductName = product,
            CompanyName = "Contoso",
            FileVersion = version,
            OriginalFileName = Path.GetFileName(path),
            SignatureStatus = signer is null ? SignatureStatus.NotSigned : SignatureStatus.Valid,
            SignerSubject = signer,
        };
        Files[path] = inspection;
        return inspection;
    }

    public ExecutableInspection Inspect(string path, bool includeHashAndSignature = true)
    {
        var canonical = TryCanonicalize(path) ?? throw new ExecutableInspectionException($"File not found: {path}");
        return Files[canonical] with { RequestedPath = path };
    }

    public string? TryCanonicalize(string path) =>
        Aliases.TryGetValue(path, out var target) ? target : Files.ContainsKey(path) ? Files.Keys.First(k => string.Equals(k, path, StringComparison.OrdinalIgnoreCase)) : null;
}

public sealed class FakeProcessMonitor : IProcessMonitor
{
    private readonly List<ObservedProcess> _running = [];
    private readonly HashSet<(int, DateTimeOffset)> _tracked = [];
    private int _nextPid = 1000;

    public event EventHandler<ObservedProcess>? ProcessStarted;

    public event EventHandler<ObservedProcess>? ProcessExited;

    public string MonitoringMode => "Fake";

    public void Start()
    {
    }

    public IReadOnlyList<ObservedProcess> Snapshot()
    {
        lock (_running)
        {
            return _running.ToList();
        }
    }

    public bool TrackExit(ObservedProcess process)
    {
        lock (_running)
        {
            if (!_running.Contains(process))
            {
                return false;
            }

            _tracked.Add((process.ProcessId, process.StartTime));
            return true;
        }
    }

    public ObservedProcess Launch(string path, int parentPid = 0, DateTimeOffset? start = null)
    {
        var process = new ObservedProcess(Interlocked.Increment(ref _nextPid), parentPid, path, start ?? DateTimeOffset.UtcNow);
        lock (_running)
        {
            _running.Add(process);
        }

        ProcessStarted?.Invoke(this, process);
        return process;
    }

    /// <summary>Adds a process that was already running before monitoring started (no event).</summary>
    public ObservedProcess AlreadyRunning(string path)
    {
        var process = new ObservedProcess(Interlocked.Increment(ref _nextPid), 0, path, DateTimeOffset.UtcNow.AddMinutes(-5));
        lock (_running)
        {
            _running.Add(process);
        }

        return process;
    }

    public void Exit(ObservedProcess process)
    {
        bool tracked;
        lock (_running)
        {
            _running.Remove(process);
            tracked = _tracked.Remove((process.ProcessId, process.StartTime));
        }

        if (tracked)
        {
            ProcessExited?.Invoke(this, process);
        }
    }

    public void Dispose()
    {
    }
}

public sealed class FakeDiscovery : IApplicationDiscovery
{
    public IReadOnlyList<DiscoveredApplicationDto> Discover(DiscoveryRequest request, IReadOnlyDictionary<string, Guid> managedPaths) => [];

    public IReadOnlyList<RelatedExecutableDto> ScanDirectory(string directory, IReadOnlyDictionary<string, Guid> managedPaths) => [];
}

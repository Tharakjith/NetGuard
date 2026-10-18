using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Enforcement;
using NetGuard.Core.Events;
using NetGuard.Core.Policies;
using NetGuard.Domain;

namespace NetGuard.Core.Monitoring;

/// <summary>
/// Matches process start/exit events to managed applications by canonical path, keeps the runtime registry current,
/// triggers launch-time enforcement and verification, and records child-process / relocation / identity observations.
/// All work runs on a single consumer so index access needs no locking.
/// </summary>
public sealed class ProcessTracker : IDisposable
{
    private readonly IProcessMonitor _monitor;
    private readonly IExecutableInspector _inspector;
    private readonly IPolicyStore _store;
    private readonly RuntimeRegistry _registry;
    private readonly EnforcementScheduler _scheduler;
    private readonly ExecutableFactory _executables;
    private readonly AuditWriter _audit;
    private readonly EventBroker _events;
    private readonly ObservationLog _observations;
    private readonly ILogger<ProcessTracker> _logger;
    private readonly Channel<Work> _work = Channel.CreateUnbounded<Work>(new UnboundedChannelOptions { SingleReader = true });
    private readonly Dictionary<Guid, CancellationTokenSource> _standbyTimers = new();
    private readonly HashSet<string> _relocationChecked = new(StringComparer.OrdinalIgnoreCase);

    private Dictionary<string, (ManagedApplication App, ManagedExecutable Exe)> _byPath = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<string, List<(ManagedApplication App, ManagedExecutable Exe)>> _byFileName = new(StringComparer.OrdinalIgnoreCase);
    private Dictionary<Guid, ManagedApplication> _apps = new();
    private Dictionary<Guid, PolicyProfile> _profiles = new();
    private ServiceSettings _settings = new();
    private CancellationToken _stopping;
    private Task? _loop;

    public ProcessTracker(
        IProcessMonitor monitor,
        IExecutableInspector inspector,
        IPolicyStore store,
        RuntimeRegistry registry,
        EnforcementScheduler scheduler,
        ExecutableFactory executables,
        AuditWriter audit,
        EventBroker events,
        ObservationLog observations,
        ILogger<ProcessTracker> logger)
    {
        _monitor = monitor;
        _inspector = inspector;
        _store = store;
        _registry = registry;
        _scheduler = scheduler;
        _executables = executables;
        _audit = audit;
        _events = events;
        _observations = observations;
        _logger = logger;
    }

    private enum WorkKind
    {
        Started,
        Exited,
        Rebuild,
    }

    private sealed record Work(WorkKind Kind, ObservedProcess? Process, TaskCompletionSource? Completion = null);

    /// <summary>Subscribes to process events, builds the index and registers already-running managed processes.</summary>
    public async Task StartAsync(CancellationToken stoppingToken)
    {
        _stopping = stoppingToken;
        _monitor.ProcessStarted += OnStarted;
        _monitor.ProcessExited += OnExited;

        // Start monitoring before the initial snapshot so no launch falls between the two; duplicates are ignored.
        _monitor.Start();
        _loop = Task.Run(() => RunAsync(stoppingToken), stoppingToken);
        await RebuildNowAsync().ConfigureAwait(false);
    }

    /// <summary>Rebuilds the index and waits until it is in effect (used after policy changes).</summary>
    public Task RebuildNowAsync()
    {
        var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _work.Writer.TryWrite(new Work(WorkKind.Rebuild, null, completion));
        return completion.Task;
    }

    public void Dispose()
    {
        _monitor.ProcessStarted -= OnStarted;
        _monitor.ProcessExited -= OnExited;
        _work.Writer.TryComplete();
        foreach (var timer in _standbyTimers.Values)
        {
            timer.Cancel();
            timer.Dispose();
        }
    }

    private void OnStarted(object? sender, ObservedProcess process) => _work.Writer.TryWrite(new Work(WorkKind.Started, process));

    private void OnExited(object? sender, ObservedProcess process) => _work.Writer.TryWrite(new Work(WorkKind.Exited, process));

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var work in _work.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    switch (work.Kind)
                    {
                        case WorkKind.Started:
                            await HandleStartedAsync(work.Process!).ConfigureAwait(false);
                            break;
                        case WorkKind.Exited:
                            await HandleExitedAsync(work.Process!).ConfigureAwait(false);
                            break;
                        case WorkKind.Rebuild:
                            await RebuildIndexAsync().ConfigureAwait(false);
                            break;
                    }

                    work.Completion?.TrySetResult();
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Process tracking work item {Kind} failed", work.Kind);
                    work.Completion?.TrySetException(ex);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task RebuildIndexAsync()
    {
        var applications = await _store.GetApplicationsAsync(_stopping).ConfigureAwait(false);
        _profiles = (await _store.GetProfilesAsync(_stopping).ConfigureAwait(false)).ToDictionary(p => p.Id);
        _settings = await _store.GetSettingsAsync(_stopping).ConfigureAwait(false);
        _apps = applications.ToDictionary(a => a.Id);
        _byPath = new(StringComparer.OrdinalIgnoreCase);
        _byFileName = new(StringComparer.OrdinalIgnoreCase);
        _relocationChecked.Clear();
        foreach (var app in applications)
        {
            foreach (var exe in app.Executables)
            {
                _byPath[exe.Path] = (app, exe);
                if (!_byFileName.TryGetValue(exe.FileName, out var list))
                {
                    _byFileName[exe.FileName] = list = [];
                }

                list.Add((app, exe));
            }
        }

        _registry.Retain(applications.ToDictionary(a => a.Id, a => (IReadOnlySet<Guid>)a.Executables.Select(e => e.Id).ToHashSet()));

        // Register managed processes that are already running (service start, or an application added while running).
        var newlyRunning = new HashSet<Guid>();
        foreach (var process in _monitor.Snapshot())
        {
            var match = Match(process.ImagePath);
            if (match is null)
            {
                continue;
            }

            var (app, exe) = match.Value;
            if (_registry.Add(app.Id, new RunningInstance(process.ProcessId, exe.Path, exe.Id, process.StartTime)))
            {
                if (_monitor.TrackExit(process))
                {
                    newlyRunning.Add(app.Id);
                }
                else
                {
                    _registry.Remove(process.ProcessId, process.StartTime);
                }
            }
        }

        if (newlyRunning.Count > 0)
        {
            _scheduler.Request(ReconcileTrigger.ProcessLaunch, $"{newlyRunning.Count} managed application(s) already running");
            _events.PublishStateChanged();
        }
    }

    private (ManagedApplication App, ManagedExecutable Exe)? Match(string imagePath)
    {
        if (_byPath.TryGetValue(imagePath, out var direct))
        {
            return direct;
        }

        // Only canonicalize when the file name could match, to avoid opening every launched executable.
        if (!_byFileName.ContainsKey(Path.GetFileName(imagePath)))
        {
            return null;
        }

        var canonical = _inspector.TryCanonicalize(imagePath);
        return canonical is not null && _byPath.TryGetValue(canonical, out var resolved) ? resolved : null;
    }

    private async Task HandleStartedAsync(ObservedProcess process)
    {
        var match = Match(process.ImagePath);
        if (match is not null)
        {
            await OnManagedStartedAsync(match.Value.App, match.Value.Exe, process).ConfigureAwait(false);
            return;
        }

        var parent = _registry.FindByProcessId(process.ParentProcessId);
        if (parent is not null && parent.Value.Instance.StartTime <= process.StartTime && _apps.TryGetValue(parent.Value.ApplicationId, out var parentApp))
        {
            await OnChildStartedAsync(parentApp, process).ConfigureAwait(false);
            return;
        }

        if (_byFileName.ContainsKey(Path.GetFileName(process.ImagePath)))
        {
            await CheckRelocationAsync(process).ConfigureAwait(false);
        }
    }

    private async Task OnManagedStartedAsync(ManagedApplication app, ManagedExecutable exe, ObservedProcess process)
    {
        if (!_registry.Add(app.Id, new RunningInstance(process.ProcessId, exe.Path, exe.Id, process.StartTime)))
        {
            return;
        }

        if (!_monitor.TrackExit(process))
        {
            // Exited before we could watch it (very short-lived process).
            _registry.Remove(process.ProcessId, process.StartTime);
            return;
        }

        if (_standbyTimers.Remove(app.Id, out var timer))
        {
            timer.Cancel();
            timer.Dispose();
        }

        await _audit.WriteAsync(AuditEventType.ProcessStarted, AuditOutcome.Info, $"{exe.FileName} started (PID {process.ProcessId}).",
            application: app, executablePath: exe.Path, details: new { process.ProcessId, process.ParentProcessId }, cancellationToken: _stopping).ConfigureAwait(false);

        // Launch-time enforcement and verification. For persistent policies the rules already exist; this confirms them.
        var report = await _scheduler.RunNowAsync(new ReconcileOptions(ReconcileTrigger.ProcessLaunch, $"{app.DisplayName} started"), _stopping).ConfigureAwait(false);
        if (report.Statuses.TryGetValue(app.Id, out var status))
        {
            if (status.State == EnforcementState.Enforced)
            {
                var policy = app.GetEffectivePolicy(app.ProfileId is { } pid ? _profiles.GetValueOrDefault(pid) : null);
                var what = policy.Mode == PolicyMode.Block ? "Internet access is blocked" : "Network access is limited to the allow-list";
                _events.Notify(NotificationKind.ApplicationBlocked, $"{app.DisplayName} started", $"{what} (verified).", app.Id);
            }
            else if (status.State is EnforcementState.Failed or EnforcementState.Degraded)
            {
                _events.Notify(NotificationKind.EnforcementFailed, $"{app.DisplayName} started without verified restriction", status.Message, app.Id);
            }
        }

        _events.PublishStateChanged(app.Id);
        await VerifyIdentityAsync(app, exe).ConfigureAwait(false);
    }

    private async Task HandleExitedAsync(ObservedProcess process)
    {
        var removed = _registry.Remove(process.ProcessId, process.StartTime);
        if (removed is null || !_apps.TryGetValue(removed.Value.ApplicationId, out var app))
        {
            return;
        }

        await _audit.WriteAsync(AuditEventType.ProcessExited, AuditOutcome.Info, $"Process {process.ProcessId} exited.",
            application: app, executablePath: process.ImagePath, cancellationToken: _stopping).ConfigureAwait(false);
        _events.PublishStateChanged(app.Id);

        if (removed.Value.Remaining > 0)
        {
            return;
        }

        var policy = app.GetEffectivePolicy(app.ProfileId is { } pid ? _profiles.GetValueOrDefault(pid) : null);
        if (policy.RequiresRules && policy.Retention == RetentionMode.WhileRunning)
        {
            // Persistent policies are never relaxed on exit. While-running rules are removed after a grace period
            // so that a crash-and-restart does not cycle the rules.
            var cts = CancellationTokenSource.CreateLinkedTokenSource(_stopping);
            _standbyTimers[app.Id] = cts;
            _scheduler.RequestAfter(TimeSpan.FromSeconds(_settings.WhileRunningGraceSeconds), ReconcileTrigger.ProcessExit, $"{app.DisplayName} exited", cts.Token);
        }
    }

    private async Task OnChildStartedAsync(ManagedApplication app, ObservedProcess process)
    {
        var policy = app.GetEffectivePolicy(app.ProfileId is { } pid ? _profiles.GetValueOrDefault(pid) : null);
        if (!app.IsEnabled || !policy.RequiresRules)
        {
            return;
        }

        var path = _inspector.TryCanonicalize(process.ImagePath) ?? process.ImagePath;
        var windows = _inspector.WindowsDirectory;
        var installDirectory = app.InstallDirectory ?? Path.GetDirectoryName(app.PrimaryExecutable?.Path);
        string detail;

        if (ExecutablePathRules.IsSystemComponent(path, windows) ||
            ExecutablePathRules.GetProtectionReason(path, windows, _inspector.ProductDirectory) is not null)
        {
            detail = $"Started by {app.DisplayName}. Not restricted: it is a shared Windows component, and a program-path rule would affect every application that uses it. Traffic it carries on behalf of {app.DisplayName} is not covered by this policy.";
        }
        else if (app.IncludeChildProcesses &&
                 ExecutableFactory.IsSpecificInstallDirectory(installDirectory, windows) &&
                 ExecutablePathRules.IsUnder(path, installDirectory!) &&
                 !ExecutablePathRules.IsPackagedApplication(path) &&
                 app.Executables.Count < PolicyValidator.MaxExecutablesPerApplication)
        {
            if (await AddExecutableAutomaticallyAsync(app, path, ExecutableOrigin.ChildProcess,
                    $"Helper executable {Path.GetFileName(path)} (started by {app.DisplayName}) was added to the policy automatically.").ConfigureAwait(false))
            {
                return;
            }

            detail = $"Started by {app.DisplayName} from its install directory but could not be added automatically; see the activity log.";
        }
        else
        {
            detail = app.IncludeChildProcesses
                ? $"Started by {app.DisplayName} from outside its install directory, so it was not restricted automatically. Add it manually if it communicates on behalf of {app.DisplayName}."
                : $"Started by {app.DisplayName}. Automatic inclusion of helper processes is disabled for this application.";
        }

        if (_observations.Record(ObservationKind.ChildProcess, app.Id, app.DisplayName, path, detail))
        {
            await _audit.WriteAsync(AuditEventType.ChildProcessObserved, AuditOutcome.Info, detail, application: app, executablePath: path,
                details: new { process.ProcessId, process.ParentProcessId }, cancellationToken: _stopping).ConfigureAwait(false);
        }
    }

    private async Task CheckRelocationAsync(ObservedProcess process)
    {
        var path = _inspector.TryCanonicalize(process.ImagePath) ?? process.ImagePath;
        if (_byPath.ContainsKey(path) || !_relocationChecked.Add(path) || ExecutablePathRules.IsSystemComponent(path, _inspector.WindowsDirectory))
        {
            return;
        }

        if (!_byFileName.TryGetValue(Path.GetFileName(path), out var candidates))
        {
            return;
        }

        ExecutableInspection inspection;
        try
        {
            inspection = await Task.Run(() => _inspector.Inspect(path), _stopping).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Could not inspect possible relocation {Path}", path);
            return;
        }

        foreach (var (app, exe) in candidates)
        {
            var policy = app.GetEffectivePolicy(app.ProfileId is { } pid ? _profiles.GetValueOrDefault(pid) : null);
            if (!app.IsEnabled || !policy.RequiresRules)
            {
                continue;
            }

            var signerMatch = inspection.SignatureStatus == SignatureStatus.Valid &&
                              exe.SignatureStatus == SignatureStatus.Valid &&
                              exe.SignerSubject is not null &&
                              string.Equals(inspection.SignerSubject, exe.SignerSubject, StringComparison.Ordinal);
            var productMatch = (inspection.ProductName is not null && string.Equals(inspection.ProductName, exe.ProductName, StringComparison.OrdinalIgnoreCase)) ||
                               (inspection.OriginalFileName is not null && string.Equals(inspection.OriginalFileName, exe.OriginalFileName, StringComparison.OrdinalIgnoreCase));
            var oldPathMissing = !File.Exists(exe.Path);

            if (signerMatch && productMatch && app.FollowSignedUpdates)
            {
                var message = $"{app.DisplayName} started from a new location ({path}) with a valid signature from the same publisher. The policy now also applies to the new path.";
                if (await AddExecutableAutomaticallyAsync(app, path, ExecutableOrigin.LocationChange, message).ConfigureAwait(false))
                {
                    _events.Notify(NotificationKind.ExecutableLocationChanged, $"{app.DisplayName} moved", message, app.Id);
                    await _audit.WriteAsync(AuditEventType.ExecutableLocationChanged, AuditOutcome.Success, message, application: app,
                        executablePath: path, details: new { previousPath = exe.Path, inspection.SignerSubject }, cancellationToken: _stopping).ConfigureAwait(false);
                }

                return;
            }

            if (oldPathMissing || (signerMatch && productMatch))
            {
                var reason = !app.FollowSignedUpdates
                    ? "automatic following of updates is disabled for this application"
                    : !signerMatch
                        ? "its digital signature could not be matched to the publisher recorded for the original executable"
                        : "its product identity differs";
                var message = $"An executable named {Path.GetFileName(path)} started from {path}. It was not restricted automatically because {reason}. Review it and add it to {app.DisplayName} if it is the same application.";
                if (_observations.Record(ObservationKind.LocationChange, app.Id, app.DisplayName, path, message))
                {
                    _events.Notify(NotificationKind.ExecutableLocationChanged, $"{app.DisplayName}: possible new location", message, app.Id);
                    await _audit.WriteAsync(AuditEventType.ExecutableLocationChanged, AuditOutcome.Warning, message, application: app,
                        executablePath: path, details: new { previousPath = exe.Path, inspection.SignatureStatus, inspection.SignerSubject }, cancellationToken: _stopping).ConfigureAwait(false);
                }

                return;
            }
        }
    }

    private async Task VerifyIdentityAsync(ManagedApplication app, ManagedExecutable exe)
    {
        ExecutableInspection inspection;
        try
        {
            inspection = await Task.Run(() => _inspector.Inspect(exe.Path), _stopping).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Identity verification failed for {Path}", exe.Path);
            return;
        }

        var warningKey = "identity:" + exe.Id;
        if (exe.Sha256 is null || string.Equals(exe.Sha256, inspection.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            _registry.ClearWarning(app.Id, warningKey);
            if (exe.Sha256 is null && inspection.Sha256 is not null)
            {
                await UpdateExecutableAsync(app.Id, exe.Id, e => _executables.FromInspection(inspection, e.Origin, e.IsPrimary) with { Id = e.Id, AddedAt = e.AddedAt }).ConfigureAwait(false);
            }

            return;
        }

        var sameSigner = inspection.SignatureStatus == SignatureStatus.Valid && exe.SignerSubject is not null &&
                         string.Equals(inspection.SignerSubject, exe.SignerSubject, StringComparison.Ordinal);
        if (sameSigner)
        {
            await UpdateExecutableAsync(app.Id, exe.Id, e => _executables.FromInspection(inspection, e.Origin, e.IsPrimary) with { Id = e.Id, AddedAt = e.AddedAt }).ConfigureAwait(false);
            _registry.ClearWarning(app.Id, warningKey);
            await _audit.WriteAsync(AuditEventType.ApplicationUpdated, AuditOutcome.Info,
                $"{exe.FileName} was updated in place (version {inspection.FileVersion ?? "unknown"}); the signature matches the recorded publisher.",
                application: app, executablePath: exe.Path, details: new { previous = exe.FileVersion, current = inspection.FileVersion }, cancellationToken: _stopping).ConfigureAwait(false);
            return;
        }

        var message = $"{exe.FileName} changed since it was added and its signature does not match the recorded publisher ({exe.SignerSubject ?? "unsigned"} â†’ {inspection.SignerSubject ?? "unsigned"}). The path-based restriction still applies; review the file.";
        _registry.SetWarning(app.Id, warningKey, message);
        if (_observations.Record(ObservationKind.IdentityChange, app.Id, app.DisplayName, exe.Path, message))
        {
            _events.Notify(NotificationKind.IdentityChanged, $"{app.DisplayName}: executable changed", message, app.Id);
            await _audit.WriteAsync(AuditEventType.IdentityChanged, AuditOutcome.Warning, message, application: app, executablePath: exe.Path,
                details: new { recordedSha256 = exe.Sha256, currentSha256 = inspection.Sha256, inspection.SignatureStatus }, cancellationToken: _stopping).ConfigureAwait(false);
        }
    }

    private async Task<bool> AddExecutableAutomaticallyAsync(ManagedApplication app, string path, ExecutableOrigin origin, string message)
    {
        try
        {
            var executable = await Task.Run(() => _executables.Create(path, origin, isPrimary: false, allowSystemComponent: false, callerCanAdminister: false), _stopping).ConfigureAwait(false);
            var existingOwner = (await _store.GetApplicationsAsync(_stopping).ConfigureAwait(false))
                .FirstOrDefault(a => a.Executables.Any(e => string.Equals(e.Path, executable.Path, StringComparison.OrdinalIgnoreCase)));
            if (existingOwner is not null)
            {
                return true;
            }

            var saved = await SaveWithRetryAsync(app.Id, current => current with
            {
                Executables = [.. current.Executables, executable],
                ModifiedBy = "system",
            }).ConfigureAwait(false);
            if (saved is null)
            {
                return false;
            }

            await _audit.WriteAsync(AuditEventType.ApplicationUpdated, AuditOutcome.Success, message, application: saved, executablePath: executable.Path,
                details: new { origin = origin.ToString() }, cancellationToken: _stopping).ConfigureAwait(false);
            await RebuildIndexAsync().ConfigureAwait(false);
            await _scheduler.RunNowAsync(new ReconcileOptions(ReconcileTrigger.PolicyChange, message), _stopping).ConfigureAwait(false);
            _events.Notify(NotificationKind.PolicyApplied, $"{app.DisplayName}: helper restricted", message, app.Id);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Could not add {Path} to {Application} automatically", path, app.DisplayName);
            await _audit.WriteAsync(AuditEventType.Error, AuditOutcome.Failure, $"Could not add {path} automatically: {ex.Message}",
                application: app, executablePath: path, cancellationToken: _stopping).ConfigureAwait(false);
            return false;
        }
    }

    private async Task UpdateExecutableAsync(Guid applicationId, Guid executableId, Func<ManagedExecutable, ManagedExecutable> update)
    {
        await SaveWithRetryAsync(applicationId, current => current with
        {
            Executables = current.Executables.Select(e => e.Id == executableId ? update(e) : e).ToList(),
            ModifiedBy = "system",
        }).ConfigureAwait(false);
        await RebuildIndexAsync().ConfigureAwait(false);
    }

    private async Task<ManagedApplication?> SaveWithRetryAsync(Guid applicationId, Func<ManagedApplication, ManagedApplication> change)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var current = await _store.GetApplicationAsync(applicationId, _stopping).ConfigureAwait(false);
            if (current is null)
            {
                return null;
            }

            try
            {
                return await _store.SaveApplicationAsync(change(current), current.Revision, _stopping).ConfigureAwait(false);
            }
            catch (ConcurrencyException)
            {
                // Someone else changed the application concurrently; re-read and retry.
            }
        }

        return null;
    }
}

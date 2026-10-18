using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Enforcement;
using NetGuard.Core.Events;
using NetGuard.Core.Monitoring;
using NetGuard.Core.Security;
using NetGuard.Domain;

namespace NetGuard.Core.Policies;

/// <summary>
/// All policy mutations. Each operation validates input, refuses to change organization-managed items, applies
/// optimistic concurrency, writes an audit record, and then reconciles and verifies before returning.
/// </summary>
public sealed class PolicyService
{
    private readonly IPolicyStore _store;
    private readonly ExecutableFactory _executables;
    private readonly IApplicationDiscovery _discovery;
    private readonly EnforcementScheduler _scheduler;
    private readonly ProcessTracker _tracker;
    private readonly AuditWriter _audit;
    private readonly EventBroker _events;
    private readonly PolicyChangeNotifier _notifier;
    private readonly IClock _clock;
    private readonly SemaphoreSlim _mutation = new(1, 1);

    public PolicyService(
        IPolicyStore store,
        ExecutableFactory executables,
        IApplicationDiscovery discovery,
        EnforcementScheduler scheduler,
        ProcessTracker tracker,
        AuditWriter audit,
        EventBroker events,
        PolicyChangeNotifier notifier,
        IClock clock)
    {
        _store = store;
        _executables = executables;
        _discovery = discovery;
        _scheduler = scheduler;
        _tracker = tracker;
        _audit = audit;
        _events = events;
        _notifier = notifier;
        _clock = clock;
    }

    // ------------------------------------------------------------------ applications

    public Task<Guid> AddApplicationAsync(AddApplicationRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            if (request.ExecutablePaths.Count == 0)
            {
                throw new DomainValidationException("Select at least one executable.");
            }

            if (request.ExecutablePaths.Count > PolicyValidator.MaxExecutablesPerApplication)
            {
                throw new DomainValidationException($"An application may contain at most {PolicyValidator.MaxExecutablesPerApplication} executables.");
            }

            PolicyValidator.EnsureValid(request.Policy);
            await EnsureProfileExistsAsync(request.ProfileId, cancellationToken).ConfigureAwait(false);

            var settings = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
            var canAdminister = actor.Has(Permission.Administer, settings);
            var inspections = await Task.Run(
                () => request.ExecutablePaths.Select(_executables.InspectChecked).ToList(), cancellationToken).ConfigureAwait(false);

            var executables = new List<ManagedExecutable>();
            for (var i = 0; i < inspections.Count; i++)
            {
                _executables.EnsureAllowed(inspections[i].CanonicalPath, request.AllowSystemComponent, canAdminister);
                executables.Add(_executables.FromInspection(inspections[i], ExecutableOrigin.UserSelected, isPrimary: i == 0));
            }

            await EnsureNotManagedElsewhereAsync(executables.Select(e => e.Path), null, cancellationToken).ConfigureAwait(false);

            var primary = inspections[0];
            var now = _clock.UtcNow;
            var application = new ManagedApplication
            {
                DisplayName = FirstNonEmpty(request.DisplayName, primary.ProductName, primary.FileDescription, Path.GetFileNameWithoutExtension(primary.CanonicalPath))!,
                Publisher = FirstNonEmpty(primary.CompanyName, PublisherFromSubject(primary.SignerSubject)),
                InstallDirectory = Path.GetDirectoryName(primary.CanonicalPath),
                Executables = executables,
                Policy = request.Policy,
                ProfileId = request.ProfileId,
                IsEnabled = true,
                Source = PolicySource.User,
                IncludeChildProcesses = request.IncludeChildProcesses,
                FollowSignedUpdates = request.FollowSignedUpdates,
                CreatedAt = now,
                CreatedBy = actor.Name,
                ModifiedAt = now,
                ModifiedBy = actor.Name,
            };
            PolicyValidator.EnsureValid(application);

            var saved = await _store.SaveApplicationAsync(application, null, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.ApplicationAdded, AuditOutcome.Success,
                $"Application added with {DescribePolicy(saved.Policy)} policy.", actor.Name, saved,
                details: new { policy = saved.Policy, executables = saved.Executables.Select(e => new { e.Path, e.SignatureStatus, e.SignerSubject, e.Sha256 }) },
                cancellationToken: cancellationToken).ConfigureAwait(false);

            await ApplyAsync($"{saved.DisplayName} added by {actor.Name}", actor, cancellationToken).ConfigureAwait(false);
            return saved.Id;
        }, cancellationToken);

    public Task UpdateApplicationAsync(UpdateApplicationRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var current = await LoadEditableAsync(request.Id, request.ExpectedRevision, cancellationToken).ConfigureAwait(false);
            var settings = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
            var canAdminister = actor.Has(Permission.Administer, settings);

            var executables = current.Executables.Where(e => !request.RemoveExecutableIds.Contains(e.Id)).ToList();
            if (request.AddExecutablePaths.Count > 0)
            {
                var added = await Task.Run(
                    () => request.AddExecutablePaths.Select(p => _executables.Create(p, ExecutableOrigin.UserSelected, false, request.AllowSystemComponent, canAdminister)).ToList(),
                    cancellationToken).ConfigureAwait(false);
                await EnsureNotManagedElsewhereAsync(added.Select(e => e.Path), current.Id, cancellationToken).ConfigureAwait(false);
                executables.AddRange(added.Where(a => executables.All(e => !string.Equals(e.Path, a.Path, StringComparison.OrdinalIgnoreCase))));
            }

            if (executables.Count == 0)
            {
                throw new DomainValidationException("An application must keep at least one executable. Remove the application instead.");
            }

            if (!executables.Any(e => e.IsPrimary))
            {
                executables[0] = executables[0] with { IsPrimary = true };
            }

            var profileId = request.ClearProfile ? null : request.ProfileId ?? current.ProfileId;
            await EnsureProfileExistsAsync(profileId, cancellationToken).ConfigureAwait(false);

            var updated = current with
            {
                DisplayName = string.IsNullOrWhiteSpace(request.DisplayName) ? current.DisplayName : request.DisplayName.Trim(),
                Policy = request.Policy ?? current.Policy,
                ProfileId = profileId,
                IncludeChildProcesses = request.IncludeChildProcesses ?? current.IncludeChildProcesses,
                FollowSignedUpdates = request.FollowSignedUpdates ?? current.FollowSignedUpdates,
                Executables = executables,
                ModifiedAt = _clock.UtcNow,
                ModifiedBy = actor.Name,
            };
            PolicyValidator.EnsureValid(updated);

            var saved = await _store.SaveApplicationAsync(updated, current.Revision, cancellationToken).ConfigureAwait(false);
            var policyChanged = current.Policy != saved.Policy || current.ProfileId != saved.ProfileId;
            await _audit.WriteAsync(policyChanged ? AuditEventType.PolicyChanged : AuditEventType.ApplicationUpdated, AuditOutcome.Success,
                policyChanged
                    ? $"Policy changed from {DescribePolicy(current.Policy)} to {DescribePolicy(saved.Policy)}."
                    : "Application settings updated.",
                actor.Name, saved,
                details: new
                {
                    before = new { current.Policy, current.ProfileId, current.DisplayName, executables = current.Executables.Select(e => e.Path) },
                    after = new { saved.Policy, saved.ProfileId, saved.DisplayName, executables = saved.Executables.Select(e => e.Path) },
                },
                cancellationToken: cancellationToken).ConfigureAwait(false);

            await ApplyAsync($"{saved.DisplayName} updated by {actor.Name}", actor, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    public Task SetEnabledAsync(SetEnabledRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var current = await LoadEditableAsync(request.Id, request.ExpectedRevision, cancellationToken).ConfigureAwait(false);
            if (current.IsEnabled == request.Enabled)
            {
                return;
            }

            var saved = await _store.SaveApplicationAsync(
                current with { IsEnabled = request.Enabled, ModifiedAt = _clock.UtcNow, ModifiedBy = actor.Name },
                current.Revision, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.PolicyChanged, AuditOutcome.Success,
                request.Enabled ? "Management enabled." : "Management disabled; NetGuard rules will be removed.", actor.Name, saved,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            await ApplyAsync($"{saved.DisplayName} {(request.Enabled ? "enabled" : "disabled")} by {actor.Name}", actor, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    /// <summary>
    /// Restores the firewall configuration that existed before NetGuard managed this application: removes only
    /// NetGuard-owned rules (other rules were never changed) and keeps the application listed but disabled.
    /// </summary>
    public Task<EnforcementStatus?> RestoreApplicationAsync(ApplicationIdRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var current = await LoadEditableAsync(request.Id, request.ExpectedRevision, cancellationToken).ConfigureAwait(false);
            await _store.DeleteExceptionAsync(current.Id, cancellationToken).ConfigureAwait(false);
            var saved = await _store.SaveApplicationAsync(
                current with { IsEnabled = false, ModifiedAt = _clock.UtcNow, ModifiedBy = actor.Name },
                current.Revision, cancellationToken).ConfigureAwait(false);
            var report = await ApplyAsync($"{saved.DisplayName} restored by {actor.Name}", actor, cancellationToken).ConfigureAwait(false);
            var status = report.Statuses.GetValueOrDefault(saved.Id);
            await _audit.WriteAsync(AuditEventType.PolicyChanged,
                status?.State == EnforcementState.Disabled ? AuditOutcome.Success : AuditOutcome.Failure,
                status?.State == EnforcementState.Disabled
                    ? "Previous firewall state restored: all NetGuard rules for this application were removed. Rules not created by NetGuard were not changed."
                    : $"Restore incomplete: {status?.Message}",
                actor.Name, saved, cancellationToken: cancellationToken).ConfigureAwait(false);
            return status;
        }, cancellationToken);

    public Task RemoveApplicationAsync(ApplicationIdRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var current = await LoadEditableAsync(request.Id, request.ExpectedRevision, cancellationToken).ConfigureAwait(false);

            // Remove the rules first and verify; only then forget the application. If removal fails the record is
            // kept (disabled) so its rules stay tracked instead of becoming orphans.
            var disabled = current.IsEnabled
                ? await _store.SaveApplicationAsync(current with { IsEnabled = false, ModifiedAt = _clock.UtcNow, ModifiedBy = actor.Name }, current.Revision, cancellationToken).ConfigureAwait(false)
                : current;
            var report = await ApplyAsync($"{current.DisplayName} being removed by {actor.Name}", actor, cancellationToken).ConfigureAwait(false);
            if (report.Statuses.GetValueOrDefault(current.Id) is { State: not EnforcementState.Disabled } status)
            {
                await _audit.WriteAsync(AuditEventType.ApplicationRemoved, AuditOutcome.Failure,
                    $"Removal stopped because NetGuard rules could not be removed: {status.Message}", actor.Name, disabled,
                    cancellationToken: cancellationToken).ConfigureAwait(false);
                throw new NetGuardException(IpcErrorCodes.FirewallUnavailable,
                    $"The application was disabled but not removed because its firewall rules could not be removed: {status.Message}");
            }

            await _store.DeleteExceptionAsync(current.Id, cancellationToken).ConfigureAwait(false);
            await _store.DeleteApplicationAsync(current.Id, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.ApplicationRemoved, AuditOutcome.Success,
                "Application removed from management; its NetGuard rules were removed and verified absent.", actor.Name, current,
                cancellationToken: cancellationToken).ConfigureAwait(false);
            await _tracker.RebuildNowAsync().ConfigureAwait(false);
            _notifier.Raise();
            _events.PublishStateChanged();
        }, cancellationToken);

    public Task GrantTemporaryExceptionAsync(TemporaryExceptionRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var application = await _store.GetApplicationAsync(request.Id, cancellationToken).ConfigureAwait(false)
                ?? throw new NotFoundException("Application not found.");
            if (application.Source == PolicySource.Organization && !actor.IsElevatedAdministrator && !actor.IsSystem)
            {
                throw new OrganizationManagedException(application.DisplayName);
            }

            var settings = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
            if (request.DurationMinutes < 1 || request.DurationMinutes > settings.MaxTemporaryExceptionMinutes)
            {
                throw new DomainValidationException($"Duration must be between 1 and {settings.MaxTemporaryExceptionMinutes} minutes.");
            }

            var reason = request.Reason?.Trim() ?? string.Empty;
            if (reason.Length is 0 or > 500 || reason.Any(char.IsControl))
            {
                throw new DomainValidationException("Enter a reason (up to 500 characters) for the audit log.");
            }

            var profile = application.ProfileId is { } pid ? (await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false)).FirstOrDefault(p => p.Id == pid) : null;
            if (!application.IsEnabled || !application.GetEffectivePolicy(profile).RequiresRules)
            {
                throw new DomainValidationException("This application is not currently restricted, so there is nothing to suspend.");
            }

            var now = _clock.UtcNow;
            var exception = new TemporaryException
            {
                ApplicationId = application.Id,
                GrantedAt = now,
                ExpiresAt = now.AddMinutes(request.DurationMinutes),
                GrantedBy = actor.Name,
                Reason = reason,
            };
            await _store.SaveExceptionAsync(exception, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.TemporaryExceptionGranted, AuditOutcome.Warning,
                $"Temporary network exception granted for {request.DurationMinutes} minute(s): {reason}", actor.Name, application,
                details: new { exception.ExpiresAt, request.DurationMinutes }, cancellationToken: cancellationToken).ConfigureAwait(false);
            await ApplyAsync($"temporary exception for {application.DisplayName}", actor, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    public Task RevokeTemporaryExceptionAsync(ApplicationIdRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var application = await _store.GetApplicationAsync(request.Id, cancellationToken).ConfigureAwait(false)
                ?? throw new NotFoundException("Application not found.");
            await _store.DeleteExceptionAsync(application.Id, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.TemporaryExceptionEnded, AuditOutcome.Success, "Temporary exception revoked; restriction re-applied.",
                actor.Name, application, cancellationToken: cancellationToken).ConfigureAwait(false);
            await ApplyAsync($"exception revoked for {application.DisplayName}", actor, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    // ------------------------------------------------------------------ discovery / inspection

    public async Task<ExecutableInspectionDto> InspectAsync(string path, CancellationToken cancellationToken)
    {
        var inspection = await Task.Run(() => _executables.InspectChecked(path), cancellationToken).ConfigureAwait(false);
        var owner = (await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false))
            .FirstOrDefault(a => a.Executables.Any(e => string.Equals(e.Path, inspection.CanonicalPath, StringComparison.OrdinalIgnoreCase)));
        return _executables.Describe(inspection, owner?.Id);
    }

    public async Task<IReadOnlyList<DiscoveredApplicationDto>> DiscoverAsync(DiscoveryRequest request, ActorContext actor, CancellationToken cancellationToken)
    {
        var managed = await GetManagedPathsAsync(cancellationToken).ConfigureAwait(false);
        var result = await Task.Run(() => _discovery.Discover(request, managed), cancellationToken).ConfigureAwait(false);
        await _audit.WriteAsync(AuditEventType.ApplicationDiscovery, AuditOutcome.Info,
            $"Application discovery found {result.Count} application(s) ({result.Count(r => r.IsRunning)} running).", actor.Name,
            details: new { request.IncludeSystemComponents, request.IncludeRunningProcesses }, cancellationToken: cancellationToken).ConfigureAwait(false);
        return result;
    }

    public async Task<IReadOnlyList<RelatedExecutableDto>> ScanDirectoryAsync(string directory, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(directory) || directory.StartsWith(@"\\", StringComparison.Ordinal) || !Path.IsPathFullyQualified(directory))
        {
            throw new DomainValidationException("Enter an absolute local directory path.");
        }

        if (!Directory.Exists(directory))
        {
            throw new DomainValidationException($"Directory '{directory}' does not exist.");
        }

        if (!ExecutableFactory.IsSpecificInstallDirectory(directory, _executables.Inspector.WindowsDirectory))
        {
            throw new DomainValidationException("This directory is too broad to scan. Choose the application's own folder.");
        }

        var managed = await GetManagedPathsAsync(cancellationToken).ConfigureAwait(false);
        return await Task.Run(() => _discovery.ScanDirectory(directory, managed), cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyDictionary<string, Guid>> GetManagedPathsAsync(CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);
        foreach (var application in await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false))
        {
            foreach (var executable in application.Executables)
            {
                map[executable.Path] = application.Id;
            }
        }

        return map;
    }

    // ------------------------------------------------------------------ profiles

    public Task<Guid> SaveProfileAsync(PolicyProfile profile, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var name = profile.Name?.Trim() ?? string.Empty;
            if (name.Length is 0 or > 64 || name.Any(char.IsControl))
            {
                throw new DomainValidationException("Profile name must be 1-64 printable characters.");
            }

            if (profile.Description.Length > 500)
            {
                throw new DomainValidationException("Profile description must be at most 500 characters.");
            }

            PolicyValidator.EnsureValid(profile.Policy);
            var profiles = await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false);
            var existing = profiles.FirstOrDefault(p => p.Id == profile.Id);
            if (existing?.Source == PolicySource.Organization && !actor.IsSystem)
            {
                throw new OrganizationManagedException(existing.Name);
            }

            if (profiles.Any(p => p.Id != profile.Id && string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                throw new ConflictException($"A profile named '{name}' already exists.");
            }

            var saved = profile with
            {
                Id = profile.Id == Guid.Empty ? Guid.NewGuid() : profile.Id,
                Name = existing?.IsBuiltIn == true ? existing.Name : name,
                IsBuiltIn = existing?.IsBuiltIn ?? false,
                Source = existing?.Source ?? PolicySource.User,
                ModifiedAt = _clock.UtcNow,
                ModifiedBy = actor.Name,
            };
            await _store.SaveProfileAsync(saved, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.ProfileChanged, AuditOutcome.Success,
                $"Profile '{saved.Name}' {(existing is null ? "created" : "updated")} ({DescribePolicy(saved.Policy)}, {(saved.IsEnabled ? "enabled" : "disabled")}).",
                actor.Name, details: new { before = existing, after = saved }, cancellationToken: cancellationToken).ConfigureAwait(false);
            await ApplyAsync($"profile '{saved.Name}' saved", actor, cancellationToken).ConfigureAwait(false);
            return saved.Id;
        }, cancellationToken);

    public Task SetProfileEnabledAsync(SetProfileEnabledRequest request, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var profile = (await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false)).FirstOrDefault(p => p.Id == request.Id)
                ?? throw new NotFoundException("Profile not found.");
            if (profile.Source == PolicySource.Organization && !actor.IsSystem)
            {
                throw new OrganizationManagedException(profile.Name);
            }

            if (request.Enabled)
            {
                PolicyValidator.EnsureValid(profile.Policy);
            }

            await _store.SaveProfileAsync(profile with { IsEnabled = request.Enabled, ModifiedAt = _clock.UtcNow, ModifiedBy = actor.Name }, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.ProfileChanged, AuditOutcome.Success,
                $"Profile '{profile.Name}' {(request.Enabled ? "enabled: its policy now overrides member applications" : "disabled: members use their own policies")}.",
                actor.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
            await ApplyAsync($"profile '{profile.Name}' {(request.Enabled ? "enabled" : "disabled")}", actor, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    public Task DeleteProfileAsync(Guid id, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            var profile = (await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false)).FirstOrDefault(p => p.Id == id)
                ?? throw new NotFoundException("Profile not found.");
            if (profile.IsBuiltIn)
            {
                throw new DomainValidationException("Built-in profiles cannot be deleted; disable the profile instead.");
            }

            if (profile.Source == PolicySource.Organization && !actor.IsSystem)
            {
                throw new OrganizationManagedException(profile.Name);
            }

            foreach (var member in (await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false)).Where(a => a.ProfileId == id))
            {
                await _store.SaveApplicationAsync(member with { ProfileId = null, ModifiedAt = _clock.UtcNow, ModifiedBy = actor.Name }, member.Revision, cancellationToken).ConfigureAwait(false);
            }

            await _store.DeleteProfileAsync(id, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.ProfileChanged, AuditOutcome.Success, $"Profile '{profile.Name}' deleted; members now use their own policies.",
                actor.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
            await ApplyAsync($"profile '{profile.Name}' deleted", actor, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);

    // ------------------------------------------------------------------ service-level

    public Task<ServiceSettings> UpdateSettingsAsync(ServiceSettings settings, ActorContext actor, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            settings.Validate();
            var before = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
            await _store.SaveSettingsAsync(settings, cancellationToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.ConfigurationChanged, AuditOutcome.Success, "Service settings changed.", actor.Name,
                details: new { before, after = settings }, cancellationToken: cancellationToken).ConfigureAwait(false);
            await _tracker.RebuildNowAsync().ConfigureAwait(false);
            _events.PublishStateChanged();
            return settings;
        }, cancellationToken);

    public async Task<ReconcileReport> ReconcileAsync(ActorContext actor, bool removeOrphans, CancellationToken cancellationToken)
    {
        var report = await _scheduler.RunNowAsync(
            new ReconcileOptions(ReconcileTrigger.Manual, removeOrphans ? "orphaned rule clean-up" : "manual verification", actor.Name, removeOrphans),
            cancellationToken).ConfigureAwait(false);
        await _audit.WriteAsync(AuditEventType.Recovery, report.Failures == 0 ? AuditOutcome.Success : AuditOutcome.Failure,
            removeOrphans
                ? $"Orphaned rule clean-up requested: {report.RulesRemoved} rule(s) removed."
                : $"Manual re-verification: {report.RulesAdded} added, {report.RulesUpdated} corrected, {report.RulesRemoved} removed, {report.Failures} failure(s).",
            actor.Name, details: report.ToDto(), cancellationToken: cancellationToken).ConfigureAwait(false);
        return report;
    }

    public async Task<BackupResultDto> CreateBackupAsync(ActorContext actor, CancellationToken cancellationToken)
    {
        var path = await _store.CreateBackupAsync("manual", cancellationToken).ConfigureAwait(false);
        var size = new FileInfo(path).Length;
        await _audit.WriteAsync(AuditEventType.BackupCreated, AuditOutcome.Success, $"Configuration backup created: {Path.GetFileName(path)}", actor.Name,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return new BackupResultDto { Path = path, SizeBytes = size };
    }

    /// <summary>Runs <paramref name="action"/> under the global mutation lock so policy changes are linearizable.</summary>
    public async Task<T> MutateAsync<T>(Func<Task<T>> action, CancellationToken cancellationToken)
    {
        await _mutation.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await action().ConfigureAwait(false);
        }
        catch (ConcurrencyException ex)
        {
            throw new ConflictException(ex.Message);
        }
        finally
        {
            _mutation.Release();
        }
    }

    public Task MutateAsync(Func<Task> action, CancellationToken cancellationToken) =>
        MutateAsync(async () =>
        {
            await action().ConfigureAwait(false);
            return true;
        }, cancellationToken);

    /// <summary>Refreshes the process index (so running state is current) and reconciles synchronously.</summary>
    public async Task<ReconcileReport> ApplyAsync(string reason, ActorContext actor, CancellationToken cancellationToken)
    {
        await _tracker.RebuildNowAsync().ConfigureAwait(false);
        var report = await _scheduler.RunNowAsync(new ReconcileOptions(ReconcileTrigger.PolicyChange, reason, actor.Name), cancellationToken).ConfigureAwait(false);
        _notifier.Raise();
        _events.PublishStateChanged();
        return report;
    }

    private async Task<ManagedApplication> LoadEditableAsync(Guid id, long? expectedRevision, CancellationToken cancellationToken)
    {
        var current = await _store.GetApplicationAsync(id, cancellationToken).ConfigureAwait(false)
            ?? throw new NotFoundException("Application not found. It may have been removed by another administrator.");
        if (current.Source == PolicySource.Organization)
        {
            throw new OrganizationManagedException(current.DisplayName);
        }

        if (expectedRevision is not null && expectedRevision != current.Revision)
        {
            throw new ConflictException($"'{current.DisplayName}' was changed by someone else. Refresh and try again.");
        }

        return current;
    }

    private async Task EnsureProfileExistsAsync(Guid? profileId, CancellationToken cancellationToken)
    {
        if (profileId is null)
        {
            return;
        }

        var profiles = await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false);
        if (profiles.All(p => p.Id != profileId))
        {
            throw new DomainValidationException("The selected profile does not exist.");
        }
    }

    private async Task EnsureNotManagedElsewhereAsync(IEnumerable<string> paths, Guid? exceptApplication, CancellationToken cancellationToken)
    {
        var all = paths.ToList();
        var duplicates = all.GroupBy(p => p, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        if (duplicates.Count > 0)
        {
            throw new DomainValidationException("The same executable was selected more than once: " + string.Join(", ", duplicates));
        }

        var managed = await GetManagedPathsAsync(cancellationToken).ConfigureAwait(false);
        foreach (var path in all)
        {
            if (managed.TryGetValue(path, out var owner) && owner != exceptApplication)
            {
                var ownerApp = await _store.GetApplicationAsync(owner, cancellationToken).ConfigureAwait(false);
                throw new ConflictException($"{path} is already managed by '{ownerApp?.DisplayName}'. Each executable can belong to one application.");
            }
        }
    }

    public static string DescribePolicy(ApplicationPolicy policy)
    {
        var mode = policy.Mode switch
        {
            PolicyMode.Allow => "Allow",
            PolicyMode.Block => "Block",
            _ => "Custom",
        };
        if (!policy.RequiresRules)
        {
            return mode;
        }

        var retention = policy.Retention == RetentionMode.Persistent ? "persistent" : "while running";
        return policy.Profiles == NetworkProfiles.All ? $"{mode} ({retention})" : $"{mode} ({retention}; {StatusEvaluator.Describe(policy.Profiles)})";
    }

    private static string? FirstNonEmpty(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim();

    /// <summary>Extracts O= (or CN=) from an X.500 subject for display.</summary>
    public static string? PublisherFromSubject(string? subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return null;
        }

        string? Find(string key)
        {
            foreach (var part in SplitDistinguishedName(subject))
            {
                var trimmed = part.Trim();
                if (trimmed.StartsWith(key + "=", StringComparison.OrdinalIgnoreCase))
                {
                    return trimmed[(key.Length + 1)..].Trim().Trim('"');
                }
            }

            return null;
        }

        return Find("O") ?? Find("CN");
    }

    private static IEnumerable<string> SplitDistinguishedName(string subject)
    {
        var inQuotes = false;
        var start = 0;
        for (var i = 0; i < subject.Length; i++)
        {
            if (subject[i] == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (subject[i] == ',' && !inQuotes)
            {
                yield return subject[start..i];
                start = i + 1;
            }
        }

        yield return subject[start..];
    }
}

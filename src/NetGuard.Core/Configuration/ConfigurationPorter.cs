using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Policies;
using NetGuard.Core.Security;
using NetGuard.Domain;

namespace NetGuard.Core.Configuration;

/// <summary>
/// Upgrades older policy documents to the current schema. Each step converts version N to N+1 on the raw JSON so
/// that older exports keep importing after the format evolves. Add a step whenever <see cref="PolicyDocument.CurrentSchemaVersion"/> increases.
/// </summary>
public static class ConfigurationMigrations
{
    private static readonly IReadOnlyDictionary<int, Func<JsonObject, JsonObject>> Steps = new Dictionary<int, Func<JsonObject, JsonObject>>
    {
        // Example for a future version 2:
        // [1] = doc => { doc["schemaVersion"] = 2; /* rename or add properties */ return doc; },
    };

    public static JsonObject Upgrade(JsonObject document, int fromVersion, List<string> warnings)
    {
        var version = fromVersion;
        while (version < PolicyDocument.CurrentSchemaVersion)
        {
            if (!Steps.TryGetValue(version, out var step))
            {
                throw new InvalidOperationException($"No migration from schema version {version}.");
            }

            document = step(document);
            warnings.Add($"Upgraded document from schema version {version} to {version + 1}.");
            version++;
        }

        return document;
    }
}

public sealed class ConfigurationPorter
{
    public const int MaxDocumentBytes = 2 * 1024 * 1024;

    private static readonly JsonSerializerOptions StrictOptions = new(NetGuardJson.Options)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly IPolicyStore _store;
    private readonly PolicyService _policies;
    private readonly ExecutableFactory _executables;
    private readonly AuditWriter _audit;
    private readonly IClock _clock;

    public ConfigurationPorter(IPolicyStore store, PolicyService policies, ExecutableFactory executables, AuditWriter audit, IClock clock)
    {
        _store = store;
        _policies = policies;
        _executables = executables;
        _audit = audit;
        _clock = clock;
    }

    public async Task<ExportResultDto> ExportAsync(ConfigurationExportRequest request, ActorContext actor, CancellationToken cancellationToken)
    {
        var now = _clock.UtcNow;
        var applications = (await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false))
            .Where(a => a.Source == PolicySource.User || request.IncludeOrganizationPolicies)
            .OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var profiles = await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false);
        var settings = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);

        var document = new PolicyDocument
        {
            Schema = PolicyDocument.SchemaId,
            SchemaVersion = PolicyDocument.CurrentSchemaVersion,
            Product = "NetGuard Enterprise",
            ExportedAt = now,
            ExportedBy = actor.Name,
            Scope = "user",
            Profiles = profiles
                .Where(p => p.Source == PolicySource.User || request.IncludeOrganizationPolicies)
                .Select(p => new ProfileEntry { Id = p.Id, Name = p.Name, Description = p.Description, Enabled = p.IsEnabled, Policy = PolicyEntry.From(p.Policy) })
                .ToList(),
            Applications = applications.Select(a => new ApplicationEntry
            {
                Id = a.Id,
                DisplayName = a.DisplayName,
                Publisher = a.Publisher,
                Enabled = a.IsEnabled,
                ProfileId = a.ProfileId,
                IncludeChildProcesses = a.IncludeChildProcesses,
                FollowSignedUpdates = a.FollowSignedUpdates,
                AllowSystemComponent = a.Executables.Any(e => ExecutablePathRules.IsSystemComponent(e.Path, _executables.Inspector.WindowsDirectory)),
                Policy = PolicyEntry.From(a.Policy),
                Executables = a.Executables.Select(e => new ExecutableEntry { Path = e.Path, Primary = e.IsPrimary, Sha256 = e.Sha256, SignerSubject = e.SignerSubject }).ToList(),
            }).ToList(),
            Settings = request.IncludeSettings ? SettingsEntry.From(settings) : null,
        };

        var json = JsonSerializer.Serialize(document, NetGuardJson.Indented);
        await _audit.WriteAsync(AuditEventType.ConfigurationExported, AuditOutcome.Success,
            $"Configuration exported ({document.Applications.Count} application(s), {document.Profiles.Count} profile(s)).", actor.Name,
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return new ExportResultDto
        {
            SuggestedFileName = $"netguard-policy-{now:yyyyMMdd-HHmm}.json",
            ContentType = "application/json",
            Content = json,
        };
    }

    /// <summary>Parses and structurally validates a document (schema version, unknown properties, types).</summary>
    public static PolicyDocument? Parse(string json, List<string> errors, List<string> warnings)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            errors.Add("The document is empty.");
            return null;
        }

        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaxDocumentBytes)
        {
            errors.Add($"The document exceeds {MaxDocumentBytes / 1024 / 1024} MB.");
            return null;
        }

        JsonObject root;
        try
        {
            root = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { MaxDepth = 32 }) as JsonObject
                ?? throw new JsonException("The document must be a JSON object.");
        }
        catch (JsonException ex)
        {
            errors.Add($"Invalid JSON: {ex.Message}");
            return null;
        }

        if (root["schemaVersion"] is not JsonValue versionNode || !versionNode.TryGetValue<int>(out var version))
        {
            errors.Add("schemaVersion is missing or not an integer. Only documents exported by NetGuard Enterprise can be imported.");
            return null;
        }

        if (version > PolicyDocument.CurrentSchemaVersion)
        {
            errors.Add($"The document uses schema version {version}, which is newer than this version of NetGuard supports ({PolicyDocument.CurrentSchemaVersion}). Upgrade NetGuard Enterprise first.");
            return null;
        }

        if (version < 1)
        {
            errors.Add($"Schema version {version} is not supported.");
            return null;
        }

        try
        {
            root = ConfigurationMigrations.Upgrade(root, version, warnings);
            return root.Deserialize<PolicyDocument>(StrictOptions);
        }
        catch (JsonException ex)
        {
            errors.Add($"Schema validation failed at {ex.Path ?? "$"}: {ex.Message}");
            return null;
        }
        catch (InvalidOperationException ex)
        {
            errors.Add(ex.Message);
            return null;
        }
    }

    public Task<ImportResultDto> ImportAsync(string json, ImportMode mode, bool dryRun, PolicySource scope, ActorContext actor, CancellationToken cancellationToken) =>
        _policies.MutateAsync(() => ImportCoreAsync(json, mode, dryRun, scope, actor, cancellationToken), cancellationToken);

    private async Task<ImportResultDto> ImportCoreAsync(string json, ImportMode mode, bool dryRun, PolicySource scope, ActorContext actor, CancellationToken cancellationToken)
    {
        var errors = new List<string>();
        var warnings = new List<string>();
        var document = Parse(json, errors, warnings);
        if (document is null)
        {
            return await RejectAsync(errors, warnings, 0, dryRun, actor, cancellationToken).ConfigureAwait(false);
        }

        if (scope == PolicySource.User && string.Equals(document.Scope, "organization", StringComparison.OrdinalIgnoreCase))
        {
            warnings.Add("The document is marked as organization policy but is imported as local (user-scoped) policy. Deploy organization policy through the Policies folder instead.");
        }

        var existingApps = await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false);
        var existingProfiles = await _store.GetProfilesAsync(cancellationToken).ConfigureAwait(false);
        var now = _clock.UtcNow;

        // ---- profiles
        var profileResults = new List<PolicyProfile>();
        var addedProfiles = new List<string>();
        var updatedProfiles = new List<string>();
        foreach (var (entry, index) in document.Profiles.Select((p, i) => (p, i)))
        {
            var path = $"profiles[{index}]";
            var policy = entry.Policy.ToDomain(errors, path + ".policy");
            if (string.IsNullOrWhiteSpace(entry.Name) || entry.Name.Length > 64 || entry.Name.Any(char.IsControl))
            {
                errors.Add($"{path}.name must be 1-64 printable characters.");
            }

            var existing = existingProfiles.FirstOrDefault(p => p.Id == entry.Id);
            if (existing is { Source: PolicySource.Organization } && scope == PolicySource.User)
            {
                warnings.Add($"{path}: profile '{existing.Name}' is organization-managed and was skipped.");
                continue;
            }

            if (existingProfiles.Any(p => p.Id != entry.Id && string.Equals(p.Name, entry.Name, StringComparison.OrdinalIgnoreCase)) ||
                document.Profiles.Count(p => string.Equals(p.Name, entry.Name, StringComparison.OrdinalIgnoreCase)) > 1)
            {
                errors.Add($"{path}: a different profile named '{entry.Name}' already exists.");
            }

            profileResults.Add(new PolicyProfile
            {
                Id = entry.Id,
                Name = existing?.IsBuiltIn == true ? existing.Name : entry.Name.Trim(),
                Description = entry.Description,
                IsBuiltIn = existing?.IsBuiltIn ?? false,
                IsEnabled = entry.Enabled,
                Source = scope,
                Policy = policy,
                ModifiedAt = now,
                ModifiedBy = actor.Name,
            });
            (existing is null ? addedProfiles : updatedProfiles).Add(entry.Name);
        }

        var knownProfileIds = existingProfiles.Select(p => p.Id).Concat(profileResults.Select(p => p.Id)).ToHashSet();

        // ---- applications
        var upserts = new List<ManagedApplication>();
        var added = new List<string>();
        var updated = new List<string>();
        var matched = new HashSet<Guid>();
        var claimedPaths = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var (entry, index) in document.Applications.Select((a, i) => (a, i)))
        {
            var path = $"applications[{index}]";
            var policy = entry.Policy.ToDomain(errors, path + ".policy");
            if (entry.ProfileId is { } profileId && !knownProfileIds.Contains(profileId))
            {
                errors.Add($"{path}.profileId refers to a profile that does not exist.");
            }

            if (entry.Executables.Count is 0 or > PolicyValidator.MaxExecutablesPerApplication)
            {
                errors.Add($"{path}.executables must contain 1-{PolicyValidator.MaxExecutablesPerApplication} entries.");
                continue;
            }

            if (entry.Executables.Count(e => e.Primary) > 1)
            {
                errors.Add($"{path}.executables: only one executable can be primary.");
            }

            var executables = new List<ManagedExecutable>();
            foreach (var (exeEntry, exeIndex) in entry.Executables.Select((e, i) => (e, i)))
            {
                var exePath = $"{path}.executables[{exeIndex}]";
                var executable = await ResolveExecutableAsync(exeEntry, entry.AllowSystemComponent, exePath, errors, warnings, cancellationToken).ConfigureAwait(false);
                if (executable is null)
                {
                    continue;
                }

                if (claimedPaths.TryGetValue(executable.Path, out var otherIndex))
                {
                    errors.Add($"{exePath}: {executable.Path} is also listed in applications[{otherIndex}].");
                    continue;
                }

                claimedPaths[executable.Path] = index;
                executables.Add(executable with { IsPrimary = exeEntry.Primary || (exeIndex == 0 && !entry.Executables.Any(e => e.Primary)) });
            }

            var existing = (entry.Id is { } id ? existingApps.FirstOrDefault(a => a.Id == id) : null)
                ?? existingApps.FirstOrDefault(a => a.Executables.Any(e => executables.Any(x => string.Equals(x.Path, e.Path, StringComparison.OrdinalIgnoreCase))));

            if (existing is not null && existing.Source == PolicySource.Organization && scope == PolicySource.User)
            {
                warnings.Add($"{path}: '{existing.DisplayName}' is organization-managed and was skipped.");
                continue;
            }

            if (existing is not null && existing.Source == PolicySource.User && scope == PolicySource.Organization)
            {
                warnings.Add($"{path}: '{existing.DisplayName}' is now managed by organization policy.");
            }

            // Executables claimed by a different existing application are a conflict.
            foreach (var executable in executables)
            {
                var owner = existingApps.FirstOrDefault(a => a.Id != existing?.Id && a.Executables.Any(e => string.Equals(e.Path, executable.Path, StringComparison.OrdinalIgnoreCase)));
                if (owner is not null && document.Applications.All(other => other.Id != owner.Id))
                {
                    errors.Add($"{path}: {executable.Path} is already managed by '{owner.DisplayName}'.");
                }
            }

            // Keep executable ids for unchanged paths so rule keys stay stable and no rule churn occurs.
            var stable = executables.Select(e =>
            {
                var previous = existing?.Executables.FirstOrDefault(p => string.Equals(p.Path, e.Path, StringComparison.OrdinalIgnoreCase));
                return previous is null ? e : e with { Id = previous.Id, AddedAt = previous.AddedAt };
            }).ToList();

            var application = new ManagedApplication
            {
                Id = existing?.Id ?? entry.Id ?? Guid.NewGuid(),
                DisplayName = entry.DisplayName?.Trim() ?? string.Empty,
                Publisher = entry.Publisher,
                InstallDirectory = Path.GetDirectoryName(stable.FirstOrDefault(e => e.IsPrimary)?.Path ?? stable.FirstOrDefault()?.Path),
                Executables = stable,
                Policy = policy,
                ProfileId = entry.ProfileId,
                IsEnabled = entry.Enabled,
                Source = scope,
                IncludeChildProcesses = entry.IncludeChildProcesses,
                FollowSignedUpdates = entry.FollowSignedUpdates,
                CreatedAt = existing?.CreatedAt ?? now,
                CreatedBy = existing?.CreatedBy ?? actor.Name,
                ModifiedAt = now,
                ModifiedBy = actor.Name,
                Revision = existing?.Revision ?? 0,
            };
            errors.AddRange(PolicyValidator.Validate(application).Select(e => $"{path}: {e}"));
            if (existing is not null)
            {
                matched.Add(existing.Id);
            }

            upserts.Add(application);
            (existing is null ? added : updated).Add(application.DisplayName);
        }

        var deletions = mode == ImportMode.Replace
            ? existingApps.Where(a => a.Source == scope && !matched.Contains(a.Id)).ToList()
            : [];

        ServiceSettings? settings = null;
        if (document.Settings is not null)
        {
            try
            {
                settings = document.Settings.ToDomain().Validate();
            }
            catch (DomainValidationException ex)
            {
                errors.AddRange(ex.Errors.Select(e => "settings: " + e));
            }
        }

        if (errors.Count > 0)
        {
            return await RejectAsync(errors, warnings, document.SchemaVersion, dryRun, actor, cancellationToken).ConfigureAwait(false);
        }

        var result = new ImportResultDto
        {
            Applied = false,
            SchemaVersion = document.SchemaVersion,
            AddedApplications = added,
            UpdatedApplications = updated,
            RemovedApplications = deletions.Select(d => d.DisplayName).ToList(),
            AddedProfiles = addedProfiles,
            UpdatedProfiles = updatedProfiles,
            SettingsChanged = settings is not null,
            Warnings = warnings,
        };

        if (dryRun)
        {
            return result;
        }

        await _store.CreateBackupAsync("pre-import", cancellationToken).ConfigureAwait(false);

        // Applications that will be deleted are disabled first so their rules are removed and verified while
        // they are still tracked; otherwise the rules would become orphans.
        if (deletions.Count > 0)
        {
            foreach (var application in deletions)
            {
                await _store.SaveApplicationAsync(application with { IsEnabled = false, ModifiedAt = now, ModifiedBy = actor.Name }, application.Revision, cancellationToken).ConfigureAwait(false);
            }

            var report = await _policies.ApplyAsync("import: removing applications", actor, cancellationToken).ConfigureAwait(false);
            var failed = deletions.Where(d => report.Statuses.GetValueOrDefault(d.Id)?.State != EnforcementState.Disabled).ToList();
            if (failed.Count > 0)
            {
                var message = "Import stopped: rules for these applications could not be removed: " + string.Join(", ", failed.Select(f => f.DisplayName));
                await _audit.WriteAsync(AuditEventType.ConfigurationImported, AuditOutcome.Failure, message, actor.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
                return result with { Errors = [message] };
            }
        }

        await _store.ApplyImportAsync(new ImportChangeSet
        {
            UpsertApplications = upserts,
            DeleteApplications = deletions.Select(d => d.Id).ToList(),
            UpsertProfiles = profileResults,
            Settings = settings,
        }, cancellationToken).ConfigureAwait(false);

        await _audit.WriteAsync(AuditEventType.ConfigurationImported, AuditOutcome.Success,
            $"{(scope == PolicySource.Organization ? "Organization" : "Local")} policy imported ({mode}): {added.Count} added, {updated.Count} updated, {deletions.Count} removed, {profileResults.Count} profile(s).",
            actor.Name, details: new { added, updated, removed = result.RemovedApplications, warnings }, cancellationToken: cancellationToken).ConfigureAwait(false);
        await _policies.ApplyAsync("configuration imported", actor, cancellationToken).ConfigureAwait(false);
        return result with { Applied = true };
    }

    private async Task<ManagedExecutable?> ResolveExecutableAsync(
        ExecutableEntry entry,
        bool allowSystemComponent,
        string path,
        List<string> errors,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        var syntax = ExecutablePathRules.ValidateSyntax(entry.Path);
        if (syntax is not null)
        {
            errors.Add($"{path}.path: {syntax}");
            return null;
        }

        ManagedExecutable executable;
        var canonical = _executables.Inspector.TryCanonicalize(entry.Path);
        if (canonical is not null)
        {
            try
            {
                var inspection = await Task.Run(() => _executables.InspectChecked(entry.Path), cancellationToken).ConfigureAwait(false);
                executable = _executables.FromInspection(inspection, ExecutableOrigin.Import, entry.Primary);
                if (entry.Sha256 is not null && inspection.Sha256 is not null && !string.Equals(entry.Sha256, inspection.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    warnings.Add($"{path}: {entry.Path} differs from the exported file (different version or build). The local file's identity is recorded.");
                }
            }
            catch (DomainValidationException ex)
            {
                errors.Add($"{path}: {ex.Message}");
                return null;
            }
        }
        else
        {
            warnings.Add($"{path}: {entry.Path} was not found on this computer. The restriction is still created for this path and applies if the program is installed later.");
            executable = new ManagedExecutable
            {
                Path = entry.Path,
                IsPrimary = entry.Primary,
                Origin = ExecutableOrigin.Import,
                Sha256 = entry.Sha256,
                SignerSubject = entry.SignerSubject,
                AddedAt = _clock.UtcNow,
            };
        }

        try
        {
            _executables.EnsureAllowed(executable.Path, allowSystemComponent, callerCanAdminister: true);
        }
        catch (DomainValidationException ex)
        {
            errors.Add($"{path}: {ex.Message}");
            return null;
        }

        return executable;
    }

    private async Task<ImportResultDto> RejectAsync(List<string> errors, List<string> warnings, int version, bool dryRun, ActorContext actor, CancellationToken cancellationToken)
    {
        if (!dryRun)
        {
            await _audit.WriteAsync(AuditEventType.ConfigurationImported, AuditOutcome.Failure,
                $"Configuration import rejected with {errors.Count} error(s). Nothing was changed.", actor.Name,
                details: new { errors = errors.Take(50) }, cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        return new ImportResultDto { Applied = false, SchemaVersion = version, Errors = errors, Warnings = warnings };
    }
}

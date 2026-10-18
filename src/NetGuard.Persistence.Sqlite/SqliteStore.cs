using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;

namespace NetGuard.Persistence.Sqlite;

/// <summary>
/// SQLite implementation of configuration, state and audit storage. One connection per operation (pooled); WAL
/// journaling; foreign keys enforced; every multi-statement change runs in a transaction.
/// </summary>
public sealed class SqliteStore : IPolicyStore, IAuditLog
{
    private const int MaxBackups = 20;

    private readonly string _databasePath;
    private readonly string _backupDirectory;
    private readonly string _connectionString;
    private readonly IClock _clock;
    private readonly ILogger<SqliteStore> _logger;

    public SqliteStore(string dataDirectory, IClock clock, ILogger<SqliteStore> logger)
    {
        Directory.CreateDirectory(dataDirectory);
        _databasePath = Path.Combine(dataDirectory, "netguard.db");
        _backupDirectory = Path.Combine(dataDirectory, "backups");
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = true,
            DefaultTimeout = 30,
        }.ToString();
        _clock = clock;
        _logger = logger;
    }

    public string DatabasePath => _databasePath;

    /// <summary>Messages describing recovery actions taken during initialization (for the audit log).</summary>
    public List<string> RecoveryNotes { get; } = [];

    /// <summary>Checks integrity, recovers from corruption, applies migrations and seeds built-in data.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(_backupDirectory);
        if (File.Exists(_databasePath) && !await IsHealthyAsync(cancellationToken).ConfigureAwait(false))
        {
            Recover();
        }

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "PRAGMA journal_mode = WAL;", cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL, description TEXT NOT NULL, applied_at TEXT NOT NULL);", cancellationToken).ConfigureAwait(false);

        var current = Convert.ToInt32(await ScalarAsync(connection, "SELECT IFNULL(MAX(version), 0) FROM schema_version;", cancellationToken).ConfigureAwait(false), CultureInfo.InvariantCulture);
        if (current > Migrations.LatestVersion)
        {
            throw new InvalidOperationException($"The database schema (version {current}) is newer than this version of NetGuard supports ({Migrations.LatestVersion}). A newer version was installed previously; reinstall it or restore a backup.");
        }

        var pending = Migrations.All.Where(m => m.Version > current).ToList();
        if (pending.Count > 0 && current > 0)
        {
            await BackupCoreAsync(connection, $"pre-migration-v{current}", cancellationToken).ConfigureAwait(false);
        }

        foreach (var (version, description, sql) in pending)
        {
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await ExecuteAsync(connection, sql, cancellationToken, transaction).ConfigureAwait(false);
            await ExecuteAsync(connection, "INSERT INTO schema_version (version, description, applied_at) VALUES ($v, $d, $t);", cancellationToken, transaction,
                ("$v", version), ("$d", description), ("$t", Format(_clock.UtcNow))).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("Applied database migration {Version}: {Description}", version, description);
        }

        foreach (var profile in PolicyProfile.CreateBuiltIns(_clock.UtcNow))
        {
            await ExecuteAsync(connection, """
                INSERT OR IGNORE INTO profiles (id, name, description, is_builtin, is_enabled, source, policy_json, modified_at, modified_by)
                VALUES ($id, $name, $description, 1, 0, 0, $policy, $modified, $by);
                """, cancellationToken, null,
                ("$id", profile.Id.ToString()), ("$name", profile.Name), ("$description", profile.Description),
                ("$policy", Json(profile.Policy)), ("$modified", Format(profile.ModifiedAt)), ("$by", profile.ModifiedBy)).ConfigureAwait(false);
        }
    }

    // ------------------------------------------------------------------ applications

    public async Task<IReadOnlyList<ManagedApplication>> GetApplicationsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        return await ReadApplicationsAsync(connection, null, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ManagedApplication?> GetApplicationAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        return (await ReadApplicationsAsync(connection, id, cancellationToken).ConfigureAwait(false)).FirstOrDefault();
    }

    public async Task<ManagedApplication> SaveApplicationAsync(ManagedApplication application, long? expectedRevision, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        var saved = await UpsertApplicationAsync(connection, transaction, application, expectedRevision, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return saved;
    }

    public async Task DeleteApplicationAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "DELETE FROM applications WHERE id = $id;", cancellationToken, transaction, ("$id", id.ToString())).ConfigureAwait(false);
        await ExecuteAsync(connection, "DELETE FROM enforcement_status WHERE application_id = $id;", cancellationToken, transaction, ("$id", id.ToString())).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<ManagedApplication> UpsertApplicationAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        ManagedApplication application,
        long? expectedRevision,
        CancellationToken cancellationToken)
    {
        var id = application.Id.ToString();
        var stored = await ScalarAsync(connection, "SELECT revision FROM applications WHERE id = $id;", cancellationToken, transaction, ("$id", id)).ConfigureAwait(false);
        long revision;
        if (stored is null)
        {
            if (expectedRevision is > 0)
            {
                throw new ConcurrencyException($"'{application.DisplayName}' no longer exists.");
            }

            revision = 1;
            await ExecuteAsync(connection, """
                INSERT INTO applications (id, display_name, publisher, install_directory, policy_json, profile_id, is_enabled, source,
                    include_children, follow_updates, created_at, created_by, modified_at, modified_by, revision)
                VALUES ($id, $name, $publisher, $dir, $policy, $profile, $enabled, $source, $children, $follow, $created, $createdBy, $modified, $modifiedBy, $revision);
                """, cancellationToken, transaction, AppParameters(application, revision)).ConfigureAwait(false);
        }
        else
        {
            var current = (long)stored;
            if (expectedRevision is not null && expectedRevision != current)
            {
                throw new ConcurrencyException($"'{application.DisplayName}' was changed by someone else. Refresh and try again.");
            }

            revision = current + 1;
            await ExecuteAsync(connection, """
                UPDATE applications SET display_name = $name, publisher = $publisher, install_directory = $dir, policy_json = $policy,
                    profile_id = $profile, is_enabled = $enabled, source = $source, include_children = $children, follow_updates = $follow,
                    created_at = $created, created_by = $createdBy, modified_at = $modified, modified_by = $modifiedBy, revision = $revision
                WHERE id = $id;
                """, cancellationToken, transaction, AppParameters(application, revision)).ConfigureAwait(false);
        }

        await ExecuteAsync(connection, "DELETE FROM executables WHERE application_id = $id;", cancellationToken, transaction, ("$id", id)).ConfigureAwait(false);
        foreach (var e in application.Executables)
        {
            try
            {
                await ExecuteAsync(connection, """
                    INSERT INTO executables (id, application_id, path, is_primary, origin, sha256, file_size, file_version, product_name, company_name,
                        original_file_name, signature_status, signer_subject, signer_thumbprint, added_at, identity_verified_at)
                    VALUES ($id, $app, $path, $primary, $origin, $sha, $size, $version, $product, $company, $original, $sig, $subject, $thumb, $added, $verified);
                    """, cancellationToken, transaction,
                    ("$id", e.Id.ToString()), ("$app", id), ("$path", e.Path), ("$primary", e.IsPrimary), ("$origin", (int)e.Origin),
                    ("$sha", e.Sha256), ("$size", e.FileSize), ("$version", e.FileVersion), ("$product", e.ProductName), ("$company", e.CompanyName),
                    ("$original", e.OriginalFileName), ("$sig", (int)e.SignatureStatus), ("$subject", e.SignerSubject), ("$thumb", e.SignerThumbprint),
                    ("$added", Format(e.AddedAt)), ("$verified", e.IdentityVerifiedAt is { } v ? Format(v) : null)).ConfigureAwait(false);
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
            {
                throw new ConflictException($"{e.Path} is already managed by another application.");
            }
        }

        return application with { Revision = revision };
    }

    private static (string, object?)[] AppParameters(ManagedApplication a, long revision) =>
    [
        ("$id", a.Id.ToString()), ("$name", a.DisplayName), ("$publisher", a.Publisher), ("$dir", a.InstallDirectory),
        ("$policy", Json(a.Policy)), ("$profile", a.ProfileId?.ToString()), ("$enabled", a.IsEnabled), ("$source", (int)a.Source),
        ("$children", a.IncludeChildProcesses), ("$follow", a.FollowSignedUpdates), ("$created", Format(a.CreatedAt)),
        ("$createdBy", a.CreatedBy), ("$modified", Format(a.ModifiedAt)), ("$modifiedBy", a.ModifiedBy), ("$revision", revision),
    ];

    private static async Task<IReadOnlyList<ManagedApplication>> ReadApplicationsAsync(SqliteConnection connection, Guid? id, CancellationToken cancellationToken)
    {
        var executables = new Dictionary<string, List<ManagedExecutable>>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id, application_id, path, is_primary, origin, sha256, file_size, file_version, product_name, company_name, original_file_name, signature_status, signer_subject, signer_thumbprint, added_at, identity_verified_at FROM executables" +
                                  (id is null ? ";" : " WHERE application_id = $app;");
            if (id is not null)
            {
                command.Parameters.AddWithValue("$app", id.Value.ToString());
            }

            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var appId = reader.GetString(1);
                if (!executables.TryGetValue(appId, out var list))
                {
                    executables[appId] = list = [];
                }

                list.Add(new ManagedExecutable
                {
                    Id = Guid.Parse(reader.GetString(0)),
                    Path = reader.GetString(2),
                    IsPrimary = reader.GetBoolean(3),
                    Origin = (ExecutableOrigin)reader.GetInt32(4),
                    Sha256 = NullableString(reader, 5),
                    FileSize = reader.IsDBNull(6) ? null : reader.GetInt64(6),
                    FileVersion = NullableString(reader, 7),
                    ProductName = NullableString(reader, 8),
                    CompanyName = NullableString(reader, 9),
                    OriginalFileName = NullableString(reader, 10),
                    SignatureStatus = (SignatureStatus)reader.GetInt32(11),
                    SignerSubject = NullableString(reader, 12),
                    SignerThumbprint = NullableString(reader, 13),
                    AddedAt = Parse(reader.GetString(14)),
                    IdentityVerifiedAt = reader.IsDBNull(15) ? null : Parse(reader.GetString(15)),
                });
            }
        }

        var result = new List<ManagedApplication>();
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT id, display_name, publisher, install_directory, policy_json, profile_id, is_enabled, source, include_children, follow_updates, created_at, created_by, modified_at, modified_by, revision FROM applications" +
                                  (id is null ? " ORDER BY display_name COLLATE NOCASE;" : " WHERE id = $id;");
            if (id is not null)
            {
                command.Parameters.AddWithValue("$id", id.Value.ToString());
            }

            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var appId = reader.GetString(0);
                result.Add(new ManagedApplication
                {
                    Id = Guid.Parse(appId),
                    DisplayName = reader.GetString(1),
                    Publisher = NullableString(reader, 2),
                    InstallDirectory = NullableString(reader, 3),
                    Policy = FromJson<ApplicationPolicy>(reader.GetString(4)),
                    ProfileId = reader.IsDBNull(5) ? null : Guid.Parse(reader.GetString(5)),
                    IsEnabled = reader.GetBoolean(6),
                    Source = (PolicySource)reader.GetInt32(7),
                    IncludeChildProcesses = reader.GetBoolean(8),
                    FollowSignedUpdates = reader.GetBoolean(9),
                    CreatedAt = Parse(reader.GetString(10)),
                    CreatedBy = reader.GetString(11),
                    ModifiedAt = Parse(reader.GetString(12)),
                    ModifiedBy = reader.GetString(13),
                    Revision = reader.GetInt64(14),
                    Executables = (executables.GetValueOrDefault(appId) ?? []).OrderByDescending(e => e.IsPrimary).ThenBy(e => e.AddedAt).ToList(),
                });
            }
        }

        return result;
    }

    // ------------------------------------------------------------------ profiles

    public async Task<IReadOnlyList<PolicyProfile>> GetProfilesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, name, description, is_builtin, is_enabled, source, policy_json, modified_at, modified_by FROM profiles ORDER BY is_builtin DESC, name COLLATE NOCASE;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var result = new List<PolicyProfile>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new PolicyProfile
            {
                Id = Guid.Parse(reader.GetString(0)),
                Name = reader.GetString(1),
                Description = reader.GetString(2),
                IsBuiltIn = reader.GetBoolean(3),
                IsEnabled = reader.GetBoolean(4),
                Source = (PolicySource)reader.GetInt32(5),
                Policy = FromJson<ApplicationPolicy>(reader.GetString(6)),
                ModifiedAt = Parse(reader.GetString(7)),
                ModifiedBy = reader.GetString(8),
            });
        }

        return result;
    }

    public async Task SaveProfileAsync(PolicyProfile profile, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await UpsertProfileAsync(connection, null, profile, cancellationToken).ConfigureAwait(false);
    }

    private static async Task UpsertProfileAsync(SqliteConnection connection, SqliteTransaction? transaction, PolicyProfile profile, CancellationToken cancellationToken)
    {
        try
        {
            await ExecuteAsync(connection, """
                INSERT INTO profiles (id, name, description, is_builtin, is_enabled, source, policy_json, modified_at, modified_by)
                VALUES ($id, $name, $description, $builtin, $enabled, $source, $policy, $modified, $by)
                ON CONFLICT(id) DO UPDATE SET name = excluded.name, description = excluded.description, is_builtin = excluded.is_builtin,
                    is_enabled = excluded.is_enabled, source = excluded.source, policy_json = excluded.policy_json,
                    modified_at = excluded.modified_at, modified_by = excluded.modified_by;
                """, cancellationToken, transaction,
                ("$id", profile.Id.ToString()), ("$name", profile.Name), ("$description", profile.Description), ("$builtin", profile.IsBuiltIn),
                ("$enabled", profile.IsEnabled), ("$source", (int)profile.Source), ("$policy", Json(profile.Policy)),
                ("$modified", Format(profile.ModifiedAt)), ("$by", profile.ModifiedBy)).ConfigureAwait(false);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            throw new ConflictException($"A profile named '{profile.Name}' already exists.");
        }
    }

    public async Task DeleteProfileAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "DELETE FROM profiles WHERE id = $id AND is_builtin = 0;", cancellationToken, null, ("$id", id.ToString())).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ exceptions / status / settings

    public async Task<IReadOnlyList<TemporaryException>> GetExceptionsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT application_id, granted_at, expires_at, granted_by, reason FROM temporary_exceptions;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var result = new List<TemporaryException>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new TemporaryException
            {
                ApplicationId = Guid.Parse(reader.GetString(0)),
                GrantedAt = Parse(reader.GetString(1)),
                ExpiresAt = Parse(reader.GetString(2)),
                GrantedBy = reader.GetString(3),
                Reason = reader.GetString(4),
            });
        }

        return result;
    }

    public async Task SaveExceptionAsync(TemporaryException exception, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, """
            INSERT INTO temporary_exceptions (application_id, granted_at, expires_at, granted_by, reason) VALUES ($app, $granted, $expires, $by, $reason)
            ON CONFLICT(application_id) DO UPDATE SET granted_at = excluded.granted_at, expires_at = excluded.expires_at, granted_by = excluded.granted_by, reason = excluded.reason;
            """, cancellationToken, null,
            ("$app", exception.ApplicationId.ToString()), ("$granted", Format(exception.GrantedAt)), ("$expires", Format(exception.ExpiresAt)),
            ("$by", exception.GrantedBy), ("$reason", exception.Reason)).ConfigureAwait(false);
    }

    public async Task DeleteExceptionAsync(Guid applicationId, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "DELETE FROM temporary_exceptions WHERE application_id = $app;", cancellationToken, null, ("$app", applicationId.ToString())).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<EnforcementStatus>> GetStatusesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT application_id, state, message, warnings_json, expected_rules, verified_rules, evaluated_at, last_verified_at FROM enforcement_status;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var result = new List<EnforcementStatus>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            result.Add(new EnforcementStatus
            {
                ApplicationId = Guid.Parse(reader.GetString(0)),
                State = (EnforcementState)reader.GetInt32(1),
                Message = reader.GetString(2),
                Warnings = FromJson<List<string>>(reader.GetString(3)),
                ExpectedRuleCount = reader.GetInt32(4),
                VerifiedRuleCount = reader.GetInt32(5),
                EvaluatedAt = Parse(reader.GetString(6)),
                LastVerifiedAt = reader.IsDBNull(7) ? null : Parse(reader.GetString(7)),
            });
        }

        return result;
    }

    public async Task SaveStatusesAsync(IReadOnlyCollection<EnforcementStatus> statuses, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await ExecuteAsync(connection, "DELETE FROM enforcement_status;", cancellationToken, transaction).ConfigureAwait(false);
        foreach (var s in statuses)
        {
            await ExecuteAsync(connection, """
                INSERT INTO enforcement_status (application_id, state, message, warnings_json, expected_rules, verified_rules, evaluated_at, last_verified_at)
                VALUES ($app, $state, $message, $warnings, $expected, $verified, $evaluated, $last);
                """, cancellationToken, transaction,
                ("$app", s.ApplicationId.ToString()), ("$state", (int)s.State), ("$message", s.Message), ("$warnings", Json(s.Warnings)),
                ("$expected", s.ExpectedRuleCount), ("$verified", s.VerifiedRuleCount), ("$evaluated", Format(s.EvaluatedAt)),
                ("$last", s.LastVerifiedAt is { } last ? Format(last) : null)).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<ServiceSettings> GetSettingsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var json = await ScalarAsync(connection, "SELECT value_json FROM settings WHERE key = 'service';", cancellationToken).ConfigureAwait(false) as string;
        if (json is null)
        {
            return new ServiceSettings();
        }

        try
        {
            return FromJson<ServiceSettings>(json).Validate();
        }
        catch (Exception ex) when (ex is JsonException or DomainValidationException)
        {
            _logger.LogError(ex, "Stored settings are invalid; using defaults");
            return new ServiceSettings();
        }
    }

    public async Task SaveSettingsAsync(ServiceSettings settings, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await SaveSettingsCoreAsync(connection, null, settings, cancellationToken).ConfigureAwait(false);
    }

    private static Task SaveSettingsCoreAsync(SqliteConnection connection, SqliteTransaction? transaction, ServiceSettings settings, CancellationToken cancellationToken) =>
        ExecuteAsync(connection, "INSERT INTO settings (key, value_json) VALUES ('service', $json) ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json;",
            cancellationToken, transaction, ("$json", Json(settings.Validate())));

    public async Task ApplyImportAsync(ImportChangeSet changes, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        foreach (var profile in changes.UpsertProfiles)
        {
            await UpsertProfileAsync(connection, transaction, profile, cancellationToken).ConfigureAwait(false);
        }

        foreach (var id in changes.DeleteApplications)
        {
            await ExecuteAsync(connection, "DELETE FROM applications WHERE id = $id;", cancellationToken, transaction, ("$id", id.ToString())).ConfigureAwait(false);
        }

        // Clear executables of all upserted applications first so paths can move between applications in one import.
        foreach (var application in changes.UpsertApplications)
        {
            await ExecuteAsync(connection, "DELETE FROM executables WHERE application_id = $id;", cancellationToken, transaction, ("$id", application.Id.ToString())).ConfigureAwait(false);
        }

        foreach (var application in changes.UpsertApplications)
        {
            await UpsertApplicationAsync(connection, transaction, application, null, cancellationToken).ConfigureAwait(false);
        }

        if (changes.Settings is not null)
        {
            await SaveSettingsCoreAsync(connection, transaction, changes.Settings, cancellationToken).ConfigureAwait(false);
        }

        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ audit

    public async Task<long> AppendAsync(AuditEvent auditEvent, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var id = await ScalarAsync(connection, """
            INSERT INTO audit_events (ts, type, outcome, actor, application_id, application_name, executable_path, message, details)
            VALUES ($ts, $type, $outcome, $actor, $app, $appName, $path, $message, $details);
            SELECT last_insert_rowid();
            """, cancellationToken, null,
            ("$ts", Format(auditEvent.Timestamp)), ("$type", (int)auditEvent.Type), ("$outcome", (int)auditEvent.Outcome),
            ("$actor", Truncate(auditEvent.Actor, 256)), ("$app", auditEvent.ApplicationId?.ToString()), ("$appName", Truncate(auditEvent.ApplicationName, 256)),
            ("$path", Truncate(auditEvent.ExecutablePath, 1024)), ("$message", Truncate(auditEvent.Message, 4000)),
            ("$details", Truncate(auditEvent.Details, 16_000))).ConfigureAwait(false);
        return Convert.ToInt64(id, CultureInfo.InvariantCulture);
    }

    public async Task<AuditPage> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default)
    {
        var where = new List<string>();
        var parameters = new List<(string, object?)>();
        if (!string.IsNullOrWhiteSpace(query.Text))
        {
            where.Add("(message LIKE $text ESCAPE '\\' OR application_name LIKE $text ESCAPE '\\' OR executable_path LIKE $text ESCAPE '\\' OR actor LIKE $text ESCAPE '\\')");
            parameters.Add(("$text", "%" + EscapeLike(query.Text.Trim()) + "%"));
        }

        if (query.From is { } from)
        {
            where.Add("ts >= $from");
            parameters.Add(("$from", Format(from)));
        }

        if (query.To is { } to)
        {
            where.Add("ts <= $to");
            parameters.Add(("$to", Format(to)));
        }

        if (query.ApplicationId is { } appId)
        {
            where.Add("application_id = $appId");
            parameters.Add(("$appId", appId.ToString()));
        }

        if (query.Types is { Count: > 0 } types)
        {
            where.Add($"type IN ({string.Join(',', types.Select(t => ((int)t).ToString(CultureInfo.InvariantCulture)))})");
        }

        if (query.Outcomes is { Count: > 0 } outcomes)
        {
            where.Add($"outcome IN ({string.Join(',', outcomes.Select(o => ((int)o).ToString(CultureInfo.InvariantCulture)))})");
        }

        var filter = where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : string.Empty;
        var take = Math.Clamp(query.Take, 1, 50_000);
        var skip = Math.Max(query.Skip, 0);

        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        var total = Convert.ToInt32(await ScalarAsync(connection, "SELECT COUNT(*) FROM audit_events" + filter + ";", cancellationToken, null, [.. parameters]).ConfigureAwait(false), CultureInfo.InvariantCulture);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id, ts, type, outcome, actor, application_id, application_name, executable_path, message, details FROM audit_events" +
                              filter + " ORDER BY id DESC LIMIT $take OFFSET $skip;";
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        command.Parameters.AddWithValue("$take", take);
        command.Parameters.AddWithValue("$skip", skip);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        var items = new List<AuditEvent>();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            items.Add(new AuditEvent
            {
                Id = reader.GetInt64(0),
                Timestamp = Parse(reader.GetString(1)),
                Type = (AuditEventType)reader.GetInt32(2),
                Outcome = (AuditOutcome)reader.GetInt32(3),
                Actor = reader.GetString(4),
                ApplicationId = reader.IsDBNull(5) ? null : Guid.Parse(reader.GetString(5)),
                ApplicationName = NullableString(reader, 6),
                ExecutablePath = NullableString(reader, 7),
                Message = reader.GetString(8),
                Details = NullableString(reader, 9),
            });
        }

        return new AuditPage(items, total);
    }

    public async Task<int> PurgeOlderThanAsync(DateTimeOffset cutoff, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM audit_events WHERE ts < $cutoff;";
        command.Parameters.AddWithValue("$cutoff", Format(cutoff));
        return await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ backup / recovery

    public async Task<string> CreateBackupAsync(string reason, CancellationToken cancellationToken = default)
    {
        await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
        return await BackupCoreAsync(connection, reason, cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> BackupCoreAsync(SqliteConnection connection, string reason, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_backupDirectory);
        var safeReason = new string(reason.Where(c => char.IsAsciiLetterOrDigit(c) || c == '-').ToArray());
        var path = Path.Combine(_backupDirectory, $"netguard-{_clock.UtcNow:yyyyMMdd-HHmmss-fff}-{safeReason}.db");

        // VACUUM INTO produces a consistent, defragmented copy while the database stays online.
        await using (var command = connection.CreateCommand())
        {
            command.CommandText = "VACUUM INTO $path;";
            command.Parameters.AddWithValue("$path", path);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        foreach (var old in new DirectoryInfo(_backupDirectory).GetFiles("netguard-*.db").OrderByDescending(f => f.Name, StringComparer.Ordinal).Skip(MaxBackups))
        {
            try
            {
                old.Delete();
            }
            catch (IOException ex)
            {
                _logger.LogWarning(ex, "Could not delete old backup {Backup}", old.FullName);
            }
        }

        return path;
    }

    private async Task<bool> IsHealthyAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            var result = await ScalarAsync(connection, "PRAGMA quick_check;", cancellationToken).ConfigureAwait(false) as string;
            return string.Equals(result, "ok", StringComparison.OrdinalIgnoreCase);
        }
        catch (SqliteException ex)
        {
            _logger.LogError(ex, "Database integrity check failed");
            return false;
        }
    }

    /// <summary>Moves a corrupt database aside (never deletes it) and restores the newest backup if one exists.</summary>
    private void Recover()
    {
        SqliteConnection.ClearAllPools();
        var stamp = _clock.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var quarantine = _databasePath + $".corrupt-{stamp}";
        File.Move(_databasePath, quarantine);
        foreach (var suffix in new[] { "-wal", "-shm" })
        {
            if (File.Exists(_databasePath + suffix))
            {
                File.Move(_databasePath + suffix, quarantine + suffix);
            }
        }

        var latest = Directory.Exists(_backupDirectory)
            ? new DirectoryInfo(_backupDirectory).GetFiles("netguard-*.db").OrderByDescending(f => f.Name, StringComparer.Ordinal).FirstOrDefault()
            : null;
        if (latest is not null)
        {
            File.Copy(latest.FullName, _databasePath);
            RecoveryNotes.Add($"The database failed its integrity check and was moved to {Path.GetFileName(quarantine)}. Restored from backup {latest.Name}.");
        }
        else
        {
            RecoveryNotes.Add($"The database failed its integrity check and was moved to {Path.GetFileName(quarantine)}. No backup was available; a new database was created. Existing NetGuard firewall rules were kept and are reported as orphaned.");
        }

        _logger.LogCritical("Database recovery: {Note}", RecoveryNotes[^1]);
    }

    // ------------------------------------------------------------------ helpers

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 10000; PRAGMA synchronous = NORMAL;";
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }

    private static async Task ExecuteAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken, SqliteTransaction? transaction = null, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<object?> ScalarAsync(SqliteConnection connection, string sql, CancellationToken cancellationToken, SqliteTransaction? transaction = null, params (string Name, object? Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        foreach (var (name, value) in parameters)
        {
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        }

        var result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return result is DBNull ? null : result;
    }

    private static string Format(DateTimeOffset value) => value.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture);

    private static DateTimeOffset Parse(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    private static string Json<T>(T value) => JsonSerializer.Serialize(value, NetGuardJson.Options);

    private static T FromJson<T>(string json) => JsonSerializer.Deserialize<T>(json, NetGuardJson.Options) ?? throw new JsonException("Unexpected null.");

    private static string? NullableString(SqliteDataReader reader, int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);

    private static string? Truncate(string? value, int max) => value is null || value.Length <= max ? value : value[..max];

    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);
}

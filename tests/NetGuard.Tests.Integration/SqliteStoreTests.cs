using Microsoft.Extensions.Logging.Abstractions;
using NetGuard.Core;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;
using NetGuard.Persistence.Sqlite;
using Xunit;

namespace NetGuard.Tests.Integration;

public sealed class SqliteStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ng-db-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, true);
        }
        catch (IOException)
        {
        }
    }

    private async Task<SqliteStore> OpenAsync()
    {
        var store = new SqliteStore(_dir, new SystemClock(), NullLogger<SqliteStore>.Instance);
        await store.InitializeAsync();
        return store;
    }

    private static ManagedApplication App(string path, string name = "Contoso") => new()
    {
        DisplayName = name,
        Executables = [new ManagedExecutable { Path = path, IsPrimary = true, AddedAt = DateTimeOffset.UtcNow, SignatureStatus = SignatureStatus.Valid }],
        Policy = new ApplicationPolicy { Mode = PolicyMode.Custom, Custom = new CustomNetworkPolicy { AllowedRemoteAddresses = ["10.0.0.0/8"], AllowedTcpPorts = "443" } },
        CreatedAt = DateTimeOffset.UtcNow,
        ModifiedAt = DateTimeOffset.UtcNow,
        CreatedBy = "test",
        ModifiedBy = "test",
    };

    [Fact]
    public async Task Initialize_CreatesSchemaAndBuiltInProfiles_AndIsIdempotent()
    {
        await OpenAsync();
        var store = await OpenAsync();
        var profiles = await store.GetProfilesAsync();
        Assert.Equal(4, profiles.Count(p => p.IsBuiltIn));
    }

    [Fact]
    public async Task Application_RoundTripsWithPolicyAndIdentity()
    {
        var store = await OpenAsync();
        var saved = await store.SaveApplicationAsync(App(@"C:\A\a.exe"), null);
        var loaded = await store.GetApplicationAsync(saved.Id);

        Assert.NotNull(loaded);
        Assert.Equal(1, loaded!.Revision);
        Assert.Equal(saved.Policy, loaded.Policy);
        Assert.Equal(@"C:\A\a.exe", loaded.Executables.Single().Path);
        Assert.Equal(SignatureStatus.Valid, loaded.Executables.Single().SignatureStatus);
    }

    [Fact]
    public async Task OptimisticConcurrency_RejectsStaleRevision()
    {
        var store = await OpenAsync();
        var saved = await store.SaveApplicationAsync(App(@"C:\A\a.exe"), null);
        await store.SaveApplicationAsync(saved with { DisplayName = "B" }, saved.Revision);
        await Assert.ThrowsAsync<ConcurrencyException>(() => store.SaveApplicationAsync(saved with { DisplayName = "C" }, saved.Revision));
    }

    [Fact]
    public async Task ExecutablePath_IsUniqueAcrossApplications_CaseInsensitive()
    {
        var store = await OpenAsync();
        await store.SaveApplicationAsync(App(@"C:\A\a.exe"), null);
        await Assert.ThrowsAsync<ConflictException>(() => store.SaveApplicationAsync(App(@"c:\a\A.EXE", "Other"), null));
    }

    [Fact]
    public async Task Audit_FiltersPagesAndPurges()
    {
        var store = await OpenAsync();
        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < 30; i++)
        {
            await store.AppendAsync(new AuditEvent
            {
                Timestamp = now.AddMinutes(-i),
                Type = i % 2 == 0 ? AuditEventType.PolicyChanged : AuditEventType.EnforcementFailed,
                Outcome = i % 2 == 0 ? AuditOutcome.Success : AuditOutcome.Failure,
                Message = $"event {i} 100%_done",
                Actor = "tester",
            });
        }

        var failures = await store.QueryAsync(new AuditQuery { Outcomes = [AuditOutcome.Failure], Take = 10 });
        Assert.Equal(15, failures.TotalCount);
        Assert.Equal(10, failures.Items.Count);

        var text = await store.QueryAsync(new AuditQuery { Text = "event 7 100%_" });
        Assert.Single(text.Items);

        var ranged = await store.QueryAsync(new AuditQuery { From = now.AddMinutes(-4.5), To = now });
        Assert.Equal(5, ranged.TotalCount);

        Assert.Equal(10, await store.PurgeOlderThanAsync(now.AddMinutes(-19.5)));
    }

    [Fact]
    public async Task Backup_ProducesUsableCopy()
    {
        var store = await OpenAsync();
        await store.SaveApplicationAsync(App(@"C:\A\a.exe"), null);
        var backup = await store.CreateBackupAsync("test");

        Assert.True(File.Exists(backup));
        var restoredDir = Path.Combine(_dir, "restored");
        Directory.CreateDirectory(restoredDir);
        File.Copy(backup, Path.Combine(restoredDir, "netguard.db"));
        var restored = new SqliteStore(restoredDir, new SystemClock(), NullLogger<SqliteStore>.Instance);
        await restored.InitializeAsync();
        Assert.Single(await restored.GetApplicationsAsync());
    }

    [Fact]
    public async Task CorruptDatabase_IsQuarantined_AndRestoredFromBackup()
    {
        var store = await OpenAsync();
        await store.SaveApplicationAsync(App(@"C:\A\a.exe"), null);
        await store.CreateBackupAsync("test");
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        // Overwrite the database with garbage, simulating corruption after a forced shutdown.
        var dbPath = Path.Combine(_dir, "netguard.db");
        foreach (var suffix in new[] { "-wal", "-shm" })
        {
            File.Delete(dbPath + suffix);
        }

        await File.WriteAllBytesAsync(dbPath, Enumerable.Repeat((byte)0x5A, 8192).ToArray());

        var recovered = new SqliteStore(_dir, new SystemClock(), NullLogger<SqliteStore>.Instance);
        await recovered.InitializeAsync();

        Assert.Single(recovered.RecoveryNotes);
        Assert.Contains("Restored from backup", recovered.RecoveryNotes[0]);
        Assert.Single(await recovered.GetApplicationsAsync());
        Assert.Single(Directory.GetFiles(_dir, "netguard.db.corrupt-*"));
    }

    [Fact]
    public async Task Statuses_ReplaceAtomically()
    {
        var store = await OpenAsync();
        var id = Guid.NewGuid();
        await store.SaveStatusesAsync([new EnforcementStatus { ApplicationId = id, State = EnforcementState.Enforced, Warnings = ["w"], EvaluatedAt = DateTimeOffset.UtcNow }]);
        var loaded = Assert.Single(await store.GetStatusesAsync());
        Assert.Equal(EnforcementState.Enforced, loaded.State);
        Assert.Equal(["w"], loaded.Warnings);
    }
}

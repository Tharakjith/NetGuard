using NetGuard.Contracts;
using NetGuard.Domain;
using Xunit;

namespace NetGuard.Tests.Unit;

public sealed class ProcessTrackerTests
{
    private static readonly ApplicationPolicy WhileRunning = ApplicationPolicy.BlockAll with { Retention = RetentionMode.WhileRunning };

    [Fact]
    public async Task Launch_OfManagedApp_IsTrackedVerifiedAndNotified()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);

        h.Monitor.Launch(Harness.AppPath);

        await Harness.WaitUntilAsync(() => h.Registry.IsRunning(id));
        await Harness.WaitUntilAsync(() => h.Events.LatestSequence > 0 &&
            h.Events.WaitAsync(0, TimeSpan.Zero, default).Result.Events.Any(e => e.Notification == NotificationKind.ApplicationBlocked));
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.ProcessStarted && e.ApplicationId == id);
    }

    [Fact]
    public async Task SameFileNameAtDifferentPath_IsNotTreatedAsManaged()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        const string impostor = @"C:\Users\Public\contoso.exe";
        h.Inspector.AddFile(impostor, signer: null, product: "Something else", sha: "BB");

        h.Monitor.Launch(impostor);
        await Task.Delay(300);

        Assert.False(h.Registry.IsRunning(id));
        Assert.Equal(0, h.OwnedRulesFor(impostor));
        var app = await h.Store.GetApplicationAsync(id);
        Assert.Single(app!.Executables);
    }

    [Fact]
    public async Task AliasPath_ResolvesToCanonicalPath()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        h.Inspector.Aliases[@"C:\PROGRA~1\Contoso\App\contoso.exe"] = Harness.AppPath;

        h.Monitor.Launch(@"C:\PROGRA~1\Contoso\App\contoso.exe");

        await Harness.WaitUntilAsync(() => h.Registry.IsRunning(id));
    }

    [Fact]
    public async Task Exit_DoesNotRemovePersistentRestriction()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        var process = h.Monitor.Launch(Harness.AppPath);
        await Harness.WaitUntilAsync(() => h.Registry.IsRunning(id));

        h.Monitor.Exit(process);
        await Harness.WaitUntilAsync(() => !h.Registry.IsRunning(id));
        await h.ReconcileAsync(ReconcileTriggerFor.Exit);

        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
        Assert.Equal(EnforcementState.Enforced, (await h.StatusAsync(id)).State);
    }

    [Fact]
    public async Task WhileRunning_CreatesOnLaunch_RemovesAfterLastInstanceExits()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath, WhileRunning);
        Assert.Equal(0, h.OwnedRulesFor(Harness.AppPath));
        Assert.Equal(EnforcementState.Standby, (await h.StatusAsync(id)).State);

        var first = h.Monitor.Launch(Harness.AppPath);
        var second = h.Monitor.Launch(Harness.AppPath);
        await Harness.WaitUntilAsync(() => h.OwnedRulesFor(Harness.AppPath) == 1 && h.Registry.GetInstances(id).Count == 2);

        h.Monitor.Exit(first);
        await Task.Delay(400);
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));

        h.Monitor.Exit(second);
        await Harness.WaitUntilAsync(() => h.OwnedRulesFor(Harness.AppPath) == 0);
        await Harness.WaitUntilAsync(async () => (await h.StatusAsync(id)).State == EnforcementState.Standby);
    }

    [Fact]
    public async Task AlreadyRunningApplication_IsDetectedWhenAdded()
    {
        await using var h = await Harness.StartAsync();
        h.Monitor.AlreadyRunning(Harness.AppPath);

        var id = await h.AddAsync(Harness.AppPath, WhileRunning);

        Assert.True(h.Registry.IsRunning(id));
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task ChildProcessInInstallDirectory_IsAddedAndRestricted()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        var parent = h.Monitor.Launch(Harness.AppPath);
        await Harness.WaitUntilAsync(() => h.Registry.IsRunning(id));

        h.Monitor.Launch(Harness.HelperPath, parent.ProcessId, parent.StartTime.AddSeconds(1));

        await Harness.WaitUntilAsync(() => h.OwnedRulesFor(Harness.HelperPath) == 1);
        var app = await h.Store.GetApplicationAsync(id);
        Assert.Contains(app!.Executables, e => e.Path == Harness.HelperPath && e.Origin == ExecutableOrigin.ChildProcess);
    }

    [Fact]
    public async Task ChildProcessOutsideInstallDirectory_IsOnlyObserved()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        var parent = h.Monitor.Launch(Harness.AppPath);
        await Harness.WaitUntilAsync(() => h.Registry.IsRunning(id));

        h.Monitor.Launch(Harness.OtherPath, parent.ProcessId, parent.StartTime.AddSeconds(1));

        await Harness.WaitUntilAsync(() => h.Observations.GetAll(id).Any(o => o.Kind == ObservationKind.ChildProcess));
        Assert.Equal(0, h.OwnedRulesFor(Harness.OtherPath));
    }

    [Fact]
    public async Task SignedRelocation_IsFollowed()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        const string moved = @"C:\Program Files\Contoso\App-2.0\contoso.exe";
        h.Inspector.AddFile(moved, sha: "CC", version: "2.0.0.0");

        h.Monitor.Launch(moved);

        await Harness.WaitUntilAsync(() => h.OwnedRulesFor(moved) == 1);
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.ExecutableLocationChanged && e.Outcome == AuditOutcome.Success);
    }

    [Fact]
    public async Task UnsignedLookalike_IsNotFollowed()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        h.Inspector.Files.Remove(Harness.AppPath); // the original was "uninstalled"
        const string lookalike = @"C:\Temp\contoso.exe";
        h.Inspector.AddFile(lookalike, signer: null, sha: "DD");

        h.Monitor.Launch(lookalike);

        await Harness.WaitUntilAsync(() => h.Observations.GetAll(id).Any(o => o.Kind == ObservationKind.LocationChange));
        Assert.Equal(0, h.OwnedRulesFor(lookalike));
    }

    [Fact]
    public async Task ChangedBinaryWithDifferentSigner_RaisesIdentityWarning_ButStaysBlocked()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        h.Inspector.AddFile(Harness.AppPath, signer: "CN=Someone Else", sha: "EE");

        h.Monitor.Launch(Harness.AppPath);

        await Harness.WaitUntilAsync(() => h.Registry.GetWarnings(id).Count > 0);
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.IdentityChanged);
    }

    private static class ReconcileTriggerFor
    {
        public const Core.Enforcement.ReconcileTrigger Exit = Core.Enforcement.ReconcileTrigger.ProcessExit;
    }
}

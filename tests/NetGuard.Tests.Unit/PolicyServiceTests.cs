using NetGuard.Contracts;
using NetGuard.Core;
using NetGuard.Domain;
using Xunit;

namespace NetGuard.Tests.Unit;

public sealed class PolicyServiceTests
{
    [Fact]
    public async Task Add_RejectsProtectedSystemComponents()
    {
        await using var h = await Harness.StartAsync();
        h.Inspector.AddFile(@"C:\Windows\System32\svchost.exe");

        var ex = await Assert.ThrowsAsync<DomainValidationException>(() => h.AddAsync(@"C:\Windows\System32\svchost.exe"));
        Assert.Contains("core Windows", ex.Message);
        Assert.Empty(h.Firewall.Rules);
    }

    [Fact]
    public async Task Add_SystemComponent_RequiresExplicitFlagAndAdministrator()
    {
        await using var h = await Harness.StartAsync();
        const string curl = @"C:\Windows\System32\curl.exe";
        h.Inspector.AddFile(curl);

        await Assert.ThrowsAsync<DomainValidationException>(() => h.AddAsync(curl));
        await Assert.ThrowsAsync<AuthorizationException>(() => h.Policies.AddApplicationAsync(
            new AddApplicationRequest { ExecutablePaths = [curl], AllowSystemComponent = true }, Harness.Operator, h.Token));

        var id = await h.Policies.AddApplicationAsync(new AddApplicationRequest { ExecutablePaths = [curl], AllowSystemComponent = true }, Harness.Admin, h.Token);
        Assert.Equal(EnforcementState.Enforced, (await h.StatusAsync(id)).State);
    }

    [Fact]
    public async Task Add_RejectsMissingFilesAndBadPaths()
    {
        await using var h = await Harness.StartAsync();
        await Assert.ThrowsAsync<DomainValidationException>(() => h.AddAsync(@"C:\Nope\missing.exe"));
        await Assert.ThrowsAsync<DomainValidationException>(() => h.AddAsync(@"\\server\share\app.exe"));
        await Assert.ThrowsAsync<DomainValidationException>(() => h.AddAsync(@"C:\Program Files\NetGuard Enterprise\NetGuard.Service.exe"));
    }

    [Fact]
    public async Task Add_SameExecutableTwice_IsConflict()
    {
        await using var h = await Harness.StartAsync();
        await h.AddAsync(Harness.AppPath);
        await Assert.ThrowsAsync<ConflictException>(() => h.AddAsync(Harness.AppPath));
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task Update_WithStaleRevision_IsConflict()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        var revision = (await h.Store.GetApplicationAsync(id))!.Revision;
        await h.Policies.UpdateApplicationAsync(new UpdateApplicationRequest { Id = id, ExpectedRevision = revision, DisplayName = "First" }, Harness.Admin, h.Token);

        await Assert.ThrowsAsync<ConflictException>(() =>
            h.Policies.UpdateApplicationAsync(new UpdateApplicationRequest { Id = id, ExpectedRevision = revision, DisplayName = "Second" }, Harness.Admin, h.Token));
        Assert.Equal("First", (await h.Store.GetApplicationAsync(id))!.DisplayName);
    }

    [Fact]
    public async Task OrganizationManagedApplications_CannotBeChangedLocally()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        var app = (await h.Store.GetApplicationAsync(id))!;
        await h.Store.SaveApplicationAsync(app with { Source = PolicySource.Organization }, app.Revision);

        await Assert.ThrowsAsync<OrganizationManagedException>(() =>
            h.Policies.SetEnabledAsync(new SetEnabledRequest { Id = id, Enabled = false }, Harness.Admin, h.Token));
        await Assert.ThrowsAsync<OrganizationManagedException>(() =>
            h.Policies.RemoveApplicationAsync(new ApplicationIdRequest { Id = id }, Harness.Admin, h.Token));
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task Remove_RemovesOnlyOwnedRules_ThenForgetsApplication()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);

        await h.Policies.RemoveApplicationAsync(new ApplicationIdRequest { Id = id }, Harness.Admin, h.Token);

        Assert.Empty(h.Firewall.Rules);
        Assert.Null(await h.Store.GetApplicationAsync(id));
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.ApplicationRemoved && e.Outcome == AuditOutcome.Success);
    }

    [Fact]
    public async Task Remove_WhenRuleRemovalFails_KeepsApplicationSoRulesStayTracked()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);
        h.Firewall.FailRemove = true;

        await Assert.ThrowsAsync<NetGuardException>(() => h.Policies.RemoveApplicationAsync(new ApplicationIdRequest { Id = id }, Harness.Admin, h.Token));

        Assert.NotNull(await h.Store.GetApplicationAsync(id));
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task Restore_RemovesNetGuardRulesAndDisablesManagement()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);

        var status = await h.Policies.RestoreApplicationAsync(new ApplicationIdRequest { Id = id }, Harness.Admin, h.Token);

        Assert.Equal(EnforcementState.Disabled, status!.State);
        Assert.Equal(0, h.OwnedRulesFor(Harness.AppPath));
        Assert.False((await h.Store.GetApplicationAsync(id))!.IsEnabled);
    }

    [Fact]
    public async Task TemporaryException_SuspendsThenReappliesOnExpiry()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);

        await h.Policies.GrantTemporaryExceptionAsync(new TemporaryExceptionRequest { Id = id, DurationMinutes = 30, Reason = "license check" }, Harness.Operator, h.Token);
        Assert.Equal(0, h.OwnedRulesFor(Harness.AppPath));
        Assert.Equal(EnforcementState.Suspended, (await h.StatusAsync(id)).State);

        h.Clock.Advance(TimeSpan.FromMinutes(31));
        await h.ReconcileAsync(Core.Enforcement.ReconcileTrigger.ExceptionExpiry);

        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
        Assert.Equal(EnforcementState.Enforced, (await h.StatusAsync(id)).State);
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.TemporaryExceptionEnded);
    }

    [Fact]
    public async Task TemporaryException_RequiresReasonAndBoundedDuration()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath);

        await Assert.ThrowsAsync<DomainValidationException>(() =>
            h.Policies.GrantTemporaryExceptionAsync(new TemporaryExceptionRequest { Id = id, DurationMinutes = 30, Reason = "" }, Harness.Admin, h.Token));
        await Assert.ThrowsAsync<DomainValidationException>(() =>
            h.Policies.GrantTemporaryExceptionAsync(new TemporaryExceptionRequest { Id = id, DurationMinutes = 100_000, Reason = "x" }, Harness.Admin, h.Token));
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task EnablingProfile_AppliesItsPolicyToMembers()
    {
        await using var h = await Harness.StartAsync();
        var offline = (await h.Store.GetProfilesAsync()).Single(p => p.Name == "Offline Work");
        var id = await h.Policies.AddApplicationAsync(new AddApplicationRequest
        {
            ExecutablePaths = [Harness.AppPath], Policy = ApplicationPolicy.AllowAll, ProfileId = offline.Id,
        }, Harness.Admin, h.Token);
        Assert.Equal(0, h.OwnedRulesFor(Harness.AppPath));

        await h.Policies.SetProfileEnabledAsync(new SetProfileEnabledRequest { Id = offline.Id, Enabled = true }, Harness.Admin, h.Token);
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));

        await h.Policies.SetProfileEnabledAsync(new SetProfileEnabledRequest { Id = offline.Id, Enabled = false }, Harness.Admin, h.Token);
        Assert.Equal(0, h.OwnedRulesFor(Harness.AppPath));
        Assert.Equal(EnforcementState.NotRequired, (await h.StatusAsync(id)).State);
    }

    [Fact]
    public async Task BuiltInProfiles_CannotBeDeleted()
    {
        await using var h = await Harness.StartAsync();
        var builtIn = (await h.Store.GetProfilesAsync()).First(p => p.IsBuiltIn);
        await Assert.ThrowsAsync<DomainValidationException>(() => h.Policies.DeleteProfileAsync(builtIn.Id, Harness.Admin, h.Token));
    }

    [Fact]
    public async Task EveryPrivilegedChange_IsAudited_WithActor()
    {
        await using var h = await Harness.StartAsync();
        var id = await h.AddAsync(Harness.AppPath, actor: Harness.Operator);
        await h.Policies.SetEnabledAsync(new SetEnabledRequest { Id = id, Enabled = false }, Harness.Operator, h.Token);

        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.ApplicationAdded && e.Actor == Harness.Operator.Name);
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.PolicyChanged && e.Actor == Harness.Operator.Name);
    }
}

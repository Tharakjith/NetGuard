using System.Text.Json.Nodes;
using NetGuard.Contracts;
using NetGuard.Core.Configuration;
using NetGuard.Domain;
using Xunit;

namespace NetGuard.Tests.Unit;

public sealed class ConfigurationTests
{
    [Fact]
    public async Task ExportThenImport_RoundTripsWithoutRuleChurn()
    {
        await using var h = await Harness.StartAsync();
        await h.AddAsync(Harness.AppPath);
        var export = await h.Porter.ExportAsync(new ConfigurationExportRequest(), Harness.Admin, h.Token);
        var mutations = h.Firewall.MutationCount;

        var preview = await h.Porter.ImportAsync(export.Content, ImportMode.Merge, dryRun: true, PolicySource.User, Harness.Admin, h.Token);
        Assert.Empty(preview.Errors);
        Assert.Single(preview.UpdatedApplications);
        Assert.False(preview.Applied);

        var applied = await h.Porter.ImportAsync(export.Content, ImportMode.Merge, dryRun: false, PolicySource.User, Harness.Admin, h.Token);
        Assert.True(applied.Applied);
        Assert.Equal(mutations, h.Firewall.MutationCount);
        Assert.Equal(1, h.Store.BackupCount);
    }

    [Fact]
    public async Task Import_IntoFreshInstall_CreatesAndEnforces()
    {
        await using var source = await Harness.StartAsync();
        await source.AddAsync(Harness.AppPath);
        var export = await source.Porter.ExportAsync(new ConfigurationExportRequest(), Harness.Admin, source.Token);

        await using var target = await Harness.StartAsync();
        var result = await target.Porter.ImportAsync(export.Content, ImportMode.Merge, false, PolicySource.User, Harness.Admin, target.Token);

        Assert.True(result.Applied, string.Join("; ", result.Errors));
        Assert.Equal(1, target.OwnedRulesFor(Harness.AppPath));
    }

    [Fact]
    public async Task ReplaceMode_RemovesUnlistedApplications_AndTheirRules()
    {
        await using var h = await Harness.StartAsync();
        await h.AddAsync(Harness.AppPath);
        var empty = """{"schemaVersion":1,"applications":[],"profiles":[]}""";

        var result = await h.Porter.ImportAsync(empty, ImportMode.Replace, false, PolicySource.User, Harness.Admin, h.Token);

        Assert.True(result.Applied);
        Assert.Single(result.RemovedApplications);
        Assert.Empty(h.Firewall.Rules);
    }

    [Theory]
    [InlineData("""{"applications":[]}""", "schemaVersion")]
    [InlineData("""{"schemaVersion":99,"applications":[]}""", "newer")]
    [InlineData("""{"schemaVersion":1,"applications":[],"unexpected":true}""", "Schema validation failed")]
    [InlineData("""{"schemaVersion":1,"applications":[{"displayName":"x","policy":{"mode":"Block"},"executables":[{"path":"relative.exe"}]}]}""", "applications[0].executables[0].path")]
    [InlineData("""{"schemaVersion":1,"applications":[{"displayName":"x","policy":{"mode":1},"executables":[]}]}""", "Schema validation failed")]
    [InlineData("""{"schemaVersion":1,"applications":[{"displayName":"x","policy":{"mode":"Custom"},"executables":[{"path":"C:\\A\\a.exe"}]}]}""", "allow-list")]
    [InlineData("not json", "Invalid JSON")]
    public async Task InvalidDocuments_AreRejected_AndNothingChanges(string json, string expected)
    {
        await using var h = await Harness.StartAsync();
        var result = await h.Porter.ImportAsync(json, ImportMode.Replace, false, PolicySource.User, Harness.Admin, h.Token);

        Assert.False(result.Applied);
        Assert.Contains(result.Errors, e => e.Contains(expected, StringComparison.OrdinalIgnoreCase));
        Assert.Equal(0, h.Store.BackupCount);
        Assert.Contains(h.Store.Audit, e => e.Type == AuditEventType.ConfigurationImported && e.Outcome == AuditOutcome.Failure);
    }

    [Fact]
    public async Task UserImport_DoesNotOverrideOrganizationPolicy()
    {
        await using var h = await Harness.StartAsync();
        var org = $$"""
            {"schemaVersion":1,"scope":"organization","applications":[{"displayName":"Contoso","policy":{"mode":"Block"},"executables":[{"path":"{{Harness.AppPath.Replace("\\", "\\\\")}}"}]}]}
            """;
        Assert.True((await h.Porter.ImportAsync(org, ImportMode.Replace, false, PolicySource.Organization, Harness.Admin, h.Token)).Applied);

        var user = $$"""
            {"schemaVersion":1,"applications":[{"displayName":"Contoso","policy":{"mode":"Allow"},"executables":[{"path":"{{Harness.AppPath.Replace("\\", "\\\\")}}"}]}]}
            """;
        var result = await h.Porter.ImportAsync(user, ImportMode.Replace, false, PolicySource.User, Harness.Admin, h.Token);

        Assert.Contains(result.Warnings, w => w.Contains("organization-managed"));
        Assert.Equal(1, h.OwnedRulesFor(Harness.AppPath));
        Assert.Equal(PolicySource.Organization, (await h.Store.GetApplicationsAsync()).Single().Source);
    }

    [Fact]
    public void ExportedDocument_DeclaresSchemaAndVersion()
    {
        var errors = new List<string>();
        var document = ConfigurationPorter.Parse("""{"schemaVersion":1,"$schema":"x","applications":[]}""", errors, []);
        Assert.NotNull(document);
        Assert.Empty(errors);
        Assert.Equal(PolicyDocument.CurrentSchemaVersion, document!.SchemaVersion);
    }

    [Fact]
    public void SchemaFile_MatchesCurrentVersion()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "netguard-policy.v1.schema.json");
        var schema = JsonNode.Parse(File.ReadAllText(path))!;
        Assert.Equal(PolicyDocument.CurrentSchemaVersion, (int)schema["properties"]!["schemaVersion"]!["const"]!);
        Assert.Equal(PolicyDocument.SchemaId, (string)schema["$id"]!);
    }
}

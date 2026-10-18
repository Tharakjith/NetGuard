using System.Reflection;
using System.Text;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core.Auditing;
using NetGuard.Core.Diagnostics;
using NetGuard.Core.Events;
using NetGuard.Core.Security;
using NetGuard.Domain;
using NetGuard.Ipc;
using NetGuard.Logging;
using NetGuard.Tests.Unit.Fakes;
using Xunit;

namespace NetGuard.Tests.Unit;

public sealed class AuthorizationTests
{
    [Fact]
    public void EveryCommand_HasExactlyOnePermission()
    {
        var commands = typeof(Commands).GetFields(BindingFlags.Public | BindingFlags.Static).Select(f => (string)f.GetValue(null)!).ToList();
        Assert.All(commands, c => Assert.True(CommandPermissions.TryGet(c, out _), $"{c} has no permission mapping"));
        Assert.Equal(commands.Count, CommandPermissions.All.Count);
    }

    [Theory]
    [InlineData(Commands.AddApplication, Permission.Modify)]
    [InlineData(Commands.RemoveApplication, Permission.Modify)]
    [InlineData(Commands.GrantTemporaryException, Permission.Modify)]
    [InlineData(Commands.ImportConfiguration, Permission.Administer)]
    [InlineData(Commands.UpdateSettings, Permission.Administer)]
    [InlineData(Commands.CleanupOrphanedRules, Permission.Administer)]
    [InlineData(Commands.QueryAudit, Permission.Read)]
    public void SensitiveCommands_RequireTheRightPermission(string command, Permission expected)
    {
        Assert.True(CommandPermissions.TryGet(command, out var permission));
        Assert.Equal(expected, permission);
    }

    [Fact]
    public void PermissionMatrix()
    {
        var settings = new ServiceSettings();
        Assert.True(Harness.Reader.Has(Permission.Read, settings));
        Assert.False(Harness.Reader.Has(Permission.Modify, settings));
        Assert.False(Harness.Reader.Has(Permission.Read, settings with { AllowStandardUserRead = false }));
        Assert.True(Harness.Operator.Has(Permission.Modify, settings));
        Assert.False(Harness.Operator.Has(Permission.Administer, settings));
        Assert.True(Harness.Admin.Has(Permission.Administer, settings));

        // A non-elevated administrator token has Administrators as deny-only; it is presented as a plain user.
        var unelevatedAdmin = new ActorContext { Name = "admin", IsElevatedAdministrator = false };
        Assert.False(unelevatedAdmin.Has(Permission.Modify, settings));
    }

    [Fact]
    public void UnknownCommands_AreNotMapped() => Assert.False(CommandPermissions.TryGet("DeleteAllRules", out _));
}

public sealed class AuditExportTests
{
    [Theory]
    [InlineData("=cmd|' /C calc'!A0")]
    [InlineData("+SUM(1,2)")]
    [InlineData("-2+3")]
    [InlineData("@SUM(A1)")]
    public void Csv_NeutralizesFormulaInjection(string value) => Assert.StartsWith("\"'", AuditExporter.Field(value));

    [Fact]
    public void Csv_EscapesQuotesAndKeepsOneRecordPerLine()
    {
        var csv = AuditExporter.ToCsv([new AuditEvent { Message = "say \"hi\"\nnext", Actor = "a,b", Timestamp = DateTimeOffset.UnixEpoch }]);
        Assert.Contains("\"say \"\"hi\"\"\nnext\"", csv);
        Assert.Contains("\"a,b\"", csv);
    }
}

public sealed class RedactionTests
{
    [Fact]
    public void Redacts_UserProfilesAccountsAndComputerName()
    {
        var redactor = new Redactor(true, "WORKSTATION7");
        Assert.Equal(@"C:\Users\<user>\AppData\x.exe", redactor.Text(@"C:\Users\alice\AppData\x.exe"));
        Assert.Equal("on <computer>", redactor.Text("on WORKSTATION7"));
        Assert.Equal("<account-1>", redactor.Account(@"CONTOSO\alice"));
        Assert.Equal("<account-1>", redactor.Account(@"CONTOSO\alice"));
        Assert.Equal("<account-2>", redactor.Account(@"CONTOSO\bob"));
        Assert.Equal("system", redactor.Account("system"));
    }
}

public sealed class EventBrokerTests
{
    [Fact]
    public async Task LongPoll_ReturnsWhenEventArrives()
    {
        var broker = new EventBroker(new FakeClock());
        var wait = broker.WaitAsync(0, TimeSpan.FromSeconds(10), default);
        Assert.False(wait.IsCompleted);

        broker.Notify(NotificationKind.PolicyApplied, "t", "m");
        var batch = await wait.WaitAsync(TimeSpan.FromSeconds(2));

        Assert.Single(batch.Events);
        Assert.Equal(1, batch.LatestSequence);
    }

    [Fact]
    public async Task ClientFromPreviousServiceInstance_GetsGap()
    {
        var broker = new EventBroker(new FakeClock());
        broker.PublishStateChanged();
        var batch = await broker.WaitAsync(500, TimeSpan.Zero, default);
        Assert.True(batch.Gap);
    }

    [Fact]
    public async Task Timeout_ReturnsEmptyBatch()
    {
        var broker = new EventBroker(new FakeClock());
        var batch = await broker.WaitAsync(0, TimeSpan.FromMilliseconds(50), default);
        Assert.Empty(batch.Events);
        Assert.False(batch.Gap);
    }
}

public sealed class FramingTests
{
    [Fact]
    public async Task RoundTrip()
    {
        using var stream = new MemoryStream();
        await MessageFraming.WriteAsync(stream, Encoding.UTF8.GetBytes("{}"), 1024, default);
        stream.Position = 0;
        Assert.Equal("{}", Encoding.UTF8.GetString((await MessageFraming.ReadAsync(stream, 1024, default))!));
        Assert.Null(await MessageFraming.ReadAsync(stream, 1024, default));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(5000)]
    public async Task RejectsInvalidDeclaredLengths(int length)
    {
        using var stream = new MemoryStream(BitConverter.GetBytes(length).Concat(new byte[16]).ToArray());
        await Assert.ThrowsAsync<InvalidDataException>(() => MessageFraming.ReadAsync(stream, 1024, default));
    }

    [Fact]
    public async Task RejectsTruncatedMessages()
    {
        using var stream = new MemoryStream(BitConverter.GetBytes(100).Concat(new byte[10]).ToArray());
        await Assert.ThrowsAsync<EndOfStreamException>(() => MessageFraming.ReadAsync(stream, 1024, default));
    }
}

public sealed class JsonFileLoggerTests
{
    [Fact]
    public void WritesStructuredJsonLines()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ng-log-" + Guid.NewGuid().ToString("N"));
        using (var provider = new JsonFileLoggerProvider(new JsonFileLoggerOptions { Directory = dir, FilePrefix = "t" }))
        {
            provider.CreateLogger("Cat").LogWarning("Blocked {Path} for {Count} rule(s)", @"C:\a.exe", 2);
        }

        var line = File.ReadAllLines(Directory.GetFiles(dir).Single()).Single();
        var json = System.Text.Json.Nodes.JsonNode.Parse(line)!;
        Assert.Equal("Warning", (string)json["level"]!);
        Assert.Equal(@"C:\a.exe", (string)json["path"]!);
        Assert.Equal(2, (int)json["count"]!);
        Directory.Delete(dir, true);
    }
}

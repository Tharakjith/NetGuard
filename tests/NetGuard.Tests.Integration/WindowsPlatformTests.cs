using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;
using NetGuard.Platform.Windows.Discovery;
using NetGuard.Platform.Windows.Files;
using NetGuard.Platform.Windows.Processes;
using Xunit;

namespace NetGuard.Tests.Integration;

public sealed class ExecutableInspectorTests
{
    private readonly ExecutableInspector _inspector = new();

    private static string DotnetPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");

    [Fact]
    public void SignedExecutable_HasValidSignatureHashAndCanonicalPath()
    {
        var inspection = _inspector.Inspect(DotnetPath);

        Assert.Equal(SignatureStatus.Valid, inspection.SignatureStatus);
        Assert.Contains("Microsoft", inspection.SignerSubject);
        Assert.Equal(64, inspection.Sha256!.Length);
        Assert.Equal(DotnetPath, inspection.CanonicalPath, ignoreCase: true);
    }

    [Fact]
    public void ShortAndRelativeForms_ResolveToTheSameCanonicalPath()
    {
        var shortPath = GetShortPath(DotnetPath);
        Assert.Equal(DotnetPath, _inspector.TryCanonicalize(shortPath), ignoreCase: true);

        var dotted = Path.Combine(Path.GetDirectoryName(DotnetPath)!, "..", "dotnet", "dotnet.exe");
        Assert.Equal(DotnetPath, _inspector.TryCanonicalize(dotted), ignoreCase: true);
    }

    [Fact]
    public void UnsignedFile_IsReportedAsNotSigned()
    {
        var copy = Path.Combine(Path.GetTempPath(), $"ng-unsigned-{Guid.NewGuid():N}.exe");
        var bytes = File.ReadAllBytes(DotnetPath);
        File.WriteAllBytes(copy, bytes.Take(bytes.Length / 2).ToArray()); // truncated: still MZ, signature gone or broken
        try
        {
            var inspection = _inspector.Inspect(copy);
            Assert.NotEqual(SignatureStatus.Valid, inspection.SignatureStatus);
        }
        finally
        {
            File.Delete(copy);
        }
    }

    [Fact]
    public void NonExecutable_IsRejected()
    {
        var text = Path.Combine(Path.GetTempPath(), $"ng-{Guid.NewGuid():N}.exe");
        File.WriteAllText(text, "this is not a program, just text padded to more than sixty-four bytes in length.");
        try
        {
            Assert.Throws<ExecutableInspectionException>(() => _inspector.Inspect(text));
        }
        finally
        {
            File.Delete(text);
        }
    }

    [Fact]
    public void MissingFile_GivesActionableError()
    {
        var ex = Assert.Throws<ExecutableInspectionException>(() => _inspector.Inspect(@"C:\Definitely\Not\Here.exe"));
        Assert.Contains("not found", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static string GetShortPath(string path)
    {
        var builder = new System.Text.StringBuilder(1024);
        return GetShortPathName(path, builder, builder.Capacity) > 0 ? builder.ToString() : path;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern uint GetShortPathName(string longPath, System.Text.StringBuilder shortPath, int bufferSize);
}

public sealed class DiscoveryTests
{
    [Fact]
    public void Discover_FindsInstalledAndRunningApplications()
    {
        var discovery = new WindowsApplicationDiscovery(NullLogger<WindowsApplicationDiscovery>.Instance);
        var result = discovery.Discover(new DiscoveryRequest { IncludeRunningProcesses = true }, new Dictionary<string, Guid>());

        Assert.NotEmpty(result);
        Assert.Contains(result, r => r.IsRunning);
        Assert.All(result, r => Assert.NotEmpty(r.Executables));
        Assert.DoesNotContain(result, r => r.IsSystemComponent);
    }

    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\",0", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Program Files\App\app.exe,1", @"C:\Program Files\App\app.exe")]
    [InlineData(@"C:\Program Files\App\app.ico", null)]
    [InlineData("", null)]
    public void ParsesDisplayIconValues(string value, string? expected) =>
        Assert.Equal(expected, WindowsApplicationDiscovery.ParseIconPath(value));
}

public sealed class ProcessMonitorTests
{
    [Fact]
    public async Task ObservesLaunchAndExit_WithCanonicalImagePath()
    {
        using var monitor = new WmiProcessMonitor(NullLogger<WmiProcessMonitor>.Instance);
        var started = new TaskCompletionSource<ObservedProcess>(TaskCreationOptions.RunContinuationsAsynchronously);
        var exited = new TaskCompletionSource<ObservedProcess>(TaskCreationOptions.RunContinuationsAsynchronously);
        var marker = Path.Combine(Environment.SystemDirectory, "PING.EXE");
        monitor.ProcessStarted += (_, p) =>
        {
            if (string.Equals(p.ImagePath, marker, StringComparison.OrdinalIgnoreCase) && monitor.TrackExit(p))
            {
                started.TrySetResult(p);
            }
        };
        monitor.ProcessExited += (_, p) => exited.TrySetResult(p);
        monitor.Start();

        // A new ETW session needs ~2 s before it starts delivering (events in that window arrive late, not lost).
        // The service starts monitoring at boot, so measure steady-state latency: warm up with a throwaway process.
        var warmUp = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        monitor.ProcessStarted += (_, p) =>
        {
            if (string.Equals(p.ImagePath, cmd, StringComparison.OrdinalIgnoreCase))
            {
                warmUp.TrySetResult();
            }
        };
        using (Process.Start(new ProcessStartInfo(cmd, "/c choice /t 4 /d y >nul") { CreateNoWindow = true, UseShellExecute = false }))
        {
            await warmUp.Task.WaitAsync(TimeSpan.FromSeconds(15));
        }

        using var process = Process.Start(new ProcessStartInfo(marker, "-n 6 127.0.0.1") { CreateNoWindow = true, UseShellExecute = false })!;
        var clock = Stopwatch.StartNew();
        var observed = await started.Task.WaitAsync(TimeSpan.FromSeconds(15));
        Assert.Equal(process.Id, observed.ProcessId);

        // Elevated runs use the ETW kernel session, which must be immediate rather than polling-bound.
        if (monitor.MonitoringMode.StartsWith("Kernel process events via ETW (", StringComparison.Ordinal))
        {
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"ETW detection took {clock.ElapsedMilliseconds} ms. Mode: {monitor.MonitoringMode}");
        }

        var gone = await exited.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Equal(observed, gone);
    }

    [Fact]
    public void Snapshot_IncludesCurrentProcess()
    {
        using var monitor = new WmiProcessMonitor(NullLogger<WmiProcessMonitor>.Instance);
        Assert.Contains(monitor.Snapshot(), p => p.ProcessId == Environment.ProcessId);
    }
}

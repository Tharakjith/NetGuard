using NetGuard.Contracts;
using NetGuard.Domain;

namespace NetGuard.Core.Abstractions;

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}

public sealed record ExecutableInspection
{
    public required string RequestedPath { get; init; }

    public required string CanonicalPath { get; init; }

    public bool Exists { get; init; }

    public long FileSize { get; init; }

    public DateTimeOffset LastWriteUtc { get; init; }

    public string? Sha256 { get; init; }

    public string? FileVersion { get; init; }

    public string? ProductName { get; init; }

    public string? FileDescription { get; init; }

    public string? CompanyName { get; init; }

    public string? OriginalFileName { get; init; }

    public SignatureStatus SignatureStatus { get; init; }

    public string? SignerSubject { get; init; }

    public string? SignerThumbprint { get; init; }
}

public sealed class ExecutableInspectionException : Exception
{
    public ExecutableInspectionException(string message, Exception? inner = null)
        : base(message, inner)
    {
    }
}

/// <summary>Resolves canonical paths and file identity (hash, version resource, Authenticode signature).</summary>
public interface IExecutableInspector
{
    string WindowsDirectory { get; }

    /// <summary>Install directory of NetGuard itself (protected), or null when unknown.</summary>
    string? ProductDirectory { get; }

    /// <summary>
    /// Opens the file (denying writers while it is read), resolves its final path from the open handle and reads
    /// identity information. Throws <see cref="ExecutableInspectionException"/> with an actionable message.
    /// </summary>
    ExecutableInspection Inspect(string path, bool includeHashAndSignature = true);

    /// <summary>Returns the canonical path, or null if the file cannot be opened.</summary>
    string? TryCanonicalize(string path);
}

public sealed record ObservedProcess(int ProcessId, int ParentProcessId, string ImagePath, DateTimeOffset StartTime);

/// <summary>Event-driven process start notifications plus exit notification for processes explicitly tracked.</summary>
public interface IProcessMonitor : IDisposable
{
    event EventHandler<ObservedProcess>? ProcessStarted;

    event EventHandler<ObservedProcess>? ProcessExited;

    /// <summary>Description of the mechanism in use, shown in diagnostics.</summary>
    string MonitoringMode { get; }

    void Start();

    /// <summary>One-time enumeration of processes currently running (used at startup and after policy changes).</summary>
    IReadOnlyList<ObservedProcess> Snapshot();

    /// <summary>Raises <see cref="ProcessExited"/> when the process exits. Returns false if it already exited.</summary>
    bool TrackExit(ObservedProcess process);
}

public interface IApplicationDiscovery
{
    IReadOnlyList<DiscoveredApplicationDto> Discover(DiscoveryRequest request, IReadOnlyDictionary<string, Guid> managedPaths);

    /// <summary>Lists executables inside an application's directory (bounded depth and count).</summary>
    IReadOnlyList<RelatedExecutableDto> ScanDirectory(string directory, IReadOnlyDictionary<string, Guid> managedPaths);
}

/// <summary>Observes connections blocked by the Windows Filtering Platform (Security event 5157) when auditing is enabled.</summary>
public interface IBlockedConnectionSource : IDisposable
{
    bool IsAvailable { get; }

    string Status { get; }

    event EventHandler<BlockedConnection>? ConnectionBlocked;

    void Start();
}

public sealed record BlockedConnection(DateTimeOffset Timestamp, string ApplicationPath, string RemoteAddress, int RemotePort, int Protocol, int ProcessId);

/// <summary>Raises <see cref="Changed"/> when firewall rules are changed by anyone (used to detect drift quickly).</summary>
public interface IFirewallChangeSource : IDisposable
{
    event EventHandler? Changed;

    void Start();
}

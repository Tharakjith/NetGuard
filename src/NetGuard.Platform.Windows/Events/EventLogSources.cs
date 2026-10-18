using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using NetGuard.Core.Abstractions;
using NetGuard.Platform.Windows.Native;

namespace NetGuard.Platform.Windows.Events;

/// <summary>
/// Subscribes to the Windows Firewall operational log, which records every rule addition, change and deletion. Used
/// to detect drift (someone deleting or editing a NetGuard rule) within seconds instead of waiting for the periodic
/// integrity check. Event-driven; no polling.
/// </summary>
public sealed class FirewallChangeWatcher : IFirewallChangeSource
{
    private const string Channel = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall";

    private readonly ILogger<FirewallChangeWatcher> _logger;
    private EventLogWatcher? _watcher;

    public FirewallChangeWatcher(ILogger<FirewallChangeWatcher> logger) => _logger = logger;

    public event EventHandler? Changed;

    public void Start()
    {
        try
        {
            _watcher = new EventLogWatcher(new EventLogQuery(Channel, PathType.LogName));
            _watcher.EventRecordWritten += (_, e) =>
            {
                e.EventRecord?.Dispose();
                Changed?.Invoke(this, EventArgs.Empty);
            };
            _watcher.Enabled = true;
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Firewall change notifications are unavailable; drift is detected by the periodic integrity check only");
            _watcher?.Dispose();
            _watcher = null;
        }
    }

    public void Dispose() => _watcher?.Dispose();
}

/// <summary>
/// Observes connections blocked by the Windows Filtering Platform (Security log event 5157). This is the only
/// reliable, supported signal that an application attempted a connection that was blocked. It is available only when
/// the "Filtering Platform Connection" failure audit policy is enabled; NetGuard never changes audit policy itself.
/// </summary>
public sealed class BlockedConnectionMonitor : IBlockedConnectionSource
{
    private const string OutboundDirection = "%%14593";

    private readonly ILogger<BlockedConnectionMonitor> _logger;
    private readonly DevicePathConverter _paths = new();
    private EventLogWatcher? _watcher;

    public BlockedConnectionMonitor(ILogger<BlockedConnectionMonitor> logger) => _logger = logger;

    public event EventHandler<BlockedConnection>? ConnectionBlocked;

    public bool IsAvailable => _watcher is not null;

    public string Status { get; private set; } = "Not started";

    public void Start()
    {
        if (!IsAuditPolicyEnabled())
        {
            Status = "Unavailable: the \"Filtering Platform Connection\" failure audit policy is not enabled (see docs/LIMITATIONS.md).";
            return;
        }

        try
        {
            _watcher = new EventLogWatcher(new EventLogQuery("Security", PathType.LogName, "*[System[(EventID=5157)]]"));
            _watcher.EventRecordWritten += OnEvent;
            _watcher.Enabled = true;
            Status = "Active (Security event 5157)";
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Cannot subscribe to blocked-connection audit events");
            Status = "Unavailable: the Security event log could not be read.";
            _watcher?.Dispose();
            _watcher = null;
        }
    }

    public void Dispose() => _watcher?.Dispose();

    private void OnEvent(object? sender, EventRecordWrittenEventArgs e)
    {
        using var record = e.EventRecord;
        if (record is null || record.Properties.Count < 8)
        {
            return;
        }

        try
        {
            var direction = record.Properties[2].Value?.ToString();
            if (!string.Equals(direction, OutboundDirection, StringComparison.Ordinal))
            {
                return;
            }

            var devicePath = record.Properties[1].Value?.ToString() ?? string.Empty;
            var path = _paths.ToDosPath(devicePath);
            if (path is null)
            {
                return;
            }

            ConnectionBlocked?.Invoke(this, new BlockedConnection(
                record.TimeCreated is { } time ? new DateTimeOffset(time.ToUniversalTime(), TimeSpan.Zero) : DateTimeOffset.UtcNow,
                path,
                record.Properties[5].Value?.ToString() ?? string.Empty,
                Convert.ToInt32(record.Properties[6].Value, System.Globalization.CultureInfo.InvariantCulture),
                Convert.ToInt32(record.Properties[7].Value, System.Globalization.CultureInfo.InvariantCulture),
                Convert.ToInt32(record.Properties[0].Value, System.Globalization.CultureInfo.InvariantCulture)));
        }
        catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException)
        {
            _logger.LogDebug(ex, "Ignoring malformed 5157 event");
        }
    }

    private static bool IsAuditPolicyEnabled()
    {
        try
        {
            if (!NativeMethods.AuditQuerySystemPolicy([NativeMethods.AuditFilteringPlatformConnection], 1, out var buffer) || buffer == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                var info = Marshal.PtrToStructure<NativeMethods.AuditPolicyInformation>(buffer);
                return (info.AuditingInformation & NativeMethods.PolicyAuditEventFailure) != 0;
            }
            finally
            {
                NativeMethods.AuditFree(buffer);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }
}

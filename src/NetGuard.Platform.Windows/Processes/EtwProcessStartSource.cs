using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

namespace NetGuard.Platform.Windows.Processes;

/// <summary>
/// Real-time ETW session on the Microsoft-Windows-Kernel-Process provider (process start events). Event-driven with
/// negligible idle cost. Requires administrative rights (the LocalSystem service has them).
/// </summary>
internal sealed class EtwProcessStartSource : IDisposable
{
    private const string SessionName = "NetGuardEnterprise-ProcessMonitor";
    private const string ProviderName = "Microsoft-Windows-Kernel-Process";
    private const ulong ProcessKeyword = 0x10; // WINEVENT_KEYWORD_PROCESS
    private const int ProcessStartEventId = 1;

    /// <summary>
    /// Real-time ETW buffers are otherwise delivered by the default flush timer (~2 s on Windows 11). An explicit
    /// flush is a single cheap kernel call that pushes already-captured events; it does not poll the process list.
    /// </summary>
    private static readonly TimeSpan FlushInterval = TimeSpan.FromMilliseconds(500);

    private TraceEventSession? _session;
    private Thread? _thread;
    private Timer? _flushTimer;
    private long _events;

    public long EventCount => Interlocked.Read(ref _events);

    public bool IsRunning => _session is not null;

    /// <summary>Starts the session. Returns false (with a reason) if ETW is unavailable, for example without elevation.</summary>
    public bool TryStart(Action<int, int> onProcessStart, out string? error)
    {
        error = null;
        try
        {
            if (TraceEventSession.IsElevated() != true)
            {
                error = "requires administrative rights";
                return false;
            }

            // A session left by a crashed instance has the same name; creating it again replaces it.
            _session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session.EnableProvider(ProviderName, TraceEventLevel.Informational, ProcessKeyword);
            _session.Source.Dynamic.All += e =>
            {
                if ((int)e.ID != ProcessStartEventId)
                {
                    return;
                }

                Interlocked.Increment(ref _events);
                try
                {
                    var pid = Convert.ToInt32(e.PayloadByName("ProcessID"), System.Globalization.CultureInfo.InvariantCulture);
                    var parent = Convert.ToInt32(e.PayloadByName("ParentProcessID"), System.Globalization.CultureInfo.InvariantCulture);
                    onProcessStart(pid, parent);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    // An exception here would end the ETW processing loop; one bad event must not stop monitoring.
                }
            };

            _thread = new Thread(() =>
            {
                try
                {
                    _session.Source.Process();
                }
                catch (Exception) when (_session is null)
                {
                    // Disposed while processing.
                }
            })
            {
                IsBackground = true,
                Name = "NetGuard ETW process events",
            };
            _thread.Start();
            _flushTimer = new Timer(_ => FlushQuietly(), null, FlushInterval, FlushInterval);
            return true;
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Runtime.InteropServices.COMException or InvalidOperationException or ArgumentException)
        {
            error = ex.Message.Trim();
            Dispose();
            return false;
        }
    }

    public void Dispose()
    {
        _flushTimer?.Dispose();
        _flushTimer = null;
        var session = _session;
        _session = null;
        session?.Dispose();
    }

    private void FlushQuietly()
    {
        try
        {
            _session?.Flush();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Flushing only reduces latency; events are still delivered by the default timer if it fails.
        }
    }
}

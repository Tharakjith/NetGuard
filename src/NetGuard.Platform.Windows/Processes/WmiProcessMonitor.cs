using System.Collections.Concurrent;
using System.Diagnostics;
using System.Management;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;
using NetGuard.Core.Abstractions;
using NetGuard.Platform.Windows.Native;

namespace NetGuard.Platform.Windows.Processes;

/// <summary>
/// Process monitoring from two independent sources, de-duplicated by (PID, start time):
/// <list type="bullet">
/// <item>Real-time ETW session on Microsoft-Windows-Kernel-Process: event-driven and immediate; requires
/// administrative rights (the LocalSystem service has them).</item>
/// <item>WMI instance-creation events as a safety net: WMI polls the process table every 5 seconds while ETW is
/// active, or every second when ETW is unavailable (for example a non-elevated diagnostic run).</item>
/// </list>
/// The WMI wrapper <c>Win32_ProcessStartTrace</c> is deliberately not used: on current Windows 11 builds it accepts a
/// subscription but delivers no events, which would silently disable launch detection. Diagnostics reports how many
/// events each source delivered. Exit is detected by waiting on a process handle, which also guards against PID reuse
/// because the handle pins the original process object.
/// </summary>
public sealed class WmiProcessMonitor : IProcessMonitor
{
    private static readonly TimeSpan DuplicateWindow = TimeSpan.FromMinutes(2);

    private readonly ILogger<WmiProcessMonitor> _logger;
    private readonly ConcurrentDictionary<(int Pid, DateTimeOffset Start), ExitWatch> _exitWatches = new();
    private readonly ConcurrentDictionary<(int Pid, DateTimeOffset Start), DateTime> _seen = new();
    private readonly EtwProcessStartSource _etw = new();
    private ManagementEventWatcher? _instanceWatcher;
    private string? _etwError;
    private int _pollSeconds;
    private bool _started;
    private long _instanceEvents;

    public WmiProcessMonitor(ILogger<WmiProcessMonitor> logger) => _logger = logger;

    public event EventHandler<ObservedProcess>? ProcessStarted;

    public event EventHandler<ObservedProcess>? ProcessExited;

    public string MonitoringMode
    {
        get
        {
            if (!_started)
            {
                return "Not started";
            }

            var etw = _etw.IsRunning
                ? $"Kernel process events via ETW ({_etw.EventCount} received)"
                : $"Kernel process events via ETW unavailable ({_etwError ?? "not started"}; run the service as LocalSystem)";
            var instance = _instanceWatcher is not null
                ? $"WMI instance-creation events as backup, {_pollSeconds}-second polling ({Interlocked.Read(ref _instanceEvents)} received)"
                : "WMI instance-creation backup unavailable";
            return $"{etw}; {instance}";
        }
    }

    public void Start()
    {
        if (_started)
        {
            return;
        }

        _started = true;
        if (_etw.TryStart(Raise, out _etwError))
        {
            _logger.LogInformation("Process monitoring: ETW kernel process session started");
        }
        else
        {
            _logger.LogWarning("ETW kernel process events unavailable ({Reason}); relying on WMI instance-creation events", _etwError);
        }

        _pollSeconds = _etw.IsRunning ? 5 : 1;
        try
        {
            _instanceWatcher = new ManagementEventWatcher(new EventQuery(
                $"SELECT * FROM __InstanceCreationEvent WITHIN {_pollSeconds} WHERE TargetInstance ISA 'Win32_Process'"));
            _instanceWatcher.EventArrived += OnInstanceEvent;
            _instanceWatcher.Start();
            _logger.LogInformation("Process monitoring: WMI instance-creation backup started ({Seconds}-second polling)", _pollSeconds);
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            _logger.LogError(ex, "WMI instance-creation events unavailable");
            _instanceWatcher?.Dispose();
            _instanceWatcher = null;
            if (!_etw.IsRunning)
            {
                throw;
            }
        }
    }

    public IReadOnlyList<ObservedProcess> Snapshot()
    {
        var result = new List<ObservedProcess>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id is 0 or 4)
                {
                    continue;
                }

                var observed = Describe(process.Id, 0);
                if (observed is not null)
                {
                    result.Add(observed);
                }
            }
        }

        return result;
    }

    public bool TrackExit(ObservedProcess process)
    {
        var key = (process.ProcessId, process.StartTime);
        if (_exitWatches.ContainsKey(key))
        {
            return true;
        }

        var handle = ProcessQuery.Open(process.ProcessId, synchronize: true);
        if (handle is null)
        {
            return false;
        }

        // Make sure the PID still refers to the same process instance.
        if (ProcessQuery.GetStartTime(handle) != process.StartTime)
        {
            handle.Dispose();
            return false;
        }

        var watch = new ExitWatch(handle);
        if (!_exitWatches.TryAdd(key, watch))
        {
            watch.Dispose();
            return true;
        }

        watch.Registration = ThreadPool.RegisterWaitForSingleObject(
            watch.WaitHandle,
            (_, _) =>
            {
                if (_exitWatches.TryRemove(key, out var completed))
                {
                    completed.Dispose();
                }

                ProcessExited?.Invoke(this, process);
            },
            null,
            Timeout.Infinite,
            executeOnlyOnce: true);
        return true;
    }

    public void Dispose()
    {
        _etw.Dispose();
        if (_instanceWatcher is not null)
        {
            try
            {
                _instanceWatcher.Stop();
            }
            catch (ManagementException)
            {
            }

            _instanceWatcher.Dispose();
        }

        foreach (var watch in _exitWatches.Values)
        {
            watch.Dispose();
        }

        _exitWatches.Clear();
    }

    private void OnInstanceEvent(object sender, EventArrivedEventArgs e)
    {
        try
        {
            if (e.NewEvent["TargetInstance"] is ManagementBaseObject instance)
            {
                Interlocked.Increment(ref _instanceEvents);
                var pid = Convert.ToInt32(instance["ProcessId"], System.Globalization.CultureInfo.InvariantCulture);
                var parent = Convert.ToInt32(instance["ParentProcessId"], System.Globalization.CultureInfo.InvariantCulture);
                Raise(pid, parent);
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogDebug(ex, "Ignoring malformed process instance event");
        }
    }

    private void Raise(int pid, int parent)
    {
        var observed = Describe(pid, parent);
        if (observed is null)
        {
            return;
        }

        // Both sources report most launches; deliver each process instance exactly once.
        var now = DateTime.UtcNow;
        if (!_seen.TryAdd((observed.ProcessId, observed.StartTime), now))
        {
            return;
        }

        if (_seen.Count > 4096)
        {
            foreach (var stale in _seen.Where(kv => now - kv.Value > DuplicateWindow).Select(kv => kv.Key).ToList())
            {
                _seen.TryRemove(stale, out _);
            }
        }

        ProcessStarted?.Invoke(this, observed);
    }

    private static ObservedProcess? Describe(int pid, int parent)
    {
        using var handle = ProcessQuery.Open(pid, synchronize: false);
        if (handle is null)
        {
            // Exited already, or a protected process we cannot query; neither can be a managed desktop application.
            return null;
        }

        var path = ProcessQuery.GetImagePath(handle);
        var start = ProcessQuery.GetStartTime(handle);
        return path is null || start is null ? null : new ObservedProcess(pid, parent, path, start.Value);
    }

    private sealed class ExitWatch : IDisposable
    {
        private readonly SafeProcessHandle _process;

        public ExitWatch(SafeProcessHandle process)
        {
            _process = process;
            WaitHandle = new ProcessWaitHandle(process);
        }

        public WaitHandle WaitHandle { get; }

        public RegisteredWaitHandle? Registration { get; set; }

        public void Dispose()
        {
            Registration?.Unregister(null);
            WaitHandle.Dispose();
            _process.Dispose();
        }
    }

    private sealed class ProcessWaitHandle : WaitHandle
    {
        public ProcessWaitHandle(SafeProcessHandle process) =>
            SafeWaitHandle = new SafeWaitHandle(process.DangerousGetHandle(), ownsHandle: false);
    }
}

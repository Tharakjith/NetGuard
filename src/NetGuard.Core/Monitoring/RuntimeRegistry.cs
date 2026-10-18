namespace NetGuard.Core.Monitoring;

/// <summary>Thread-safe registry of running instances of managed applications, keyed by (PID, start time) to survive PID reuse.</summary>
public sealed class RuntimeRegistry : IRuntimeState
{
    private readonly object _gate = new();
    private readonly Dictionary<Guid, Dictionary<(int Pid, DateTimeOffset Start), RunningInstance>> _instances = new();
    private readonly Dictionary<Guid, Dictionary<string, string>> _warnings = new();

    public bool Add(Guid applicationId, RunningInstance instance)
    {
        lock (_gate)
        {
            if (!_instances.TryGetValue(applicationId, out var set))
            {
                _instances[applicationId] = set = new();
            }

            return set.TryAdd((instance.ProcessId, instance.StartTime), instance);
        }
    }

    /// <summary>Removes an instance. Returns the owning application and the number of instances still running.</summary>
    public (Guid ApplicationId, int Remaining)? Remove(int processId, DateTimeOffset startTime)
    {
        lock (_gate)
        {
            foreach (var (appId, set) in _instances)
            {
                if (set.Remove((processId, startTime)))
                {
                    return (appId, set.Count);
                }
            }

            return null;
        }
    }

    /// <summary>Finds the managed application that owns a running process, if any.</summary>
    public (Guid ApplicationId, RunningInstance Instance)? FindByProcessId(int processId)
    {
        lock (_gate)
        {
            foreach (var (appId, set) in _instances)
            {
                foreach (var instance in set.Values)
                {
                    if (instance.ProcessId == processId)
                    {
                        return (appId, instance);
                    }
                }
            }

            return null;
        }
    }

    /// <summary>Drops instances whose application or executable is no longer managed.</summary>
    public void Retain(IReadOnlyDictionary<Guid, IReadOnlySet<Guid>> managedExecutablesByApp)
    {
        lock (_gate)
        {
            foreach (var appId in _instances.Keys.ToList())
            {
                if (!managedExecutablesByApp.TryGetValue(appId, out var executables))
                {
                    _instances.Remove(appId);
                    _warnings.Remove(appId);
                    continue;
                }

                var set = _instances[appId];
                foreach (var key in set.Where(kv => !executables.Contains(kv.Value.ExecutableId)).Select(kv => kv.Key).ToList())
                {
                    set.Remove(key);
                }
            }
        }
    }

    public void SetWarning(Guid applicationId, string key, string message)
    {
        lock (_gate)
        {
            if (!_warnings.TryGetValue(applicationId, out var map))
            {
                _warnings[applicationId] = map = new(StringComparer.OrdinalIgnoreCase);
            }

            map[key] = message;
        }
    }

    public void ClearWarning(Guid applicationId, string key)
    {
        lock (_gate)
        {
            if (_warnings.TryGetValue(applicationId, out var map))
            {
                map.Remove(key);
            }
        }
    }

    public bool IsRunning(Guid applicationId)
    {
        lock (_gate)
        {
            return _instances.TryGetValue(applicationId, out var set) && set.Count > 0;
        }
    }

    public IReadOnlyList<RunningInstance> GetInstances(Guid applicationId)
    {
        lock (_gate)
        {
            return _instances.TryGetValue(applicationId, out var set) ? set.Values.OrderBy(i => i.StartTime).ToList() : [];
        }
    }

    public IReadOnlyList<string> GetWarnings(Guid applicationId)
    {
        lock (_gate)
        {
            return _warnings.TryGetValue(applicationId, out var map) ? map.Values.ToList() : [];
        }
    }
}

/// <summary>Signals that managed applications or profiles changed, so caches (process index) must be rebuilt.</summary>
public sealed class PolicyChangeNotifier
{
    public event EventHandler? Changed;

    public void Raise() => Changed?.Invoke(this, EventArgs.Empty);
}

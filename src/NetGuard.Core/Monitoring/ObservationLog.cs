using NetGuard.Contracts;
using NetGuard.Core.Abstractions;

namespace NetGuard.Core.Monitoring;

/// <summary>
/// Bounded, de-duplicated record of diagnostic observations (child processes, relocations, blocked connections).
/// Repeated observations increment a counter instead of growing the list.
/// </summary>
public sealed class ObservationLog
{
    private const int Capacity = 500;

    private readonly IClock _clock;
    private readonly object _gate = new();
    private readonly LinkedList<ObservationDto> _items = new();

    public ObservationLog(IClock clock) => _clock = clock;

    /// <summary>Records an observation. Returns true when it is new (not a repeat).</summary>
    public bool Record(ObservationKind kind, Guid? applicationId, string? applicationName, string path, string detail)
    {
        lock (_gate)
        {
            for (var node = _items.First; node is not null; node = node.Next)
            {
                var existing = node.Value;
                if (existing.Kind == kind && existing.ApplicationId == applicationId &&
                    string.Equals(existing.ExecutablePath, path, StringComparison.OrdinalIgnoreCase))
                {
                    _items.Remove(node);
                    _items.AddFirst(existing with { Count = existing.Count + 1, Timestamp = _clock.UtcNow, Detail = detail });
                    return false;
                }
            }

            _items.AddFirst(new ObservationDto
            {
                Timestamp = _clock.UtcNow,
                Kind = kind,
                ApplicationId = applicationId,
                ApplicationName = applicationName,
                ExecutablePath = path,
                Detail = detail,
            });
            while (_items.Count > Capacity)
            {
                _items.RemoveLast();
            }

            return true;
        }
    }

    public IReadOnlyList<ObservationDto> GetAll(Guid? applicationId = null)
    {
        lock (_gate)
        {
            return _items.Where(o => applicationId is null || o.ApplicationId == applicationId).ToList();
        }
    }
}

public sealed record RunningInstance(int ProcessId, string ExecutablePath, Guid ExecutableId, DateTimeOffset StartTime);

/// <summary>Live process state for managed applications.</summary>
public interface IRuntimeState
{
    bool IsRunning(Guid applicationId);

    IReadOnlyList<RunningInstance> GetInstances(Guid applicationId);

    /// <summary>Warnings discovered at runtime (for example identity changes) that qualify the enforcement state.</summary>
    IReadOnlyList<string> GetWarnings(Guid applicationId);
}

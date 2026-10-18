using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;

namespace NetGuard.Core.Events;

/// <summary>
/// In-memory, sequence-numbered event buffer that desktop clients long-poll. Events are hints for refreshing and
/// for notifications; durable history lives in the audit log.
/// </summary>
public sealed class EventBroker
{
    private const int Capacity = 512;

    private readonly IClock _clock;
    private readonly object _gate = new();
    private readonly LinkedList<ServiceEventDto> _buffer = new();
    private long _sequence;
    private TaskCompletionSource _signal = NewSignal();

    public EventBroker(IClock clock) => _clock = clock;

    public long LatestSequence
    {
        get
        {
            lock (_gate)
            {
                return _sequence;
            }
        }
    }

    public ServiceEventDto Publish(ServiceEventKind kind, string title, string message, NotificationKind? notification = null, Guid? applicationId = null)
    {
        TaskCompletionSource toRelease;
        ServiceEventDto item;
        lock (_gate)
        {
            item = new ServiceEventDto
            {
                Sequence = ++_sequence,
                Timestamp = _clock.UtcNow,
                Kind = kind,
                Notification = notification,
                ApplicationId = applicationId,
                Title = title,
                Message = message,
            };
            _buffer.AddLast(item);
            while (_buffer.Count > Capacity)
            {
                _buffer.RemoveFirst();
            }

            toRelease = _signal;
            _signal = NewSignal();
        }

        toRelease.TrySetResult();
        return item;
    }

    public void PublishStateChanged(Guid? applicationId = null) =>
        Publish(ServiceEventKind.StateChanged, "State changed", string.Empty, null, applicationId);

    public void Notify(NotificationKind kind, string title, string message, Guid? applicationId = null) =>
        Publish(ServiceEventKind.Notification, title, message, kind, applicationId);

    /// <summary>Returns events after <paramref name="afterSequence"/>, waiting up to <paramref name="timeout"/> for new ones.</summary>
    public async Task<EventBatchDto> WaitAsync(long afterSequence, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (true)
        {
            Task signal;
            lock (_gate)
            {
                var batch = Collect(afterSequence);
                if (batch.Events.Count > 0 || batch.Gap)
                {
                    return batch;
                }

                signal = _signal.Task;
            }

            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero)
            {
                lock (_gate)
                {
                    return Collect(afterSequence);
                }
            }

            try
            {
                await signal.WaitAsync(remaining, cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                // Fall through and return whatever is available (normally nothing).
            }
        }
    }

    private EventBatchDto Collect(long afterSequence)
    {
        var events = _buffer.Where(e => e.Sequence > afterSequence).ToList();
        var oldest = _buffer.First?.Value.Sequence ?? _sequence + 1;

        // A gap exists when the client is behind the buffer, or when the client's sequence is from a previous
        // service instance (ahead of ours).
        var gap = (afterSequence > 0 && afterSequence < oldest - 1) || afterSequence > _sequence;
        return new EventBatchDto { LatestSequence = _sequence, Gap = gap, Events = gap ? [] : events };
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
}

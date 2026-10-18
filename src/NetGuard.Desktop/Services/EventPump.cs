using System.ServiceProcess;
using System.Windows.Threading;
using NetGuard.Contracts;
using NetGuard.Ipc;

namespace NetGuard.Desktop.Services;

public enum ConnectionState
{
    Connecting,
    Connected,
    Disconnected,
}

/// <summary>
/// Long-polls the service for events on a dedicated connection (no busy polling: each request waits on the service
/// until something happens or 20 seconds pass). A broken connection is detected immediately, which is how the UI
/// learns that the service stopped.
/// </summary>
public sealed class EventPump : IAsyncDisposable
{
    private readonly Dispatcher _dispatcher;
    private readonly CancellationTokenSource _stop = new();
    private Task? _loop;
    private long _sequence;

    public EventPump(Dispatcher dispatcher) => _dispatcher = dispatcher;

    public event Action<ServiceEventDto>? EventReceived;

    /// <summary>Raised when the client should reload everything (reconnected or events were missed).</summary>
    public event Action? RefreshRequired;

    public event Action<ConnectionState, string>? ConnectionChanged;

    public ConnectionState State { get; private set; } = ConnectionState.Connecting;

    public void Start() => _loop = Task.Run(() => RunAsync(_stop.Token));

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        if (_loop is not null)
        {
            await _loop.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        }

        _stop.Dispose();
    }

    private async Task RunAsync(CancellationToken stop)
    {
        var delay = TimeSpan.FromSeconds(1);
        while (!stop.IsCancellationRequested)
        {
            await using var client = new PipeClient(new PipeClientOptions
            {
                ConnectTimeout = TimeSpan.FromSeconds(2),
                TrustedServerOwners = PipeTrust.Options.TrustedServerOwners,
            });
            try
            {
                var first = true;
                while (!stop.IsCancellationRequested)
                {
                    var batch = await client.SendAsync<EventBatchDto>(Commands.WaitForEvents,
                        new WaitForEventsRequest { AfterSequence = _sequence, TimeoutSeconds = first ? 0 : 20 }, stop).ConfigureAwait(false);
                    if (first || batch.Gap)
                    {
                        _sequence = batch.LatestSequence;
                        if (State != ConnectionState.Connected)
                        {
                            SetState(ConnectionState.Connected, "Connected to the NetGuard service.");
                        }

                        Post(() => RefreshRequired?.Invoke());
                        first = false;
                        delay = TimeSpan.FromSeconds(1);
                        continue;
                    }

                    foreach (var item in batch.Events)
                    {
                        _sequence = Math.Max(_sequence, item.Sequence);
                        Post(() => EventReceived?.Invoke(item));
                    }
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                return;
            }
            catch (IpcException ex)
            {
                var wasConnected = State == ConnectionState.Connected;
                SetState(ConnectionState.Disconnected, Describe(ex));
                if (wasConnected)
                {
                    Post(() => EventReceived?.Invoke(new ServiceEventDto
                    {
                        Kind = ServiceEventKind.Notification,
                        Notification = Domain.NotificationKind.ServiceStopped,
                        Timestamp = DateTimeOffset.UtcNow,
                        Title = "NetGuard service stopped",
                        Message = "The background service is not running. Persistent firewall rules stay in effect, but new launches are not verified until it restarts.",
                    }));
                }
            }

            try
            {
                await Task.Delay(delay, stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            delay = TimeSpan.FromSeconds(Math.Min(30, delay.TotalSeconds * 2));
        }
    }

    private static string Describe(IpcException ex)
    {
        if (ex.Code == IpcErrorCodes.Unauthorized)
        {
            return ex.Message;
        }

        try
        {
            using var service = new ServiceController(IpcConstants.ServiceName);
            return $"The NetGuard service is {service.Status}.";
        }
        catch (InvalidOperationException)
        {
            return "The NetGuard service is not installed.";
        }
    }

    private void SetState(ConnectionState state, string message)
    {
        State = state;
        Post(() => ConnectionChanged?.Invoke(state, message));
    }

    private void Post(Action action) => _dispatcher.BeginInvoke(action);
}

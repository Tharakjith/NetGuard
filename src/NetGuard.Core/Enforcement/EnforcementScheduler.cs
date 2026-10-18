using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;

namespace NetGuard.Core.Enforcement;

/// <summary>
/// Coalesces reconcile requests from many sources (launch/exit events, firewall change notifications, timers) so
/// bursts result in a single run, and drives the periodic integrity check and temporary-exception expiry.
/// </summary>
public sealed class EnforcementScheduler
{
    private readonly EnforcementEngine _engine;
    private readonly IPolicyStore _store;
    private readonly IClock _clock;
    private readonly ILogger<EnforcementScheduler> _logger;
    private readonly Channel<ReconcileOptions> _requests = Channel.CreateUnbounded<ReconcileOptions>(new UnboundedChannelOptions { SingleReader = true });
    private readonly object _timerGate = new();
    private DateTimeOffset? _nextExceptionExpiry;
    private CancellationTokenSource? _expiryTimer;

    public EnforcementScheduler(EnforcementEngine engine, IPolicyStore store, IClock clock, ILogger<EnforcementScheduler> logger)
    {
        _engine = engine;
        _store = store;
        _clock = clock;
        _logger = logger;
    }

    /// <summary>Queues a reconcile. Requests that arrive while one is pending are merged into it.</summary>
    public void Request(ReconcileTrigger trigger, string reason) => _requests.Writer.TryWrite(new ReconcileOptions(trigger, reason));

    /// <summary>Queues a reconcile after a delay (for example the while-running grace period).</summary>
    public void RequestAfter(TimeSpan delay, ReconcileTrigger trigger, string reason, CancellationToken cancellationToken)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                Request(trigger, reason);
            }
            catch (OperationCanceledException)
            {
                // Superseded (for example the application was relaunched within the grace period).
            }
        }, CancellationToken.None);
    }

    /// <summary>Runs a reconcile immediately and returns its report (used by interactive commands).</summary>
    public async Task<ReconcileReport> RunNowAsync(ReconcileOptions options, CancellationToken cancellationToken)
    {
        var report = await _engine.ReconcileAsync(options, cancellationToken).ConfigureAwait(false);
        ScheduleExceptionExpiry(report.NextExceptionExpiry);
        return report;
    }

    public async Task RunAsync(CancellationToken stoppingToken)
    {
        var integrity = Task.Run(() => RunIntegrityLoopAsync(stoppingToken), stoppingToken);
        var reader = _requests.Reader;
        try
        {
            while (await reader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
            {
                // Short debounce so bursts (several helper processes starting together) collapse into one run.
                await Task.Delay(TimeSpan.FromMilliseconds(150), stoppingToken).ConfigureAwait(false);
                var batch = new List<ReconcileOptions>();
                while (reader.TryRead(out var request))
                {
                    batch.Add(request);
                }

                if (batch.Count == 0)
                {
                    continue;
                }

                var first = batch.OrderBy(b => Priority(b.Trigger)).First();
                var reason = batch.Count == 1 ? first.Reason : $"{first.Reason} (+{batch.Count - 1} coalesced)";
                try
                {
                    await RunNowAsync(first with { Reason = reason }, stoppingToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Scheduled reconcile failed ({Reason})", reason);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }

        await integrity.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
    }

    private async Task RunIntegrityLoopAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            ServiceSettings settings;
            try
            {
                settings = await _store.GetSettingsAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Could not read settings; using defaults for the integrity interval");
                settings = new ServiceSettings();
            }

            try
            {
                await Task.Delay(TimeSpan.FromMinutes(settings.IntegrityCheckIntervalMinutes), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            Request(ReconcileTrigger.IntegrityCheck, "periodic integrity check");
        }
    }

    private void ScheduleExceptionExpiry(DateTimeOffset? next)
    {
        lock (_timerGate)
        {
            if (next == _nextExceptionExpiry)
            {
                return;
            }

            _expiryTimer?.Cancel();
            _expiryTimer?.Dispose();
            _expiryTimer = null;
            _nextExceptionExpiry = next;
            if (next is null)
            {
                return;
            }

            var delay = next.Value - _clock.UtcNow + TimeSpan.FromSeconds(1);
            if (delay < TimeSpan.Zero)
            {
                delay = TimeSpan.Zero;
            }

            _expiryTimer = new CancellationTokenSource();
            var token = _expiryTimer.Token;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(delay, token).ConfigureAwait(false);
                    lock (_timerGate)
                    {
                        _nextExceptionExpiry = null;
                    }

                    Request(ReconcileTrigger.ExceptionExpiry, "temporary exception expired");
                }
                catch (OperationCanceledException)
                {
                }
            }, CancellationToken.None);
        }
    }

    private static int Priority(ReconcileTrigger trigger) => trigger switch
    {
        ReconcileTrigger.PolicyChange => 0,
        ReconcileTrigger.ProcessLaunch => 1,
        ReconcileTrigger.ExceptionExpiry => 2,
        ReconcileTrigger.FirewallChanged => 3,
        ReconcileTrigger.ProcessExit => 4,
        _ => 5,
    };
}

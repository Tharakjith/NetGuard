using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Enforcement;
using NetGuard.Core.Events;
using NetGuard.Core.Monitoring;
using NetGuard.Domain;
using NetGuard.Ipc;
using NetGuard.Persistence.Sqlite;

namespace NetGuard.Service;

/// <summary>
/// Service lifecycle. Startup order matters: storage (with integrity check and recovery) → process monitoring →
/// initial reconcile (re-establishes and verifies every rule after a reboot, crash or update) → event sources →
/// control pipe. Persistent rules live in the firewall itself, so they protect the system even before this runs.
/// </summary>
public sealed class NetGuardWorker : BackgroundService
{
    private readonly SqliteStore _store;
    private readonly AuditWriter _audit;
    private readonly ProcessTracker _tracker;
    private readonly EnforcementScheduler _scheduler;
    private readonly IFirewallChangeSource _firewallChanges;
    private readonly BlockedConnectionObserver _blockedConnections;
    private readonly OrganizationPolicyLoader _organizationPolicy;
    private readonly PipeServer _pipeServer;
    private readonly EventBroker _events;
    private readonly IClock _clock;
    private readonly ILogger<NetGuardWorker> _logger;

    public NetGuardWorker(
        SqliteStore store,
        AuditWriter audit,
        ProcessTracker tracker,
        EnforcementScheduler scheduler,
        IFirewallChangeSource firewallChanges,
        BlockedConnectionObserver blockedConnections,
        OrganizationPolicyLoader organizationPolicy,
        PipeServer pipeServer,
        EventBroker events,
        IClock clock,
        ILogger<NetGuardWorker> logger)
    {
        _store = store;
        _audit = audit;
        _tracker = tracker;
        _scheduler = scheduler;
        _firewallChanges = firewallChanges;
        _blockedConnections = blockedConnections;
        _organizationPolicy = organizationPolicy;
        _pipeServer = pipeServer;
        _events = events;
        _clock = clock;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await _store.InitializeAsync(stoppingToken).ConfigureAwait(false);
            foreach (var note in _store.RecoveryNotes)
            {
                await _audit.WriteAsync(AuditEventType.Recovery, AuditOutcome.Warning, note, cancellationToken: stoppingToken).ConfigureAwait(false);
            }

            var settings = await _store.GetSettingsAsync(stoppingToken).ConfigureAwait(false);
            ServicePaths.LogRetentionDays = settings.LogRetentionDays;
            await _audit.WriteAsync(AuditEventType.ServiceStarted, AuditOutcome.Success,
                $"NetGuard Enterprise service {typeof(NetGuardWorker).Assembly.GetName().Version} started.", cancellationToken: stoppingToken).ConfigureAwait(false);

            var schedulerLoop = Task.Run(() => _scheduler.RunAsync(stoppingToken), stoppingToken);
            await _tracker.StartAsync(stoppingToken).ConfigureAwait(false);

            var startup = await _scheduler.RunNowAsync(new ReconcileOptions(ReconcileTrigger.Startup, "service start"), stoppingToken).ConfigureAwait(false);
            await _audit.WriteAsync(AuditEventType.Recovery, startup.Failures == 0 ? AuditOutcome.Success : AuditOutcome.Failure,
                $"Startup verification: {startup.Statuses.Count} application(s), {startup.RulesAdded} rule(s) re-created, {startup.RulesUpdated} corrected, {startup.RulesRemoved} removed, {startup.OrphanedRules} orphaned, {startup.Failures} failure(s).",
                details: startup.ToDto(), cancellationToken: stoppingToken).ConfigureAwait(false);

            // Optional subsystems degrade gracefully: their failure must never stop enforcement.
            await StartOptionalAsync("firewall change notifications", () =>
            {
                _firewallChanges.Changed += (_, _) => _scheduler.Request(ReconcileTrigger.FirewallChanged, "firewall configuration changed");
                _firewallChanges.Start();
                return Task.CompletedTask;
            }, stoppingToken).ConfigureAwait(false);
            if (settings.ObserveBlockedConnections)
            {
                await StartOptionalAsync("blocked-connection observation", () => _blockedConnections.StartAsync(stoppingToken), stoppingToken).ConfigureAwait(false);
            }

            await StartOptionalAsync("organization policy", () => _organizationPolicy.StartAsync(stoppingToken), stoppingToken).ConfigureAwait(false);

            var maintenance = Task.Run(() => RunMaintenanceAsync(stoppingToken), stoppingToken);
            var pipe = Task.Run(() => _pipeServer.RunAsync(stoppingToken), stoppingToken);
            _logger.LogInformation("NetGuard service is running");

            await Task.WhenAll(schedulerLoop, maintenance, pipe).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            // Fail safe: firewall rules already in place remain in effect. Report and let the Service Control
            // Manager's recovery actions restart the service.
            _logger.LogCritical(ex, "NetGuard service failed");
            await _audit.WriteAsync(AuditEventType.Error, AuditOutcome.Failure, $"Service failure: {ex.Message}. Existing firewall rules remain in effect.", cancellationToken: CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _events.Publish(ServiceEventKind.ServiceStopping, "Service stopping", "The NetGuard service is stopping. Existing firewall rules remain in effect.");
        await _audit.WriteAsync(AuditEventType.ServiceStopped, AuditOutcome.Info,
            "NetGuard Enterprise service stopped. Persistent firewall rules remain in effect while the service is stopped.", cancellationToken: cancellationToken).ConfigureAwait(false);
        _tracker.Dispose();
        _firewallChanges.Dispose();
        _blockedConnections.Dispose();
        _organizationPolicy.Dispose();
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task StartOptionalAsync(string name, Func<Task> start, CancellationToken stoppingToken)
    {
        try
        {
            await start().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Optional subsystem '{Subsystem}' failed to start; enforcement continues without it", name);
            await _audit.WriteAsync(AuditEventType.Error, AuditOutcome.Warning,
                $"{name} is unavailable: {ex.Message}. Enforcement is not affected.", cancellationToken: stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task RunMaintenanceAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var settings = await _store.GetSettingsAsync(stoppingToken).ConfigureAwait(false);
                ServicePaths.LogRetentionDays = settings.LogRetentionDays;
                var purged = await _store.PurgeOlderThanAsync(_clock.UtcNow.AddDays(-settings.AuditRetentionDays), stoppingToken).ConfigureAwait(false);
                if (purged > 0)
                {
                    await _audit.WriteAsync(AuditEventType.ConfigurationChanged, AuditOutcome.Info,
                        $"Audit retention: {purged} record(s) older than {settings.AuditRetentionDays} days were deleted.", cancellationToken: stoppingToken).ConfigureAwait(false);
                }

                await _store.CreateBackupAsync("daily", stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Maintenance failed");
            }

            try
            {
                await Task.Delay(TimeSpan.FromHours(24), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}

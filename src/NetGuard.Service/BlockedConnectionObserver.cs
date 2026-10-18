using System.Collections.Concurrent;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Events;
using NetGuard.Core.Firewall;
using NetGuard.Core.Monitoring;
using NetGuard.Domain;

namespace NetGuard.Service;

/// <summary>
/// Turns WFP "connection blocked" audit events for managed executables into observations and (rate-limited)
/// notifications. Only events actually reported by Windows are surfaced, so a notification that an application
/// attempted a blocked connection is always backed by an observed event.
/// </summary>
public sealed class BlockedConnectionObserver : IDisposable
{
    private static readonly TimeSpan NotificationInterval = TimeSpan.FromMinutes(10);

    private readonly IBlockedConnectionSource _source;
    private readonly IPolicyStore _store;
    private readonly IFirewallManager _firewall;
    private readonly ObservationLog _observations;
    private readonly EventBroker _events;
    private readonly AuditWriter _audit;
    private readonly PolicyChangeNotifier _notifier;
    private readonly ConcurrentDictionary<Guid, DateTimeOffset> _lastNotified = new();
    private volatile IReadOnlyDictionary<string, ManagedApplication> _byPath = new Dictionary<string, ManagedApplication>();

    public BlockedConnectionObserver(
        IBlockedConnectionSource source,
        IPolicyStore store,
        IFirewallManager firewall,
        ObservationLog observations,
        EventBroker events,
        AuditWriter audit,
        PolicyChangeNotifier notifier)
    {
        _source = source;
        _store = store;
        _firewall = firewall;
        _observations = observations;
        _events = events;
        _audit = audit;
        _notifier = notifier;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await RefreshAsync(cancellationToken).ConfigureAwait(false);
        _notifier.Changed += OnPolicyChanged;
        _source.ConnectionBlocked += OnBlocked;
        _source.Start();
    }

    public void Dispose()
    {
        _notifier.Changed -= OnPolicyChanged;
        _source.ConnectionBlocked -= OnBlocked;
        _source.Dispose();
    }

    private void OnPolicyChanged(object? sender, EventArgs e) => _ = RefreshAsync(CancellationToken.None);

    private async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var map = new Dictionary<string, ManagedApplication>(StringComparer.OrdinalIgnoreCase);
        foreach (var application in await _store.GetApplicationsAsync(cancellationToken).ConfigureAwait(false))
        {
            foreach (var executable in application.Executables)
            {
                map[executable.Path] = application;
            }
        }

        _byPath = map;
    }

    private void OnBlocked(object? sender, BlockedConnection connection)
    {
        if (!_byPath.TryGetValue(connection.ApplicationPath, out var application))
        {
            return;
        }

        // Attribute the block to NetGuard only when a NetGuard rule exists for this program; otherwise another
        // rule or the default policy blocked it, which is reported differently.
        var byNetGuard = SafeHasOwnedRule(application.Id);
        var detail = $"Outbound {Protocol(connection.Protocol)} connection to {connection.RemoteAddress}:{connection.RemotePort} was blocked by Windows Filtering Platform" +
                     (byNetGuard ? " (NetGuard policy)." : " (a rule or default policy not managed by NetGuard).");
        _observations.Record(ObservationKind.BlockedConnection, application.Id, application.DisplayName, connection.ApplicationPath, detail);

        var now = connection.Timestamp;
        if (_lastNotified.TryGetValue(application.Id, out var last) && now - last < NotificationInterval)
        {
            return;
        }

        _lastNotified[application.Id] = now;
        _events.Notify(NotificationKind.BlockedConnectionObserved, $"{application.DisplayName} tried to connect",
            detail + " Open NetGuard to grant a temporary exception if this was expected.", application.Id);
        _ = _audit.WriteAsync(AuditEventType.BlockedConnectionObserved, AuditOutcome.Info, detail, application: application,
            executablePath: connection.ApplicationPath, details: new { connection.RemoteAddress, connection.RemotePort, connection.Protocol, connection.ProcessId });
    }

    private bool SafeHasOwnedRule(Guid applicationId)
    {
        var cache = _ownedCache;
        if (DateTime.UtcNow - cache.ReadAt > TimeSpan.FromSeconds(30))
        {
            try
            {
                cache = (DateTime.UtcNow, _firewall.GetRules().Select(OwnedRules.GetApplicationId).OfType<Guid>().ToHashSet());
            }
            catch (Exception ex) when (ex is FirewallUnavailableException or System.Runtime.InteropServices.COMException)
            {
                cache = (DateTime.UtcNow, []);
            }

            _ownedCache = cache;
        }

        return cache.Owners.Contains(applicationId);
    }

    private (DateTime ReadAt, HashSet<Guid> Owners) _ownedCache = (DateTime.MinValue, []);

    private static string Protocol(int protocol) => FirewallProtocols.Describe(protocol);
}

using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Configuration;
using NetGuard.Core.Diagnostics;
using NetGuard.Core.Enforcement;
using NetGuard.Core.Events;
using NetGuard.Core.Firewall;
using NetGuard.Core.Monitoring;
using NetGuard.Core.Policies;
using NetGuard.Core.Queries;
using NetGuard.Ipc;
using NetGuard.Logging;
using NetGuard.Persistence.Sqlite;
using NetGuard.Platform.Windows.Discovery;
using NetGuard.Platform.Windows.Events;
using NetGuard.Platform.Windows.Files;
using NetGuard.Platform.Windows.Firewall;
using NetGuard.Platform.Windows.Processes;
using NetGuard.Platform.Windows.Security;
using NetGuard.Service;

// Maintenance verbs (used by the installer and administrators). They never touch rules NetGuard does not own.
if (args.Length > 0 && args[0] is "cleanup-rules" or "list-rules")
{
    return RunMaintenanceVerb(args[0]);
}

var paths = new ServicePaths(GetOption(args, "--data-dir") ?? ServicePaths.DefaultRoot);
var privileged = WindowsSecurity.IsRunningAsLocalSystem() || WindowsSecurity.IsElevated();
var bootstrapLogger = NullLogger.Instance;
if (privileged)
{
    WindowsSecurity.HardenDirectory(paths.Root, bootstrapLogger);
}

Directory.CreateDirectory(paths.Data);
Directory.CreateDirectory(paths.Logs);
Directory.CreateDirectory(paths.Policies);

// Single instance per machine, even when started from a console for diagnostics.
using var instance = new Mutex(initiallyOwned: true, @"Global\NetGuardEnterprise.Service", out var createdNew);
if (!createdNew)
{
    Console.Error.WriteLine("Another instance of the NetGuard service is already running.");
    return 2;
}

var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.Services.AddWindowsService(options => options.ServiceName = IpcConstants.ServiceName);

builder.Logging.ClearProviders();
builder.Logging.AddJsonFile(new JsonFileLoggerOptions
{
    Directory = paths.Logs,
    FilePrefix = "netguard-service",
    RetentionDays = () => ServicePaths.LogRetentionDays,
});
if (OperatingSystem.IsWindows() && privileged)
{
    builder.Logging.AddEventLog(settings =>
    {
        settings.SourceName = "NetGuard Enterprise";
        settings.Filter = (_, level) => level >= LogLevel.Warning;
    });
}

if (!WindowsServiceHelpers.IsWindowsService())
{
    builder.Logging.AddSimpleConsole(o => o.SingleLine = true);
}

var version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
var services = builder.Services;
services.AddSingleton(paths);
services.AddSingleton<IClock, SystemClock>();
services.AddSingleton(sp => new SqliteStore(paths.Data, sp.GetRequiredService<IClock>(), sp.GetRequiredService<ILogger<SqliteStore>>()));
services.AddSingleton<IPolicyStore>(sp => sp.GetRequiredService<SqliteStore>());
services.AddSingleton<IAuditLog>(sp => sp.GetRequiredService<SqliteStore>());
services.AddSingleton<IFirewallManager, WindowsFirewallManager>();
services.AddSingleton<IExecutableInspector>(_ => new ExecutableInspector(AppContext.BaseDirectory));
services.AddSingleton<WmiProcessMonitor>();
services.AddSingleton<IProcessMonitor>(sp => sp.GetRequiredService<WmiProcessMonitor>());
services.AddSingleton<IApplicationDiscovery, WindowsApplicationDiscovery>();
services.AddSingleton<IFirewallChangeSource, FirewallChangeWatcher>();
services.AddSingleton<BlockedConnectionMonitor>();
services.AddSingleton<IBlockedConnectionSource>(sp => sp.GetRequiredService<BlockedConnectionMonitor>());
services.AddSingleton<EventBroker>();
services.AddSingleton<ObservationLog>();
services.AddSingleton<RuntimeRegistry>();
services.AddSingleton<IRuntimeState>(sp => sp.GetRequiredService<RuntimeRegistry>());
services.AddSingleton<PolicyChangeNotifier>();
services.AddSingleton<AuditWriter>();
services.AddSingleton<EnforcementEngine>();
services.AddSingleton<EnforcementScheduler>();
services.AddSingleton<ExecutableFactory>();
services.AddSingleton<ProcessTracker>();
services.AddSingleton<PolicyService>();
services.AddSingleton<QueryService>();
services.AddSingleton<ConfigurationPorter>();
services.AddSingleton<DiagnosticReportBuilder>();
services.AddSingleton<OrganizationPolicyLoader>();
services.AddSingleton<BlockedConnectionObserver>();
services.AddSingleton(sp => new ServiceRuntimeInfo
{
    Version = version,
    StartedAt = DateTimeOffset.UtcNow,
    DataDirectory = paths.Root,
    MonitoringMode = () => sp.GetRequiredService<WmiProcessMonitor>().MonitoringMode,
    BlockedConnectionAuditing = () => sp.GetRequiredService<BlockedConnectionMonitor>().IsAvailable,
});
services.AddSingleton<RequestDispatcher>();
services.AddSingleton(sp => new PipeServer(
    sp.GetRequiredService<RequestDispatcher>(),
    new PipeServerOptions { OperatorsGroup = privileged ? WindowsSecurity.EnsureOperatorsGroup(sp.GetRequiredService<ILogger<PipeServer>>(), create: true) : null },
    sp.GetRequiredService<ILogger<PipeServer>>()));
services.AddHostedService<NetGuardWorker>();

if (!privileged)
{
    Console.Error.WriteLine("WARNING: not running elevated. Firewall changes will fail and be reported as enforcement failures; process monitoring uses the WMI fallback.");
}

await builder.Build().RunAsync().ConfigureAwait(false);
return 0;

static string? GetOption(string[] args, string name)
{
    var index = Array.IndexOf(args, name);
    return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
}

static int RunMaintenanceVerb(string verb)
{
    if (!WindowsSecurity.IsElevated() && !WindowsSecurity.IsRunningAsLocalSystem())
    {
        Console.Error.WriteLine("This command must be run from an elevated (administrator) prompt.");
        return 5;
    }

    var firewall = new WindowsFirewallManager(NullLogger<WindowsFirewallManager>.Instance);
    var owned = firewall.GetRules().Where(OwnedRules.IsOwned).ToList();
    if (verb == "list-rules")
    {
        foreach (var rule in owned)
        {
            Console.WriteLine($"{rule.Name}\t{rule.ApplicationName}\t{FirewallProtocols.Describe(rule.Protocol)}\t{rule.RemoteAddresses}\t{rule.RemotePorts}");
        }

        Console.WriteLine($"{owned.Count} NetGuard-owned rule(s).");
        return 0;
    }

    var failures = 0;
    foreach (var name in owned.Select(r => r.Name).Distinct(StringComparer.Ordinal))
    {
        try
        {
            firewall.RemoveOwnedRule(name);
            Console.WriteLine($"Removed: {name}");
        }
        catch (FirewallOperationException ex)
        {
            failures++;
            Console.Error.WriteLine($"Failed: {name}: {ex.Message}");
        }
    }

    Console.WriteLine($"Removed {owned.Count - failures} NetGuard-owned rule(s); rules not created by NetGuard were not changed.");
    return failures == 0 ? 0 : 1;
}

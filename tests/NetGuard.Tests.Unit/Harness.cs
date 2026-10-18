using Microsoft.Extensions.Logging.Abstractions;
using NetGuard.Contracts;
using NetGuard.Core.Auditing;
using NetGuard.Core.Configuration;
using NetGuard.Core.Enforcement;
using NetGuard.Core.Events;
using NetGuard.Core.Monitoring;
using NetGuard.Core.Policies;
using NetGuard.Core.Queries;
using NetGuard.Core.Security;
using NetGuard.Domain;
using NetGuard.Tests.Unit.Fakes;

namespace NetGuard.Tests.Unit;

/// <summary>Wires the real core components exactly as the service does, with fakes only at the OS boundary.</summary>
public sealed class Harness : IAsyncDisposable
{
    public const string AppPath = @"C:\Program Files\Contoso\App\contoso.exe";
    public const string HelperPath = @"C:\Program Files\Contoso\App\helper\updater.exe";
    public const string OtherPath = @"C:\Program Files\Fabrikam\browser.exe";

    private readonly CancellationTokenSource _stop = new();
    private Task? _schedulerLoop;

    private Harness()
    {
        Clock = new FakeClock();
        Store = new InMemoryStore(Clock);
        Firewall = new FakeFirewall();
        Inspector = new FakeInspector();
        Monitor = new FakeProcessMonitor();
        Registry = new RuntimeRegistry();
        Events = new EventBroker(Clock);
        Observations = new ObservationLog(Clock);
        Audit = new AuditWriter(Store, Clock, NullLogger<AuditWriter>.Instance);
        Engine = new EnforcementEngine(Store, Firewall, Registry, Audit, Events, Clock, NullLogger<EnforcementEngine>.Instance);
        Scheduler = new EnforcementScheduler(Engine, Store, Clock, NullLogger<EnforcementScheduler>.Instance);
        Executables = new ExecutableFactory(Inspector, Clock);
        Tracker = new ProcessTracker(Monitor, Inspector, Store, Registry, Scheduler, Executables, Audit, Events, Observations, NullLogger<ProcessTracker>.Instance);
        Notifier = new PolicyChangeNotifier();
        Policies = new PolicyService(Store, Executables, new FakeDiscovery(), Scheduler, Tracker, Audit, Events, Notifier, Clock);
        Queries = new QueryService(Store, Store, Firewall, Registry, Observations, Engine, new ServiceRuntimeInfo { Version = "test" });
        Porter = new ConfigurationPorter(Store, Policies, Executables, Audit, Clock);

        Inspector.AddFile(AppPath);
        Inspector.AddFile(HelperPath, product: "Contoso Updater");
        Inspector.AddFile(OtherPath, signer: "CN=Fabrikam", product: "Fabrikam Browser");
    }

    public static ActorContext Admin { get; } = new() { Name = @"CONTOSO\admin", Sid = "S-1-5-21-1-1-1-500", IsElevatedAdministrator = true };

    public static ActorContext Operator { get; } = new() { Name = @"CONTOSO\operator", Sid = "S-1-5-21-1-1-1-1001", IsOperator = true };

    public static ActorContext Reader { get; } = new() { Name = @"CONTOSO\user", Sid = "S-1-5-21-1-1-1-1002" };

    public FakeClock Clock { get; }

    public InMemoryStore Store { get; }

    public FakeFirewall Firewall { get; }

    public FakeInspector Inspector { get; }

    public FakeProcessMonitor Monitor { get; }

    public RuntimeRegistry Registry { get; }

    public EventBroker Events { get; }

    public ObservationLog Observations { get; }

    public AuditWriter Audit { get; }

    public EnforcementEngine Engine { get; }

    public EnforcementScheduler Scheduler { get; }

    public ExecutableFactory Executables { get; }

    public ProcessTracker Tracker { get; }

    public PolicyChangeNotifier Notifier { get; }

    public PolicyService Policies { get; }

    public QueryService Queries { get; }

    public ConfigurationPorter Porter { get; }

    public CancellationToken Token => _stop.Token;

    public static async Task<Harness> StartAsync(Action<Harness>? configure = null)
    {
        var harness = new Harness();
        configure?.Invoke(harness);
        await harness.Store.SaveSettingsAsync(new ServiceSettings { WhileRunningGraceSeconds = 0 });
        harness._schedulerLoop = Task.Run(() => harness.Scheduler.RunAsync(harness._stop.Token));
        await harness.Tracker.StartAsync(harness._stop.Token);
        return harness;
    }

    public async Task<Guid> AddAsync(string path, ApplicationPolicy? policy = null, ActorContext? actor = null, bool includeChildren = true) =>
        await Policies.AddApplicationAsync(new AddApplicationRequest
        {
            ExecutablePaths = [path],
            Policy = policy ?? ApplicationPolicy.BlockAll,
            IncludeChildProcesses = includeChildren,
        }, actor ?? Admin, Token);

    public async Task<EnforcementStatus> StatusAsync(Guid id) =>
        (await Store.GetStatusesAsync()).Single(s => s.ApplicationId == id);

    public Task<ReconcileReport> ReconcileAsync(ReconcileTrigger trigger = ReconcileTrigger.Manual, bool removeOrphans = false) =>
        Scheduler.RunNowAsync(new ReconcileOptions(trigger, "test", "test", removeOrphans), Token);

    public int OwnedRulesFor(string path) =>
        Firewall.Rules.Count(r => Core.Firewall.OwnedRules.IsOwned(r) && string.Equals(r.ApplicationName, path, StringComparison.OrdinalIgnoreCase));

    public static async Task WaitUntilAsync(Func<Task<bool>> condition, int timeoutMs = 5000)
    {
        var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
        while (DateTime.UtcNow < deadline)
        {
            if (await condition())
            {
                return;
            }

            await Task.Delay(20);
        }

        Xunit.Assert.Fail("Condition was not met in time.");
    }

    public static Task WaitUntilAsync(Func<bool> condition, int timeoutMs = 5000) => WaitUntilAsync(() => Task.FromResult(condition()), timeoutMs);

    public async ValueTask DisposeAsync()
    {
        _stop.Cancel();
        Tracker.Dispose();
        if (_schedulerLoop is not null)
        {
            await Task.WhenAny(_schedulerLoop, Task.Delay(2000));
        }

        _stop.Dispose();
    }
}

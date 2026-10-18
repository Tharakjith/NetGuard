using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;

namespace NetGuard.Desktop.ViewModels;

public sealed class DashboardViewModel : PageViewModel
{
    private DashboardDto? _dashboard;

    public DashboardViewModel(UiContext context)
        : base(context)
    {
        OpenApplicationCommand = new RelayCommand(p =>
        {
            if (p is ApplicationSummaryDto app)
            {
                Context.Navigate(typeof(ApplicationsViewModel), app.Id);
            }
        });
        ShowFailuresCommand = new RelayCommand(() => Context.Navigate(typeof(LogsViewModel), LogsViewModel.FailuresFilter));
    }

    public override string Title => "Overview";

    public override string Glyph => "";

    public DashboardDto? Dashboard
    {
        get => _dashboard;
        private set
        {
            if (Set(ref _dashboard, value))
            {
                OnPropertyChanged(nameof(ServiceSummary));
                OnPropertyChanged(nameof(FirewallSummary));
                OnPropertyChanged(nameof(HasFirewallIssues));
            }
        }
    }

    public string ServiceSummary => Dashboard?.Service is { } s
        ? $"Running since {s.StartedAt.ToLocalTime():g} · version {s.Version}\nMonitoring: {s.MonitoringMode}\nLast verification: {(s.LastReconcileAt is { } at ? at.ToLocalTime().ToString("T") : "pending")}" +
          (s.LastReconcileError is { } err ? $"\nLast error: {err}" : string.Empty)
        : "Not connected.";

    public string FirewallSummary => Dashboard?.Service.Firewall is { } f
        ? f.Available
            ? $"Windows Defender Firewall available · current network: {f.CurrentProfiles}\n" +
              string.Join("  ", f.Profiles.Select(p => $"{p.Profile}: {(p.Enabled ? "on" : "OFF")}{(p.IsCurrent ? " (current)" : string.Empty)}")) +
              $"\n{f.OwnedRuleCount} NetGuard rule(s) of {f.TotalRuleCount} total · local policy: {f.LocalPolicyModifyState}"
            : $"Unavailable: {f.Error}"
        : string.Empty;

    public bool HasFirewallIssues => Dashboard?.Service.Firewall.Issues.Count > 0;

    public RelayCommand OpenApplicationCommand { get; }

    public RelayCommand ShowFailuresCommand { get; }

    public override async Task LoadAsync()
    {
        await RunAsync(async () => Dashboard = await Context.Client.GetDashboardAsync());
    }
}

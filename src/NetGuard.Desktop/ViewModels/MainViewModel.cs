using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Threading;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;

namespace NetGuard.Desktop.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly UiContext _context;
    private readonly TrayService _tray;
    private readonly DispatcherTimer _refreshDebounce;
    private PageViewModel _currentPage;
    private ConnectionState _connection = ConnectionState.Connecting;
    private string _connectionText = "Connecting to the NetGuard service…";

    public MainViewModel(UiContext context, EventPump events, TrayService tray)
    {
        _context = context;
        _tray = tray;
        Pages =
        [
            new DashboardViewModel(context),
            new ApplicationsViewModel(context),
            new DiscoveryViewModel(context),
            new FirewallViewModel(context),
            new ProfilesViewModel(context),
            new LogsViewModel(context),
            new DiagnosticsViewModel(context),
            new SettingsViewModel(context),
            new AboutViewModel(context),
        ];
        _currentPage = Pages[0];
        context.Navigate = (type, parameter) => _ = NavigateAsync(type, parameter);

        RestartElevatedCommand = new RelayCommand(RestartElevated, () => !Elevation.IsElevated());
        NavigateIndexCommand = new RelayCommand(p =>
        {
            if (int.TryParse(p as string, out var index) && index >= 0 && index < Pages.Count)
            {
                CurrentPage = Pages[index];
            }
        });

        // Bursts of state-change events collapse into one refresh.
        _refreshDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        _refreshDebounce.Tick += async (_, _) =>
        {
            _refreshDebounce.Stop();
            await RefreshAsync();
        };

        events.ConnectionChanged += OnConnectionChanged;
        events.RefreshRequired += () => _ = RefreshAsync();
        events.EventReceived += OnServiceEvent;
    }

    public ObservableCollection<PageViewModel> Pages { get; }

    public UiContext Context => _context;

    public PageViewModel CurrentPage
    {
        get => _currentPage;
        set
        {
            if (value is not null && Set(ref _currentPage, value))
            {
                _ = value.LoadAsync();
            }
        }
    }

    public ConnectionState Connection
    {
        get => _connection;
        private set
        {
            if (Set(ref _connection, value))
            {
                OnPropertyChanged(nameof(IsConnected));
            }
        }
    }

    public bool IsConnected => Connection == ConnectionState.Connected;

    public string ConnectionText
    {
        get => _connectionText;
        private set => Set(ref _connectionText, value);
    }

    public string PermissionText => _context.Caller switch
    {
        { CanAdminister: true } => $"Signed in as {_context.Caller.Name} — administrator (all changes allowed)",
        { CanModify: true } => $"Signed in as {_context.Caller.Name} — NetGuard Operator (policy changes allowed)",
        { CanRead: true } => $"Signed in as {_context.Caller.Name} — read-only. Restart as administrator to change policies.",
        _ => "No access to NetGuard status on this computer.",
    };

    public bool ShowElevationHint => IsConnected && !_context.CanModify;

    public RelayCommand RestartElevatedCommand { get; }

    public RelayCommand NavigateIndexCommand { get; }

    public async Task RefreshAsync()
    {
        try
        {
            var info = await _context.Client.GetServiceInfoAsync();
            _context.Service = info;
            _context.Caller = info.Caller;
            OnPropertyChanged(nameof(PermissionText));
            OnPropertyChanged(nameof(ShowElevationHint));
        }
        catch (Ipc.IpcException)
        {
            // Connection state is reported by the event pump.
        }

        await CurrentPage.LoadAsync();
    }

    private async Task NavigateAsync(Type pageType, object? parameter)
    {
        var page = Pages.First(p => p.GetType() == pageType);
        _currentPage = page;
        OnPropertyChanged(nameof(CurrentPage));
        await page.OnNavigatedToAsync(parameter);
    }

    private void OnConnectionChanged(ConnectionState state, string message)
    {
        Connection = state;
        ConnectionText = state == ConnectionState.Connected ? "Service connected" : message;
        OnPropertyChanged(nameof(ShowElevationHint));
    }

    private void OnServiceEvent(ServiceEventDto item)
    {
        switch (item.Kind)
        {
            case ServiceEventKind.Notification:
                _tray.Show(item);
                _refreshDebounce.Stop();
                _refreshDebounce.Start();
                break;
            case ServiceEventKind.StateChanged:
                _refreshDebounce.Stop();
                _refreshDebounce.Start();
                break;
            case ServiceEventKind.ServiceStopping:
                ConnectionText = "The NetGuard service is stopping.";
                break;
        }
    }

    private void RestartElevated()
    {
        if (Elevation.RestartElevated())
        {
            Application.Current.Shutdown();
        }
    }
}

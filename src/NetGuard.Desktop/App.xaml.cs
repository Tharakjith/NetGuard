using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Threading;
using NetGuard.Desktop.Services;
using NetGuard.Desktop.ViewModels;

namespace NetGuard.Desktop;

public partial class App : Application
{
    private const string InstanceMutexName = @"Local\NetGuardEnterprise.Desktop";
    private const string ActivateEventName = @"Local\NetGuardEnterprise.Desktop.Activate";

    private Mutex? _instance;
    private EventWaitHandle? _activate;
    private NetGuardClient? _client;
    private EventPump? _events;
    private TrayService? _tray;
    private MainWindow? _window;
    private bool _exiting;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        DispatcherUnhandledException += OnUnhandledException;

        // WPF formats bindings in en-US unless told otherwise; use the user's Windows regional format everywhere.
        FrameworkElement.LanguageProperty.OverrideMetadata(
            typeof(FrameworkElement),
            new FrameworkPropertyMetadata(System.Windows.Markup.XmlLanguage.GetLanguage(CultureInfo.CurrentCulture.IetfLanguageTag)));
        PipeTrust.Configure(e.Args);

        // When restarted elevated, wait for the previous (non-elevated) instance to exit first.
        var afterIndex = Array.IndexOf(e.Args, "--after");
        if (afterIndex >= 0 && afterIndex + 1 < e.Args.Length && int.TryParse(e.Args[afterIndex + 1], out var previousPid))
        {
            try
            {
                using var previous = Process.GetProcessById(previousPid);
                await Task.Run(() => previous.WaitForExit(10_000));
            }
            catch (ArgumentException)
            {
            }
        }

        _instance = new Mutex(true, InstanceMutexName, out var createdNew);
        if (!createdNew)
        {
            // Another instance is running in this session: ask it to show itself.
            try
            {
                EventWaitHandle.OpenExisting(ActivateEventName).Set();
            }
            catch (WaitHandleCannotBeOpenedException)
            {
            }

            Shutdown();
            return;
        }

        var preferences = UserPreferences.Load();
        ThemeManager.Apply(preferences.Theme);

        _client = new NetGuardClient();
        _events = new EventPump(Dispatcher);
        _tray = new TrayService(preferences, ShowMainWindow, ExitApplication);
        var context = new UiContext(_client, preferences);
        var viewModel = new MainViewModel(context, _events, _tray);

        _window = new MainWindow(viewModel);
        _window.Closing += (_, args) =>
        {
            if (!_exiting && preferences.CloseToTray)
            {
                args.Cancel = true;
                _window.Hide();
            }
        };
        _window.Closed += (_, _) => ExitApplication();
        MainWindow = _window;

        _activate = new EventWaitHandle(false, EventResetMode.AutoReset, ActivateEventName);
        _ = Task.Run(() =>
        {
            while (_activate.WaitOne())
            {
                if (_exiting)
                {
                    return;
                }

                Dispatcher.BeginInvoke(ShowMainWindow);
            }
        });

        if (!e.Args.Contains("--tray"))
        {
            _window.Show();
        }

        _events.Start();
    }

    private void ShowMainWindow()
    {
        if (_window is null)
        {
            return;
        }

        _window.Show();
        if (_window.WindowState == WindowState.Minimized)
        {
            _window.WindowState = WindowState.Normal;
        }

        _window.Activate();
    }

    private async void ExitApplication()
    {
        if (_exiting)
        {
            return;
        }

        _exiting = true;
        _activate?.Set();
        _tray?.Dispose();
        if (_events is not null)
        {
            await _events.DisposeAsync();
        }

        if (_client is not null)
        {
            await _client.DisposeAsync();
        }

        _window?.Close();
        _instance?.ReleaseMutex();
        Shutdown();
    }

    private void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        // The interface is a convenience; enforcement continues in the service. Report and keep running.
        Dialogs.Error("Unexpected error", $"{e.Exception.Message}\n\nEnforcement is not affected: it runs in the NetGuard service.");
        e.Handled = true;
    }
}

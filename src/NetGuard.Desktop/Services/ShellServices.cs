using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using NetGuard.Contracts;
using NetGuard.Domain;
using Forms = System.Windows.Forms;

namespace NetGuard.Desktop.Services;

/// <summary>Notification-area icon and Windows notifications. Respects per-user notification preferences.</summary>
public sealed class TrayService : IDisposable
{
    private readonly Forms.NotifyIcon _icon;
    private readonly UserPreferences _preferences;

    public TrayService(UserPreferences preferences, Action open, Action exit)
    {
        _preferences = preferences;
        var stream = Application.GetResourceStream(new Uri("pack://application:,,,/Assets/netguard.ico"))!.Stream;
        _icon = new Forms.NotifyIcon
        {
            Icon = new System.Drawing.Icon(stream),
            Text = "NetGuard Enterprise",
            Visible = true,
            ContextMenuStrip = new Forms.ContextMenuStrip(),
        };
        _icon.ContextMenuStrip.Items.Add("Open NetGuard Enterprise", null, (_, _) => open());
        _icon.ContextMenuStrip.Items.Add(new Forms.ToolStripSeparator());
        _icon.ContextMenuStrip.Items.Add("Exit (enforcement continues in the background service)", null, (_, _) => exit());
        _icon.DoubleClick += (_, _) => open();
        _icon.BalloonTipClicked += (_, _) => open();
    }

    public void Show(ServiceEventDto item)
    {
        if (item.Kind != ServiceEventKind.Notification || item.Notification is not { } kind || !_preferences.IsEnabled(kind))
        {
            return;
        }

        var icon = kind switch
        {
            NotificationKind.EnforcementFailed or NotificationKind.ServiceStopped or NotificationKind.IdentityChanged => Forms.ToolTipIcon.Warning,
            _ => Forms.ToolTipIcon.Info,
        };
        _icon.ShowBalloonTip(8000, Truncate(item.Title, 63), Truncate(item.Message, 255), icon);
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..(max - 1)] + "…";
}

public static class ThemeManager
{
    public static void Apply(ThemePreference preference)
    {
        var dark = preference == ThemePreference.Dark || (preference == ThemePreference.System && IsSystemDark());
        var app = Application.Current;
        app.ThemeMode = preference switch
        {
            ThemePreference.Light => ThemeMode.Light,
            ThemePreference.Dark => ThemeMode.Dark,
            _ => ThemeMode.System,
        };

        var palette = new ResourceDictionary { Source = new Uri($"pack://application:,,,/Themes/{(dark ? "Dark" : "Light")}.xaml") };
        var merged = app.Resources.MergedDictionaries;
        // App.xaml registers the palette with a relative URI ("Themes/Light.xaml"); match on the file name.
        foreach (var existing in merged.Where(d => d.Source?.OriginalString is { } s &&
                                                   (s.EndsWith("Themes/Light.xaml", StringComparison.OrdinalIgnoreCase) ||
                                                    s.EndsWith("Themes/Dark.xaml", StringComparison.OrdinalIgnoreCase))).ToList())
        {
            merged.Remove(existing);
        }

        merged.Insert(0, palette);
    }

    private static bool IsSystemDark()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        return key?.GetValue("AppsUseLightTheme") is int value && value == 0;
    }
}

public static class Dialogs
{
    public static bool Confirm(string title, string message, string confirmLabel = "Continue")
    {
        return Show(message + $"\n\nSelect OK to {confirmLabel.ToLowerInvariant()}.", title, MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel) == MessageBoxResult.OK;
    }

    /// <summary>Yes/No/Cancel question. Returns true for Yes, false for No, null for Cancel.</summary>
    public static bool? Ask(string title, string message) =>
        Show(message, title, MessageBoxButton.YesNoCancel, MessageBoxImage.Question, MessageBoxResult.Cancel) switch
        {
            MessageBoxResult.Yes => true,
            MessageBoxResult.No => false,
            _ => null,
        };

    public static void Error(string title, string message, IReadOnlyList<string>? details = null)
    {
        var text = details is { Count: > 0 } ? message + "\n\n• " + string.Join("\n• ", details.Take(15)) : message;
        Show(text, title, MessageBoxButton.OK, MessageBoxImage.Error);
    }

    public static void Info(string title, string message) =>
        Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);

    /// <summary>Owned by the main window when there is one; WPF throws for a null owner (startup, elevated verbs).</summary>
    private static MessageBoxResult Show(string text, string title, MessageBoxButton buttons, MessageBoxImage image, MessageBoxResult defaultResult = MessageBoxResult.None) =>
        Application.Current?.MainWindow is { } owner
            ? MessageBox.Show(owner, text, title, buttons, image, defaultResult)
            : MessageBox.Show(text, title, buttons, image, defaultResult);

    public static string? OpenExecutable()
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select the application's executable",
            Filter = "Applications (*.exe)|*.exe",
            CheckFileExists = true,
            DereferenceLinks = true,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        };
        return dialog.ShowDialog(Application.Current.MainWindow) == true ? dialog.FileName : null;
    }

    public static string? OpenJson(string title)
    {
        var dialog = new OpenFileDialog { Title = title, Filter = "NetGuard policy (*.json)|*.json", CheckFileExists = true };
        return dialog.ShowDialog(Application.Current.MainWindow) == true ? dialog.FileName : null;
    }

    public static bool SaveExport(ExportResultDto export)
    {
        var extension = Path.GetExtension(export.SuggestedFileName);
        var dialog = new SaveFileDialog
        {
            FileName = export.SuggestedFileName,
            Filter = extension == ".csv" ? "CSV (*.csv)|*.csv" : "JSON (*.json)|*.json",
            OverwritePrompt = true,
        };
        if (dialog.ShowDialog(Application.Current.MainWindow) != true)
        {
            return false;
        }

        File.WriteAllText(dialog.FileName, export.Content);
        return true;
    }
}

/// <summary>Extracts and caches executable icons for display.</summary>
public static class IconCache
{
    private static readonly Dictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static ImageSource? Get(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return null;
        }

        if (Cache.TryGetValue(path, out var cached))
        {
            return cached;
        }

        ImageSource? image = null;
        try
        {
            if (File.Exists(path))
            {
                using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
                if (icon is not null)
                {
                    var source = Imaging.CreateBitmapSourceFromHIcon(icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                    source.Freeze();
                    image = source;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
        }

        Cache[path] = image;
        return image;
    }
}

public static class Elevation
{
    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>Starts an elevated copy (UAC prompt). Returns false if the user declined.</summary>
    public static bool RestartElevated()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = $"--after {Environment.ProcessId}",
            });
            return true;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }
}

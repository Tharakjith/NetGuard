using System.IO;
using System.Text.Json;
using Microsoft.Win32;
using NetGuard.Contracts;
using NetGuard.Domain;

namespace NetGuard.Desktop.Services;

public enum ThemePreference
{
    System,
    Light,
    Dark,
}

/// <summary>Per-user interface preferences (%LOCALAPPDATA%\NetGuard). Never contains policy or security settings.</summary>
public sealed class UserPreferences
{
    private static readonly string FilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetGuard", "desktop-preferences.json");

    public ThemePreference Theme { get; set; } = ThemePreference.System;

    public bool CloseToTray { get; set; } = true;

    /// <summary>Notification kinds the user turned off. Enforcement failures and service-stopped cannot be disabled.</summary>
    public HashSet<NotificationKind> DisabledNotifications { get; set; } = [];

    public static IReadOnlySet<NotificationKind> EssentialNotifications { get; } =
        new HashSet<NotificationKind> { NotificationKind.EnforcementFailed, NotificationKind.ServiceStopped };

    public bool IsEnabled(NotificationKind kind) => EssentialNotifications.Contains(kind) || !DisabledNotifications.Contains(kind);

    public static UserPreferences Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<UserPreferences>(File.ReadAllText(FilePath), NetGuardJson.Options) ?? new UserPreferences()
                : new UserPreferences();
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return new UserPreferences();
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(this, NetGuardJson.Indented));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Preferences are a convenience; failing to save them is not an error worth interrupting the user for.
        }
    }
}

/// <summary>
/// Explicit, visible "start with Windows" for the tray interface (HKCU Run key, listed in Task Manager → Startup apps).
/// Off by default. Enforcement never depends on it: the service runs regardless.
/// </summary>
public static class StartupRegistration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "NetGuard Enterprise";

    public static bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(RunKey);
        return key?.GetValue(ValueName) is string;
    }

    public static void Set(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKey);
        if (enabled)
        {
            key.SetValue(ValueName, $"\"{Environment.ProcessPath}\" --tray");
        }
        else
        {
            key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
    }
}

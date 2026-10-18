using System.Collections.ObjectModel;
using System.IO;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;
using NetGuard.Domain;

namespace NetGuard.Desktop.ViewModels;

public sealed class NotificationToggle : ObservableObject
{
    private readonly UserPreferences _preferences;

    public NotificationToggle(UserPreferences preferences, NotificationKind kind, string label)
    {
        _preferences = preferences;
        Kind = kind;
        Label = label;
    }

    public NotificationKind Kind { get; }

    public string Label { get; }

    public bool IsEssential => UserPreferences.EssentialNotifications.Contains(Kind);

    public bool CanChange => !IsEssential;

    public bool IsEnabled
    {
        get => _preferences.IsEnabled(Kind);
        set
        {
            if (IsEssential)
            {
                return;
            }

            if (value)
            {
                _preferences.DisabledNotifications.Remove(Kind);
            }
            else
            {
                _preferences.DisabledNotifications.Add(Kind);
            }

            _preferences.Save();
            OnPropertyChanged();
        }
    }
}

public sealed class SettingsViewModel : PageViewModel
{
    private ServiceSettings? _settings;
    private int _auditRetention;
    private int _logRetention;
    private int _integrityInterval;
    private int _graceSeconds;
    private int _maxExceptionMinutes;
    private bool _allowStandardRead;
    private bool _observeBlocked;

    public SettingsViewModel(UiContext context)
        : base(context)
    {
        Notifications =
        [
            new(context.Preferences, NotificationKind.PolicyApplied, "A policy was applied or changed"),
            new(context.Preferences, NotificationKind.ApplicationBlocked, "A restricted application started (restriction verified)"),
            new(context.Preferences, NotificationKind.EnforcementFailed, "A firewall rule failed to apply or may not be effective (always shown)"),
            new(context.Preferences, NotificationKind.ExecutableLocationChanged, "A managed application started from a new location"),
            new(context.Preferences, NotificationKind.IdentityChanged, "A managed executable changed unexpectedly"),
            new(context.Preferences, NotificationKind.BlockedConnectionObserved, "Windows reported a blocked connection attempt (requires audit policy)"),
            new(context.Preferences, NotificationKind.TemporaryExceptionEnded, "A temporary exception ended"),
            new(context.Preferences, NotificationKind.ServiceStopped, "The background service stopped (always shown)"),
        ];
        SaveServiceSettingsCommand = new AsyncCommand(SaveServiceSettingsAsync, () => Context.CanAdminister && _settings is not null);
        ExportCommand = new AsyncCommand(ExportAsync, () => Context.CanModify);
        ImportCommand = new AsyncCommand(ImportAsync, () => Context.CanAdminister);
        BackupCommand = new AsyncCommand(BackupAsync, () => Context.CanAdminister);
    }

    public override string Title => "Settings";

    public override string Glyph => "";

    public ObservableCollection<NotificationToggle> Notifications { get; }

    public bool ThemeSystem
    {
        get => Context.Preferences.Theme == ThemePreference.System;
        set => SetTheme(value, ThemePreference.System);
    }

    public bool ThemeLight
    {
        get => Context.Preferences.Theme == ThemePreference.Light;
        set => SetTheme(value, ThemePreference.Light);
    }

    public bool ThemeDark
    {
        get => Context.Preferences.Theme == ThemePreference.Dark;
        set => SetTheme(value, ThemePreference.Dark);
    }

    public bool CloseToTray
    {
        get => Context.Preferences.CloseToTray;
        set
        {
            Context.Preferences.CloseToTray = value;
            Context.Preferences.Save();
            OnPropertyChanged();
        }
    }

    public bool StartWithWindows
    {
        get => StartupRegistration.IsEnabled();
        set
        {
            StartupRegistration.Set(value);
            OnPropertyChanged();
        }
    }

    public bool CanEditServiceSettings => Context.CanAdminister;

    public int AuditRetentionDays
    {
        get => _auditRetention;
        set => Set(ref _auditRetention, value);
    }

    public int LogRetentionDays
    {
        get => _logRetention;
        set => Set(ref _logRetention, value);
    }

    public int IntegrityCheckIntervalMinutes
    {
        get => _integrityInterval;
        set => Set(ref _integrityInterval, value);
    }

    public int WhileRunningGraceSeconds
    {
        get => _graceSeconds;
        set => Set(ref _graceSeconds, value);
    }

    public int MaxTemporaryExceptionMinutes
    {
        get => _maxExceptionMinutes;
        set => Set(ref _maxExceptionMinutes, value);
    }

    public bool AllowStandardUserRead
    {
        get => _allowStandardRead;
        set => Set(ref _allowStandardRead, value);
    }

    public bool ObserveBlockedConnections
    {
        get => _observeBlocked;
        set => Set(ref _observeBlocked, value);
    }

    public AsyncCommand SaveServiceSettingsCommand { get; }

    public AsyncCommand ExportCommand { get; }

    public AsyncCommand ImportCommand { get; }

    public AsyncCommand BackupCommand { get; }

    public override async Task LoadAsync()
    {
        OnPropertyChanged(nameof(CanEditServiceSettings));
        await RunAsync(async () => Apply(await Context.Client.GetSettingsAsync()));
    }

    private void Apply(ServiceSettings settings)
    {
        _settings = settings;
        AuditRetentionDays = settings.AuditRetentionDays;
        LogRetentionDays = settings.LogRetentionDays;
        IntegrityCheckIntervalMinutes = settings.IntegrityCheckIntervalMinutes;
        WhileRunningGraceSeconds = settings.WhileRunningGraceSeconds;
        MaxTemporaryExceptionMinutes = settings.MaxTemporaryExceptionMinutes;
        AllowStandardUserRead = settings.AllowStandardUserRead;
        ObserveBlockedConnections = settings.ObserveBlockedConnections;
    }

    private void SetTheme(bool value, ThemePreference theme)
    {
        if (!value)
        {
            return;
        }

        Context.Preferences.Theme = theme;
        Context.Preferences.Save();
        ThemeManager.Apply(theme);
        OnPropertyChanged(nameof(ThemeSystem));
        OnPropertyChanged(nameof(ThemeLight));
        OnPropertyChanged(nameof(ThemeDark));
    }

    private async Task SaveServiceSettingsAsync()
    {
        var updated = (_settings ?? new ServiceSettings()) with
        {
            AuditRetentionDays = AuditRetentionDays,
            LogRetentionDays = LogRetentionDays,
            IntegrityCheckIntervalMinutes = IntegrityCheckIntervalMinutes,
            WhileRunningGraceSeconds = WhileRunningGraceSeconds,
            MaxTemporaryExceptionMinutes = MaxTemporaryExceptionMinutes,
            AllowStandardUserRead = AllowStandardUserRead,
            ObserveBlockedConnections = ObserveBlockedConnections,
        };
        await RunAsync(async () => Apply(await Context.Client.UpdateSettingsAsync(updated)), "Service settings saved.", showDialogOnError: true);
    }

    private async Task ExportAsync()
    {
        ExportResultDto? export = null;
        if (await RunAsync(async () => export = await Context.Client.ExportConfigurationAsync(includeSettings: true), showDialogOnError: true) &&
            export is not null && Dialogs.SaveExport(export))
        {
            StatusMessage = "Configuration exported.";
        }
    }

    private async Task ImportAsync()
    {
        var path = Dialogs.OpenJson("Import NetGuard policy");
        if (path is null)
        {
            return;
        }

        var json = await File.ReadAllTextAsync(path);
        var replace = Dialogs.Ask("Import mode",
            "How should this file be applied?\n\nYes — Replace: make the local configuration match the file (applications not in the file are removed from management).\n" +
            "No — Merge: add new applications and update matching ones; leave everything else unchanged.\nCancel — do not import.");
        if (replace is null)
        {
            return;
        }

        var mode = replace.Value ? ImportMode.Replace : ImportMode.Merge;

        ImportResultDto? preview = null;
        if (!await RunAsync(async () => preview = await Context.Client.ImportConfigurationAsync(json, mode, dryRun: true), showDialogOnError: true) || preview is null)
        {
            return;
        }

        if (preview.Errors.Count > 0)
        {
            Dialogs.Error("Import rejected", "The file failed validation. Nothing was changed.", preview.Errors);
            return;
        }

        var summary = $"Schema version {preview.SchemaVersion}. This import will:\n" +
                      $"• add {preview.AddedApplications.Count} application(s)\n" +
                      $"• update {preview.UpdatedApplications.Count} application(s)\n" +
                      $"• remove {preview.RemovedApplications.Count} application(s){(preview.RemovedApplications.Count > 0 ? ": " + string.Join(", ", preview.RemovedApplications.Take(10)) : string.Empty)}\n" +
                      $"• add {preview.AddedProfiles.Count} and update {preview.UpdatedProfiles.Count} profile(s)\n" +
                      $"• {(preview.SettingsChanged ? "replace" : "keep")} service settings\n" +
                      (preview.Warnings.Count > 0 ? "\nWarnings:\n• " + string.Join("\n• ", preview.Warnings.Take(10)) : string.Empty) +
                      "\n\nA database backup is created first.";
        if (!Dialogs.Confirm("Confirm import", summary, "apply the import"))
        {
            return;
        }

        ImportResultDto? result = null;
        if (await RunAsync(async () => result = await Context.Client.ImportConfigurationAsync(json, mode, dryRun: false), showDialogOnError: true) && result is not null)
        {
            if (result.Applied)
            {
                StatusMessage = "Configuration imported and applied.";
            }
            else
            {
                Dialogs.Error("Import not applied", "The import was not applied.", result.Errors);
            }

            await LoadAsync();
        }
    }

    private async Task BackupAsync()
    {
        BackupResultDto? result = null;
        if (await RunAsync(async () => result = await Context.Client.CreateBackupAsync(), showDialogOnError: true) && result is not null)
        {
            StatusMessage = $"Backup created: {result.Path} ({result.SizeBytes / 1024} KB).";
        }
    }
}

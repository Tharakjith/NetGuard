using System.Collections.ObjectModel;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;
using NetGuard.Domain;
using NetGuard.Ipc;

namespace NetGuard.Desktop.ViewModels;

public sealed class ExecutableOption : ObservableObject
{
    private bool _isSelected;

    public required string Path { get; init; }

    public string Detail { get; init; } = string.Empty;

    public bool IsPrimary { get; init; }

    public Guid? ExistingId { get; init; }

    public bool IsSelected
    {
        get => _isSelected;
        set => Set(ref _isSelected, value);
    }

    /// <summary>The primary executable of a new application cannot be deselected.</summary>
    public bool CanToggle => !(IsPrimary && ExistingId is null);
}

public sealed record ProfileOption(Guid? Id, string Name);

public sealed class PolicyEditorViewModel : ObservableObject
{
    private enum EditorKind
    {
        NewApplication,
        ExistingApplication,
        Profile,
    }

    private readonly UiContext _context;
    private readonly EditorKind _kind;
    private readonly ApplicationDetailDto? _existing;
    private readonly PolicyProfile? _profile;
    private string _name = string.Empty;
    private string _description = string.Empty;
    private PolicyMode _mode = PolicyMode.Block;
    private RetentionMode _retention = RetentionMode.Persistent;
    private bool _domain = true;
    private bool _private = true;
    private bool _public = true;
    private string _addresses = string.Empty;
    private bool _allowLocal;
    private string _tcpPorts = "443";
    private string _udpPorts = string.Empty;
    private bool _allowIcmp;
    private ProfileOption? _selectedProfile;
    private bool _includeChildren = true;
    private bool _followUpdates = true;
    private bool _allowSystemComponent;
    private string? _errorText;
    private bool _isBusy;

    private PolicyEditorViewModel(UiContext context, EditorKind kind, ApplicationDetailDto? existing, PolicyProfile? profile)
    {
        _context = context;
        _kind = kind;
        _existing = existing;
        _profile = profile;
        SaveCommand = new AsyncCommand(SaveAsync, () => !IsBusy);
        CancelCommand = new RelayCommand(() => Close?.Invoke(false));
        AddExecutableCommand = new AsyncCommand(AddExecutableAsync);
        ScanRelatedCommand = new AsyncCommand(ScanRelatedAsync);
    }

    public static PolicyEditorViewModel ForNewApplication(UiContext context, IReadOnlyList<ExecutableInspectionDto> inspections)
    {
        var primary = inspections[0];
        var vm = new PolicyEditorViewModel(context, EditorKind.NewApplication, null, null)
        {
            _name = primary.ProductName ?? primary.FileDescription ?? System.IO.Path.GetFileNameWithoutExtension(primary.CanonicalPath),
            ShowSystemComponentOption = inspections.Any(i => i.IsSystemComponent),
        };
        for (var i = 0; i < inspections.Count; i++)
        {
            var inspection = inspections[i];
            vm.Executables.Add(new ExecutableOption
            {
                Path = inspection.CanonicalPath,
                Detail = Describe(inspection),
                IsPrimary = i == 0,
                IsSelected = true,
            });
            foreach (var warning in inspection.Warnings.Concat(inspection.ProtectionReason is null ? [] : [inspection.ProtectionReason]))
            {
                vm.Warnings.Add($"{System.IO.Path.GetFileName(inspection.CanonicalPath)}: {warning}");
            }
        }

        vm.InstallDirectory = System.IO.Path.GetDirectoryName(primary.CanonicalPath);
        _ = vm.LoadProfilesAsync(null);
        return vm;
    }

    public static PolicyEditorViewModel ForExistingApplication(UiContext context, ApplicationDetailDto detail)
    {
        var app = detail.Application;
        var vm = new PolicyEditorViewModel(context, EditorKind.ExistingApplication, detail, null)
        {
            _name = app.DisplayName,
            _includeChildren = app.IncludeChildProcesses,
            _followUpdates = app.FollowSignedUpdates,
            InstallDirectory = app.InstallDirectory,
        };
        vm.LoadPolicy(app.Policy);
        foreach (var exe in app.Executables)
        {
            vm.Executables.Add(new ExecutableOption
            {
                Path = exe.Path,
                Detail = $"{exe.Origin} · signature: {exe.SignatureStatus}{(exe.SignerSubject is null ? string.Empty : " · " + exe.SignerSubject)}",
                IsPrimary = exe.IsPrimary,
                ExistingId = exe.Id,
                IsSelected = true,
            });
        }

        _ = vm.LoadProfilesAsync(app.ProfileId);
        return vm;
    }

    public static PolicyEditorViewModel ForProfile(UiContext context, PolicyProfile? profile)
    {
        var vm = new PolicyEditorViewModel(context, EditorKind.Profile, null, profile)
        {
            _name = profile?.Name ?? "New profile",
            _description = profile?.Description ?? string.Empty,
        };
        vm.LoadPolicy(profile?.Policy ?? ApplicationPolicy.BlockAll);
        return vm;
    }

    public Action<bool>? Close { get; set; }

    public object? Result { get; private set; }

    public string WindowTitle => _kind switch
    {
        EditorKind.NewApplication => "Manage application",
        EditorKind.ExistingApplication => $"Edit policy — {_existing!.Summary.DisplayName}",
        _ => _profile is null ? "New policy profile" : $"Edit profile — {_profile.Name}",
    };

    public bool IsApplication => _kind != EditorKind.Profile;

    public bool IsProfile => _kind == EditorKind.Profile;

    public bool IsNameEditable => !(IsProfile && _profile?.IsBuiltIn == true);

    public string? InstallDirectory { get; private set; }

    public ObservableCollection<ExecutableOption> Executables { get; } = [];

    public ObservableCollection<string> Warnings { get; } = [];

    public ObservableCollection<ProfileOption> ProfileOptions { get; } = [];

    public ObservableCollection<string> ValidationErrors { get; } = [];

    public bool ShowSystemComponentOption { get; private set; }

    public string Name
    {
        get => _name;
        set => Set(ref _name, value);
    }

    public string Description
    {
        get => _description;
        set => Set(ref _description, value);
    }

    public bool IsAllow
    {
        get => _mode == PolicyMode.Allow;
        set => SetMode(value, PolicyMode.Allow);
    }

    public bool IsBlock
    {
        get => _mode == PolicyMode.Block;
        set => SetMode(value, PolicyMode.Block);
    }

    public bool IsCustom
    {
        get => _mode == PolicyMode.Custom;
        set => SetMode(value, PolicyMode.Custom);
    }

    public bool IsRestricting => _mode != PolicyMode.Allow;

    public bool IsPersistent
    {
        get => _retention == RetentionMode.Persistent;
        set
        {
            if (value)
            {
                _retention = RetentionMode.Persistent;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsWhileRunning));
            }
        }
    }

    public bool IsWhileRunning
    {
        get => _retention == RetentionMode.WhileRunning;
        set
        {
            if (value)
            {
                _retention = RetentionMode.WhileRunning;
                OnPropertyChanged();
                OnPropertyChanged(nameof(IsPersistent));
            }
        }
    }

    public bool DomainProfile
    {
        get => _domain;
        set => Set(ref _domain, value);
    }

    public bool PrivateProfile
    {
        get => _private;
        set => Set(ref _private, value);
    }

    public bool PublicProfile
    {
        get => _public;
        set => Set(ref _public, value);
    }

    public string AllowedAddresses
    {
        get => _addresses;
        set => Set(ref _addresses, value);
    }

    public bool AllowLocalNetwork
    {
        get => _allowLocal;
        set => Set(ref _allowLocal, value);
    }

    public string TcpPorts
    {
        get => _tcpPorts;
        set => Set(ref _tcpPorts, value);
    }

    public string UdpPorts
    {
        get => _udpPorts;
        set => Set(ref _udpPorts, value);
    }

    public bool AllowIcmp
    {
        get => _allowIcmp;
        set => Set(ref _allowIcmp, value);
    }

    public ProfileOption? SelectedProfile
    {
        get => _selectedProfile;
        set => Set(ref _selectedProfile, value);
    }

    public bool IncludeChildProcesses
    {
        get => _includeChildren;
        set => Set(ref _includeChildren, value);
    }

    public bool FollowSignedUpdates
    {
        get => _followUpdates;
        set => Set(ref _followUpdates, value);
    }

    public bool AllowSystemComponent
    {
        get => _allowSystemComponent;
        set => Set(ref _allowSystemComponent, value);
    }

    public string? ErrorText
    {
        get => _errorText;
        private set => Set(ref _errorText, value);
    }

    public bool IsBusy
    {
        get => _isBusy;
        private set => Set(ref _isBusy, value);
    }

    public AsyncCommand SaveCommand { get; }

    public RelayCommand CancelCommand { get; }

    public AsyncCommand AddExecutableCommand { get; }

    public AsyncCommand ScanRelatedCommand { get; }

    private void SetMode(bool value, PolicyMode mode)
    {
        if (!value || _mode == mode)
        {
            return;
        }

        _mode = mode;
        OnPropertyChanged(nameof(IsAllow));
        OnPropertyChanged(nameof(IsBlock));
        OnPropertyChanged(nameof(IsCustom));
        OnPropertyChanged(nameof(IsRestricting));
    }

    private void LoadPolicy(ApplicationPolicy policy)
    {
        _mode = policy.Mode;
        _retention = policy.Retention;
        _domain = policy.Profiles.HasFlag(NetworkProfiles.Domain);
        _private = policy.Profiles.HasFlag(NetworkProfiles.Private);
        _public = policy.Profiles.HasFlag(NetworkProfiles.Public);
        if (policy.Custom is { } custom)
        {
            _addresses = string.Join(Environment.NewLine, custom.AllowedRemoteAddresses);
            _allowLocal = custom.AllowLocalNetwork;
            _tcpPorts = custom.AllowedTcpPorts;
            _udpPorts = custom.AllowedUdpPorts;
            _allowIcmp = custom.AllowIcmp;
        }
    }

    private ApplicationPolicy BuildPolicy()
    {
        var profiles = (DomainProfile ? NetworkProfiles.Domain : 0) | (PrivateProfile ? NetworkProfiles.Private : 0) | (PublicProfile ? NetworkProfiles.Public : 0);
        return new ApplicationPolicy
        {
            Mode = _mode,
            Retention = _retention,
            Profiles = profiles,
            Custom = _mode == PolicyMode.Custom
                ? new CustomNetworkPolicy
                {
                    AllowedRemoteAddresses = AllowedAddresses
                        .Split(['\r', '\n', ',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                        .ToList(),
                    AllowLocalNetwork = AllowLocalNetwork,
                    AllowedTcpPorts = TcpPorts.Trim(),
                    AllowedUdpPorts = UdpPorts.Trim(),
                    AllowIcmp = AllowIcmp,
                }
                : null,
        };
    }

    private async Task LoadProfilesAsync(Guid? selected)
    {
        ProfileOptions.Add(new ProfileOption(null, "(none — use this application's own policy)"));
        try
        {
            foreach (var profile in await _context.Client.ListProfilesAsync())
            {
                ProfileOptions.Add(new ProfileOption(profile.Profile.Id, profile.Profile.Name + (profile.Profile.IsEnabled ? " (enabled — overrides policy)" : " (disabled)")));
            }
        }
        catch (IpcException ex)
        {
            ErrorText = ex.Message;
        }

        SelectedProfile = ProfileOptions.FirstOrDefault(p => p.Id == selected) ?? ProfileOptions[0];
    }

    private async Task AddExecutableAsync()
    {
        var path = Dialogs.OpenExecutable();
        if (path is null)
        {
            return;
        }

        try
        {
            var inspection = await _context.Client.InspectAsync(path);
            if (Executables.Any(e => string.Equals(e.Path, inspection.CanonicalPath, StringComparison.OrdinalIgnoreCase)))
            {
                return;
            }

            Executables.Add(new ExecutableOption { Path = inspection.CanonicalPath, Detail = Describe(inspection), IsSelected = true });
            ShowSystemComponentOption |= inspection.IsSystemComponent;
            OnPropertyChanged(nameof(ShowSystemComponentOption));
        }
        catch (IpcException ex)
        {
            ErrorText = ex.Message;
        }
    }

    private async Task ScanRelatedAsync()
    {
        if (InstallDirectory is null)
        {
            return;
        }

        try
        {
            IsBusy = true;
            var related = await _context.Client.ScanDirectoryAsync(InstallDirectory);
            foreach (var item in related.Where(r => !r.IsManaged && Executables.All(e => !string.Equals(e.Path, r.Path, StringComparison.OrdinalIgnoreCase))))
            {
                Executables.Add(new ExecutableOption
                {
                    Path = item.Path,
                    Detail = $"Helper in the same folder · {item.ProductName ?? "no product name"} · {item.CompanyName ?? "no company"}",
                    IsSelected = false,
                });
            }

            if (related.Count == 0)
            {
                ErrorText = "No other executables were found in the application's folder.";
            }
        }
        catch (IpcException ex)
        {
            ErrorText = ex.Message;
        }
        finally
        {
            IsBusy = false;
        }
    }

    private async Task SaveAsync()
    {
        ErrorText = null;
        ValidationErrors.Clear();
        IsBusy = true;
        try
        {
            var policy = BuildPolicy();
            switch (_kind)
            {
                case EditorKind.NewApplication:
                    Result = await _context.Client.AddApplicationAsync(new AddApplicationRequest
                    {
                        DisplayName = Name,
                        ExecutablePaths = Executables.Where(e => e.IsSelected).OrderByDescending(e => e.IsPrimary).Select(e => e.Path).ToList(),
                        Policy = policy,
                        ProfileId = SelectedProfile?.Id,
                        IncludeChildProcesses = IncludeChildProcesses,
                        FollowSignedUpdates = FollowSignedUpdates,
                        AllowSystemComponent = AllowSystemComponent,
                    });
                    break;

                case EditorKind.ExistingApplication:
                    Result = await _context.Client.UpdateApplicationAsync(new UpdateApplicationRequest
                    {
                        Id = _existing!.Summary.Id,
                        ExpectedRevision = _existing.Summary.Revision,
                        DisplayName = Name,
                        Policy = policy,
                        ProfileId = SelectedProfile?.Id,
                        ClearProfile = SelectedProfile?.Id is null,
                        IncludeChildProcesses = IncludeChildProcesses,
                        FollowSignedUpdates = FollowSignedUpdates,
                        AddExecutablePaths = Executables.Where(e => e.IsSelected && e.ExistingId is null).Select(e => e.Path).ToList(),
                        RemoveExecutableIds = Executables.Where(e => !e.IsSelected && e.ExistingId is not null).Select(e => e.ExistingId!.Value).ToList(),
                        AllowSystemComponent = AllowSystemComponent,
                    });
                    break;

                case EditorKind.Profile:
                    Result = await _context.Client.SaveProfileAsync(new PolicyProfile
                    {
                        Id = _profile?.Id ?? Guid.Empty,
                        Name = Name,
                        Description = Description,
                        IsEnabled = _profile?.IsEnabled ?? false,
                        Policy = policy,
                    });
                    break;
            }

            Close?.Invoke(true);
        }
        catch (IpcException ex)
        {
            ErrorText = ex.Message;
            foreach (var error in ex.ValidationErrors)
            {
                ValidationErrors.Add(error);
            }
        }
        finally
        {
            IsBusy = false;
        }
    }

    private static string Describe(ExecutableInspectionDto i) =>
        $"{i.ProductName ?? i.FileDescription ?? "Unknown product"} {i.FileVersion} · {i.CompanyName ?? "unknown publisher"} · signature: {i.SignatureStatus}" +
        (i.SignerSubject is null ? string.Empty : $" ({i.SignerSubject})");
}

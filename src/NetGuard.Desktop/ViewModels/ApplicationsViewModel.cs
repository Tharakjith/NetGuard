using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows.Data;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;
using NetGuard.Desktop.Views;
using NetGuard.Domain;

namespace NetGuard.Desktop.ViewModels;

public sealed class ApplicationsViewModel : PageViewModel
{
    private readonly ObservableCollection<ApplicationSummaryDto> _items = [];
    private ApplicationSummaryDto? _selected;
    private ApplicationDetailDto? _detail;
    private string _search = string.Empty;
    private string _policyFilter = "All policies";
    private string _stateFilter = "All states";
    private Guid? _pendingSelection;

    public ApplicationsViewModel(UiContext context)
        : base(context)
    {
        Items = CollectionViewSource.GetDefaultView(_items);
        Items.Filter = Filter;
        Items.SortDescriptions.Add(new SortDescription(nameof(ApplicationSummaryDto.DisplayName), ListSortDirection.Ascending));

        AddCommand = new AsyncCommand(AddAsync, () => Context.CanModify);
        EditCommand = new AsyncCommand(EditAsync, () => CanEditSelected);
        ToggleEnabledCommand = new AsyncCommand(ToggleEnabledAsync, () => CanEditSelected);
        GrantExceptionCommand = new AsyncCommand(GrantExceptionAsync, () => Context.CanModify && Detail is { Exception: null } d && d.Summary.EffectivePolicy.RequiresRules && d.Summary.IsEnabled);
        RevokeExceptionCommand = new AsyncCommand(RevokeExceptionAsync, () => Context.CanModify && Detail?.Exception is not null);
        RestoreCommand = new AsyncCommand(RestoreAsync, () => CanEditSelected && Detail?.Summary.IsEnabled == true);
        RemoveCommand = new AsyncCommand(RemoveAsync, () => CanEditSelected);
        ViewLogsCommand = new RelayCommand(() => Context.Navigate(typeof(LogsViewModel), Selected), () => Selected is not null);
        ReverifyCommand = new AsyncCommand(ReverifyAsync, () => Context.CanModify);
        OpenFolderCommand = new RelayCommand(OpenFolder, () => Detail is not null);
    }

    public override string Title => "Managed Applications";

    public override string Glyph => "";

    public ICollectionView Items { get; }

    public IReadOnlyList<string> PolicyFilters { get; } = ["All policies", "Block", "Custom", "Allow", "Disabled"];

    public IReadOnlyList<string> StateFilters { get; } = ["All states", "Enforced", "Problems", "Running", "Standby", "Exception active"];

    public string SearchText
    {
        get => _search;
        set
        {
            if (Set(ref _search, value))
            {
                Items.Refresh();
            }
        }
    }

    public string PolicyFilter
    {
        get => _policyFilter;
        set
        {
            if (Set(ref _policyFilter, value))
            {
                Items.Refresh();
            }
        }
    }

    public string StateFilter
    {
        get => _stateFilter;
        set
        {
            if (Set(ref _stateFilter, value))
            {
                Items.Refresh();
            }
        }
    }

    public ApplicationSummaryDto? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                _ = LoadDetailAsync();
            }
        }
    }

    public ApplicationDetailDto? Detail
    {
        get => _detail;
        private set
        {
            if (Set(ref _detail, value))
            {
                OnPropertyChanged(nameof(IsOrganizationManaged));
                OnPropertyChanged(nameof(EnableButtonText));
                OnPropertyChanged(nameof(ExceptionText));
            }
        }
    }

    public bool IsOrganizationManaged => Detail?.Summary.Source == PolicySource.Organization;

    public string EnableButtonText => Detail?.Summary.IsEnabled == false ? "Enable" : "Disable";

    public string? ExceptionText => Detail?.Exception is { } e
        ? $"Temporary exception until {e.ExpiresAt.ToLocalTime():g}, granted by {e.GrantedBy}: {e.Reason}"
        : null;

    public int Count => _items.Count;

    public AsyncCommand AddCommand { get; }

    public AsyncCommand EditCommand { get; }

    public AsyncCommand ToggleEnabledCommand { get; }

    public AsyncCommand GrantExceptionCommand { get; }

    public AsyncCommand RevokeExceptionCommand { get; }

    public AsyncCommand RestoreCommand { get; }

    public AsyncCommand RemoveCommand { get; }

    public RelayCommand ViewLogsCommand { get; }

    public AsyncCommand ReverifyCommand { get; }

    public RelayCommand OpenFolderCommand { get; }

    private bool CanEditSelected => Context.CanModify && Detail is not null && !IsOrganizationManaged;

    public override async Task OnNavigatedToAsync(object? parameter)
    {
        _pendingSelection = parameter as Guid?;
        await LoadAsync();
    }

    public override async Task LoadAsync()
    {
        var keep = _pendingSelection ?? Selected?.Id;
        _pendingSelection = null;
        await RunAsync(async () =>
        {
            var list = await Context.Client.ListApplicationsAsync();
            _items.Clear();
            foreach (var item in list)
            {
                _items.Add(item);
            }

            OnPropertyChanged(nameof(Count));
            Selected = keep is null ? _items.FirstOrDefault() : _items.FirstOrDefault(i => i.Id == keep) ?? _items.FirstOrDefault();
            if (Selected is not null && Detail?.Summary.Id == Selected.Id)
            {
                await LoadDetailAsync();
            }
        });
    }

    private async Task LoadDetailAsync()
    {
        if (Selected is null)
        {
            Detail = null;
            return;
        }

        var id = Selected.Id;
        await RunAsync(async () =>
        {
            var detail = await Context.Client.GetApplicationAsync(id);
            if (Selected?.Id == id)
            {
                Detail = detail;
            }
        });
    }

    private bool Filter(object obj)
    {
        if (obj is not ApplicationSummaryDto app)
        {
            return false;
        }

        if (!string.IsNullOrWhiteSpace(SearchText) &&
            !(app.DisplayName.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ||
              (app.Publisher?.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ?? false) ||
              (app.PrimaryPath?.Contains(SearchText, StringComparison.OrdinalIgnoreCase) ?? false)))
        {
            return false;
        }

        var policyMatch = PolicyFilter switch
        {
            "Block" => app.IsEnabled && app.EffectivePolicy.Mode == PolicyMode.Block,
            "Custom" => app.IsEnabled && app.EffectivePolicy.Mode == PolicyMode.Custom,
            "Allow" => app.IsEnabled && app.EffectivePolicy.Mode == PolicyMode.Allow,
            "Disabled" => !app.IsEnabled,
            _ => true,
        };

        var stateMatch = StateFilter switch
        {
            "Enforced" => app.Enforcement.State == EnforcementState.Enforced,
            "Problems" => app.Enforcement.State is EnforcementState.Failed or EnforcementState.Degraded or EnforcementState.Unsupported,
            "Running" => app.IsRunning,
            "Standby" => app.Enforcement.State == EnforcementState.Standby,
            "Exception active" => app.Enforcement.State == EnforcementState.Suspended,
            _ => true,
        };

        return policyMatch && stateMatch;
    }

    private async Task AddAsync()
    {
        var path = Dialogs.OpenExecutable();
        if (path is null)
        {
            return;
        }

        ExecutableInspectionDto? inspection = null;
        if (!await RunAsync(async () => inspection = await Context.Client.InspectAsync(path), showDialogOnError: true) || inspection is null)
        {
            return;
        }

        if (inspection.ManagedByApplicationId is { } existing)
        {
            Dialogs.Info("Already managed", "This executable is already managed. Opening it.");
            _pendingSelection = existing;
            await LoadAsync();
            return;
        }

        var editor = PolicyEditorViewModel.ForNewApplication(Context, [inspection]);
        if (PolicyEditorWindow.ShowEditor(editor) is ApplicationDetailDto added)
        {
            _pendingSelection = added.Summary.Id;
            await LoadAsync();
        }
    }

    private async Task EditAsync()
    {
        if (Detail is null)
        {
            return;
        }

        var editor = PolicyEditorViewModel.ForExistingApplication(Context, Detail);
        if (PolicyEditorWindow.ShowEditor(editor) is ApplicationDetailDto)
        {
            await LoadAsync();
        }
    }

    private async Task ToggleEnabledAsync()
    {
        if (Detail is null)
        {
            return;
        }

        var enable = !Detail.Summary.IsEnabled;
        if (!enable && !Dialogs.Confirm("Disable management",
                $"Disable management of {Detail.Summary.DisplayName}?\n\nNetGuard will remove its firewall rules for this application, so it can reach the network again until management is re-enabled.",
                "disable"))
        {
            return;
        }

        var revision = Detail.Summary.Revision;
        await RunAsync(async () => Detail = await Context.Client.SetEnabledAsync(Detail.Summary.Id, enable, revision),
            enable ? "Management enabled; restriction verified." : "Management disabled.", showDialogOnError: true);
        await LoadAsync();
    }

    private async Task GrantExceptionAsync()
    {
        if (Detail is null)
        {
            return;
        }

        var request = ExceptionDialog.Ask(Detail.Summary.DisplayName);
        if (request is null)
        {
            return;
        }

        await RunAsync(async () => Detail = await Context.Client.GrantExceptionAsync(Detail.Summary.Id, request.Value.Minutes, request.Value.Reason),
            "Temporary exception granted. The restriction is re-applied automatically when it expires.", showDialogOnError: true);
        await LoadAsync();
    }

    private async Task RevokeExceptionAsync()
    {
        if (Detail is null)
        {
            return;
        }

        await RunAsync(async () => Detail = await Context.Client.RevokeExceptionAsync(Detail.Summary.Id), "Exception revoked; restriction re-applied.", showDialogOnError: true);
        await LoadAsync();
    }

    private async Task RestoreAsync()
    {
        if (Detail is null)
        {
            return;
        }

        if (!Dialogs.Confirm("Restore previous state",
                $"Restore the firewall configuration for {Detail.Summary.DisplayName} to its state before NetGuard managed it?\n\n" +
                "Only rules created by NetGuard are removed. Rules created by you, your administrator or other software are not changed. The application stays in the list, disabled.",
                "restore"))
        {
            return;
        }

        var revision = Detail.Summary.Revision;
        await RunAsync(async () => Detail = await Context.Client.RestoreAsync(Detail.Summary.Id, revision), "Previous state restored.", showDialogOnError: true);
        await LoadAsync();
    }

    private async Task RemoveAsync()
    {
        if (Detail is null)
        {
            return;
        }

        if (!Dialogs.Confirm("Remove application",
                $"Stop managing {Detail.Summary.DisplayName} and remove it from NetGuard?\n\nIts NetGuard firewall rules are removed and verified absent first; if that fails, the application is kept (disabled) so its rules stay tracked.",
                "remove"))
        {
            return;
        }

        var revision = Detail.Summary.Revision;
        if (await RunAsync(() => Context.Client.RemoveAsync(Detail.Summary.Id, revision), "Application removed.", showDialogOnError: true))
        {
            Detail = null;
            await LoadAsync();
        }
    }

    private async Task ReverifyAsync()
    {
        ReconcileResultDto? result = null;
        if (await RunAsync(async () => result = await Context.Client.ReconcileAsync(), showDialogOnError: true) && result is not null)
        {
            StatusMessage = $"Verification complete: {result.RulesAdded} rule(s) re-created, {result.RulesUpdated} corrected, {result.RulesRemoved} removed, {result.Failures} failure(s).";
            await LoadAsync();
        }
    }

    private void OpenFolder()
    {
        var path = Detail?.Summary.PrimaryPath;
        if (path is not null && File.Exists(path))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = false });
        }
    }
}

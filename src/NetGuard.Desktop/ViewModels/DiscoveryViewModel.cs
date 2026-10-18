using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;
using NetGuard.Desktop.Views;

namespace NetGuard.Desktop.ViewModels;

public sealed class DiscoveryViewModel : PageViewModel
{
    private readonly ObservableCollection<DiscoveredApplicationDto> _items = [];
    private DiscoveredApplicationDto? _selected;
    private string _search = string.Empty;
    private bool _includeSystem;
    private bool _includeRunning = true;
    private bool _hideManaged = true;
    private bool _scanned;

    public DiscoveryViewModel(UiContext context)
        : base(context)
    {
        Items = CollectionViewSource.GetDefaultView(_items);
        Items.Filter = o => o is DiscoveredApplicationDto d &&
                            (!HideManaged || !d.IsManaged) &&
                            (string.IsNullOrWhiteSpace(SearchText) ||
                             d.Name.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ||
                             (d.Publisher?.Contains(SearchText, StringComparison.CurrentCultureIgnoreCase) ?? false) ||
                             d.Executables.Any(e => e.Path.Contains(SearchText, StringComparison.OrdinalIgnoreCase)));
        Items.SortDescriptions.Add(new SortDescription(nameof(DiscoveredApplicationDto.Name), ListSortDirection.Ascending));
        ScanCommand = new AsyncCommand(ScanAsync, () => Context.CanModify);
        ManageCommand = new AsyncCommand(ManageAsync, () => Context.CanModify && Selected is { IsManaged: false });
        BrowseCommand = new AsyncCommand(BrowseAsync, () => Context.CanModify);
    }

    public override string Title => "Application Discovery";

    public override string Glyph => "";

    public ICollectionView Items { get; }

    public DiscoveredApplicationDto? Selected
    {
        get => _selected;
        set => Set(ref _selected, value);
    }

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

    public bool IncludeSystemComponents
    {
        get => _includeSystem;
        set => Set(ref _includeSystem, value);
    }

    public bool IncludeRunningProcesses
    {
        get => _includeRunning;
        set => Set(ref _includeRunning, value);
    }

    public bool HideManaged
    {
        get => _hideManaged;
        set
        {
            if (Set(ref _hideManaged, value))
            {
                Items.Refresh();
            }
        }
    }

    public string Summary => _scanned
        ? $"{_items.Count} application(s) found · {_items.Count(i => i.IsRunning)} running · {_items.Count(i => i.IsManaged)} already managed · {_items.Count(i => i.IsPossibleDuplicate)} possible duplicates"
        : Context.CanModify ? "Select Scan to list installed and running applications." : "Discovery requires an administrator or NetGuard Operator.";

    public AsyncCommand ScanCommand { get; }

    public AsyncCommand ManageCommand { get; }

    public AsyncCommand BrowseCommand { get; }

    public override Task LoadAsync()
    {
        OnPropertyChanged(nameof(Summary));
        return Task.CompletedTask;
    }

    private async Task ScanAsync()
    {
        await RunAsync(async () =>
        {
            var result = await Context.Client.DiscoverAsync(new DiscoveryRequest
            {
                IncludeSystemComponents = IncludeSystemComponents,
                IncludeRunningProcesses = IncludeRunningProcesses,
            });
            _items.Clear();
            foreach (var item in result)
            {
                _items.Add(item);
            }

            _scanned = true;
            OnPropertyChanged(nameof(Summary));
        });
    }

    private async Task ManageAsync()
    {
        if (Selected is null)
        {
            return;
        }

        var inspections = new List<ExecutableInspectionDto>();
        var failures = new List<string>();
        foreach (var exe in Selected.Executables.Where(e => e.ManagedByApplicationId is null))
        {
            try
            {
                inspections.Add(await Context.Client.InspectAsync(exe.Path));
            }
            catch (Ipc.IpcException ex)
            {
                failures.Add($"{exe.Path}: {ex.Message}");
            }
        }

        if (inspections.Count == 0)
        {
            Dialogs.Error("Cannot manage application", "None of this application's executables can be managed.", failures);
            return;
        }

        // Put the running executable first: it is most likely the main program.
        inspections = inspections.OrderByDescending(i => Selected.Executables.Any(e => e.IsRunning && string.Equals(e.Path, i.CanonicalPath, StringComparison.OrdinalIgnoreCase))).ToList();
        var editor = PolicyEditorViewModel.ForNewApplication(Context, inspections);
        if (!string.IsNullOrWhiteSpace(Selected.Name))
        {
            editor.Name = Selected.Name;
        }

        if (PolicyEditorWindow.ShowEditor(editor) is ApplicationDetailDto added)
        {
            Context.Navigate(typeof(ApplicationsViewModel), added.Summary.Id);
        }
    }

    private async Task BrowseAsync()
    {
        var path = Dialogs.OpenExecutable();
        if (path is null)
        {
            return;
        }

        ExecutableInspectionDto? inspection = null;
        if (await RunAsync(async () => inspection = await Context.Client.InspectAsync(path), showDialogOnError: true) && inspection is not null)
        {
            if (inspection.ManagedByApplicationId is { } id)
            {
                Context.Navigate(typeof(ApplicationsViewModel), id);
                return;
            }

            if (PolicyEditorWindow.ShowEditor(PolicyEditorViewModel.ForNewApplication(Context, [inspection])) is ApplicationDetailDto added)
            {
                Context.Navigate(typeof(ApplicationsViewModel), added.Summary.Id);
            }
        }
    }
}

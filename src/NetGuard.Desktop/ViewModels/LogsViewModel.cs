using System.Collections.ObjectModel;
using System.Text.Json;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;
using NetGuard.Domain;

namespace NetGuard.Desktop.ViewModels;

public sealed class LogsViewModel : PageViewModel
{
    public const string FailuresFilter = "failures";
    private const int PageSize = 100;

    private string _search = string.Empty;
    private DateTime? _from;
    private DateTime? _to;
    private string _type = "All types";
    private string _outcome = "All outcomes";
    private Guid? _applicationId;
    private string? _applicationName;
    private int _skip;
    private int _total;
    private AuditEvent? _selected;

    public LogsViewModel(UiContext context)
        : base(context)
    {
        Types = ["All types", .. Enum.GetNames<AuditEventType>()];
        Outcomes = ["All outcomes", .. Enum.GetNames<AuditOutcome>()];
        SearchCommand = new AsyncCommand(() => QueryAsync(0));
        NextCommand = new AsyncCommand(() => QueryAsync(_skip + PageSize), () => _skip + PageSize < _total);
        PreviousCommand = new AsyncCommand(() => QueryAsync(Math.Max(0, _skip - PageSize)), () => _skip > 0);
        ClearFiltersCommand = new AsyncCommand(ClearAsync);
        ExportCsvCommand = new AsyncCommand(() => ExportAsync(ExportFormat.Csv));
        ExportJsonCommand = new AsyncCommand(() => ExportAsync(ExportFormat.Json));
    }

    public override string Title => "Activity Logs";

    public override string Glyph => "";

    public ObservableCollection<AuditEvent> Items { get; } = [];

    public IReadOnlyList<string> Types { get; }

    public IReadOnlyList<string> Outcomes { get; }

    public string SearchText
    {
        get => _search;
        set => Set(ref _search, value);
    }

    public DateTime? From
    {
        get => _from;
        set => Set(ref _from, value);
    }

    public DateTime? To
    {
        get => _to;
        set => Set(ref _to, value);
    }

    public string SelectedType
    {
        get => _type;
        set => Set(ref _type, value);
    }

    public string SelectedOutcome
    {
        get => _outcome;
        set => Set(ref _outcome, value);
    }

    public string? ApplicationFilterText => _applicationName is null ? null : $"Showing events for {_applicationName}";

    public string PageText => _total == 0 ? "No matching events" : $"{_skip + 1}–{Math.Min(_skip + PageSize, _total)} of {_total}";

    public AuditEvent? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                OnPropertyChanged(nameof(SelectedDetails));
            }
        }
    }

    public string? SelectedDetails
    {
        get
        {
            if (Selected?.Details is not { Length: > 0 } details)
            {
                return null;
            }

            try
            {
                using var document = JsonDocument.Parse(details);
                return JsonSerializer.Serialize(document.RootElement, NetGuardJson.Indented);
            }
            catch (JsonException)
            {
                return details;
            }
        }
    }

    public AsyncCommand SearchCommand { get; }

    public AsyncCommand NextCommand { get; }

    public AsyncCommand PreviousCommand { get; }

    public AsyncCommand ClearFiltersCommand { get; }

    public AsyncCommand ExportCsvCommand { get; }

    public AsyncCommand ExportJsonCommand { get; }

    public override async Task OnNavigatedToAsync(object? parameter)
    {
        _applicationId = null;
        _applicationName = null;
        switch (parameter)
        {
            case ApplicationSummaryDto app:
                _applicationId = app.Id;
                _applicationName = app.DisplayName;
                break;
            case FailuresFilter:
                SelectedOutcome = nameof(AuditOutcome.Failure);
                break;
        }

        OnPropertyChanged(nameof(ApplicationFilterText));
        await QueryAsync(0);
    }

    public override Task LoadAsync() => QueryAsync(_skip);

    private AuditQuery BuildQuery() => new()
    {
        Text = string.IsNullOrWhiteSpace(SearchText) ? null : SearchText.Trim(),
        From = From is { } f ? new DateTimeOffset(f.Date) : null,
        To = To is { } t ? new DateTimeOffset(t.Date.AddDays(1).AddTicks(-1)) : null,
        Types = Enum.TryParse<AuditEventType>(SelectedType, out var type) ? [type] : null,
        Outcomes = Enum.TryParse<AuditOutcome>(SelectedOutcome, out var outcome) ? [outcome] : null,
        ApplicationId = _applicationId,
    };

    private async Task QueryAsync(int skip)
    {
        await RunAsync(async () =>
        {
            var page = await Context.Client.QueryAuditAsync(BuildQuery() with { Skip = skip, Take = PageSize });
            _skip = skip;
            _total = page.TotalCount;
            Items.Clear();
            foreach (var item in page.Items)
            {
                Items.Add(item);
            }

            OnPropertyChanged(nameof(PageText));
        });
    }

    private async Task ClearAsync()
    {
        SearchText = string.Empty;
        From = To = null;
        SelectedType = Types[0];
        SelectedOutcome = Outcomes[0];
        _applicationId = null;
        _applicationName = null;
        OnPropertyChanged(nameof(ApplicationFilterText));
        await QueryAsync(0);
    }

    private async Task ExportAsync(ExportFormat format)
    {
        ExportResultDto? export = null;
        if (await RunAsync(async () => export = await Context.Client.ExportAuditAsync(BuildQuery(), format), showDialogOnError: true) && export is not null && Dialogs.SaveExport(export))
        {
            StatusMessage = $"Exported to {export.SuggestedFileName}.";
        }
    }
}

using System.Collections.ObjectModel;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;

namespace NetGuard.Desktop.ViewModels;

public sealed class DiagnosticsViewModel : PageViewModel
{
    private bool _redact = true;
    private ExportResultDto? _report;

    public DiagnosticsViewModel(UiContext context)
        : base(context)
    {
        GenerateCommand = new AsyncCommand(GenerateAsync);
        SaveCommand = new RelayCommand(() =>
        {
            if (_report is not null && Dialogs.SaveExport(_report))
            {
                StatusMessage = "Diagnostic report saved.";
            }
        }, () => _report is not null);
    }

    public override string Title => "Diagnostics";

    public override string Glyph => "";

    public ObservableCollection<ObservationDto> Observations { get; } = [];

    public bool Redact
    {
        get => _redact;
        set => Set(ref _redact, value);
    }

    public string? ReportText => _report?.Content;

    public string ServiceText => Context.Service is { } s
        ? $"Version {s.Version} (protocol {s.ProtocolVersion}) · started {s.StartedAt.ToLocalTime():g}\n" +
          $"Process monitoring: {s.MonitoringMode}\n" +
          $"Blocked-connection observation: {(s.BlockedConnectionAuditingAvailable ? "active (Windows Filtering Platform audit events)" : "unavailable — enable the 'Filtering Platform Connection' failure audit policy to observe blocked attempts")}\n" +
          (string.IsNullOrEmpty(s.DataDirectory) ? string.Empty : $"Data directory: {s.DataDirectory}")
        : "Not connected to the service.";

    public AsyncCommand GenerateCommand { get; }

    public RelayCommand SaveCommand { get; }

    public override async Task LoadAsync()
    {
        OnPropertyChanged(nameof(ServiceText));
        await RunAsync(async () =>
        {
            var items = await Context.Client.GetObservationsAsync();
            Observations.Clear();
            foreach (var item in items)
            {
                Observations.Add(item);
            }
        });
    }

    private async Task GenerateAsync()
    {
        if (await RunAsync(async () => _report = await Context.Client.GenerateDiagnosticsAsync(Redact), "Report generated. Review it before sharing.", showDialogOnError: true))
        {
            OnPropertyChanged(nameof(ReportText));
        }
    }
}

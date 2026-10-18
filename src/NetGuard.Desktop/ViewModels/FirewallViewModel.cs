using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;

namespace NetGuard.Desktop.ViewModels;

public sealed class FirewallViewModel : PageViewModel
{
    private FirewallOverviewDto? _overview;

    public FirewallViewModel(UiContext context)
        : base(context)
    {
        ReverifyCommand = new AsyncCommand(ReverifyAsync, () => Context.CanModify);
        CleanupCommand = new AsyncCommand(CleanupAsync, () => Context.CanAdminister && Overview?.OrphanedRules.Count > 0);
    }

    public override string Title => "Firewall Policies";

    public override string Glyph => "";

    public FirewallOverviewDto? Overview
    {
        get => _overview;
        private set => Set(ref _overview, value);
    }

    public IReadOnlyList<string> Limitations { get; } =
    [
        "Rules apply to executable paths. Traffic an application hands to another process (a Windows service such as BITS or the DNS Client, a browser, an updater, or a helper outside its folder) is governed by that process's rules.",
        "A blocked application can still resolve DNS names, because resolution is done by the DNS Client service; it cannot connect to the results.",
        "Loopback traffic (127.0.0.1 / ::1) is never filtered by Windows Firewall.",
        "Connections established before a rule was created may continue until they close. Restart the application for a clean state.",
        "Block rules created by NetGuard take precedence over allow rules. NetGuard never creates allow rules and never changes rules it does not own.",
    ];

    public AsyncCommand ReverifyCommand { get; }

    public AsyncCommand CleanupCommand { get; }

    public override async Task LoadAsync() =>
        await RunAsync(async () => Overview = await Context.Client.GetFirewallOverviewAsync());

    private async Task ReverifyAsync()
    {
        ReconcileResultDto? result = null;
        if (await RunAsync(async () => result = await Context.Client.ReconcileAsync(), showDialogOnError: true) && result is not null)
        {
            StatusMessage = $"Verified in {result.DurationMs} ms: {result.RulesAdded} re-created, {result.RulesUpdated} corrected, {result.RulesRemoved} removed, {result.Failures} failure(s), {result.OrphanedRules} orphaned.";
            await LoadAsync();
        }
    }

    private async Task CleanupAsync()
    {
        if (!Dialogs.Confirm("Remove orphaned rules",
                $"Remove {Overview?.OrphanedRules.Count} rule(s) that carry NetGuard's marker but belong to no managed application?\n\nThese are usually left over from a reinstalled or restored configuration. Programs they restrict will be able to connect again.",
                "remove them"))
        {
            return;
        }

        ReconcileResultDto? result = null;
        if (await RunAsync(async () => result = await Context.Client.CleanupOrphansAsync(), showDialogOnError: true) && result is not null)
        {
            StatusMessage = $"{result.RulesRemoved} orphaned rule(s) removed.";
            await LoadAsync();
        }
    }
}

using System.Collections.ObjectModel;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;
using NetGuard.Desktop.Views;
using NetGuard.Domain;

namespace NetGuard.Desktop.ViewModels;

public sealed class ProfilesViewModel : PageViewModel
{
    private ProfileDto? _selected;

    public ProfilesViewModel(UiContext context)
        : base(context)
    {
        NewCommand = new AsyncCommand(() => EditAsync(null), () => Context.CanModify);
        EditCommand = new AsyncCommand(() => EditAsync(Selected?.Profile), () => Context.CanModify && Selected is { Profile.Source: PolicySource.User });
        ToggleCommand = new AsyncCommand(ToggleAsync, () => Context.CanModify && Selected is { Profile.Source: PolicySource.User });
        DeleteCommand = new AsyncCommand(DeleteAsync, () => Context.CanModify && Selected is { Profile.IsBuiltIn: false, Profile.Source: PolicySource.User });
    }

    public override string Title => "Policy Profiles";

    public override string Glyph => "";

    public ObservableCollection<ProfileDto> Items { get; } = [];

    public ProfileDto? Selected
    {
        get => _selected;
        set
        {
            if (Set(ref _selected, value))
            {
                OnPropertyChanged(nameof(ToggleText));
            }
        }
    }

    public string ToggleText => Selected?.Profile.IsEnabled == true ? "Disable profile" : "Enable profile";

    public AsyncCommand NewCommand { get; }

    public AsyncCommand EditCommand { get; }

    public AsyncCommand ToggleCommand { get; }

    public AsyncCommand DeleteCommand { get; }

    public override async Task LoadAsync() => await RunAsync(async () => Replace(await Context.Client.ListProfilesAsync()));

    private void Replace(IReadOnlyList<ProfileDto> profiles)
    {
        var keep = Selected?.Profile.Id;
        Items.Clear();
        foreach (var profile in profiles)
        {
            Items.Add(profile);
        }

        Selected = Items.FirstOrDefault(p => p.Profile.Id == keep) ?? Items.FirstOrDefault();
    }

    private async Task EditAsync(PolicyProfile? profile)
    {
        if (PolicyEditorWindow.ShowEditor(PolicyEditorViewModel.ForProfile(Context, profile)) is List<ProfileDto> updated)
        {
            Replace(updated);
            StatusMessage = "Profile saved and policies re-applied.";
        }

        await Task.CompletedTask;
    }

    private async Task ToggleAsync()
    {
        if (Selected is null)
        {
            return;
        }

        var enable = !Selected.Profile.IsEnabled;
        var message = enable
            ? $"Enable '{Selected.Profile.Name}'? Its policy ({StatusText.Policy(Selected.Profile.Policy)}) will override the policy of {Selected.MemberCount} member application(s) until disabled."
            : $"Disable '{Selected.Profile.Name}'? Its {Selected.MemberCount} member application(s) will return to their own policies.";
        if (!Dialogs.Confirm(enable ? "Enable profile" : "Disable profile", message, enable ? "enable" : "disable"))
        {
            return;
        }

        var id = Selected.Profile.Id;
        await RunAsync(async () => Replace(await Context.Client.SetProfileEnabledAsync(id, enable)), "Profile updated and policies re-applied.", showDialogOnError: true);
    }

    private async Task DeleteAsync()
    {
        if (Selected is null || !Dialogs.Confirm("Delete profile", $"Delete '{Selected.Profile.Name}'? Member applications keep their own policies.", "delete"))
        {
            return;
        }

        var id = Selected.Profile.Id;
        await RunAsync(async () => Replace(await Context.Client.DeleteProfileAsync(id)), "Profile deleted.", showDialogOnError: true);
    }
}

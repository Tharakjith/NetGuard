using System.IO;
using NetGuard.Contracts;
using NetGuard.Desktop.Infrastructure;
using NetGuard.Desktop.Services;
using NetGuard.Ipc;

namespace NetGuard.Desktop.ViewModels;

/// <summary>Shared state available to every page.</summary>
public sealed class UiContext : ObservableObject
{
    private CallerDto _caller = new();
    private ServiceInfoDto? _service;

    public UiContext(NetGuardClient client, UserPreferences preferences)
    {
        Client = client;
        Preferences = preferences;
    }

    public NetGuardClient Client { get; }

    public UserPreferences Preferences { get; }

    public CallerDto Caller
    {
        get => _caller;
        set
        {
            if (Set(ref _caller, value))
            {
                OnPropertyChanged(nameof(CanModify));
                OnPropertyChanged(nameof(CanAdminister));
            }
        }
    }

    public bool CanModify => Caller.CanModify;

    public bool CanAdminister => Caller.CanAdminister;

    public ServiceInfoDto? Service
    {
        get => _service;
        set => Set(ref _service, value);
    }

    /// <summary>Set by the main view model; navigates to a page, optionally passing a parameter.</summary>
    public Action<Type, object?> Navigate { get; set; } = (_, _) => { };
}

public abstract class PageViewModel : ObservableObject
{
    private bool _isBusy;
    private string? _error;
    private string? _status;

    protected PageViewModel(UiContext context)
    {
        Context = context;
        RefreshCommand = new AsyncCommand(LoadAsync);
    }

    public UiContext Context { get; }

    public abstract string Title { get; }

    /// <summary>Segoe Fluent Icons glyph for navigation.</summary>
    public abstract string Glyph { get; }

    public AsyncCommand RefreshCommand { get; }

    public bool IsBusy
    {
        get => _isBusy;
        protected set => Set(ref _isBusy, value);
    }

    public string? ErrorMessage
    {
        get => _error;
        protected set => Set(ref _error, value);
    }

    public string? StatusMessage
    {
        get => _status;
        protected set => Set(ref _status, value);
    }

    public abstract Task LoadAsync();

    /// <summary>Called when navigated to with a parameter (for example an application id).</summary>
    public virtual Task OnNavigatedToAsync(object? parameter) => LoadAsync();

    /// <summary>Runs a service call with consistent busy/error handling. Returns false on failure.</summary>
    protected async Task<bool> RunAsync(Func<Task> action, string? successMessage = null, bool showDialogOnError = false)
    {
        IsBusy = true;
        ErrorMessage = null;
        try
        {
            await action();
            if (successMessage is not null)
            {
                StatusMessage = successMessage;
            }

            return true;
        }
        catch (IpcException ex)
        {
            ErrorMessage = ex.ValidationErrors.Count > 0 ? $"{ex.Message}" : ex.Message;
            if (showDialogOnError || ex.ValidationErrors.Count > 0)
            {
                Dialogs.Error(Title, ex.Message, ex.ValidationErrors);
            }

            return false;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            ErrorMessage = ex.Message;
            if (showDialogOnError)
            {
                Dialogs.Error(Title, ex.Message);
            }

            return false;
        }
        finally
        {
            IsBusy = false;
        }
    }
}

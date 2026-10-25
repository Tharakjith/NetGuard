using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core.Auditing;
using NetGuard.Core.Configuration;
using NetGuard.Core.Security;
using NetGuard.Domain;

namespace NetGuard.Service;

/// <summary>
/// Applies administrator-enforced organization policy from %ProgramData%\NetGuard\Policies\organization-policy.json.
/// The folder is writable only by SYSTEM and Administrators, so device-management tools (Group Policy file
/// preferences, Intune, SCCM) can deploy it while local users cannot alter it. Organization-sourced applications and
/// profiles are read-only in the desktop interface. Removing the file removes the organization policies.
/// This is the extension point for centralized policy distribution.
/// </summary>
public sealed class OrganizationPolicyLoader : IDisposable
{
    public const string FileName = "organization-policy.json";

    private static readonly ActorContext OrganizationActor = ActorContext.System with { Name = "organization-policy" };

    private readonly ServicePaths _paths;
    private readonly ConfigurationPorter _porter;
    private readonly AuditWriter _audit;
    private readonly ILogger<OrganizationPolicyLoader> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private FileSystemWatcher? _watcher;
    private CancellationTokenSource? _debounce;
    private CancellationToken _stopping;

    public OrganizationPolicyLoader(ServicePaths paths, ConfigurationPorter porter, AuditWriter audit, ILogger<OrganizationPolicyLoader> logger)
    {
        _paths = paths;
        _porter = porter;
        _audit = audit;
        _logger = logger;
    }

    private string PolicyFile => Path.Combine(_paths.Policies, FileName);

    private string MarkerFile => Path.Combine(_paths.Data, "organization-policy.applied");

    public async Task StartAsync(CancellationToken stoppingToken)
    {
        _stopping = stoppingToken;
        Directory.CreateDirectory(_paths.Policies);
        await ApplyAsync().ConfigureAwait(false);

        _watcher = new FileSystemWatcher(_paths.Policies, FileName)
        {
            NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
        };
        _watcher.Changed += (_, _) => Schedule();
        _watcher.Created += (_, _) => Schedule();
        _watcher.Deleted += (_, _) => Schedule();
        _watcher.Renamed += (_, _) => Schedule();
        _watcher.EnableRaisingEvents = true;
    }

    /// <summary>Idempotent: the worker disposes this on shutdown and the host's service provider disposes it again.</summary>
    public void Dispose()
    {
        _watcher?.Dispose();
        _watcher = null;
        var debounce = Interlocked.Exchange(ref _debounce, null);
        debounce?.Cancel();
        debounce?.Dispose();
    }

    private void Schedule()
    {
        _debounce?.Cancel();
        _debounce = CancellationTokenSource.CreateLinkedTokenSource(_stopping);
        var token = _debounce.Token;
        _ = Task.Run(async () =>
        {
            try
            {
                // Deployment tools often write files in several steps; wait for the writes to settle.
                await Task.Delay(TimeSpan.FromSeconds(2), token).ConfigureAwait(false);
                await ApplyAsync().ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }, CancellationToken.None);
    }

    private async Task ApplyAsync()
    {
        await _gate.WaitAsync(_stopping).ConfigureAwait(false);
        try
        {
            string json;
            if (File.Exists(PolicyFile))
            {
                json = await File.ReadAllTextAsync(PolicyFile, _stopping).ConfigureAwait(false);
            }
            else if (File.Exists(MarkerFile))
            {
                // The file was removed: replace organization policy with an empty document to retire it.
                json = $$"""{"schemaVersion":{{PolicyDocument.CurrentSchemaVersion}},"scope":"organization","applications":[],"profiles":[]}""";
            }
            else
            {
                return;
            }

            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));
            if (File.Exists(MarkerFile) && (await File.ReadAllTextAsync(MarkerFile, _stopping).ConfigureAwait(false)).Trim() == hash)
            {
                return;
            }

            var result = await _porter.ImportAsync(json, ImportMode.Replace, dryRun: false, PolicySource.Organization, OrganizationActor, _stopping).ConfigureAwait(false);
            if (result.Applied)
            {
                await File.WriteAllTextAsync(MarkerFile, hash, _stopping).ConfigureAwait(false);
                if (!File.Exists(PolicyFile))
                {
                    File.Delete(MarkerFile);
                }

                _logger.LogInformation("Organization policy applied: {Added} added, {Updated} updated, {Removed} removed",
                    result.AddedApplications.Count, result.UpdatedApplications.Count, result.RemovedApplications.Count);
            }
            else
            {
                await _audit.WriteAsync(AuditEventType.ConfigurationImported, AuditOutcome.Failure,
                    $"Organization policy file was rejected and not applied: {string.Join(" ", result.Errors.Take(5))}", OrganizationActor.Name,
                    cancellationToken: _stopping).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _logger.LogError(ex, "Organization policy could not be read");
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            _gate.Release();
        }
    }
}

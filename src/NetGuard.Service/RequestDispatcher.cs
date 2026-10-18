using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Auditing;
using NetGuard.Core.Configuration;
using NetGuard.Core.Diagnostics;
using NetGuard.Core.Events;
using NetGuard.Core.Monitoring;
using NetGuard.Core.Policies;
using NetGuard.Core.Queries;
using NetGuard.Core.Security;
using NetGuard.Domain;
using NetGuard.Ipc;

namespace NetGuard.Service;

/// <summary>
/// Validates, authorizes and routes every control-pipe request. The caller's identity comes only from the pipe
/// client token. Each command has exactly one required permission (see <see cref="CommandPermissions"/>).
/// </summary>
public sealed class RequestDispatcher : IPipeRequestHandler
{
    private readonly IPolicyStore _store;
    private readonly IAuditLog _auditLog;
    private readonly AuditWriter _audit;
    private readonly PolicyService _policies;
    private readonly QueryService _queries;
    private readonly ConfigurationPorter _configuration;
    private readonly DiagnosticReportBuilder _diagnostics;
    private readonly EventBroker _events;
    private readonly ObservationLog _observations;
    private readonly IClock _clock;
    private readonly ILogger<RequestDispatcher> _logger;
    private readonly ConcurrentDictionary<(string, string), DateTimeOffset> _deniedAudited = new();

    public RequestDispatcher(
        IPolicyStore store,
        IAuditLog auditLog,
        AuditWriter audit,
        PolicyService policies,
        QueryService queries,
        ConfigurationPorter configuration,
        DiagnosticReportBuilder diagnostics,
        EventBroker events,
        ObservationLog observations,
        IClock clock,
        ILogger<RequestDispatcher> logger)
    {
        _store = store;
        _auditLog = auditLog;
        _audit = audit;
        _policies = policies;
        _queries = queries;
        _configuration = configuration;
        _diagnostics = diagnostics;
        _events = events;
        _observations = observations;
        _clock = clock;
        _logger = logger;
    }

    public static ActorContext ToActor(PipeCaller caller) => new()
    {
        Name = caller.Name,
        Sid = caller.Sid,
        IsElevatedAdministrator = caller.IsElevatedAdministrator,
        IsOperator = caller.IsOperator,
        IsSystem = caller.IsLocalSystem,
    };

    public async Task<IpcResponse> HandleAsync(IpcRequest request, PipeCaller caller, CancellationToken cancellationToken)
    {
        if (request.ProtocolVersion != IpcConstants.ProtocolVersion)
        {
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.ProtocolMismatch,
                $"Protocol version {request.ProtocolVersion} is not supported (service uses {IpcConstants.ProtocolVersion}). Update NetGuard Enterprise so both components match.");
        }

        if (!CommandPermissions.TryGet(request.Command, out var permission))
        {
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.UnknownCommand, $"Unknown command '{request.Command}'.");
        }

        var actor = ToActor(caller);
        try
        {
            var settings = await _store.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
            if (!actor.Has(permission, settings))
            {
                return await DenyAsync(request, actor, permission, cancellationToken).ConfigureAwait(false);
            }

            var result = await DispatchAsync(request, actor, cancellationToken).ConfigureAwait(false);
            return IpcResponse.Ok(request.RequestId, result is null ? null : JsonSerializer.SerializeToElement(result, NetGuardJson.Options));
        }
        catch (DomainValidationException ex)
        {
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.ValidationFailed, ex.Message, ex.Errors);
        }
        catch (AuthorizationException ex)
        {
            await _audit.WriteAsync(AuditEventType.AuthorizationDenied, AuditOutcome.Denied, $"{request.Command}: {ex.Message}", actor.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.Unauthorized, ex.Message);
        }
        catch (NetGuardException ex)
        {
            return IpcResponse.Fail(request.RequestId, ex.Code, ex.Message);
        }
        catch (ConcurrencyException ex)
        {
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.Conflict, ex.Message);
        }
        catch (Exception ex) when (ex is FirewallUnavailableException or FirewallOperationException)
        {
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.FirewallUnavailable, ex.Message);
        }
        catch (JsonException ex)
        {
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.BadRequest, $"Invalid request payload: {ex.Message}");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Command {Command} from {Caller} failed", request.Command, actor.Name);
            await _audit.WriteAsync(AuditEventType.Error, AuditOutcome.Failure, $"{request.Command} failed: {ex.Message}", actor.Name, cancellationToken: cancellationToken).ConfigureAwait(false);
            return IpcResponse.Fail(request.RequestId, IpcErrorCodes.InternalError, "An internal error occurred. Details were written to the service log.");
        }
    }

    private async Task<object?> DispatchAsync(IpcRequest request, ActorContext actor, CancellationToken ct)
    {
        switch (request.Command)
        {
            case Commands.GetServiceInfo:
                return await _queries.GetServiceInfoAsync(actor, ct).ConfigureAwait(false);
            case Commands.GetDashboard:
                return await _queries.GetDashboardAsync(actor, ct).ConfigureAwait(false);
            case Commands.ListApplications:
                return await _queries.ListApplicationsAsync(ct).ConfigureAwait(false);
            case Commands.GetApplication:
                return await _queries.GetApplicationAsync(Payload<ApplicationIdRequest>(request).Id, ct).ConfigureAwait(false);

            case Commands.AddApplication:
            {
                var id = await _policies.AddApplicationAsync(Payload<AddApplicationRequest>(request), actor, ct).ConfigureAwait(false);
                return await _queries.GetApplicationAsync(id, ct).ConfigureAwait(false);
            }

            case Commands.UpdateApplication:
            {
                var payload = Payload<UpdateApplicationRequest>(request);
                await _policies.UpdateApplicationAsync(payload, actor, ct).ConfigureAwait(false);
                return await _queries.GetApplicationAsync(payload.Id, ct).ConfigureAwait(false);
            }

            case Commands.SetApplicationEnabled:
            {
                var payload = Payload<SetEnabledRequest>(request);
                await _policies.SetEnabledAsync(payload, actor, ct).ConfigureAwait(false);
                return await _queries.GetApplicationAsync(payload.Id, ct).ConfigureAwait(false);
            }

            case Commands.RestoreApplication:
            {
                var payload = Payload<ApplicationIdRequest>(request);
                await _policies.RestoreApplicationAsync(payload, actor, ct).ConfigureAwait(false);
                return await _queries.GetApplicationAsync(payload.Id, ct).ConfigureAwait(false);
            }

            case Commands.RemoveApplication:
                await _policies.RemoveApplicationAsync(Payload<ApplicationIdRequest>(request), actor, ct).ConfigureAwait(false);
                return null;

            case Commands.GrantTemporaryException:
            {
                var payload = Payload<TemporaryExceptionRequest>(request);
                await _policies.GrantTemporaryExceptionAsync(payload, actor, ct).ConfigureAwait(false);
                return await _queries.GetApplicationAsync(payload.Id, ct).ConfigureAwait(false);
            }

            case Commands.RevokeTemporaryException:
            {
                var payload = Payload<ApplicationIdRequest>(request);
                await _policies.RevokeTemporaryExceptionAsync(payload, actor, ct).ConfigureAwait(false);
                return await _queries.GetApplicationAsync(payload.Id, ct).ConfigureAwait(false);
            }

            case Commands.InspectExecutable:
                return await _policies.InspectAsync(Payload<InspectExecutableRequest>(request).Path, ct).ConfigureAwait(false);
            case Commands.ScanInstallDirectory:
                return await _policies.ScanDirectoryAsync(Payload<ScanDirectoryRequest>(request).Directory, ct).ConfigureAwait(false);
            case Commands.DiscoverApplications:
                return await _policies.DiscoverAsync(PayloadOrDefault<DiscoveryRequest>(request) ?? new DiscoveryRequest(), actor, ct).ConfigureAwait(false);

            case Commands.ListProfiles:
                return await ListProfilesAsync(ct).ConfigureAwait(false);
            case Commands.SaveProfile:
                await _policies.SaveProfileAsync(Payload<SaveProfileRequest>(request).Profile ?? throw new DomainValidationException("Profile is required."), actor, ct).ConfigureAwait(false);
                return await ListProfilesAsync(ct).ConfigureAwait(false);
            case Commands.DeleteProfile:
                await _policies.DeleteProfileAsync(Payload<ProfileIdRequest>(request).Id, actor, ct).ConfigureAwait(false);
                return await ListProfilesAsync(ct).ConfigureAwait(false);
            case Commands.SetProfileEnabled:
                await _policies.SetProfileEnabledAsync(Payload<SetProfileEnabledRequest>(request), actor, ct).ConfigureAwait(false);
                return await ListProfilesAsync(ct).ConfigureAwait(false);

            case Commands.GetFirewallOverview:
                return await _queries.GetFirewallOverviewAsync(ct).ConfigureAwait(false);
            case Commands.Reconcile:
                return (await _policies.ReconcileAsync(actor, removeOrphans: false, ct).ConfigureAwait(false)).ToDto();
            case Commands.CleanupOrphanedRules:
                return (await _policies.ReconcileAsync(actor, removeOrphans: true, ct).ConfigureAwait(false)).ToDto();

            case Commands.QueryAudit:
            {
                var query = PayloadOrDefault<AuditQuery>(request) ?? new AuditQuery();
                var page = await _auditLog.QueryAsync(query with { Take = Math.Clamp(query.Take, 1, 1000) }, ct).ConfigureAwait(false);
                return new AuditPageDto { Items = page.Items, TotalCount = page.TotalCount };
            }

            case Commands.ExportAudit:
            {
                var payload = PayloadOrDefault<AuditExportRequest>(request) ?? new AuditExportRequest();
                var page = await _auditLog.QueryAsync(payload.Query with { Skip = 0, Take = AuditExporter.MaxExportRows }, ct).ConfigureAwait(false);
                await _audit.WriteAsync(AuditEventType.ConfigurationExported, AuditOutcome.Info, $"Activity log exported ({page.Items.Count} record(s), {payload.Format}).", actor.Name, cancellationToken: ct).ConfigureAwait(false);
                return AuditExporter.Export(page.Items, payload.Format, _clock.UtcNow);
            }

            case Commands.GenerateDiagnostics:
                return await _diagnostics.BuildAsync(PayloadOrDefault<DiagnosticsRequest>(request) ?? new DiagnosticsRequest(), actor, ct).ConfigureAwait(false);

            case Commands.GetSettings:
                return await _store.GetSettingsAsync(ct).ConfigureAwait(false);
            case Commands.UpdateSettings:
                return await _policies.UpdateSettingsAsync(Payload<ServiceSettings>(request), actor, ct).ConfigureAwait(false);

            case Commands.ExportConfiguration:
                return await _configuration.ExportAsync(PayloadOrDefault<ConfigurationExportRequest>(request) ?? new ConfigurationExportRequest(), actor, ct).ConfigureAwait(false);
            case Commands.ImportConfiguration:
            {
                var payload = Payload<ConfigurationImportRequest>(request);
                return await _configuration.ImportAsync(payload.Json, payload.Mode, payload.DryRun, PolicySource.User, actor, ct).ConfigureAwait(false);
            }

            case Commands.CreateBackup:
                return await _policies.CreateBackupAsync(actor, ct).ConfigureAwait(false);

            case Commands.WaitForEvents:
            {
                var payload = PayloadOrDefault<WaitForEventsRequest>(request) ?? new WaitForEventsRequest();
                return await _events.WaitAsync(payload.AfterSequence, TimeSpan.FromSeconds(Math.Clamp(payload.TimeoutSeconds, 0, 30)), ct).ConfigureAwait(false);
            }

            case Commands.GetObservations:
                return _observations.GetAll(PayloadOrDefault<ApplicationIdRequest>(request)?.Id is { } appId && appId != Guid.Empty ? appId : null);

            default:
                throw new NetGuardException(IpcErrorCodes.UnknownCommand, $"Unknown command '{request.Command}'.");
        }
    }

    private async Task<IReadOnlyList<ProfileDto>> ListProfilesAsync(CancellationToken ct)
    {
        var profiles = await _store.GetProfilesAsync(ct).ConfigureAwait(false);
        var applications = await _store.GetApplicationsAsync(ct).ConfigureAwait(false);
        return profiles.Select(p => new ProfileDto
        {
            Profile = p,
            MemberCount = applications.Count(a => a.ProfileId == p.Id),
            MemberNames = applications.Where(a => a.ProfileId == p.Id).Select(a => a.DisplayName).ToList(),
        }).ToList();
    }

    private async Task<IpcResponse> DenyAsync(IpcRequest request, ActorContext actor, Permission permission, CancellationToken ct)
    {
        var message = permission switch
        {
            Permission.Read => "Viewing NetGuard status is restricted to administrators and NetGuard Operators on this computer.",
            Permission.Modify => "Changing policies requires an elevated administrator or membership in the local 'NetGuard Operators' group. Use 'Restart as administrator'.",
            _ => "This operation requires an elevated administrator. Use 'Restart as administrator'.",
        };

        // Audit each (caller, command) denial at most once a minute so a misbehaving client cannot flood the log.
        var key = (actor.Sid ?? actor.Name, request.Command);
        var now = _clock.UtcNow;
        if (!_deniedAudited.TryGetValue(key, out var last) || now - last > TimeSpan.FromMinutes(1))
        {
            _deniedAudited[key] = now;
            await _audit.WriteAsync(AuditEventType.AuthorizationDenied, AuditOutcome.Denied,
                $"{request.Command} denied: requires {permission} permission.", actor.Name,
                details: new { request.Command, actor.IsElevatedAdministrator, actor.IsOperator }, cancellationToken: ct).ConfigureAwait(false);
        }

        return IpcResponse.Fail(request.RequestId, IpcErrorCodes.Unauthorized, message);
    }

    private static T Payload<T>(IpcRequest request)
        where T : class =>
        PayloadOrDefault<T>(request) ?? throw new DomainValidationException($"The {request.Command} request requires a payload.");

    private static T? PayloadOrDefault<T>(IpcRequest request)
        where T : class =>
        request.Payload is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined } element
            ? element.Deserialize<T>(NetGuardJson.Options)
            : null;
}

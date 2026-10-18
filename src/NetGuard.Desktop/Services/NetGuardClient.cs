using NetGuard.Contracts;
using NetGuard.Domain;
using NetGuard.Ipc;

namespace NetGuard.Desktop.Services;

/// <summary>Typed wrapper over the control pipe. All authorization decisions are made by the service.</summary>
public sealed class NetGuardClient : IAsyncDisposable
{
    private readonly PipeClient _pipe = new(PipeTrust.Options);

    public Task<ServiceInfoDto> GetServiceInfoAsync(CancellationToken ct = default) => _pipe.SendAsync<ServiceInfoDto>(Commands.GetServiceInfo, null, ct);

    public Task<DashboardDto> GetDashboardAsync(CancellationToken ct = default) => _pipe.SendAsync<DashboardDto>(Commands.GetDashboard, null, ct);

    public Task<List<ApplicationSummaryDto>> ListApplicationsAsync(CancellationToken ct = default) => _pipe.SendAsync<List<ApplicationSummaryDto>>(Commands.ListApplications, null, ct);

    public Task<ApplicationDetailDto> GetApplicationAsync(Guid id, CancellationToken ct = default) =>
        _pipe.SendAsync<ApplicationDetailDto>(Commands.GetApplication, new ApplicationIdRequest { Id = id }, ct);

    public Task<ApplicationDetailDto> AddApplicationAsync(AddApplicationRequest request, CancellationToken ct = default) =>
        _pipe.SendAsync<ApplicationDetailDto>(Commands.AddApplication, request, ct);

    public Task<ApplicationDetailDto> UpdateApplicationAsync(UpdateApplicationRequest request, CancellationToken ct = default) =>
        _pipe.SendAsync<ApplicationDetailDto>(Commands.UpdateApplication, request, ct);

    public Task<ApplicationDetailDto> SetEnabledAsync(Guid id, bool enabled, long revision, CancellationToken ct = default) =>
        _pipe.SendAsync<ApplicationDetailDto>(Commands.SetApplicationEnabled, new SetEnabledRequest { Id = id, Enabled = enabled, ExpectedRevision = revision }, ct);

    public Task<ApplicationDetailDto> RestoreAsync(Guid id, long revision, CancellationToken ct = default) =>
        _pipe.SendAsync<ApplicationDetailDto>(Commands.RestoreApplication, new ApplicationIdRequest { Id = id, ExpectedRevision = revision }, ct);

    public Task RemoveAsync(Guid id, long revision, CancellationToken ct = default) =>
        _pipe.SendAsync(Commands.RemoveApplication, new ApplicationIdRequest { Id = id, ExpectedRevision = revision }, ct);

    public Task<ApplicationDetailDto> GrantExceptionAsync(Guid id, int minutes, string reason, CancellationToken ct = default) =>
        _pipe.SendAsync<ApplicationDetailDto>(Commands.GrantTemporaryException, new TemporaryExceptionRequest { Id = id, DurationMinutes = minutes, Reason = reason }, ct);

    public Task<ApplicationDetailDto> RevokeExceptionAsync(Guid id, CancellationToken ct = default) =>
        _pipe.SendAsync<ApplicationDetailDto>(Commands.RevokeTemporaryException, new ApplicationIdRequest { Id = id }, ct);

    public Task<ExecutableInspectionDto> InspectAsync(string path, CancellationToken ct = default) =>
        _pipe.SendAsync<ExecutableInspectionDto>(Commands.InspectExecutable, new InspectExecutableRequest { Path = path }, ct);

    public Task<List<RelatedExecutableDto>> ScanDirectoryAsync(string directory, CancellationToken ct = default) =>
        _pipe.SendAsync<List<RelatedExecutableDto>>(Commands.ScanInstallDirectory, new ScanDirectoryRequest { Directory = directory }, ct);

    public Task<List<DiscoveredApplicationDto>> DiscoverAsync(DiscoveryRequest request, CancellationToken ct = default) =>
        _pipe.SendAsync<List<DiscoveredApplicationDto>>(Commands.DiscoverApplications, request, ct);

    public Task<List<ProfileDto>> ListProfilesAsync(CancellationToken ct = default) => _pipe.SendAsync<List<ProfileDto>>(Commands.ListProfiles, null, ct);

    public Task<List<ProfileDto>> SaveProfileAsync(PolicyProfile profile, CancellationToken ct = default) =>
        _pipe.SendAsync<List<ProfileDto>>(Commands.SaveProfile, new SaveProfileRequest { Profile = profile }, ct);

    public Task<List<ProfileDto>> DeleteProfileAsync(Guid id, CancellationToken ct = default) =>
        _pipe.SendAsync<List<ProfileDto>>(Commands.DeleteProfile, new ProfileIdRequest { Id = id }, ct);

    public Task<List<ProfileDto>> SetProfileEnabledAsync(Guid id, bool enabled, CancellationToken ct = default) =>
        _pipe.SendAsync<List<ProfileDto>>(Commands.SetProfileEnabled, new SetProfileEnabledRequest { Id = id, Enabled = enabled }, ct);

    public Task<FirewallOverviewDto> GetFirewallOverviewAsync(CancellationToken ct = default) => _pipe.SendAsync<FirewallOverviewDto>(Commands.GetFirewallOverview, null, ct);

    public Task<ReconcileResultDto> ReconcileAsync(CancellationToken ct = default) => _pipe.SendAsync<ReconcileResultDto>(Commands.Reconcile, null, ct);

    public Task<ReconcileResultDto> CleanupOrphansAsync(CancellationToken ct = default) => _pipe.SendAsync<ReconcileResultDto>(Commands.CleanupOrphanedRules, null, ct);

    public Task<AuditPageDto> QueryAuditAsync(AuditQuery query, CancellationToken ct = default) => _pipe.SendAsync<AuditPageDto>(Commands.QueryAudit, query, ct);

    public Task<ExportResultDto> ExportAuditAsync(AuditQuery query, ExportFormat format, CancellationToken ct = default) =>
        _pipe.SendAsync<ExportResultDto>(Commands.ExportAudit, new AuditExportRequest { Query = query, Format = format }, ct);

    public Task<ExportResultDto> GenerateDiagnosticsAsync(bool redact, CancellationToken ct = default) =>
        _pipe.SendAsync<ExportResultDto>(Commands.GenerateDiagnostics, new DiagnosticsRequest { Redact = redact }, ct);

    public Task<ServiceSettings> GetSettingsAsync(CancellationToken ct = default) => _pipe.SendAsync<ServiceSettings>(Commands.GetSettings, null, ct);

    public Task<ServiceSettings> UpdateSettingsAsync(ServiceSettings settings, CancellationToken ct = default) =>
        _pipe.SendAsync<ServiceSettings>(Commands.UpdateSettings, settings, ct);

    public Task<ExportResultDto> ExportConfigurationAsync(bool includeSettings, CancellationToken ct = default) =>
        _pipe.SendAsync<ExportResultDto>(Commands.ExportConfiguration, new ConfigurationExportRequest { IncludeSettings = includeSettings }, ct);

    public Task<ImportResultDto> ImportConfigurationAsync(string json, ImportMode mode, bool dryRun, CancellationToken ct = default) =>
        _pipe.SendAsync<ImportResultDto>(Commands.ImportConfiguration, new ConfigurationImportRequest { Json = json, Mode = mode, DryRun = dryRun }, ct);

    public Task<BackupResultDto> CreateBackupAsync(CancellationToken ct = default) => _pipe.SendAsync<BackupResultDto>(Commands.CreateBackup, null, ct);

    public Task<List<ObservationDto>> GetObservationsAsync(Guid? applicationId = null, CancellationToken ct = default) =>
        _pipe.SendAsync<List<ObservationDto>>(Commands.GetObservations, applicationId is null ? null : new ApplicationIdRequest { Id = applicationId.Value }, ct);

    public ValueTask DisposeAsync() => _pipe.DisposeAsync();
}

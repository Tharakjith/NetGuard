using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;

namespace NetGuard.Core.Auditing;

/// <summary>
/// Writes audit records to the audit store and mirrors them to the structured log. Audit failures are logged but
/// never interrupt enforcement; the structured log remains as a fallback record.
/// </summary>
public sealed class AuditWriter
{
    private readonly IAuditLog _log;
    private readonly IClock _clock;
    private readonly ILogger<AuditWriter> _logger;

    public AuditWriter(IAuditLog log, IClock clock, ILogger<AuditWriter> logger)
    {
        _log = log;
        _clock = clock;
        _logger = logger;
    }

    public async Task WriteAsync(
        AuditEventType type,
        AuditOutcome outcome,
        string message,
        string actor = "system",
        ManagedApplication? application = null,
        string? executablePath = null,
        object? details = null,
        CancellationToken cancellationToken = default)
    {
        var record = new AuditEvent
        {
            Timestamp = _clock.UtcNow,
            Type = type,
            Outcome = outcome,
            Actor = actor,
            ApplicationId = application?.Id,
            ApplicationName = application?.DisplayName,
            ExecutablePath = executablePath ?? application?.PrimaryExecutable?.Path,
            Message = message,
            Details = details is null ? null : JsonSerializer.Serialize(details, NetGuardJson.Options),
        };

        var level = outcome switch
        {
            AuditOutcome.Failure => LogLevel.Error,
            AuditOutcome.Denied or AuditOutcome.Warning => LogLevel.Warning,
            _ => LogLevel.Information,
        };

        _logger.Log(
            level,
            "Audit {AuditType} {AuditOutcome} actor={Actor} app={ApplicationName} path={ExecutablePath}: {Message}",
            type,
            outcome,
            actor,
            record.ApplicationName,
            record.ExecutablePath,
            message);

        try
        {
            await _log.AppendAsync(record, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Failed to persist audit record {AuditType}", type);
        }
    }
}

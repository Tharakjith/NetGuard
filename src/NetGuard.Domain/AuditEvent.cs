namespace NetGuard.Domain;

/// <summary>An immutable audit record. Never contains credentials, tokens or file contents.</summary>
public sealed record AuditEvent
{
    public long Id { get; init; }

    public DateTimeOffset Timestamp { get; init; }

    public AuditEventType Type { get; init; }

    public AuditOutcome Outcome { get; init; }

    /// <summary>Account that caused the event, or "system" for service-initiated work.</summary>
    public string Actor { get; init; } = "system";

    public Guid? ApplicationId { get; init; }

    public string? ApplicationName { get; init; }

    public string? ExecutablePath { get; init; }

    public string Message { get; init; } = string.Empty;

    /// <summary>Optional structured diagnostic details serialized as JSON.</summary>
    public string? Details { get; init; }
}

public sealed record AuditQuery
{
    public string? Text { get; init; }

    public DateTimeOffset? From { get; init; }

    public DateTimeOffset? To { get; init; }

    public IReadOnlyList<AuditEventType>? Types { get; init; }

    public IReadOnlyList<AuditOutcome>? Outcomes { get; init; }

    public Guid? ApplicationId { get; init; }

    public int Skip { get; init; }

    public int Take { get; init; } = 200;
}

/// <summary>Service-wide settings. Changing them requires administrator authorization.</summary>
public sealed record ServiceSettings
{
    public int AuditRetentionDays { get; init; } = 180;

    public int LogRetentionDays { get; init; } = 30;

    /// <summary>How often the service re-reads its rules from the firewall to detect drift.</summary>
    public int IntegrityCheckIntervalMinutes { get; init; } = 5;

    /// <summary>Delay before removing WhileRunning rules after the last instance exits (absorbs rapid restarts).</summary>
    public int WhileRunningGraceSeconds { get; init; } = 5;

    /// <summary>Whether standard (non-operator) users may read status and logs.</summary>
    public bool AllowStandardUserRead { get; init; } = true;

    /// <summary>Subscribe to Windows Filtering Platform audit events (5157) when the system audit policy enables them.</summary>
    public bool ObserveBlockedConnections { get; init; } = true;

    public RetentionMode DefaultRetention { get; init; } = RetentionMode.Persistent;

    public int MaxTemporaryExceptionMinutes { get; init; } = (int)TemporaryException.MaximumDuration.TotalMinutes;

    public ServiceSettings Validate()
    {
        var errors = new List<string>();
        if (AuditRetentionDays is < 7 or > 3650)
        {
            errors.Add("Audit retention must be between 7 and 3650 days.");
        }

        if (LogRetentionDays is < 1 or > 365)
        {
            errors.Add("Log retention must be between 1 and 365 days.");
        }

        if (IntegrityCheckIntervalMinutes is < 1 or > 1440)
        {
            errors.Add("Integrity check interval must be between 1 and 1440 minutes.");
        }

        if (WhileRunningGraceSeconds is < 0 or > 300)
        {
            errors.Add("While-running grace period must be between 0 and 300 seconds.");
        }

        if (MaxTemporaryExceptionMinutes is < 1 or > 24 * 60)
        {
            errors.Add("Maximum temporary exception must be between 1 and 1440 minutes.");
        }

        if (errors.Count > 0)
        {
            throw new DomainValidationException(errors);
        }

        return this;
    }
}

namespace NetGuard.Domain;

/// <summary>An executable file that belongs to a managed application, with the identity recorded when it was added.</summary>
public sealed record ManagedExecutable
{
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>Canonical (final, symlink-resolved) absolute path. Rules are scoped to exactly this path.</summary>
    public required string Path { get; init; }

    public bool IsPrimary { get; init; }

    public ExecutableOrigin Origin { get; init; } = ExecutableOrigin.UserSelected;

    public string? Sha256 { get; init; }

    public long? FileSize { get; init; }

    public string? FileVersion { get; init; }

    public string? ProductName { get; init; }

    public string? CompanyName { get; init; }

    public string? OriginalFileName { get; init; }

    public SignatureStatus SignatureStatus { get; init; }

    public string? SignerSubject { get; init; }

    public string? SignerThumbprint { get; init; }

    public DateTimeOffset AddedAt { get; init; }

    public DateTimeOffset? IdentityVerifiedAt { get; init; }

    public string FileName => System.IO.Path.GetFileName(Path);
}

public sealed record ManagedApplication
{
    public Guid Id { get; init; } = Guid.NewGuid();

    public required string DisplayName { get; init; }

    public string? Publisher { get; init; }

    /// <summary>Directory that bounds automatic inclusion of helper/child executables.</summary>
    public string? InstallDirectory { get; init; }

    public IReadOnlyList<ManagedExecutable> Executables { get; init; } = [];

    public ApplicationPolicy Policy { get; init; } = ApplicationPolicy.BlockAll;

    public Guid? ProfileId { get; init; }

    public bool IsEnabled { get; init; } = true;

    public PolicySource Source { get; init; } = PolicySource.User;

    /// <summary>
    /// Automatically manage unmanaged child processes whose executable is inside <see cref="InstallDirectory"/>.
    /// Children outside the install directory are only reported, never blocked automatically, because a
    /// path-scoped rule would affect every user of that executable.
    /// </summary>
    public bool IncludeChildProcesses { get; init; } = true;

    /// <summary>
    /// When the application starts from a new path (for example after an update) and the new executable carries a
    /// valid signature from the same publisher, apply the policy to the new path automatically.
    /// </summary>
    public bool FollowSignedUpdates { get; init; } = true;

    public DateTimeOffset CreatedAt { get; init; }

    public string CreatedBy { get; init; } = string.Empty;

    public DateTimeOffset ModifiedAt { get; init; }

    public string ModifiedBy { get; init; } = string.Empty;

    /// <summary>Optimistic concurrency token; incremented on every persisted change.</summary>
    public long Revision { get; init; }

    public ManagedExecutable? PrimaryExecutable => Executables.FirstOrDefault(e => e.IsPrimary) ?? Executables.FirstOrDefault();

    /// <summary>The policy actually enforced: an enabled profile overrides the application's own policy.</summary>
    public ApplicationPolicy GetEffectivePolicy(PolicyProfile? profile) =>
        profile is { IsEnabled: true } && profile.Id == ProfileId ? profile.Policy : Policy;
}

/// <summary>The most recent verified enforcement result for an application.</summary>
public sealed record EnforcementStatus
{
    public required Guid ApplicationId { get; init; }

    public EnforcementState State { get; init; } = EnforcementState.Unknown;

    /// <summary>Human-readable explanation suitable for display.</summary>
    public string Message { get; init; } = string.Empty;

    /// <summary>Additional reasons (conflicts, disabled profiles) that qualify the state.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];

    public int ExpectedRuleCount { get; init; }

    public int VerifiedRuleCount { get; init; }

    public DateTimeOffset EvaluatedAt { get; init; }

    public DateTimeOffset? LastVerifiedAt { get; init; }
}

using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;

namespace NetGuard.Core.Policies;

/// <summary>
/// Turns a user-supplied path into a verified <see cref="ManagedExecutable"/>. The service performs its own inspection
/// (the client's view of the file is never trusted) and enforces protected-component rules.
/// </summary>
public sealed class ExecutableFactory
{
    private readonly IExecutableInspector _inspector;
    private readonly IClock _clock;

    public ExecutableFactory(IExecutableInspector inspector, IClock clock)
    {
        _inspector = inspector;
        _clock = clock;
    }

    public IExecutableInspector Inspector => _inspector;

    public ManagedExecutable Create(string path, ExecutableOrigin origin, bool isPrimary, bool allowSystemComponent, bool callerCanAdminister)
    {
        var inspection = InspectChecked(path);
        EnsureAllowed(inspection.CanonicalPath, allowSystemComponent, callerCanAdminister);
        return FromInspection(inspection, origin, isPrimary);
    }

    public ManagedExecutable FromInspection(ExecutableInspection inspection, ExecutableOrigin origin, bool isPrimary) => new()
    {
        Path = inspection.CanonicalPath,
        IsPrimary = isPrimary,
        Origin = origin,
        Sha256 = inspection.Sha256,
        FileSize = inspection.FileSize,
        FileVersion = inspection.FileVersion,
        ProductName = inspection.ProductName,
        CompanyName = inspection.CompanyName,
        OriginalFileName = inspection.OriginalFileName,
        SignatureStatus = inspection.SignatureStatus,
        SignerSubject = inspection.SignerSubject,
        SignerThumbprint = inspection.SignerThumbprint,
        AddedAt = _clock.UtcNow,
        IdentityVerifiedAt = inspection.Sha256 is null ? null : _clock.UtcNow,
    };

    public ExecutableInspection InspectChecked(string path)
    {
        var syntaxError = ExecutablePathRules.ValidateSyntax(path);
        if (syntaxError is not null)
        {
            throw new DomainValidationException(syntaxError);
        }

        ExecutableInspection inspection;
        try
        {
            inspection = _inspector.Inspect(path);
        }
        catch (ExecutableInspectionException ex)
        {
            throw new DomainValidationException(ex.Message);
        }

        var canonicalError = ExecutablePathRules.ValidateSyntax(inspection.CanonicalPath);
        if (canonicalError is not null)
        {
            throw new DomainValidationException($"The file resolves to '{inspection.CanonicalPath}': {canonicalError}");
        }

        return inspection;
    }

    /// <summary>Rejects protected components, packaged apps and unauthorized system components.</summary>
    public void EnsureAllowed(string canonicalPath, bool allowSystemComponent, bool callerCanAdminister)
    {
        var protection = ExecutablePathRules.GetProtectionReason(canonicalPath, _inspector.WindowsDirectory, _inspector.ProductDirectory);
        if (protection is not null)
        {
            throw new DomainValidationException(protection);
        }

        if (ExecutablePathRules.IsPackagedApplication(canonicalPath))
        {
            throw new DomainValidationException(
                "Packaged (Microsoft Store/MSIX) applications are filtered by package identity, not by program path, so NetGuard cannot control them reliably.");
        }

        if (ExecutablePathRules.IsSystemComponent(canonicalPath, _inspector.WindowsDirectory))
        {
            if (!allowSystemComponent)
            {
                throw new DomainValidationException(
                    $"'{canonicalPath}' is inside the Windows directory. Restricting a Windows component affects every application that uses it. " +
                    "Select 'Allow system component' (administrators only) to proceed deliberately.");
            }

            if (!callerCanAdminister)
            {
                throw new AuthorizationException("Only an elevated administrator can restrict executables inside the Windows directory.");
            }
        }
    }

    public ExecutableInspectionDto Describe(ExecutableInspection inspection, Guid? managedBy)
    {
        var warnings = new List<string>();
        var protection = ExecutablePathRules.GetProtectionReason(inspection.CanonicalPath, _inspector.WindowsDirectory, _inspector.ProductDirectory);
        var isSystem = ExecutablePathRules.IsSystemComponent(inspection.CanonicalPath, _inspector.WindowsDirectory);
        var isPackaged = ExecutablePathRules.IsPackagedApplication(inspection.CanonicalPath);

        if (!string.Equals(inspection.CanonicalPath, inspection.RequestedPath, StringComparison.OrdinalIgnoreCase))
        {
            warnings.Add($"The selected path resolves to {inspection.CanonicalPath}; rules will use the resolved path.");
        }

        switch (inspection.SignatureStatus)
        {
            case SignatureStatus.NotSigned:
                warnings.Add("The file has no embedded digital signature, so updates cannot be followed automatically and identity changes cannot be attributed to the publisher.");
                break;
            case SignatureStatus.Invalid:
                warnings.Add("The file's digital signature is invalid (the file may have been modified).");
                break;
            case SignatureStatus.Untrusted:
                warnings.Add("The file is signed, but the certificate is not trusted on this computer.");
                break;
        }

        if (isSystem && protection is null)
        {
            warnings.Add("This is a Windows component. Restricting it affects every application that uses it.");
        }

        if (isPackaged)
        {
            warnings.Add("Packaged (Microsoft Store/MSIX) applications cannot be controlled with program-path rules.");
        }

        return new ExecutableInspectionDto
        {
            RequestedPath = inspection.RequestedPath,
            CanonicalPath = inspection.CanonicalPath,
            Exists = inspection.Exists,
            FileSize = inspection.FileSize,
            Sha256 = inspection.Sha256,
            FileVersion = inspection.FileVersion,
            ProductName = inspection.ProductName,
            FileDescription = inspection.FileDescription,
            CompanyName = inspection.CompanyName,
            OriginalFileName = inspection.OriginalFileName,
            SignatureStatus = inspection.SignatureStatus,
            SignerSubject = inspection.SignerSubject,
            SignerThumbprint = inspection.SignerThumbprint,
            IsSystemComponent = isSystem,
            IsPackagedApplication = isPackaged,
            ProtectionReason = protection,
            ManagedByApplicationId = managedBy,
            Warnings = warnings,
        };
    }

    /// <summary>
    /// Whether a directory is specific enough to bound automatic inclusion of child processes. Broad roots such as
    /// "C:\Program Files" or a user's AppData would make unrelated programs eligible.
    /// </summary>
    public static bool IsSpecificInstallDirectory(string? directory, string windowsDirectory)
    {
        if (string.IsNullOrWhiteSpace(directory) || directory.Length < 4)
        {
            return false;
        }

        var trimmed = directory.TrimEnd('\\');
        if (ExecutablePathRules.IsUnder(trimmed + "\\", windowsDirectory) || trimmed.Equals(windowsDirectory, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var segments = trimmed.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 3)
        {
            // "C:\Folder" is too broad; "C:\Program Files\Vendor" is the minimum.
            return false;
        }

        if (segments[1].Equals("Users", StringComparison.OrdinalIgnoreCase) && segments.Length < 4)
        {
            // A user's profile root ("C:\Users\name") is never an application directory.
            return false;
        }

        string[] broad = ["Program Files", "Program Files (x86)", "ProgramData", "Users", "AppData", "Local", "Roaming", "LocalLow", "Programs", "Temp", "Downloads", "Desktop", "Documents"];
        var last = segments[^1];
        return !broad.Contains(last, StringComparer.OrdinalIgnoreCase);
    }
}

using NetGuard.Domain.Networking;

namespace NetGuard.Domain;

public sealed class DomainValidationException : Exception
{
    public DomainValidationException(IReadOnlyList<string> errors)
        : base(string.Join(" ", errors))
    {
        Errors = errors;
    }

    public DomainValidationException(string error)
        : this([error])
    {
    }

    public IReadOnlyList<string> Errors { get; }
}

public static class PolicyValidator
{
    public const int MaxDisplayNameLength = 128;
    public const int MaxCustomAddressEntries = 200;
    public const int MaxExecutablesPerApplication = 64;

    public static IReadOnlyList<string> Validate(ApplicationPolicy policy)
    {
        var errors = new List<string>();
        if (!Enum.IsDefined(policy.Mode))
        {
            errors.Add("Unknown policy mode.");
        }

        if (!Enum.IsDefined(policy.Retention))
        {
            errors.Add("Unknown retention mode.");
        }

        if (policy.Profiles == NetworkProfiles.None || (policy.Profiles & ~NetworkProfiles.All) != 0)
        {
            errors.Add("Select at least one valid network profile (Domain, Private, Public).");
        }

        if (policy.Mode == PolicyMode.Custom)
        {
            if (policy.Custom is null)
            {
                errors.Add("A custom policy requires an allow-list.");
            }
            else
            {
                errors.AddRange(Validate(policy.Custom));
            }
        }

        return errors;
    }

    public static IReadOnlyList<string> Validate(CustomNetworkPolicy custom)
    {
        var errors = new List<string>();
        if (custom.AllowedRemoteAddresses.Count > MaxCustomAddressEntries)
        {
            errors.Add($"A custom policy may list at most {MaxCustomAddressEntries} address entries.");
        }

        if (!AddressSet.TryParse(custom.AllowedRemoteAddresses, out var addresses, out var addressError))
        {
            errors.Add(addressError!);
        }

        if (!PortSet.TryParse(custom.AllowedTcpPorts, out var tcp, out var tcpError))
        {
            errors.Add("TCP ports: " + tcpError);
        }

        if (!PortSet.TryParse(custom.AllowedUdpPorts, out var udp, out var udpError))
        {
            errors.Add("UDP ports: " + udpError);
        }

        if (errors.Count == 0)
        {
            var allowed = custom.AllowLocalNetwork ? addresses.Union(AddressSet.LocalNetwork) : addresses;
            if (allowed.IsEmpty)
            {
                errors.Add("The allow-list contains no destinations. Use the Block policy to block all traffic.");
            }
            else if (tcp.IsEmpty && udp.IsEmpty && !custom.AllowIcmp)
            {
                errors.Add("The allow-list permits no protocol or port. Use the Block policy to block all traffic.");
            }
            else if (allowed.IsAny && tcp.IsAll && udp.IsAll && custom.AllowIcmp)
            {
                errors.Add("The allow-list permits all traffic. Use the Allow policy instead.");
            }
        }

        return errors;
    }

    public static IReadOnlyList<string> Validate(ManagedApplication application)
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(application.DisplayName))
        {
            errors.Add("Display name is required.");
        }
        else if (application.DisplayName.Length > MaxDisplayNameLength || application.DisplayName.Any(char.IsControl))
        {
            errors.Add($"Display name must be at most {MaxDisplayNameLength} printable characters.");
        }

        if (application.Executables.Count == 0)
        {
            errors.Add("At least one executable is required.");
        }

        if (application.Executables.Count > MaxExecutablesPerApplication)
        {
            errors.Add($"An application may contain at most {MaxExecutablesPerApplication} executables.");
        }

        var duplicates = application.Executables
            .GroupBy(e => e.Path, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();
        if (duplicates.Count > 0)
        {
            errors.Add("Duplicate executable paths: " + string.Join(", ", duplicates));
        }

        foreach (var executable in application.Executables)
        {
            var pathError = ExecutablePathRules.ValidateSyntax(executable.Path);
            if (pathError is not null)
            {
                errors.Add(pathError);
            }
        }

        errors.AddRange(Validate(application.Policy));
        return errors;
    }

    public static void EnsureValid(ManagedApplication application)
    {
        var errors = Validate(application);
        if (errors.Count > 0)
        {
            throw new DomainValidationException(errors);
        }
    }

    public static void EnsureValid(ApplicationPolicy policy)
    {
        var errors = Validate(policy);
        if (errors.Count > 0)
        {
            throw new DomainValidationException(errors);
        }
    }
}

/// <summary>
/// Path rules that do not require file-system access. Canonicalization (symlinks, 8.3 names, casing) is performed
/// by the platform layer using an open file handle so the checked and used paths are the same object.
/// </summary>
public static class ExecutablePathRules
{
    public const int MaxPathLength = 1024;

    /// <summary>
    /// Executables that must never be restricted: blocking them would break Windows networking, security
    /// products, or NetGuard's own operation. Matched by file name within the Windows directory and by full path.
    /// </summary>
    private static readonly HashSet<string> ProtectedSystemFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "csrss.exe", "smss.exe",
        "System", "Registry", "MsMpEng.exe", "NisSrv.exe", "MpDefenderCoreService.exe", "SecurityHealthService.exe",
        "spoolsv.exe", "dllhost.exe", "taskhostw.exe", "explorer.exe", "dwm.exe", "fontdrvhost.exe",
        "LsaIso.exe", "sihost.exe", "ctfmon.exe", "conhost.exe", "WmiPrvSE.exe", "TrustedInstaller.exe",
        "TiWorker.exe", "wuauclt.exe", "UsoClient.exe", "MoUsoCoreWorker.exe",
    };

    private static readonly HashSet<string> ProtectedProductFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "NetGuard.Service.exe", "NetGuard.Desktop.exe",
    };

    /// <summary>Returns an error message, or null when the path is syntactically acceptable.</summary>
    public static string? ValidateSyntax(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return "Executable path is required.";
        }

        if (path.Length > MaxPathLength)
        {
            return $"Executable path exceeds {MaxPathLength} characters.";
        }

        if (path.Any(c => char.IsControl(c) || c is '"' or '<' or '>' or '|' or '*' or '?'))
        {
            return $"Executable path '{path}' contains invalid characters.";
        }

        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
        {
            return "Network (UNC) and device paths are not supported. Firewall rules require a local executable path.";
        }

        if (path.Contains('%'))
        {
            return "Environment variables must be expanded before the path is submitted.";
        }

        if (path.Length < 4 || !char.IsAsciiLetter(path[0]) || path[1] != ':' || path[2] != '\\')
        {
            return $"'{path}' is not an absolute local path (expected a form such as C:\\Folder\\App.exe).";
        }

        if (path.IndexOf(':', 2) >= 0)
        {
            return "Alternate data streams are not supported.";
        }

        if (path.Split('\\').Any(segment => segment is "." or ".."))
        {
            return "Relative path segments ('.' or '..') are not allowed.";
        }

        if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return "Only .exe files can be managed.";
        }

        return null;
    }

    /// <summary>
    /// Returns a reason when the canonical path is a protected component, or null otherwise.
    /// <paramref name="windowsDirectory"/> is normally C:\Windows.
    /// </summary>
    public static string? GetProtectionReason(string canonicalPath, string windowsDirectory, string? productDirectory)
    {
        var fileName = Path.GetFileName(canonicalPath);
        if (ProtectedProductFileNames.Contains(fileName) ||
            (productDirectory is not null && IsUnder(canonicalPath, productDirectory)))
        {
            return "NetGuard Enterprise's own executables cannot be restricted.";
        }

        if (IsUnder(canonicalPath, windowsDirectory) && ProtectedSystemFileNames.Contains(fileName))
        {
            return $"{fileName} is a core Windows or security component; restricting it would affect system networking or protection.";
        }

        return null;
    }

    /// <summary>True when the path is inside the Windows directory and therefore needs explicit system-component authorization.</summary>
    public static bool IsSystemComponent(string canonicalPath, string windowsDirectory) => IsUnder(canonicalPath, windowsDirectory);

    /// <summary>MSIX/Store apps are filtered by package identity, not by path, and cannot be controlled with program rules.</summary>
    public static bool IsPackagedApplication(string canonicalPath) =>
        canonicalPath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);

    public static bool IsUnder(string path, string directory)
    {
        if (string.IsNullOrEmpty(directory))
        {
            return false;
        }

        var prefix = directory.EndsWith('\\') ? directory : directory + "\\";
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }
}

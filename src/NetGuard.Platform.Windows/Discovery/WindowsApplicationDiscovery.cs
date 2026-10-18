using System.Diagnostics;
using System.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using NetGuard.Contracts;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;
using NetGuard.Platform.Windows.Native;

namespace NetGuard.Platform.Windows.Discovery;

/// <summary>
/// Discovers installed desktop applications from uninstall metadata (per-machine, WOW64 and loaded per-user hives),
/// App Paths registrations and running processes. Read-only; never modifies the registry or files.
/// </summary>
public sealed class WindowsApplicationDiscovery : IApplicationDiscovery
{
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string AppPathsKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
    private const int MaxExecutablesPerEntry = 12;
    private const int MaxScanFiles = 200;
    private const int MaxScanDepth = 3;

    private static readonly string[] InstallerNamePatterns = ["unins", "uninst", "setup", "install", "update", "crashpad", "crashreport", "elevation_service"];

    private readonly ILogger<WindowsApplicationDiscovery> _logger;
    private readonly string _windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

    public WindowsApplicationDiscovery(ILogger<WindowsApplicationDiscovery> logger) => _logger = logger;

    public IReadOnlyList<DiscoveredApplicationDto> Discover(DiscoveryRequest request, IReadOnlyDictionary<string, Guid> managedPaths)
    {
        var running = request.IncludeRunningProcesses ? GetRunningPaths() : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var appPaths = ReadAppPaths();
        var entries = new List<Entry>();

        foreach (var (hive, view, source) in EnumerateUninstallRoots())
        {
            using (hive)
            {
                using var key = hive.OpenSubKey(UninstallKey);
                if (key is null)
                {
                    continue;
                }

                foreach (var name in SafeSubKeyNames(key))
                {
                    try
                    {
                        using var app = key.OpenSubKey(name);
                        var entry = app is null ? null : ReadUninstallEntry(app, appPaths, source);
                        if (entry is not null)
                        {
                            entries.Add(entry);
                        }
                    }
                    catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
                    {
                        _logger.LogDebug(ex, "Skipping unreadable uninstall entry {Name} in {View}", name, view);
                    }
                }
            }
        }

        // Merge entries that point at the same executable (for example 32/64-bit registrations of one product).
        var merged = new List<Entry>();
        foreach (var entry in entries)
        {
            var match = merged.FirstOrDefault(m => m.Executables.Overlaps(entry.Executables) && entry.Executables.Count > 0);
            if (match is null)
            {
                merged.Add(entry);
            }
            else
            {
                match.Sources.UnionWith(entry.Sources);
            }
        }

        // Attach running processes to installed entries, or list them on their own.
        foreach (var path in running)
        {
            if (!request.IncludeSystemComponents && ExecutablePathRules.IsSystemComponent(path, _windowsDirectory))
            {
                continue;
            }

            var owner = merged.FirstOrDefault(e => e.Executables.Contains(path)) ??
                        merged.FirstOrDefault(e => e.InstallLocation is { Length: > 3 } dir && ExecutablePathRules.IsUnder(path, dir));
            if (owner is not null)
            {
                owner.Executables.Add(path);
                owner.Sources.Add("Running process");
                continue;
            }

            var version = TryGetVersion(path);
            merged.Add(new Entry
            {
                Name = version?.ProductName?.Trim() is { Length: > 0 } product ? product : version?.FileDescription?.Trim() is { Length: > 0 } desc ? desc : Path.GetFileNameWithoutExtension(path),
                Publisher = string.IsNullOrWhiteSpace(version?.CompanyName) ? null : version!.CompanyName!.Trim(),
                Version = version?.FileVersion,
                InstallLocation = Path.GetDirectoryName(path),
                Executables = new HashSet<string>([path], StringComparer.OrdinalIgnoreCase),
                Sources = ["Running process"],
            });
        }

        var result = merged
            .Where(e => request.IncludeSystemComponents || !e.IsSystemComponent)
            .Where(e => e.Executables.Count > 0)
            .Select(e => new DiscoveredApplicationDto
            {
                Name = e.Name,
                Publisher = e.Publisher,
                Version = e.Version,
                InstallLocation = e.InstallLocation,
                Executables = e.Executables
                    .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                    .Take(MaxExecutablesPerEntry)
                    .Select(p => new DiscoveredExecutableDto
                    {
                        Path = p,
                        IsRunning = running.Contains(p),
                        ManagedByApplicationId = managedPaths.TryGetValue(p, out var id) ? id : null,
                    })
                    .ToList(),
                Sources = e.Sources.OrderBy(s => s, StringComparer.Ordinal).ToList(),
                IsRunning = e.Executables.Any(running.Contains),
                IsManaged = e.Executables.Any(managedPaths.ContainsKey),
                IsSystemComponent = e.IsSystemComponent,
            })
            .ToList();

        // Flag possible duplicates: same product name and publisher listed more than once.
        var duplicateKeys = result
            .GroupBy(r => (r.Name.ToUpperInvariant(), (r.Publisher ?? string.Empty).ToUpperInvariant()))
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToHashSet();

        return result
            .Select(r => duplicateKeys.Contains((r.Name.ToUpperInvariant(), (r.Publisher ?? string.Empty).ToUpperInvariant())) ? r with { IsPossibleDuplicate = true } : r)
            .OrderBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    public IReadOnlyList<RelatedExecutableDto> ScanDirectory(string directory, IReadOnlyDictionary<string, Guid> managedPaths)
    {
        var result = new List<RelatedExecutableDto>();
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            MaxRecursionDepth = MaxScanDepth,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System,
        };

        foreach (var file in Directory.EnumerateFiles(directory, "*.exe", options))
        {
            if (result.Count >= MaxScanFiles)
            {
                break;
            }

            var version = TryGetVersion(file);
            long size = 0;
            try
            {
                size = new FileInfo(file).Length;
            }
            catch (IOException)
            {
            }

            result.Add(new RelatedExecutableDto
            {
                Path = file,
                ProductName = version?.ProductName,
                CompanyName = version?.CompanyName,
                FileSize = size,
                IsManaged = managedPaths.ContainsKey(file),
            });
        }

        return result.OrderBy(r => r.Path, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private Entry? ReadUninstallEntry(RegistryKey key, IReadOnlyDictionary<string, string> appPaths, string source)
    {
        var name = key.GetValue("DisplayName") as string;
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        // Skip updates/patches and entries that point at a parent product.
        if (key.GetValue("ParentKeyName") is string || key.GetValue("ReleaseType") is string release && (release.Contains("Update", StringComparison.OrdinalIgnoreCase) || release.Contains("Hotfix", StringComparison.OrdinalIgnoreCase)))
        {
            return null;
        }

        var isSystem = key.GetValue("SystemComponent") is int flag && flag == 1;
        var installLocation = Normalize(key.GetValue("InstallLocation") as string);
        var executables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var icon = ParseIconPath(key.GetValue("DisplayIcon") as string);
        if (icon is not null && IsUsableExecutable(icon))
        {
            executables.Add(icon);
            installLocation ??= Path.GetDirectoryName(icon);
        }

        if (installLocation is not null && Directory.Exists(installLocation))
        {
            foreach (var path in appPaths.Values.Where(p => ExecutablePathRules.IsUnder(p, installLocation)))
            {
                executables.Add(path);
            }

            if (executables.Count == 0)
            {
                try
                {
                    foreach (var file in Directory.EnumerateFiles(installLocation, "*.exe", new EnumerationOptions { IgnoreInaccessible = true }).Take(MaxExecutablesPerEntry))
                    {
                        if (IsUsableExecutable(file))
                        {
                            executables.Add(file);
                        }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                }
            }
        }

        return new Entry
        {
            Name = name.Trim(),
            Publisher = (key.GetValue("Publisher") as string)?.Trim(),
            Version = (key.GetValue("DisplayVersion") as string)?.Trim(),
            InstallLocation = installLocation,
            Executables = executables,
            Sources = [source],
            IsSystemComponent = isSystem || (installLocation is not null && ExecutablePathRules.IsSystemComponent(installLocation + "\\", _windowsDirectory)),
        };
    }

    private IEnumerable<(RegistryKey Hive, string View, string Source)> EnumerateUninstallRoots()
    {
        yield return (RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64), "HKLM64", "Uninstall registry (all users)");
        yield return (RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32), "HKLM32", "Uninstall registry (all users, 32-bit)");

        // Per-user installs of every signed-in user (their hives are loaded under HKEY_USERS).
        using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
        foreach (var sid in SafeSubKeyNames(users).Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !s.EndsWith("_Classes", StringComparison.Ordinal)))
        {
            RegistryKey? hive = null;
            try
            {
                hive = users.OpenSubKey(sid);
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
            {
            }

            if (hive is not null)
            {
                yield return (hive, sid, "Uninstall registry (per user)");
            }
        }
    }

    private Dictionary<string, string> ReadAppPaths()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var hive = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = hive.OpenSubKey(AppPathsKey);
                if (key is null)
                {
                    continue;
                }

                foreach (var name in SafeSubKeyNames(key))
                {
                    using var entry = key.OpenSubKey(name);
                    var path = ParseIconPath(entry?.GetValue(null) as string);
                    if (path is not null && IsUsableExecutable(path))
                    {
                        result[name] = path;
                    }
                }
            }
            catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
            {
                _logger.LogDebug(ex, "App Paths could not be read");
            }
        }

        return result;
    }

    private static HashSet<string> GetRunningPaths()
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                if (process.Id is 0 or 4)
                {
                    continue;
                }

                using var handle = ProcessQuery.Open(process.Id, synchronize: false);
                if (handle is not null && ProcessQuery.GetImagePath(handle) is { } path)
                {
                    result.Add(path);
                }
            }
        }

        return result;
    }

    private static IEnumerable<string> SafeSubKeyNames(RegistryKey key)
    {
        try
        {
            return key.GetSubKeyNames();
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException or IOException)
        {
            return [];
        }
    }

    /// <summary>Parses values like <c>"C:\App\app.exe",0</c> or <c>C:\App\app.exe</c>.</summary>
    internal static string? ParseIconPath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var text = value.Trim();
        if (text.StartsWith('"'))
        {
            var end = text.IndexOf('"', 1);
            text = end > 1 ? text[1..end] : text.Trim('"');
        }
        else
        {
            var comma = text.LastIndexOf(',');
            if (comma > 0 && int.TryParse(text[(comma + 1)..].Trim(), out _))
            {
                text = text[..comma];
            }
        }

        text = Environment.ExpandEnvironmentVariables(text.Trim());
        return text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? Normalize(text) : null;
    }

    private static bool IsUsableExecutable(string path)
    {
        if (!File.Exists(path))
        {
            return false;
        }

        var name = Path.GetFileNameWithoutExtension(path);
        return !InstallerNamePatterns.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private static string? Normalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            var full = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim().Trim('"')));
            return full.Length > 3 ? full.TrimEnd('\\') : full;
        }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    private static FileVersionInfo? TryGetVersion(string path)
    {
        try
        {
            return FileVersionInfo.GetVersionInfo(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private sealed class Entry
    {
        public required string Name { get; init; }

        public string? Publisher { get; init; }

        public string? Version { get; init; }

        public string? InstallLocation { get; init; }

        public required HashSet<string> Executables { get; init; }

        public required HashSet<string> Sources { get; init; }

        public bool IsSystemComponent { get; init; }
    }
}

using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.ServiceProcess;
using Microsoft.Win32;
using NetGuard.Contracts;

namespace NetGuard.Desktop.Services;

/// <summary>
/// Standalone (single-EXE) distribution support. The standalone build embeds the self-contained service publish
/// output as a zip resource. On first run the interface offers to install it: an elevated copy of this EXE extracts
/// the service to Program Files (writable only by administrators, because it runs as LocalSystem), registers it and
/// starts it. Running a newer standalone EXE updates the service in place. A service installed by the MSI is never
/// modified. Regular (MSI) builds have no embedded package and this class does nothing.
/// </summary>
public static class ServiceBootstrapper
{
    public const string InstallVerb = "--install-service";
    public const string UninstallVerb = "--uninstall-service";

    private const string PackageResource = "NetGuard.ServicePackage.zip";
    private const string MarkerFile = "package.sha256";
    private const string ServiceExe = "NetGuard.Service.exe";

    public enum State
    {
        /// <summary>No embedded package (MSI build), or a service this EXE does not manage (MSI install).</summary>
        NotManaged,
        Current,
        NotInstalled,
        Outdated,
    }

    public static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NetGuard Enterprise Portable", "Service");

    private static string InstalledExe => Path.Combine(InstallDirectory, ServiceExe);

    public static State GetState()
    {
        using var package = OpenPackage();
        if (package is null)
        {
            return State.NotManaged;
        }

        var imagePath = GetServiceImagePath();
        if (imagePath is null)
        {
            return State.NotInstalled;
        }

        if (!imagePath.Trim().Trim('"').Equals(InstalledExe, StringComparison.OrdinalIgnoreCase))
        {
            return State.NotManaged;
        }

        try
        {
            var installed = File.ReadAllText(Path.Combine(InstallDirectory, MarkerFile)).Trim();
            return installed.Equals(Hash(package), StringComparison.OrdinalIgnoreCase) ? State.Current : State.Outdated;
        }
        catch (IOException)
        {
            return State.Outdated;
        }
        catch (UnauthorizedAccessException)
        {
            return State.Outdated;
        }
    }

    /// <summary>Runs <paramref name="verb"/> in an elevated copy of this EXE (UAC prompt) and waits for it.</summary>
    /// <returns>True on success; false if the user declined the prompt or the operation failed (already reported).</returns>
    public static async Task<bool> RunElevatedAsync(string verb)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo(Environment.ProcessPath!)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = verb,
            });
            if (process is null)
            {
                return false;
            }

            await process.WaitForExitAsync().ConfigureAwait(false);
            return process.ExitCode == 0;
        }
        catch (Win32Exception)
        {
            return false;
        }
    }

    /// <summary>Handles the elevated verbs. Returns the process exit code, or null if no verb was given.</summary>
    public static int? TryRunVerb(string[] args)
    {
        var verb = args.FirstOrDefault(a => a is InstallVerb or UninstallVerb);
        if (verb is null)
        {
            return null;
        }

        if (!Elevation.IsElevated())
        {
            Dialogs.Error("NetGuard Enterprise", "Installing or removing the NetGuard service requires administrator rights.");
            return 5;
        }

        try
        {
            if (verb == InstallVerb)
            {
                Install();
            }
            else
            {
                Uninstall();
                Dialogs.Info("NetGuard Enterprise", "The NetGuard service was removed, together with the firewall rules NetGuard created.");
            }

            return 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or Win32Exception or InvalidDataException or System.ServiceProcess.TimeoutException)
        {
            Dialogs.Error("NetGuard Enterprise", $"The NetGuard service could not be {(verb == InstallVerb ? "installed" : "removed")}.\n\n{ex.Message}");
            return 1;
        }
    }

    private static void Install()
    {
        using var package = OpenPackage() ?? throw new InvalidOperationException("This build does not contain the NetGuard service.");
        var hash = Hash(package);
        var imagePath = GetServiceImagePath();
        if (imagePath is not null && !imagePath.Trim().Trim('"').Equals(InstalledExe, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"A NetGuard service installed from another location already exists ({imagePath}). Uninstall it first.");
        }

        if (imagePath is not null)
        {
            // Suspend crash recovery while the files are replaced, so the service control manager cannot restart
            // the old service (and lock its files) if it fails while stopping. Restored below.
            Sc("failure", IpcConstants.ServiceName, "reset=", "0", "actions=", "");
        }

        StopService();
        Retry(() =>
        {
            if (Directory.Exists(InstallDirectory))
            {
                Directory.Delete(InstallDirectory, recursive: true);
            }

            Directory.CreateDirectory(InstallDirectory);
            package.Position = 0;
            ZipFile.ExtractToDirectory(package, InstallDirectory, overwriteFiles: true);
        });
        File.WriteAllText(Path.Combine(InstallDirectory, MarkerFile), hash);

        var binPath = $"\"{InstalledExe}\"";
        if (imagePath is null)
        {
            Sc("create", IpcConstants.ServiceName, "binPath=", binPath, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "NetGuard Enterprise");
        }
        else
        {
            Sc("config", IpcConstants.ServiceName, "binPath=", binPath, "start=", "auto");
        }

        Sc("description", IpcConstants.ServiceName, "Enforces per-application network policies with Windows Defender Firewall and verifies them continuously.");
        // Recover automatically: restart after 10 s on the first three failures; reset the count daily.
        Sc("failure", IpcConstants.ServiceName, "reset=", "86400", "actions=", "restart/10000/restart/10000/restart/10000");

        using var service = new ServiceController(IpcConstants.ServiceName);
        service.Start();
        service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
    }

    private static void Uninstall()
    {
        var imagePath = GetServiceImagePath();
        if (imagePath is not null && !imagePath.Trim().Trim('"').Equals(InstalledExe, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"The NetGuard service at {imagePath} was not installed by this program. Use Apps & features to remove it.");
        }

        StopService();
        if (File.Exists(InstalledExe))
        {
            // Same clean-up the MSI performs: removes only rules NetGuard owns.
            Run(InstalledExe, "cleanup-rules");
        }

        if (imagePath is not null)
        {
            Sc("delete", IpcConstants.ServiceName);
        }

        Retry(() =>
        {
            if (Directory.Exists(InstallDirectory))
            {
                Directory.Delete(InstallDirectory, recursive: true);
            }
        });
        var parent = Path.GetDirectoryName(InstallDirectory)!;
        if (Directory.Exists(parent) && !Directory.EnumerateFileSystemEntries(parent).Any())
        {
            Directory.Delete(parent);
        }
    }

    private static Stream? OpenPackage() =>
        typeof(ServiceBootstrapper).Assembly.GetManifestResourceStream(PackageResource);

    private static string Hash(Stream stream)
    {
        stream.Position = 0;
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string? GetServiceImagePath()
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{IpcConstants.ServiceName}");
        return key?.GetValue("ImagePath") as string;
    }

    private static void StopService()
    {
        try
        {
            using var service = new ServiceController(IpcConstants.ServiceName);
            if (service.Status != ServiceControllerStatus.Stopped)
            {
                service.Stop();
                service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            }
        }
        catch (InvalidOperationException)
        {
            // Not installed.
        }
    }

    /// <summary>The service process can hold file locks for a moment after it reports Stopped.</summary>
    private static void Retry(Action action)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                action();
                return;
            }
            catch (Exception ex) when (attempt < 10 && ex is IOException or UnauthorizedAccessException)
            {
                Thread.Sleep(500);
            }
        }
    }

    private static void Sc(params string[] args)
    {
        var (code, output) = Run(Path.Combine(Environment.SystemDirectory, "sc.exe"), args);
        if (code != 0)
        {
            throw new InvalidOperationException($"sc.exe {args[0]} failed ({code}): {output.Trim()}");
        }
    }

    private static (int Code, string Output) Run(string file, params string[] args)
    {
        var info = new ProcessStartInfo(file)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var arg in args)
        {
            info.ArgumentList.Add(arg);
        }

        using var process = Process.Start(info) ?? throw new InvalidOperationException($"Could not start {file}.");
        var stderr = process.StandardError.ReadToEndAsync();
        var stdout = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, stdout + stderr.Result);
    }
}

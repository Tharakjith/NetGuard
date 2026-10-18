namespace NetGuard.Service;

/// <summary>On-disk locations. Everything lives under %ProgramData%\NetGuard, restricted to SYSTEM and Administrators.</summary>
public sealed class ServicePaths
{
    public ServicePaths(string root)
    {
        Root = root;
        Data = Path.Combine(root, "data");
        Logs = Path.Combine(root, "logs");
        Policies = Path.Combine(root, "Policies");
    }

    public string Root { get; }

    public string Data { get; }

    public string Logs { get; }

    /// <summary>Drop folder for organization policy (deployed by Group Policy, Intune or other device management).</summary>
    public string Policies { get; }

    public static string DefaultRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetGuard");

    /// <summary>Retention for file logs, refreshed from settings; read by the file logger on each clean-up.</summary>
    public static volatile int LogRetentionDays = 30;
}

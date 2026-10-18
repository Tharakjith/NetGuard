using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NetGuard.Contracts;

namespace NetGuard.Desktop.ViewModels;

public sealed class AboutViewModel : PageViewModel
{
    public AboutViewModel(UiContext context)
        : base(context)
    {
        Version = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0";
        Signature = DescribeSignature(Environment.ProcessPath);
    }

    public override string Title => "About & Security";

    public override string Glyph => "";

    public string Version { get; }

    public string Signature { get; }

    public string ServiceVersion => Context.Service?.Version ?? "not connected";

    public string CallerText => Context.Service is null
        ? "Not connected."
        : $"{Context.Caller.Name} · read: {Yes(Context.Caller.CanRead)} · change policies: {Yes(Context.Caller.CanModify)} · administer: {Yes(Context.Caller.CanAdminister)}";

    public int ProtocolVersion => IpcConstants.ProtocolVersion;

    public IReadOnlyList<string> SecurityModel { get; } =
    [
        "Enforcement runs in the NetGuard Enterprise Windows service (LocalSystem). This window is optional and runs without administrator rights.",
        "The service decides what each caller may do from the caller's Windows token: anyone signed in can view status (configurable); elevated administrators and members of the local 'NetGuard Operators' group can change policies; only elevated administrators can change service settings, import configuration or remove orphaned rules.",
        "The service only ever creates outbound BLOCK rules scoped to a single program path, marks them as its own, and only modifies rules carrying that mark. It never creates allow rules, never disables Windows Defender Firewall or other security features, and never resets firewall configuration.",
        "Organization policy deployed to %ProgramData%\\NetGuard\\Policies is read-only here and always takes precedence over local configuration.",
        "Every privileged operation is recorded in the audit log, including denied attempts.",
        "Configuration, logs and backups are stored under %ProgramData%\\NetGuard and are readable only by SYSTEM and Administrators.",
        "NetGuard does not collect browsing history, credentials, file contents or other personal data, and needs no internet connection or cloud account.",
    ];

    public override Task LoadAsync()
    {
        OnPropertyChanged(nameof(ServiceVersion));
        OnPropertyChanged(nameof(CallerText));
        return Task.CompletedTask;
    }

    private static string Yes(bool value) => value ? "yes" : "no";

    private static string DescribeSignature(string? path)
    {
        if (path is null)
        {
            return "Unknown";
        }

        try
        {
#pragma warning disable SYSLIB0057
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return $"Signed by {certificate.Subject} (valid until {certificate.NotAfter:d}).";
        }
        catch (CryptographicException)
        {
            return "This build is not code-signed. Production installations should only use signed binaries (see docs/DEPLOYMENT.md).";
        }
    }
}

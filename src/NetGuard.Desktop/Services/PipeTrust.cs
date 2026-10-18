using System.Security.Principal;
using NetGuard.Ipc;

namespace NetGuard.Desktop.Services;

/// <summary>
/// Pipe-client options shared by all connections. Release builds trust only a pipe owned by SYSTEM or Administrators.
/// Debug builds started with <c>--dev-trust-current-user</c> additionally trust a pipe owned by the current user so
/// the interface can be developed against a non-elevated console instance of the service.
/// </summary>
public static class PipeTrust
{
    public static PipeClientOptions Options { get; private set; } = new();

    public static void Configure(string[] args)
    {
#if DEBUG
        if (args.Contains("--dev-trust-current-user"))
        {
            using var identity = WindowsIdentity.GetCurrent();
            Options = new PipeClientOptions
            {
                TrustedServerOwners = [.. new PipeClientOptions().TrustedServerOwners, identity.User!],
            };
        }
#else
        _ = args;
#endif
    }
}

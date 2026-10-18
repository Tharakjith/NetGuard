using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;
using NetGuard.Platform.Windows.Native;

namespace NetGuard.Platform.Windows.Security;

public static class WindowsSecurity
{
    public static readonly SecurityIdentifier LocalSystem = new(WellKnownSidType.LocalSystemSid, null);
    public static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static bool IsRunningAsLocalSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User?.Equals(LocalSystem) == true;
    }

    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// Restricts a directory (configuration database, logs, backups) to SYSTEM and Administrators, removing inherited
    /// permissions so standard users can neither read nor tamper with policy or audit data.
    /// </summary>
    public static void HardenDirectory(string path, ILogger logger)
    {
        Directory.CreateDirectory(path);
        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            security.AddAccessRule(new FileSystemAccessRule(LocalSystem, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(Administrators, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or PrivilegeNotHeldException or InvalidOperationException)
        {
            logger.LogWarning(ex, "Could not restrict permissions on {Path}. Run the service as LocalSystem.", path);
        }
    }

    /// <summary>Creates the "NetGuard Operators" local group if missing and returns its SID (or null).</summary>
    public static SecurityIdentifier? EnsureOperatorsGroup(ILogger logger, bool create)
    {
        if (create)
        {
            var info = new NativeMethods.LocalGroupInfo1
            {
                Name = IpcConstants.OperatorsGroupName,
                Comment = "Members can change NetGuard Enterprise application policies without elevation.",
            };
            var result = NativeMethods.NetLocalGroupAdd(null, 1, ref info, out _);
            if (result is not 0 and not NativeMethods.NerrGroupExists and not NativeMethods.ErrorAliasExists)
            {
                logger.LogWarning("Could not create the local group '{Group}' (error {Error})", IpcConstants.OperatorsGroupName, result);
            }
        }

        try
        {
            return (SecurityIdentifier)new NTAccount(IpcConstants.OperatorsGroupName).Translate(typeof(SecurityIdentifier));
        }
        catch (IdentityNotMappedException)
        {
            return null;
        }
    }
}

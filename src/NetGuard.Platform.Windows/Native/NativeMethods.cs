using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NetGuard.Platform.Windows.Native;

#pragma warning disable SYSLIB1054 // DllImport is used deliberately for struct-heavy signatures.

internal static class NativeMethods
{
    public const uint ProcessQueryLimitedInformation = 0x1000;
    public const uint Synchronize = 0x00100000;

    public const uint FileReadAttributes = 0x80;
    public const uint FileShareRead = 0x1;
    public const uint FileShareWrite = 0x2;
    public const uint FileShareDelete = 0x4;
    public const uint OpenExisting = 3;
    public const uint FileFlagBackupSemantics = 0x02000000;
    public const uint VolumeNameDos = 0x0;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeProcessHandle OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    public static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, StringBuilder exeName, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessTimes(SafeProcessHandle process, out long creationTime, out long exitTime, out long kernelTime, out long userTime);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    public static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetFinalPathNameByHandleW")]
    public static extern uint GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, uint length, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryDosDeviceW")]
    public static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int max);

    // ---------------------------------------------------------------- WinVerifyTrust

    public static readonly Guid WintrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    public const uint WtdUiNone = 2;
    public const uint WtdRevokeNone = 0;
    public const uint WtdChoiceFile = 1;
    public const uint WtdStateActionVerify = 1;
    public const uint WtdStateActionClose = 2;
    public const uint WtdCacheOnlyUrlRetrieval = 0x00001000;
    public const uint WtdRevocationCheckNone = 0x00000010;

    [StructLayout(LayoutKind.Sequential)]
    public struct WintrustFileInfo
    {
        public uint CbStruct;
        public IntPtr FilePath;
        public IntPtr File;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WintrustData
    {
        public uint CbStruct;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProvFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", SetLastError = false)]
    public static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref WintrustData data);

    // ---------------------------------------------------------------- audit policy

    /// <summary>Audit subcategory "Filtering Platform Connection".</summary>
    public static readonly Guid AuditFilteringPlatformConnection = new("0CCE9226-69AE-11D9-BED3-505054503030");
    public const uint PolicyAuditEventFailure = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    public struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    /// <summary>Returns BOOLEAN (one byte), not BOOL.</summary>
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    public static extern bool AuditQuerySystemPolicy([In] Guid[] subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [DllImport("advapi32.dll")]
    public static extern void AuditFree(IntPtr buffer);

    // ---------------------------------------------------------------- local groups

    public const int NerrGroupExists = 2223;
    public const int ErrorAliasExists = 1379;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LocalGroupInfo1
    {
        public string Name;
        public string Comment;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int NetLocalGroupAdd(string? serverName, int level, ref LocalGroupInfo1 buffer, out int parameterError);
}

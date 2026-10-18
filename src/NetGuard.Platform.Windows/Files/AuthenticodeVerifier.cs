using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using NetGuard.Domain;
using NetGuard.Platform.Windows.Native;

namespace NetGuard.Platform.Windows.Files;

/// <summary>
/// Verifies embedded Authenticode signatures with WinVerifyTrust. Revocation is not checked online so verification
/// never requires network access (and never stalls on a blocked network). Catalog-signed files report NotSigned.
/// </summary>
internal static class AuthenticodeVerifier
{
    public static (SignatureStatus Status, string? Subject, string? Thumbprint) Verify(string path, SafeFileHandle handle)
    {
        var status = VerifyTrust(path, handle);
        if (status is SignatureStatus.NotSigned or SignatureStatus.Error)
        {
            return (status, null, null);
        }

        try
        {
#pragma warning disable SYSLIB0057 // CreateFromSignedFile is the supported way to read the Authenticode signer.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return (status, certificate.Subject, certificate.Thumbprint);
        }
        catch (CryptographicException)
        {
            return (status, null, null);
        }
    }

    private static SignatureStatus VerifyTrust(string path, SafeFileHandle handle)
    {
        var pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfoPtr = IntPtr.Zero;
        var addedRef = false;
        try
        {
            handle.DangerousAddRef(ref addedRef);
            var fileInfo = new NativeMethods.WintrustFileInfo
            {
                CbStruct = (uint)Marshal.SizeOf<NativeMethods.WintrustFileInfo>(),
                FilePath = pathPtr,
                File = handle.DangerousGetHandle(),
            };
            fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WintrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new NativeMethods.WintrustData
            {
                CbStruct = (uint)Marshal.SizeOf<NativeMethods.WintrustData>(),
                UiChoice = NativeMethods.WtdUiNone,
                RevocationChecks = NativeMethods.WtdRevokeNone,
                UnionChoice = NativeMethods.WtdChoiceFile,
                FileInfo = fileInfoPtr,
                StateAction = NativeMethods.WtdStateActionVerify,
                ProvFlags = NativeMethods.WtdCacheOnlyUrlRetrieval | NativeMethods.WtdRevocationCheckNone,
            };

            var action = NativeMethods.WintrustActionGenericVerifyV2;
            var result = NativeMethods.WinVerifyTrust(new IntPtr(-1), ref action, ref data);

            data.StateAction = NativeMethods.WtdStateActionClose;
            NativeMethods.WinVerifyTrust(new IntPtr(-1), ref action, ref data);

            return Map((uint)result);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return SignatureStatus.Error;
        }
        finally
        {
            if (addedRef)
            {
                handle.DangerousRelease();
            }

            if (fileInfoPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPtr);
            }

            Marshal.FreeHGlobal(pathPtr);
        }
    }

    internal static SignatureStatus Map(uint result) => result switch
    {
        0 => SignatureStatus.Valid,
        0x800B0100 or 0x800B0003 or 0x800B0001 => SignatureStatus.NotSigned, // TRUST_E_NOSIGNATURE, SUBJECT_FORM_UNKNOWN, PROVIDER_UNKNOWN
        0x80096010 or 0x80096011 or 0x80096019 or 0x80091007 => SignatureStatus.Invalid, // BAD_DIGEST, MALFORMED_SIGNATURE, BASIC_CONSTRAINTS, HASH_VALUE
        0x800B0109 or 0x800B010A or 0x800B0101 or 0x800B010C or 0x800B0111 or 0x800B0004 or 0x80092026 or 0x800B010F => SignatureStatus.Untrusted,
        _ => SignatureStatus.Error,
    };
}

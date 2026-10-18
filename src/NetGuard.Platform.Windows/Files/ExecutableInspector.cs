using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Cryptography;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;
using NetGuard.Platform.Windows.Native;

namespace NetGuard.Platform.Windows.Files;

/// <summary>
/// Inspects executables through a single open handle: the file is opened denying writers, its final path is taken
/// from that handle, and the hash and signature are computed while the handle is held. This closes the window in
/// which a path could be swapped between checking and recording it.
/// </summary>
public sealed class ExecutableInspector : IExecutableInspector
{
    private const int CacheLimit = 2048;

    private readonly ConcurrentDictionary<(string Path, long Size, DateTime WriteTime), ExecutableInspection> _cache = new();

    public ExecutableInspector(string? productDirectory = null)
    {
        WindowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\');
        ProductDirectory = productDirectory?.TrimEnd('\\');
    }

    public string WindowsDirectory { get; }

    public string? ProductDirectory { get; }

    public ExecutableInspection Inspect(string path, bool includeHashAndSignature = true)
    {
        FileStream stream;
        try
        {
            stream = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.Read,
                Options = FileOptions.SequentialScan,
            });
        }
        catch (FileNotFoundException)
        {
            throw new ExecutableInspectionException($"File not found: {path}");
        }
        catch (DirectoryNotFoundException)
        {
            throw new ExecutableInspectionException($"Folder not found: {path}");
        }
        catch (UnauthorizedAccessException ex)
        {
            throw new ExecutableInspectionException($"Access denied opening {path}.", ex);
        }
        catch (IOException ex)
        {
            throw new ExecutableInspectionException($"Could not open {path}: {ex.Message}", ex);
        }

        using (stream)
        {
            string canonical;
            try
            {
                canonical = ProcessQuery.GetFinalPath(stream.SafeFileHandle);
            }
            catch (Win32Exception ex)
            {
                throw new ExecutableInspectionException($"Could not resolve the final path of {path}: {ex.Message}", ex);
            }

            if (canonical.StartsWith(@"\\", StringComparison.Ordinal))
            {
                throw new ExecutableInspectionException($"{path} resolves to a network location ({canonical}). Only local executables can be managed.");
            }

            var info = new FileInfo(canonical);
            var size = stream.Length;
            var writeTime = info.LastWriteTimeUtc;
            if (size < 64 || !HasPeHeader(stream))
            {
                throw new ExecutableInspectionException($"{canonical} is not a Windows executable.");
            }

            if (includeHashAndSignature && _cache.TryGetValue((canonical.ToUpperInvariant(), size, writeTime), out var cached))
            {
                return cached with { RequestedPath = path };
            }

            FileVersionInfo? version = null;
            try
            {
                version = FileVersionInfo.GetVersionInfo(canonical);
            }
            catch (FileNotFoundException)
            {
            }

            string? sha256 = null;
            var signature = (Status: SignatureStatus.Unknown, Subject: (string?)null, Thumbprint: (string?)null);
            if (includeHashAndSignature)
            {
                stream.Position = 0;
                sha256 = Convert.ToHexString(SHA256.HashData(stream));
                signature = AuthenticodeVerifier.Verify(canonical, stream.SafeFileHandle);
            }

            var inspection = new ExecutableInspection
            {
                RequestedPath = path,
                CanonicalPath = canonical,
                Exists = true,
                FileSize = size,
                LastWriteUtc = new DateTimeOffset(writeTime, TimeSpan.Zero),
                Sha256 = sha256,
                FileVersion = Clean(version?.FileVersion),
                ProductName = Clean(version?.ProductName),
                FileDescription = Clean(version?.FileDescription),
                CompanyName = Clean(version?.CompanyName),
                OriginalFileName = Clean(version?.OriginalFilename),
                SignatureStatus = signature.Status,
                SignerSubject = signature.Subject,
                SignerThumbprint = signature.Thumbprint,
            };

            if (includeHashAndSignature)
            {
                if (_cache.Count > CacheLimit)
                {
                    _cache.Clear();
                }

                _cache[(canonical.ToUpperInvariant(), size, writeTime)] = inspection;
            }

            return inspection;
        }
    }

    public string? TryCanonicalize(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        using var handle = NativeMethods.CreateFile(
            path,
            NativeMethods.FileReadAttributes,
            NativeMethods.FileShareRead | NativeMethods.FileShareWrite | NativeMethods.FileShareDelete,
            IntPtr.Zero,
            NativeMethods.OpenExisting,
            NativeMethods.FileFlagBackupSemantics,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            return null;
        }

        try
        {
            return ProcessQuery.GetFinalPath(handle);
        }
        catch (Win32Exception)
        {
            return null;
        }
    }

    private static bool HasPeHeader(FileStream stream)
    {
        Span<byte> header = stackalloc byte[2];
        stream.Position = 0;
        return stream.Read(header) == 2 && header[0] == (byte)'M' && header[1] == (byte)'Z';
    }

    private static string? Clean(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var trimmed = new string(value.Where(c => !char.IsControl(c)).ToArray()).Trim();
        return trimmed.Length > 256 ? trimmed[..256] : trimmed;
    }
}

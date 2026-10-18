using System.ComponentModel;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NetGuard.Platform.Windows.Native;

/// <summary>Minimal-privilege process queries (PROCESS_QUERY_LIMITED_INFORMATION).</summary>
internal static class ProcessQuery
{
    public static SafeProcessHandle? Open(int processId, bool synchronize)
    {
        var access = NativeMethods.ProcessQueryLimitedInformation | (synchronize ? NativeMethods.Synchronize : 0);
        var handle = NativeMethods.OpenProcess(access, false, processId);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        return handle;
    }

    public static string? GetImagePath(SafeProcessHandle handle)
    {
        var capacity = 1024u;
        var builder = new StringBuilder((int)capacity);
        if (NativeMethods.QueryFullProcessImageName(handle, 0, builder, ref capacity))
        {
            return builder.ToString(0, (int)capacity);
        }

        capacity = 32768;
        builder = new StringBuilder((int)capacity);
        return NativeMethods.QueryFullProcessImageName(handle, 0, builder, ref capacity) ? builder.ToString(0, (int)capacity) : null;
    }

    public static DateTimeOffset? GetStartTime(SafeProcessHandle handle) =>
        NativeMethods.GetProcessTimes(handle, out var creation, out _, out _, out _)
            ? DateTimeOffset.FromFileTime(creation).ToUniversalTime()
            : null;

    /// <summary>Returns the final path of a file (symlinks, junctions and 8.3 names resolved) from an open handle.</summary>
    public static string GetFinalPath(SafeFileHandle file)
    {
        var builder = new StringBuilder(1024);
        var length = NativeMethods.GetFinalPathNameByHandle(file, builder, (uint)builder.Capacity, NativeMethods.VolumeNameDos);
        if (length > builder.Capacity)
        {
            builder = new StringBuilder((int)length + 1);
            length = NativeMethods.GetFinalPathNameByHandle(file, builder, (uint)builder.Capacity, NativeMethods.VolumeNameDos);
        }

        if (length == 0)
        {
            throw new Win32Exception();
        }

        return StripExtendedPrefix(builder.ToString(0, (int)length));
    }

    public static string StripExtendedPrefix(string path)
    {
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[8..];
        }

        return path.StartsWith(@"\\?\", StringComparison.Ordinal) ? path[4..] : path;
    }
}

/// <summary>Translates NT device paths (\Device\HarddiskVolume3\...) used in audit events to drive-letter paths.</summary>
internal sealed class DevicePathConverter
{
    private readonly List<(string Device, string Drive)> _map = [];
    private DateTime _builtAt;

    public string? ToDosPath(string devicePath)
    {
        if (string.IsNullOrEmpty(devicePath))
        {
            return null;
        }

        if (devicePath.Length > 2 && devicePath[1] == ':')
        {
            return devicePath;
        }

        if (DateTime.UtcNow - _builtAt > TimeSpan.FromMinutes(5))
        {
            Build();
        }

        foreach (var (device, drive) in _map)
        {
            if (devicePath.StartsWith(device + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return drive + devicePath[device.Length..];
            }
        }

        return null;
    }

    private void Build()
    {
        _map.Clear();
        foreach (var drive in DriveInfo.GetDrives().Select(d => d.Name[..2]))
        {
            var target = new StringBuilder(1024);
            if (NativeMethods.QueryDosDevice(drive, target, target.Capacity) > 0)
            {
                _map.Add((target.ToString().Split('\0')[0], drive));
            }
        }

        _builtAt = DateTime.UtcNow;
    }
}

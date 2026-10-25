using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetGuard.Domain.Networking;

/// <summary>
/// A set of IPv4 and IPv6 addresses supporting union and complement. Parses the address forms that
/// Windows Firewall accepts and returns (single address, CIDR prefix, dotted mask, hyphenated range, "*").
/// Firewall keywords such as "LocalSubnet" are deliberately not supported because they cannot be complemented.
/// </summary>
public sealed class AddressSet : IEquatable<AddressSet>
{
    private static readonly UInt128 V4Max = uint.MaxValue;
    private static readonly UInt128 V6Max = UInt128.MaxValue;

    private readonly RangeList _v4;
    private readonly RangeList _v6;

    private AddressSet(RangeList v4, RangeList v6)
    {
        _v4 = v4;
        _v6 = v6;
    }

    public static AddressSet Empty { get; } = new(new RangeList(V4Max, []), new RangeList(V6Max, []));

    public static AddressSet Any { get; } = new(new RangeList(V4Max, [(0, V4Max)]), new RangeList(V6Max, [(0, V6Max)]));

    /// <summary>
    /// Local network destinations: loopback, RFC 1918 private ranges, link-local, IPv6 unique-local,
    /// local multicast/broadcast used by discovery protocols. CGNAT (100.64.0.0/10) is intentionally excluded.
    /// </summary>
    public static AddressSet LocalNetwork { get; } = Parse(
    [
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "224.0.0.0/24", "239.255.0.0/16", "255.255.255.255",
        "::1", "fe80::/10", "fc00::/7", "ff02::/16",
    ]);

    public bool IsEmpty => _v4.IsEmpty && _v6.IsEmpty;

    public bool IsAny => _v4.IsFull && _v6.IsFull;

    /// <summary>Number of entries produced by <see cref="ToFirewallString"/>.</summary>
    public int EntryCount => IsAny ? 1 : _v4.Ranges.Count + _v6.Ranges.Count;

    public static AddressSet Parse(IEnumerable<string> entries)
    {
        if (!TryParse(entries, out var set, out var error))
        {
            throw new FormatException(error);
        }

        return set;
    }

    /// <summary>Parses a comma-separated list as stored in a firewall rule's RemoteAddresses property.</summary>
    public static bool TryParseFirewallString(string? value, out AddressSet set, out string? error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            // The firewall represents "any" as "*"; an empty value is treated the same way.
            set = Any;
            error = null;
            return true;
        }

        return TryParse(value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries), out set, out error);
    }

    public static bool TryParse(IEnumerable<string> entries, out AddressSet set, out string? error)
    {
        var v4 = new List<(UInt128, UInt128)>();
        var v6 = new List<(UInt128, UInt128)>();
        foreach (var raw in entries)
        {
            var entry = raw?.Trim() ?? string.Empty;
            if (entry.Length == 0)
            {
                continue;
            }

            if (entry == "*" || entry.Equals("any", StringComparison.OrdinalIgnoreCase))
            {
                set = Any;
                error = null;
                return true;
            }

            if (!TryParseEntry(entry, out var family, out var start, out var end, out error))
            {
                set = Empty;
                return false;
            }

            (family == AddressFamily.InterNetwork ? v4 : v6).Add((start, end));
        }

        set = new AddressSet(new RangeList(V4Max, v4), new RangeList(V6Max, v6));
        error = null;
        return true;
    }

    public bool HasIPv4 => !_v4.IsEmpty;

    public bool HasIPv6 => !_v6.IsEmpty;

    public bool IsAllIPv4 => _v4.IsFull;

    public bool IsAllIPv6 => _v6.IsFull;

    public AddressSet OnlyIPv4() => new(_v4, new RangeList(V6Max, []));

    public AddressSet OnlyIPv6() => new(new RangeList(V4Max, []), _v6);

    public AddressSet Union(AddressSet other) => new(_v4.Union(other._v4), _v6.Union(other._v6));

    public AddressSet Complement() => new(_v4.Complement(), _v6.Complement());

    public bool Contains(IPAddress address)
    {
        return address.AddressFamily switch
        {
            AddressFamily.InterNetwork => _v4.Contains(ToInteger(address)),
            AddressFamily.InterNetworkV6 => _v6.Contains(ToInteger(address)),
            _ => false,
        };
    }

    /// <summary>Formats the set for a firewall rule's RemoteAddresses property.</summary>
    public string ToFirewallString()
    {
        if (IsAny)
        {
            return "*";
        }

        if (IsEmpty)
        {
            throw new InvalidOperationException("An empty address set cannot be expressed as a firewall rule.");
        }

        var builder = new StringBuilder();
        Append(builder, _v4, AddressFamily.InterNetwork);
        Append(builder, _v6, AddressFamily.InterNetworkV6);
        return builder.ToString();
    }

    public override string ToString() => IsEmpty ? "(none)" : ToFirewallString();

    public bool Equals(AddressSet? other) => other is not null && _v4.Equals(other._v4) && _v6.Equals(other._v6);

    public override bool Equals(object? obj) => obj is AddressSet other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(_v4, _v6);

    private static readonly UInt128 IPv6Loopback = UInt128.One;

    private static void Append(StringBuilder builder, RangeList list, AddressFamily family)
    {
        foreach (var (rangeStart, rangeEnd) in list.Ranges)
        {
            var (start, end) = (rangeStart, rangeEnd);
            if (family == AddressFamily.InterNetworkV6)
            {
                // Windows Firewall rejects any entry that starts or ends at the IPv6 loopback (::1) with E_INVALIDARG,
                // although ranges spanning it are accepted. Loopback traffic is never filtered by the firewall, so
                // leaving ::1 out of the boundaries does not change what a rule matches.
                if (start == IPv6Loopback && end == IPv6Loopback)
                {
                    continue;
                }

                if (start == IPv6Loopback)
                {
                    start++;
                }

                if (end == IPv6Loopback)
                {
                    end--;
                }
            }

            if (builder.Length > 0)
            {
                builder.Append(',');
            }

            builder.Append(FromInteger(start, family));
            if (end != start)
            {
                builder.Append('-').Append(FromInteger(end, family));
            }
        }
    }

    private static bool TryParseEntry(string entry, out AddressFamily family, out UInt128 start, out UInt128 end, out string? error)
    {
        family = AddressFamily.Unspecified;
        start = end = UInt128.Zero;
        error = null;

        var dash = entry.IndexOf('-');
        if (dash > 0)
        {
            if (!TryParseAddress(entry[..dash], out var first) || !TryParseAddress(entry[(dash + 1)..], out var last))
            {
                error = $"'{entry}' is not a valid address range.";
                return false;
            }

            if (first.AddressFamily != last.AddressFamily)
            {
                error = $"'{entry}' mixes IPv4 and IPv6 addresses.";
                return false;
            }

            family = first.AddressFamily;
            start = ToInteger(first);
            end = ToInteger(last);
            if (start > end)
            {
                error = $"'{entry}' has a start address greater than its end address.";
                return false;
            }

            return true;
        }

        var slash = entry.IndexOf('/');
        if (slash > 0)
        {
            if (!TryParseAddress(entry[..slash], out var network))
            {
                error = $"'{entry}' is not a valid network address.";
                return false;
            }

            family = network.AddressFamily;
            var bits = family == AddressFamily.InterNetwork ? 32 : 128;
            var suffix = entry[(slash + 1)..];
            int prefix;
            if (int.TryParse(suffix, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var parsedPrefix))
            {
                prefix = parsedPrefix;
            }
            else if (family == AddressFamily.InterNetwork && TryParseAddress(suffix, out var mask) && mask.AddressFamily == AddressFamily.InterNetwork)
            {
                if (!TryMaskToPrefix((uint)ToInteger(mask), out prefix))
                {
                    error = $"'{entry}' has a non-contiguous subnet mask.";
                    return false;
                }
            }
            else
            {
                error = $"'{entry}' has an invalid prefix length.";
                return false;
            }

            if (prefix < 0 || prefix > bits)
            {
                error = $"'{entry}' has a prefix length outside 0-{bits}.";
                return false;
            }

            var value = ToInteger(network);
            var hostBits = bits - prefix;
            var hostMask = hostBits == 128 ? UInt128.MaxValue : (UInt128.One << hostBits) - 1;
            start = value & ~hostMask;
            end = start | hostMask;
            if (family == AddressFamily.InterNetwork)
            {
                start &= V4Max;
                end &= V4Max;
            }

            return true;
        }

        if (!TryParseAddress(entry, out var single))
        {
            error = $"'{entry}' is not a valid IP address, CIDR block or range. Firewall keywords are not supported in custom policies.";
            return false;
        }

        family = single.AddressFamily;
        start = end = ToInteger(single);
        return true;
    }

    private static bool TryParseAddress(string text, out IPAddress address)
    {
        address = IPAddress.None;
        text = text.Trim();
        if (text.Length == 0 || text.Contains('%'))
        {
            // Scoped (zone-indexed) IPv6 addresses cannot be used in firewall rules.
            return false;
        }

        if (!IPAddress.TryParse(text, out var parsed) || parsed is null)
        {
            return false;
        }

        // IPAddress.TryParse accepts shorthand such as "10" or "1.2"; require canonical dotted-quad for IPv4.
        if (parsed.AddressFamily == AddressFamily.InterNetwork && text.Count(c => c == '.') != 3)
        {
            return false;
        }

        address = parsed;
        return parsed.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6;
    }

    private static bool TryMaskToPrefix(uint mask, out int prefix)
    {
        prefix = 0;
        var seenZero = false;
        for (var bit = 31; bit >= 0; bit--)
        {
            var set = (mask & (1u << bit)) != 0;
            if (set && seenZero)
            {
                return false;
            }

            if (set)
            {
                prefix++;
            }
            else
            {
                seenZero = true;
            }
        }

        return true;
    }

    private static UInt128 ToInteger(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        UInt128 value = 0;
        foreach (var b in bytes)
        {
            value = (value << 8) | b;
        }

        return value;
    }

    private static string FromInteger(UInt128 value, AddressFamily family)
    {
        var length = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = new byte[length];
        for (var i = length - 1; i >= 0; i--)
        {
            bytes[i] = (byte)(value & 0xFF);
            value >>= 8;
        }

        return new IPAddress(bytes).ToString();
    }
}

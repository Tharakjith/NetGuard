using System.Globalization;
using System.Text;

namespace NetGuard.Domain.Networking;

/// <summary>
/// A set of TCP/UDP ports in 1-65535. Text form: "*" (all), "" (none), or "80,443,8000-8100".
/// </summary>
public sealed class PortSet : IEquatable<PortSet>
{
    private const int MinPort = 1;
    private const int MaxPort = 65535;

    private readonly RangeList _ranges;

    private PortSet(RangeList ranges) => _ranges = ranges;

    public static PortSet None { get; } = new(new RangeList(MaxPort, []));

    public static PortSet All { get; } = new(new RangeList(MaxPort, [(MinPort, MaxPort)]));

    public bool IsEmpty => _ranges.IsEmpty;

    public bool IsAll => _ranges.Ranges.Count == 1 && _ranges.Ranges[0].Start == MinPort && _ranges.Ranges[0].End == MaxPort;

    public static PortSet Parse(string? text)
    {
        if (!TryParse(text, out var set, out var error))
        {
            throw new FormatException(error);
        }

        return set;
    }

    public static bool TryParse(string? text, out PortSet set, out string? error)
    {
        set = None;
        error = null;
        if (string.IsNullOrWhiteSpace(text))
        {
            return true;
        }

        var ranges = new List<(UInt128, UInt128)>();
        foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part == "*" || part.Equals("any", StringComparison.OrdinalIgnoreCase))
            {
                set = All;
                return true;
            }

            var dash = part.IndexOf('-');
            if (dash > 0)
            {
                if (!TryParsePort(part[..dash], out var start) || !TryParsePort(part[(dash + 1)..], out var end) || start > end)
                {
                    error = $"'{part}' is not a valid port range (1-65535).";
                    return false;
                }

                ranges.Add((start, end));
            }
            else
            {
                if (!TryParsePort(part, out var port))
                {
                    error = $"'{part}' is not a valid port (1-65535).";
                    return false;
                }

                ranges.Add((port, port));
            }
        }

        set = new PortSet(new RangeList(MaxPort, ranges));
        return true;
    }

    public PortSet Complement() => new(_ranges.ComplementWithin(MinPort, MaxPort));

    public bool Contains(int port) => port is >= MinPort and <= MaxPort && _ranges.Contains((UInt128)port);

    /// <summary>Formats the set for a firewall rule's RemotePorts property.</summary>
    public string ToFirewallString()
    {
        if (IsAll)
        {
            return "*";
        }

        if (IsEmpty)
        {
            throw new InvalidOperationException("An empty port set cannot be expressed as a firewall rule.");
        }

        return ToString();
    }

    public override string ToString()
    {
        if (IsAll)
        {
            return "*";
        }

        var builder = new StringBuilder();
        foreach (var (start, end) in _ranges.Ranges)
        {
            if (builder.Length > 0)
            {
                builder.Append(',');
            }

            builder.Append(((int)start).ToString(CultureInfo.InvariantCulture));
            if (end != start)
            {
                builder.Append('-').Append(((int)end).ToString(CultureInfo.InvariantCulture));
            }
        }

        return builder.ToString();
    }

    public bool Equals(PortSet? other) => other is not null && _ranges.Equals(other._ranges);

    public override bool Equals(object? obj) => obj is PortSet other && Equals(other);

    public override int GetHashCode() => _ranges.GetHashCode();

    private static bool TryParsePort(string text, out UInt128 port)
    {
        port = 0;
        if (!int.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value is < MinPort or > MaxPort)
        {
            return false;
        }

        port = (UInt128)value;
        return true;
    }
}

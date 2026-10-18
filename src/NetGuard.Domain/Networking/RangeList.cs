namespace NetGuard.Domain.Networking;

/// <summary>
/// An immutable, sorted, non-overlapping list of closed integer ranges within [0, Max].
/// Used for IPv4/IPv6 address arithmetic and port sets.
/// </summary>
internal sealed class RangeList : IEquatable<RangeList>
{
    private readonly (UInt128 Start, UInt128 End)[] _ranges;

    public RangeList(UInt128 max, IEnumerable<(UInt128 Start, UInt128 End)> ranges)
    {
        Max = max;
        _ranges = Normalize(ranges, max);
    }

    public UInt128 Max { get; }

    public IReadOnlyList<(UInt128 Start, UInt128 End)> Ranges => _ranges;

    public bool IsEmpty => _ranges.Length == 0;

    public bool IsFull => _ranges.Length == 1 && _ranges[0].Start == UInt128.Zero && _ranges[0].End == Max;

    public RangeList Union(RangeList other)
    {
        if (other.Max != Max)
        {
            throw new ArgumentException("Range universes differ.", nameof(other));
        }

        return new RangeList(Max, _ranges.Concat(other._ranges));
    }

    public RangeList Complement() => ComplementWithin(UInt128.Zero, Max);

    /// <summary>Returns the parts of [lower, upper] that are not covered by this list.</summary>
    public RangeList ComplementWithin(UInt128 lower, UInt128 upper)
    {
        var result = new List<(UInt128, UInt128)>();
        var cursor = lower;
        var exhausted = false;
        foreach (var (start, end) in _ranges)
        {
            if (end < lower)
            {
                continue;
            }

            if (start > upper)
            {
                break;
            }

            if (start > cursor)
            {
                result.Add((cursor, start - 1));
            }

            if (end >= upper)
            {
                exhausted = true;
                break;
            }

            cursor = end + 1;
        }

        if (!exhausted && cursor <= upper)
        {
            result.Add((cursor, upper));
        }

        return new RangeList(Max, result);
    }

    public bool Contains(UInt128 value)
    {
        foreach (var (start, end) in _ranges)
        {
            if (value < start)
            {
                return false;
            }

            if (value <= end)
            {
                return true;
            }
        }

        return false;
    }

    public bool Equals(RangeList? other) =>
        other is not null && other.Max == Max && _ranges.AsSpan().SequenceEqual(other._ranges);

    public override bool Equals(object? obj) => obj is RangeList other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Max);
        foreach (var range in _ranges)
        {
            hash.Add(range);
        }

        return hash.ToHashCode();
    }

    private static (UInt128 Start, UInt128 End)[] Normalize(IEnumerable<(UInt128 Start, UInt128 End)> ranges, UInt128 max)
    {
        var sorted = ranges
            .Select(r =>
            {
                if (r.Start > r.End || r.End > max)
                {
                    throw new ArgumentOutOfRangeException(nameof(ranges), "Invalid range.");
                }

                return r;
            })
            .OrderBy(r => r.Start)
            .ToList();

        var merged = new List<(UInt128 Start, UInt128 End)>(sorted.Count);
        foreach (var range in sorted)
        {
            if (merged.Count > 0)
            {
                var last = merged[^1];
                // Merge overlapping or adjacent ranges. Guard the +1 against overflow at Max.
                if (range.Start <= last.End || (last.End != max && range.Start == last.End + 1))
                {
                    if (range.End > last.End)
                    {
                        merged[^1] = (last.Start, range.End);
                    }

                    continue;
                }
            }

            merged.Add(range);
        }

        return merged.ToArray();
    }
}

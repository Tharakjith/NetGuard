using System.Text;
using NetGuard.Core.Abstractions;
using NetGuard.Domain;
using NetGuard.Domain.Networking;

namespace NetGuard.Core.Firewall;

/// <summary>
/// Ownership marking for rules created by NetGuard. A rule is owned only when it is in the NetGuard group AND its
/// description carries a well-formed key. Rules that merely share the group name are treated as third-party rules.
/// </summary>
public static class OwnedRules
{
    public const string Grouping = "NetGuard Enterprise";

    private const string MarkerPrefix = "[ngkey:";

    public static string BuildKey(Guid applicationId, Guid executableId, string suffix) =>
        $"{applicationId:N}.{executableId:N}.{suffix}";

    public static bool TryParseKey(string? key, out Guid applicationId, out Guid executableId, out string suffix)
    {
        applicationId = executableId = Guid.Empty;
        suffix = string.Empty;
        if (string.IsNullOrEmpty(key))
        {
            return false;
        }

        var parts = key.Split('.');
        if (parts.Length != 3 ||
            !Guid.TryParseExact(parts[0], "N", out applicationId) ||
            !Guid.TryParseExact(parts[1], "N", out executableId) ||
            parts[2].Length is 0 or > 32 ||
            !parts[2].All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
        {
            return false;
        }

        suffix = parts[2];
        return true;
    }

    public static string BuildDescription(string applicationName, string key) =>
        $"Managed by NetGuard Enterprise for '{Sanitize(applicationName, 96)}'. Manual changes are reverted. {MarkerPrefix}{key}]";

    public static string BuildName(string applicationName, string executableFileName, string suffix, Guid applicationId, Guid executableId) =>
        $"NetGuard - {Sanitize(applicationName, 64)} - {Sanitize(executableFileName, 64)} ({suffix}) [{applicationId.ToString("N")[..8]}{executableId.ToString("N")[..8]}]";

    public static string? TryGetKey(string? description)
    {
        if (description is null)
        {
            return null;
        }

        var start = description.LastIndexOf(MarkerPrefix, StringComparison.Ordinal);
        if (start < 0)
        {
            return null;
        }

        start += MarkerPrefix.Length;
        var end = description.IndexOf(']', start);
        if (end < 0)
        {
            return null;
        }

        var key = description[start..end];
        return TryParseKey(key, out _, out _, out _) ? key : null;
    }

    public static bool IsOwned(FirewallRule rule) =>
        string.Equals(rule.Grouping, Grouping, StringComparison.Ordinal) && TryGetKey(rule.Description) is not null;

    /// <summary>Returns the managed application id encoded in an owned rule, or null for non-owned rules.</summary>
    public static Guid? GetApplicationId(FirewallRule rule) =>
        IsOwned(rule) && TryParseKey(TryGetKey(rule.Description), out var appId, out _, out _) ? appId : null;

    private static string Sanitize(string value, int maxLength)
    {
        var builder = new StringBuilder(Math.Min(value.Length, maxLength));
        foreach (var c in value)
        {
            if (builder.Length >= maxLength)
            {
                break;
            }

            // Brackets are reserved for the ownership marker; control characters are never stored.
            builder.Append(char.IsControl(c) || c is '[' or ']' or '|' ? ' ' : c);
        }

        return builder.ToString().Trim();
    }
}

/// <summary>Semantic comparison between a desired rule and a rule read back from the firewall.</summary>
public static class RuleMatcher
{
    public static bool Matches(FirewallRule actual, FirewallRuleSpec desired) => Explain(actual, desired) is null;

    /// <summary>Returns the first difference found, or null when the rule matches.</summary>
    public static string? Explain(FirewallRule actual, FirewallRuleSpec desired)
    {
        if (!string.Equals(actual.Name, desired.Name, StringComparison.Ordinal))
        {
            return "name differs";
        }

        if (!OwnedRules.IsOwned(actual) || OwnedRules.TryGetKey(actual.Description) != desired.Key)
        {
            return "ownership marker differs";
        }

        if (actual.Direction != FirewallDirection.Outbound)
        {
            return "direction is not outbound";
        }

        if (actual.Action != FirewallAction.Block)
        {
            return "action is not block";
        }

        if (!actual.Enabled)
        {
            return "rule is disabled";
        }

        if (!PathEquals(actual.ApplicationName, desired.ApplicationPath))
        {
            return "program path differs";
        }

        if (!string.IsNullOrEmpty(actual.ServiceName) && actual.ServiceName != "*")
        {
            return "rule is restricted to a service";
        }

        if (actual.Protocol != desired.Protocol)
        {
            return "protocol differs";
        }

        if (actual.NormalizedProfiles != desired.Profiles)
        {
            return "profiles differ";
        }

        if (!IsAny(actual.LocalAddresses) || !IsAny(actual.LocalPorts))
        {
            return "local address or port scope was added";
        }

        if (!string.IsNullOrEmpty(actual.InterfaceTypes) && !actual.InterfaceTypes.Equals("All", StringComparison.OrdinalIgnoreCase))
        {
            return "interface types were restricted";
        }

        if (!AddressSet.TryParseFirewallString(actual.RemoteAddresses, out var actualAddresses, out _) ||
            !AddressSet.TryParseFirewallString(desired.RemoteAddresses, out var desiredAddresses, out _) ||
            !actualAddresses.Equals(desiredAddresses))
        {
            return "remote addresses differ";
        }

        if (desired.Protocol is FirewallProtocols.Tcp or FirewallProtocols.Udp)
        {
            var actualPorts = string.IsNullOrWhiteSpace(actual.RemotePorts) ? "*" : actual.RemotePorts;
            if (!PortSet.TryParse(actualPorts, out var actualPortSet, out _) ||
                !PortSet.TryParse(desired.RemotePorts, out var desiredPortSet, out _) ||
                !actualPortSet.Equals(desiredPortSet))
            {
                return "remote ports differ";
            }
        }

        return null;
    }

    public static bool PathEquals(string? rulePath, string path)
    {
        if (string.IsNullOrEmpty(rulePath))
        {
            return false;
        }

        var expanded = rulePath.Contains('%') ? Environment.ExpandEnvironmentVariables(rulePath) : rulePath;
        return string.Equals(expanded, path, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAny(string? value) => string.IsNullOrWhiteSpace(value) || value == "*";
}

using System.Globalization;
using System.Windows;
using System.Windows.Data;
using NetGuard.Domain;

namespace NetGuard.Desktop.Infrastructure;

/// <summary>Plain-language enforcement labels. Only "Enforced" is presented as verified protection.</summary>
public static class StatusText
{
    public static string For(EnforcementState state) => state switch
    {
        EnforcementState.Enforced => "Enforced (verified)",
        EnforcementState.Inactive => "Inactive on this network",
        EnforcementState.Degraded => "Degraded",
        EnforcementState.Failed => "Failed",
        EnforcementState.Pending => "Pending",
        EnforcementState.Standby => "Standby (until launch)",
        EnforcementState.Suspended => "Exception active",
        EnforcementState.Disabled => "Disabled (restored)",
        EnforcementState.NotRequired => "Not required (allowed)",
        EnforcementState.Unsupported => "Unsupported",
        _ => "Unknown",
    };

    public static string BrushKey(EnforcementState state) => state switch
    {
        EnforcementState.Enforced => "StatusSuccessBrush",
        EnforcementState.Failed => "StatusErrorBrush",
        EnforcementState.Degraded or EnforcementState.Unsupported => "StatusWarningBrush",
        EnforcementState.Inactive or EnforcementState.Suspended or EnforcementState.Pending => "StatusInfoBrush",
        _ => "StatusNeutralBrush",
    };

    public static string Policy(ApplicationPolicy? policy)
    {
        if (policy is null)
        {
            return string.Empty;
        }

        var mode = policy.Mode switch
        {
            PolicyMode.Allow => "Allow",
            PolicyMode.Block => "Block",
            _ => "Custom allow-list",
        };
        if (!policy.RequiresRules)
        {
            return mode;
        }

        var retention = policy.Retention == RetentionMode.Persistent ? "persistent" : "while running";
        var profiles = policy.Profiles == NetworkProfiles.All ? string.Empty : $", {policy.Profiles.ToString().Replace(", ", "/", StringComparison.Ordinal)} only";
        return $"{mode} ({retention}{profiles})";
    }
}

public sealed class EnforcementTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is EnforcementState state ? StatusText.For(state) : string.Empty;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class EnforcementBrushConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is EnforcementState state ? Application.Current.TryFindResource(StatusText.BrushKey(state)) : null;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class PolicyTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => StatusText.Policy(value as ApplicationPolicy);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var flag = value is true;
        if (parameter is "invert")
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object parameter, CultureInfo culture)
    {
        var hasValue = value is not null && (value is not string s || s.Length > 0) && (value is not System.Collections.ICollection c || c.Count > 0);
        if (parameter is "invert")
        {
            hasValue = !hasValue;
        }

        return hasValue ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class RunningTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => value is true ? "Running" : "Stopped";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class LocalTimeConverter : IValueConverter
{
    // CurrentCulture (not the binding culture) so custom date formats from Windows regional settings are honored,
    // matching dates formatted in view models.
    public object? Convert(object? value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        DateTimeOffset dto => dto.ToLocalTime().ToString(parameter as string ?? "g", CultureInfo.CurrentCulture),
        _ => null,
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class OutcomeBrushConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture) => value switch
    {
        AuditOutcome.Success => Application.Current.TryFindResource("StatusSuccessBrush"),
        AuditOutcome.Failure => Application.Current.TryFindResource("StatusErrorBrush"),
        AuditOutcome.Warning or AuditOutcome.Denied => Application.Current.TryFindResource("StatusWarningBrush"),
        _ => Application.Current.TryFindResource("StatusNeutralBrush"),
    };

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class IconConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object parameter, CultureInfo culture) => Services.IconCache.Get(value as string);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotSupportedException();
}

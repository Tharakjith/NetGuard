using System.Globalization;
using System.Text;
using System.Text.Json;
using NetGuard.Contracts;
using NetGuard.Domain;

namespace NetGuard.Core.Auditing;

public static class AuditExporter
{
    public const int MaxExportRows = 50_000;

    public static ExportResultDto Export(IReadOnlyList<AuditEvent> events, ExportFormat format, DateTimeOffset now)
    {
        var stamp = now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture);
        return format == ExportFormat.Csv
            ? new ExportResultDto { SuggestedFileName = $"netguard-audit-{stamp}.csv", ContentType = "text/csv", Content = ToCsv(events) }
            : new ExportResultDto { SuggestedFileName = $"netguard-audit-{stamp}.json", ContentType = "application/json", Content = JsonSerializer.Serialize(events, NetGuardJson.Indented) };
    }

    public static string ToCsv(IEnumerable<AuditEvent> events)
    {
        var builder = new StringBuilder();
        builder.AppendLine("Id,TimestampUtc,Type,Outcome,Actor,Application,ApplicationId,ExecutablePath,Message,Details");
        foreach (var e in events)
        {
            builder
                .Append(e.Id.ToString(CultureInfo.InvariantCulture)).Append(',')
                .Append(Field(e.Timestamp.UtcDateTime.ToString("O", CultureInfo.InvariantCulture))).Append(',')
                .Append(Field(e.Type.ToString())).Append(',')
                .Append(Field(e.Outcome.ToString())).Append(',')
                .Append(Field(e.Actor)).Append(',')
                .Append(Field(e.ApplicationName)).Append(',')
                .Append(Field(e.ApplicationId?.ToString())).Append(',')
                .Append(Field(e.ExecutablePath)).Append(',')
                .Append(Field(e.Message)).Append(',')
                .Append(Field(e.Details))
                .AppendLine();
        }

        return builder.ToString();
    }

    /// <summary>
    /// Quotes a CSV field and neutralizes spreadsheet formula injection: values beginning with = + - @ or control
    /// characters are prefixed with an apostrophe so spreadsheet applications treat them as text.
    /// </summary>
    public static string Field(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        if (value[0] is '=' or '+' or '-' or '@' or '\t' or '\r')
        {
            value = "'" + value;
        }

        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}

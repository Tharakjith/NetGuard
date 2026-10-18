using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace NetGuard.Logging;

public sealed class JsonFileLoggerOptions
{
    public required string Directory { get; init; }

    public string FilePrefix { get; init; } = "netguard";

    public LogLevel MinimumLevel { get; init; } = LogLevel.Information;

    /// <summary>Evaluated on every clean-up so retention follows the live service setting.</summary>
    public Func<int> RetentionDays { get; init; } = () => 30;

    public long MaxFileBytes { get; init; } = 20 * 1024 * 1024;
}

/// <summary>
/// Structured JSON-lines file logging with daily and size-based rolling and age-based retention. Writes happen on a
/// background task so logging never blocks enforcement; if the queue overflows the oldest entries are dropped and a
/// counter is written instead.
/// </summary>
public sealed class JsonFileLoggerProvider : ILoggerProvider
{
    private static readonly JsonWriterOptions WriterOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly JsonFileLoggerOptions _options;
    private readonly ConcurrentDictionary<string, JsonFileLogger> _loggers = new(StringComparer.Ordinal);
    private readonly Channel<string> _queue = Channel.CreateBounded<string>(new BoundedChannelOptions(10_000) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
    private readonly Task _writer;
    private long _dropped;

    public JsonFileLoggerProvider(JsonFileLoggerOptions options)
    {
        _options = options;
        System.IO.Directory.CreateDirectory(options.Directory);
        _writer = Task.Run(WriteLoopAsync);
    }

    public ILogger CreateLogger(string categoryName) => _loggers.GetOrAdd(categoryName, name => new JsonFileLogger(name, this));

    public void Dispose()
    {
        _queue.Writer.TryComplete();
        try
        {
            _writer.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
        }
    }

    internal bool IsEnabled(LogLevel level) => level != LogLevel.None && level >= _options.MinimumLevel;

    internal void Enqueue(string line)
    {
        if (!_queue.Writer.TryWrite(line))
        {
            Interlocked.Increment(ref _dropped);
        }
    }

    internal static string Format<TState>(string category, LogLevel level, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, WriterOptions))
        {
            writer.WriteStartObject();
            writer.WriteString("ts", DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
            writer.WriteString("level", level.ToString());
            writer.WriteString("category", category);
            if (eventId.Id != 0)
            {
                writer.WriteNumber("eventId", eventId.Id);
            }

            writer.WriteString("message", formatter(state, exception));
            if (state is IEnumerable<KeyValuePair<string, object?>> properties)
            {
                foreach (var (key, value) in properties)
                {
                    if (key == "{OriginalFormat}" || key.Length == 0)
                    {
                        continue;
                    }

                    var name = char.ToLowerInvariant(key[0]) + key[1..];
                    switch (value)
                    {
                        case null:
                            writer.WriteNull(name);
                            break;
                        case bool b:
                            writer.WriteBoolean(name, b);
                            break;
                        case int or long or short or byte or uint or ulong:
                            writer.WriteNumber(name, Convert.ToInt64(value, CultureInfo.InvariantCulture));
                            break;
                        case double or float or decimal:
                            writer.WriteNumber(name, Convert.ToDouble(value, CultureInfo.InvariantCulture));
                            break;
                        default:
                            writer.WriteString(name, Convert.ToString(value, CultureInfo.InvariantCulture));
                            break;
                    }
                }
            }

            if (exception is not null)
            {
                writer.WriteString("exception", exception.ToString());
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private async Task WriteLoopAsync()
    {
        StreamWriter? file = null;
        var currentDay = DateOnly.MinValue;
        var sequence = 0;
        var lastCleanup = DateTime.MinValue;
        try
        {
            while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
            {
                var today = DateOnly.FromDateTime(DateTime.UtcNow);
                if (file is null || today != currentDay || file.BaseStream.Length > _options.MaxFileBytes)
                {
                    if (file is not null)
                    {
                        await file.DisposeAsync().ConfigureAwait(false);
                    }

                    sequence = today != currentDay ? 0 : sequence + 1;
                    currentDay = today;
                    file = OpenFile(today, ref sequence);
                }

                if (DateTime.UtcNow - lastCleanup > TimeSpan.FromHours(6))
                {
                    lastCleanup = DateTime.UtcNow;
                    DeleteExpired();
                }

                var dropped = Interlocked.Exchange(ref _dropped, 0);
                if (dropped > 0)
                {
                    await file.WriteLineAsync($"{{\"ts\":\"{DateTimeOffset.UtcNow:O}\",\"level\":\"Warning\",\"category\":\"NetGuard.Logging\",\"message\":\"{dropped} log entries were dropped because the log queue was full.\"}}").ConfigureAwait(false);
                }

                while (_queue.Reader.TryRead(out var line))
                {
                    await file.WriteLineAsync(line).ConfigureAwait(false);
                }

                await file.FlushAsync().ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
            // Logging must never crash the host. Entries are lost until the next restart if the disk is unusable.
        }
        finally
        {
            if (file is not null)
            {
                await file.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private StreamWriter OpenFile(DateOnly day, ref int sequence)
    {
        while (true)
        {
            var suffix = sequence == 0 ? string.Empty : $"-{sequence}";
            var path = Path.Combine(_options.Directory, $"{_options.FilePrefix}-{day:yyyyMMdd}{suffix}.jsonl");
            var info = new FileInfo(path);
            if (!info.Exists || info.Length < _options.MaxFileBytes)
            {
                var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
                return new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = false };
            }

            sequence++;
        }
    }

    private void DeleteExpired()
    {
        var cutoff = DateTime.UtcNow.AddDays(-Math.Max(1, _options.RetentionDays()));
        foreach (var file in new DirectoryInfo(_options.Directory).GetFiles($"{_options.FilePrefix}-*.jsonl"))
        {
            if (file.LastWriteTimeUtc < cutoff)
            {
                try
                {
                    file.Delete();
                }
                catch (IOException)
                {
                }
            }
        }
    }

    private sealed class JsonFileLogger(string category, JsonFileLoggerProvider provider) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => provider.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                provider.Enqueue(Format(category, logLevel, eventId, state, exception, formatter));
            }
        }
    }
}

public static class JsonFileLoggerExtensions
{
    public static ILoggingBuilder AddJsonFile(this ILoggingBuilder builder, JsonFileLoggerOptions options)
    {
        builder.AddProvider(new JsonFileLoggerProvider(options));
        return builder;
    }
}

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace NetGuard.Tests.Integration;

/// <summary>Collects log output so a failing test can show what the component reported.</summary>
public sealed class CapturingLogger<T> : ILogger<T>
{
    public ConcurrentQueue<string> Entries { get; } = new();

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
        Entries.Enqueue($"{logLevel}: {formatter(state, exception)} {exception}");
}

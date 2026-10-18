using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetGuard.Contracts;

namespace NetGuard.Ipc;

/// <summary>The authenticated identity of a pipe client, taken from its access token.</summary>
public sealed record PipeCaller
{
    public required string Name { get; init; }

    public string? Sid { get; init; }

    public bool IsLocalSystem { get; init; }

    /// <summary>Administrators group is enabled in the token (elevated). UAC-filtered tokens report false.</summary>
    public bool IsElevatedAdministrator { get; init; }

    public bool IsOperator { get; init; }

    public int ProcessId { get; init; }
}

public interface IPipeRequestHandler
{
    Task<IpcResponse> HandleAsync(IpcRequest request, PipeCaller caller, CancellationToken cancellationToken);
}

public sealed class PipeServerOptions
{
    public string PipeName { get; init; } = IpcConstants.PipeName;

    public int MaxConcurrentConnections { get; init; } = 16;

    public TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(10);

    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>SID of the local "NetGuard Operators" group, if it exists.</summary>
    public SecurityIdentifier? OperatorsGroup { get; init; }

    /// <summary>Requests per second allowed per connection after the burst is used.</summary>
    public double RequestsPerSecond { get; init; } = 20;

    public int Burst { get; init; } = 60;
}

/// <summary>
/// Named-pipe server. The pipe ACL grants local authenticated users read/write, denies all network logons, and does
/// not allow anyone but SYSTEM to create additional pipe instances. Each connection's identity is read from the
/// client token once (identification-level impersonation) and attached to every request.
/// </summary>
public sealed class PipeServer
{
    private readonly IPipeRequestHandler _handler;
    private readonly PipeServerOptions _options;
    private readonly ILogger<PipeServer> _logger;

    public PipeServer(IPipeRequestHandler handler, PipeServerOptions options, ILogger<PipeServer> logger)
    {
        _handler = handler;
        _options = options;
        _logger = logger;
    }

    public static PipeSecurity CreateSecurity()
    {
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

        // The server's own identity (SYSTEM when running as the service) needs CreateNewInstance for additional instances.
        using (var self = WindowsIdentity.GetCurrent())
        {
            if (self.User is { } user)
            {
                security.AddAccessRule(new PipeAccessRule(user, PipeAccessRights.FullControl, AccessControlType.Allow));
            }
        }
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));
        return security;
    }

    public async Task RunAsync(CancellationToken stoppingToken)
    {
        using var slots = new SemaphoreSlim(_options.MaxConcurrentConnections);
        var first = true;
        var connections = new List<Task>();
        while (!stoppingToken.IsCancellationRequested)
        {
            await slots.WaitAsync(stoppingToken).ConfigureAwait(false);
            NamedPipeServerStream server;
            try
            {
                server = NamedPipeServerStreamAcl.Create(
                    _options.PipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None),
                    inBufferSize: 64 * 1024,
                    outBufferSize: 64 * 1024,
                    CreateSecurity());
                first = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                slots.Release();

                // FirstPipeInstance failing means another process already owns the name (possible squatting).
                _logger.LogCritical(ex, "Could not create the control pipe {Pipe}; another process may be using the name. Retrying.", _options.PipeName);
                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
                continue;
            }

            try
            {
                await server.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                await server.DisposeAsync().ConfigureAwait(false);
                slots.Release();
                break;
            }
            catch (IOException ex)
            {
                _logger.LogWarning(ex, "Pipe connection failed before it was established");
                await server.DisposeAsync().ConfigureAwait(false);
                slots.Release();
                continue;
            }

            connections.RemoveAll(t => t.IsCompleted);
            connections.Add(Task.Run(async () =>
            {
                try
                {
                    await HandleConnectionAsync(server, stoppingToken).ConfigureAwait(false);
                }
                finally
                {
                    await server.DisposeAsync().ConfigureAwait(false);
                    slots.Release();
                }
            }, CancellationToken.None));
        }

        await Task.WhenAll(connections).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        PipeCaller caller;
        try
        {
            caller = Identify(pipe);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException or InvalidOperationException)
        {
            _logger.LogWarning(ex, "Rejected a pipe client whose identity could not be determined");
            return;
        }

        var bucket = new TokenBucket(_options.Burst, _options.RequestsPerSecond);
        while (!stoppingToken.IsCancellationRequested)
        {
            byte[]? message;
            using (var idle = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken))
            {
                idle.CancelAfter(_options.IdleTimeout);
                try
                {
                    message = await MessageFraming.ReadAsync(pipe, IpcConstants.MaxRequestBytes, idle.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException)
                {
                    _logger.LogDebug(ex, "Pipe client {Caller} disconnected or sent an invalid frame", caller.Name);
                    return;
                }
            }

            if (message is null)
            {
                return;
            }

            IpcResponse response;
            IpcRequest? request = null;
            try
            {
                request = JsonSerializer.Deserialize<IpcRequest>(message, NetGuardJson.Options);
            }
            catch (JsonException)
            {
            }

            if (request is null || string.IsNullOrEmpty(request.Command))
            {
                response = IpcResponse.Fail(Guid.Empty, IpcErrorCodes.BadRequest, "The request could not be parsed.");
            }
            else if (!bucket.TryTake())
            {
                response = IpcResponse.Fail(request.RequestId, IpcErrorCodes.RateLimited, "Too many requests. Slow down and retry.");
            }
            else
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(_options.RequestTimeout);
                try
                {
                    response = await _handler.HandleAsync(request, caller, timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
                {
                    response = IpcResponse.Fail(request.RequestId, IpcErrorCodes.Timeout, "The request timed out.");
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogError(ex, "Unhandled error processing {Command}", request.Command);
                    response = IpcResponse.Fail(request.RequestId, IpcErrorCodes.InternalError, "An internal error occurred. See the service log for details.");
                }
            }

            try
            {
                var bytes = JsonSerializer.SerializeToUtf8Bytes(response, NetGuardJson.Options);
                if (bytes.Length > IpcConstants.MaxMessageBytes)
                {
                    bytes = JsonSerializer.SerializeToUtf8Bytes(
                        IpcResponse.Fail(response.RequestId, IpcErrorCodes.InternalError, "The response was too large. Narrow the query."), NetGuardJson.Options);
                }

                await MessageFraming.WriteAsync(pipe, bytes, IpcConstants.MaxMessageBytes, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>
    /// Reads the client's identity by impersonating it at identification level. Impersonation is per thread, so this
    /// runs on a dedicated short-lived thread that reverts explicitly and then exits: a client token can never remain
    /// on a thread-pool thread that later performs privileged service work (firewall, SCM, file access).
    /// </summary>
    private PipeCaller Identify(NamedPipeServerStream pipe)
    {
        // Resolve everything that may load assemblies or touch files before impersonating.
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var operators = _options.OperatorsGroup;
        PipeCaller? caller = null;
        Exception? failure = null;

        var thread = new Thread(() =>
        {
            try
            {
                pipe.RunAsClient(() =>
                {
                    using var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query);
                    var principal = new WindowsPrincipal(identity);
                    caller = new PipeCaller
                    {
                        Name = identity.Name,
                        Sid = identity.User?.Value,
                        IsLocalSystem = identity.IsSystem,
                        IsElevatedAdministrator = principal.IsInRole(administrators),
                        IsOperator = operators is not null && principal.IsInRole(operators),
                    };
                });
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                RevertToSelf();
            }
        })
        {
            IsBackground = true,
            Name = "NetGuard pipe client identification",
        };
        thread.Start();
        if (!thread.Join(TimeSpan.FromSeconds(10)))
        {
            throw new InvalidOperationException("Timed out identifying the pipe client.");
        }

        if (failure is not null)
        {
            throw new InvalidOperationException("Client identity could not be determined.", failure);
        }

        if (caller is null)
        {
            throw new InvalidOperationException("Client identity unavailable.");
        }

        return GetNamedPipeClientProcessId(pipe.SafePipeHandle, out var pid) ? caller with { ProcessId = (int)pid } : caller;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint clientProcessId);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();

    private sealed class TokenBucket(int capacity, double ratePerSecond)
    {
        private double _tokens = capacity;
        private DateTime _last = DateTime.UtcNow;

        public bool TryTake()
        {
            var now = DateTime.UtcNow;
            _tokens = Math.Min(capacity, _tokens + ((now - _last).TotalSeconds * ratePerSecond));
            _last = now;
            if (_tokens < 1)
            {
                return false;
            }

            _tokens--;
            return true;
        }
    }
}

internal sealed class SecurityException(string message) : Exception(message);

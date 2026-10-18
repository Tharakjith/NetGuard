using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using NetGuard.Contracts;

namespace NetGuard.Ipc;

public sealed class PipeClientOptions
{
    public string PipeName { get; init; } = IpcConstants.PipeName;

    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>
    /// SIDs allowed to own the server end. A pipe created by the NetGuard service (LocalSystem) is owned by SYSTEM or
    /// Administrators; a standard user cannot create a pipe with either owner, so this defeats pipe-name squatting.
    /// </summary>
    public IReadOnlyCollection<SecurityIdentifier> TrustedServerOwners { get; init; } =
    [
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
    ];
}

/// <summary>Client for the NetGuard control pipe. One request in flight per instance; reconnects once on failure.</summary>
public sealed class PipeClient : IAsyncDisposable
{
    private readonly PipeClientOptions _options;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private NamedPipeClientStream? _pipe;

    public PipeClient(PipeClientOptions? options = null) => _options = options ?? new PipeClientOptions();

    public bool IsConnected => _pipe?.IsConnected == true;

    public async Task<TResponse> SendAsync<TResponse>(string command, object? payload, CancellationToken cancellationToken)
    {
        var response = await SendCoreAsync(command, payload, cancellationToken).ConfigureAwait(false);
        if (response.Payload is not { } element)
        {
            throw new IpcException(IpcErrorCodes.InternalError, $"The service returned no data for {command}.");
        }

        return element.Deserialize<TResponse>(NetGuardJson.Options)
               ?? throw new IpcException(IpcErrorCodes.InternalError, $"The service returned invalid data for {command}.");
    }

    public async Task SendAsync(string command, object? payload, CancellationToken cancellationToken) =>
        await SendCoreAsync(command, payload, cancellationToken).ConfigureAwait(false);

    public async ValueTask DisposeAsync()
    {
        if (_pipe is not null)
        {
            await _pipe.DisposeAsync().ConfigureAwait(false);
        }

        _gate.Dispose();
    }

    private async Task<IpcResponse> SendCoreAsync(string command, object? payload, CancellationToken cancellationToken)
    {
        var request = new IpcRequest
        {
            Command = command,
            Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, NetGuardJson.Options),
        };
        var bytes = JsonSerializer.SerializeToUtf8Bytes(request, NetGuardJson.Options);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            for (var attempt = 0; ; attempt++)
            {
                var sent = false;
                try
                {
                    var pipe = await EnsureConnectedAsync(cancellationToken).ConfigureAwait(false);
                    await MessageFraming.WriteAsync(pipe, bytes, IpcConstants.MaxRequestBytes, cancellationToken).ConfigureAwait(false);
                    sent = true;
                    var reply = await MessageFraming.ReadAsync(pipe, IpcConstants.MaxMessageBytes, cancellationToken).ConfigureAwait(false)
                                ?? throw new IOException("The service closed the connection.");
                    var response = JsonSerializer.Deserialize<IpcResponse>(reply, NetGuardJson.Options)
                                   ?? throw new IpcException(IpcErrorCodes.InternalError, "Invalid response from the service.");
                    if (!response.Success)
                    {
                        throw new IpcException(response.ErrorCode ?? IpcErrorCodes.InternalError, response.ErrorMessage ?? "The request failed.", response.ValidationErrors);
                    }

                    return response;
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException && attempt == 0 && !sent)
                {
                    // A stale connection (for example after a service restart) failed before the request was sent,
                    // so retrying cannot execute the command twice.
                    await ResetAsync().ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or ObjectDisposedException or TimeoutException)
                {
                    await ResetAsync().ConfigureAwait(false);
                    throw new IpcException("ServiceUnavailable", "The NetGuard service is not reachable. Check that the 'NetGuard Enterprise' service is running.", null, ex);
                }
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<NamedPipeClientStream> EnsureConnectedAsync(CancellationToken cancellationToken)
    {
        if (_pipe is { IsConnected: true })
        {
            return _pipe;
        }

        await ResetAsync().ConfigureAwait(false);
        var pipe = new NamedPipeClientStream(".", _options.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            await pipe.ConnectAsync(_options.ConnectTimeout, cancellationToken).ConfigureAwait(false);
            VerifyServer(pipe);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        _pipe = pipe;
        return pipe;
    }

    private void VerifyServer(NamedPipeClientStream pipe)
    {
        var owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !_options.TrustedServerOwners.Contains(owner))
        {
            throw new IpcException(IpcErrorCodes.Unauthorized,
                $"Refusing to talk to the control pipe: it is owned by {owner?.Value ?? "an unknown account"}, not by the NetGuard service. Another program may be impersonating the service.");
        }
    }

    private async Task ResetAsync()
    {
        if (_pipe is not null)
        {
            await _pipe.DisposeAsync().ConfigureAwait(false);
            _pipe = null;
        }
    }
}

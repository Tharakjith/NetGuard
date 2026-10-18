using System.Security.Principal;
using Microsoft.Extensions.Logging.Abstractions;
using NetGuard.Contracts;
using NetGuard.Ipc;
using NetGuard.Platform.Windows.Firewall;
using Xunit;

namespace NetGuard.Tests.Integration;

/// <summary>
/// Regression test: identifying a pipe client must not leave an impersonation token on any thread that later runs
/// service work. If it did, privileged operations would fail with access denied after the first client connected.
/// </summary>
public sealed class PipeImpersonationTests
{
    [Fact]
    public async Task HandlerRunsInServiceSecurityContext_AfterClientIdentification()
    {
        var pipeName = "NetGuardTest-" + Guid.NewGuid().ToString("N");
        var handler = new FirewallProbeHandler();
        var log = new CapturingLogger<PipeServer>();
        var server = new PipeServer(handler, new PipeServerOptions { PipeName = pipeName }, log);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var serverTask = server.RunAsync(stop.Token);

        using var self = WindowsIdentity.GetCurrent();
        await using var client = new PipeClient(new PipeClientOptions
        {
            PipeName = pipeName,
            TrustedServerOwners = [.. new PipeClientOptions().TrustedServerOwners, self.User!],
        });

        for (var i = 0; i < 20; i++)
        {
            ProbeResult result;
            try
            {
                result = await client.SendAsync<ProbeResult>(Commands.GetServiceInfo, null, stop.Token);
            }
            catch (IpcException ex)
            {
                throw new Xunit.Sdk.XunitException($"Request {i} failed: {ex.Message}\nServer log:\n{string.Join("\n", log.Entries)}");
            }

            Assert.True(result.FirewallAvailable, $"Request {i}: {result.Error}");
            Assert.False(result.Impersonating, $"Request {i} ran while impersonating the client.");
        }

        stop.Cancel();
        await Task.WhenAny(serverTask, Task.Delay(TimeSpan.FromSeconds(10)));
    }

    public sealed record ProbeResult(bool FirewallAvailable, bool Impersonating, string? Error);

    private sealed class FirewallProbeHandler : IPipeRequestHandler
    {
        private readonly WindowsFirewallManager _firewall = new(NullLogger<WindowsFirewallManager>.Instance);

        public async Task<IpcResponse> HandleAsync(IpcRequest request, PipeCaller caller, CancellationToken cancellationToken)
        {
            await Task.Yield();
            ProbeResult payload;
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var state = _firewall.GetState();
                payload = new ProbeResult(state.Available, identity.ImpersonationLevel != TokenImpersonationLevel.None, state.Error);
            }
            catch (Exception ex)
            {
                payload = new ProbeResult(false, true, ex.GetType().Name + ": " + ex.Message);
            }

            return IpcResponse.Ok(request.RequestId, System.Text.Json.JsonSerializer.SerializeToElement(payload, NetGuardJson.Options));
        }
    }
}

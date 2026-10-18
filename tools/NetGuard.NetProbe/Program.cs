using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

// Controlled test application for NetGuard end-to-end verification.
//   NetGuard.NetProbe <host> <port> [--udp] [--ipv4|--ipv6] [--timeout <ms>] [--hold <ms>]
// Exit code 0: connected (and, with TestServer, received an echo). 1: connection failed. 2: usage error.
// Copy it to different paths to compare a blocked copy with an unrestricted one.

if (args.Length < 2 || !int.TryParse(args[1], out var port) || port is < 1 or > 65535)
{
    Console.Error.WriteLine("Usage: NetGuard.NetProbe <host> <port> [--udp] [--ipv4|--ipv6] [--timeout <ms>]");
    return 2;
}

var host = args[0];
var udp = args.Contains("--udp");
var family = args.Contains("--ipv6") ? AddressFamily.InterNetworkV6 : args.Contains("--ipv4") ? AddressFamily.InterNetwork : AddressFamily.Unspecified;
var timeoutIndex = Array.IndexOf(args, "--timeout");
var timeout = timeoutIndex >= 0 && timeoutIndex + 1 < args.Length && int.TryParse(args[timeoutIndex + 1], out var t) ? t : 5000;

// --hold <ms>: stay running before connecting, so launch detection can be observed even when the connection is
// refused immediately.
var holdIndex = Array.IndexOf(args, "--hold");
if (holdIndex >= 0 && holdIndex + 1 < args.Length && int.TryParse(args[holdIndex + 1], out var hold) && hold > 0)
{
    await Task.Delay(hold);
}

var stopwatch = Stopwatch.StartNew();
string? remote = null;
string? error = null;
var success = false;
try
{
    var addresses = (await Dns.GetHostAddressesAsync(host)).Where(a => family == AddressFamily.Unspecified || a.AddressFamily == family).ToList();
    if (addresses.Count == 0)
    {
        throw new SocketException((int)SocketError.HostNotFound);
    }

    var address = addresses[0];
    remote = new IPEndPoint(address, port).ToString();
    using var cts = new CancellationTokenSource(timeout);
    var payload = Encoding.UTF8.GetBytes($"netguard-probe {Environment.ProcessId}\n");
    if (udp)
    {
        using var client = new UdpClient(address.AddressFamily);
        await client.SendAsync(payload, new IPEndPoint(address, port), cts.Token);
        var reply = await client.ReceiveAsync(cts.Token);
        success = reply.Buffer.Length > 0;
    }
    else
    {
        using var client = new TcpClient(address.AddressFamily);
        await client.ConnectAsync(address, port, cts.Token);
        success = true;
        var stream = client.GetStream();
        await stream.WriteAsync(payload, cts.Token);
    }
}
catch (Exception ex) when (ex is SocketException or OperationCanceledException or IOException)
{
    error = ex is OperationCanceledException ? $"timed out after {timeout} ms" : ex.Message;
}

Console.WriteLine(JsonSerializer.Serialize(new
{
    executable = Environment.ProcessPath,
    remote,
    protocol = udp ? "udp" : "tcp",
    success,
    error,
    elapsedMs = stopwatch.ElapsedMilliseconds,
}));
return success ? 0 : 1;

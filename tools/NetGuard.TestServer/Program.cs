using System.Net;
using System.Net.Sockets;

// Local test server for NetGuard end-to-end traffic verification. Run it on a DIFFERENT machine (or VM) than the one
// under test: Windows Firewall does not filter loopback traffic, including connections to the machine's own addresses.
//   NetGuard.TestServer [--port 5099]
// Listens on TCP and UDP, IPv4 and IPv6 (dual mode), echoes one line back and logs each connection.

var portIndex = Array.IndexOf(args, "--port");
var port = portIndex >= 0 && portIndex + 1 < args.Length && int.TryParse(args[portIndex + 1], out var p) ? p : 5099;
using var stop = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stop.Cancel();
};

var tcp = new TcpListener(IPAddress.IPv6Any, port);
tcp.Server.DualMode = true;
tcp.Start();
using var udp = new UdpClient(AddressFamily.InterNetworkV6);
udp.Client.DualMode = true;
udp.Client.Bind(new IPEndPoint(IPAddress.IPv6Any, port));
Console.WriteLine($"NetGuard test server listening on TCP/UDP port {port} (IPv4 and IPv6). Press Ctrl+C to stop.");

var udpLoop = Task.Run(async () =>
{
    while (!stop.IsCancellationRequested)
    {
        try
        {
            var received = await udp.ReceiveAsync(stop.Token);
            Console.WriteLine($"{DateTime.Now:T} UDP from {received.RemoteEndPoint}");
            await udp.SendAsync(received.Buffer, received.RemoteEndPoint, stop.Token);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine($"UDP error: {ex.Message}");
        }
    }
});

try
{
    while (!stop.IsCancellationRequested)
    {
        var client = await tcp.AcceptTcpClientAsync(stop.Token);
        _ = Task.Run(async () =>
        {
            using (client)
            {
                Console.WriteLine($"{DateTime.Now:T} TCP from {client.Client.RemoteEndPoint}");
                var buffer = new byte[256];
                var stream = client.GetStream();
                stream.ReadTimeout = 5000;
                try
                {
                    var read = await stream.ReadAsync(buffer, stop.Token);
                    await stream.WriteAsync(buffer.AsMemory(0, read), stop.Token);
                }
                catch (Exception ex) when (ex is IOException or OperationCanceledException)
                {
                }
            }
        });
    }
}
catch (OperationCanceledException)
{
}

tcp.Stop();
await udpLoop;

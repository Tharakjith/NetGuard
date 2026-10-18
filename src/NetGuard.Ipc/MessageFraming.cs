using System.Buffers.Binary;

namespace NetGuard.Ipc;

/// <summary>Length-prefixed framing: a 4-byte little-endian length followed by a UTF-8 JSON payload.</summary>
public static class MessageFraming
{
    public static async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> payload, int maxBytes, CancellationToken cancellationToken)
    {
        if (payload.Length == 0 || payload.Length > maxBytes)
        {
            throw new InvalidDataException($"Message size {payload.Length} is outside the allowed range (1-{maxBytes} bytes).");
        }

        var header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one message. Returns null when the peer closed the connection cleanly before a new message.</summary>
    public static async Task<byte[]?> ReadAsync(Stream stream, int maxBytes, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        var read = await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        if (read < header.Length)
        {
            throw new EndOfStreamException("Connection closed inside a message header.");
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > maxBytes)
        {
            throw new InvalidDataException($"Declared message size {length} is outside the allowed range (1-{maxBytes} bytes).");
        }

        var payload = new byte[length];
        if (await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false) < length)
        {
            throw new EndOfStreamException("Connection closed inside a message.");
        }

        return payload;
    }

    private static async Task<int> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return total;
            }

            total += read;
        }

        return total;
    }
}

public sealed class IpcException : Exception
{
    public IpcException(string code, string message, IReadOnlyList<string>? validationErrors = null, Exception? inner = null)
        : base(message, inner)
    {
        Code = code;
        ValidationErrors = validationErrors ?? [];
    }

    public string Code { get; }

    public IReadOnlyList<string> ValidationErrors { get; }
}

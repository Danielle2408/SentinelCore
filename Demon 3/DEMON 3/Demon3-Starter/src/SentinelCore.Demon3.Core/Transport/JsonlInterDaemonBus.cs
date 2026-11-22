using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using SentinelCore.Demon3.Core.Contracts;

namespace SentinelCore.Demon3.Core.Transport;

/// <summary>Test transport only: one UTF-8 JSON envelope per line. Not a secured production IPC transport.</summary>
public sealed class JsonlInterDaemonBus(TextReader reader, TextWriter writer) : IInterDaemonBus
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public async ValueTask SendAsync(DaemonEnvelope message, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(message, JsonOptions);
        var byteCount = Encoding.UTF8.GetByteCount(json);
        if (byteCount > 64 * 1024) throw new InvalidDataException("Message exceeds the 64 KiB V1 limit.");
        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            await writer.WriteLineAsync(json.AsMemory(), cancellationToken);
            await writer.FlushAsync(cancellationToken);
        }
        finally { _writeLock.Release(); }
    }

    public async IAsyncEnumerable<DaemonEnvelope> ReadAllAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null) yield break;
            if (Encoding.UTF8.GetByteCount(line) > 64 * 1024)
                throw new InvalidDataException("Received JSONL message exceeds the 64 KiB V1 limit.");
            DaemonEnvelope? message;
            try { message = JsonSerializer.Deserialize<DaemonEnvelope>(line, JsonOptions); }
            catch (JsonException ex) { throw new InvalidDataException("Invalid JSONL envelope.", ex); }
            if (message is null) throw new InvalidDataException("Empty JSONL envelope.");
            yield return message;
        }
    }
}

using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using System.Security.Principal;
using System.Threading.Channels;
using SentinelCore.Demon2.Core;

namespace SentinelCore.Demon2.Service;

/// <summary>Maintains one Guard pipe session for the lifetime of this D2 service.</summary>
public sealed class NamedPipeInterDaemonBus : IRequestReceivingInterDaemonBus, ISessionContextResponseReceivingInterDaemonBus, IAsyncDisposable
{
    private const int MaxMessageBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _pipeName;
    private readonly SemaphoreSlim _sessionGate = new(1, 1);
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, TaskCompletionSource<InterDaemonEnvelope>> _pendingAcks = new();
    private readonly Channel<InterDaemonEnvelope> _requests = Channel.CreateBounded<InterDaemonEnvelope>(new BoundedChannelOptions(32)
    { FullMode = BoundedChannelFullMode.Wait, SingleReader = false, SingleWriter = false });
    private readonly Channel<InterDaemonEnvelope> _sessionResponses = Channel.CreateBounded<InterDaemonEnvelope>(new BoundedChannelOptions(32)
    { FullMode = BoundedChannelFullMode.Wait, SingleReader = true, SingleWriter = false });
    private NamedPipeClientStream? _pipe;
    private CancellationTokenSource? _sessionStop;
    private Task? _receiveLoop;
    private bool _welcomed;
    private bool _disposed;

    public NamedPipeInterDaemonBus(string pipeName = "SentinelCore.Guard") => _pipeName = pipeName;

    public IAsyncEnumerable<InterDaemonEnvelope> ReadRequestsAsync(CancellationToken cancellationToken = default)
        => _requests.Reader.ReadAllAsync(cancellationToken);

    public IAsyncEnumerable<InterDaemonEnvelope> ReadSessionContextResponsesAsync(CancellationToken cancellationToken = default)
        => _sessionResponses.Reader.ReadAllAsync(cancellationToken);

    public async ValueTask PublishAsync(InterDaemonEnvelope message, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The Guard named pipe is Windows-only.");
        if (!InterDaemonEnvelopeValidator.TryValidate(message, DateTimeOffset.UtcNow, out var error))
            throw new InvalidOperationException(error);

        await _sessionGate.WaitAsync(cancellationToken);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(5));
            try
            {
                await EnsureSessionAsync(message, timeout.Token);
                var completion = new TaskCompletionSource<InterDaemonEnvelope>(TaskCreationOptions.RunContinuationsAsynchronously);
                if (!_pendingAcks.TryAdd(message.MessageId, completion)) throw new InvalidOperationException("Duplicate pending D2 message ID.");
                try
                {
                    await WriteFrameAsync(_pipe!, message, timeout.Token);
                    var ack = await completion.Task.WaitAsync(timeout.Token);
                    ValidateAck(ack, message);
                }
                finally { _pendingAcks.TryRemove(message.MessageId, out _); }
            }
            catch
            {
                await ResetSessionAsync();
                throw;
            }
        }
        finally { _sessionGate.Release(); }
    }

    private async Task EnsureSessionAsync(InterDaemonEnvelope firstMessage, CancellationToken ct)
    {
        if (_pipe is { IsConnected: true } && _welcomed) return;
        await ResetSessionAsync();

        var candidate = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        try
        {
            try { await candidate.ConnectAsync(2000, ct); }
            catch (TimeoutException ex)
            {
                throw new TimeoutException($"GUARD_CONNECT_TIMEOUT: aucun listener D3 n’a accepté la connexion à \\\\.\\pipe\\{_pipeName} en 2 secondes.", ex);
            }
            var hello = new InterDaemonEnvelope(Guid.NewGuid(), firstMessage.CorrelationId, DateTimeOffset.UtcNow,
                "ThreatMonitor", "RiskResponseGuard", "HELLO", 1, firstMessage.ExpiresAtUtc,
                JsonSerializer.SerializeToElement(new { daemonId = "ThreatMonitor", capabilities = new[] { "findings", "context" }, supportedSchema = 1 }, JsonOptions));
            await WriteFrameAsync(candidate, hello, ct);
            var welcome = await ReadFrameAsync(candidate, ct);
            ValidateWelcome(welcome, firstMessage.CorrelationId);
            _pipe = candidate;
            _welcomed = true;
            _sessionStop = new CancellationTokenSource();
            _receiveLoop = ReceiveLoopAsync(candidate, _sessionStop.Token);
        }
        catch
        {
            await candidate.DisposeAsync();
            throw;
        }
    }

    private static void ValidateWelcome(InterDaemonEnvelope welcome, string correlationId)
    {
        if (welcome.MessageType != "WELCOME" || welcome.SourceDaemon != "RiskResponseGuard" ||
            welcome.Destination != "ThreatMonitor" || welcome.SchemaVersion != 1 ||
            welcome.CorrelationId != correlationId || welcome.ExpiresAtUtc <= DateTimeOffset.UtcNow ||
            welcome.Payload.ValueKind != JsonValueKind.Object ||
            !welcome.Payload.TryGetProperty("sessionId", out var sessionId) ||
            sessionId.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(sessionId.GetString()) ||
            !welcome.Payload.TryGetProperty("supportedSchema", out var schema) ||
            schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out var schemaVersion) || schemaVersion < 1)
            throw new InvalidDataException("Guard did not return a valid WELCOME for the v1 session.");
    }

    private static void ValidateAck(InterDaemonEnvelope ack, InterDaemonEnvelope sent)
    {
        if (ack.MessageType != "ACK" || ack.SourceDaemon != "RiskResponseGuard" || ack.Destination != "ThreatMonitor" ||
            ack.SchemaVersion != 1 || ack.CorrelationId != sent.CorrelationId || ack.Payload.ValueKind != JsonValueKind.Object ||
            !ack.Payload.TryGetProperty("messageId", out var id) || id.ValueKind != JsonValueKind.String ||
            !Guid.TryParse(id.GetString(), out var ackId) || ackId != sent.MessageId)
            throw new InvalidDataException("Guard returned an invalid ACK.");
        var status = ack.Payload.TryGetProperty("status", out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        if (status is not ("ACCEPTED" or "DUPLICATE"))
            throw new InvalidDataException($"Guard rejected message: {status ?? "unknown status"}.");
    }

    private async Task ReceiveLoopAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested && pipe.IsConnected)
            {
                var message = await ReadFrameAsync(pipe, cancellationToken);
                if (message.MessageType == "ACK")
                {
                    if (message.Payload.TryGetProperty("messageId", out var id) && id.ValueKind == JsonValueKind.String
                        && Guid.TryParse(id.GetString(), out var messageId) && _pendingAcks.TryGetValue(messageId, out var pending))
                        pending.TrySetResult(message);
                    continue;
                }
                if (message.MessageType == "SESSION_CONTEXT_RESPONSE")
                {
                    if (!SessionContextResponseValidator.TryValidate(message, DateTimeOffset.UtcNow, out _, out _))
                    {
                        await WriteStandaloneAckAsync(pipe, message, "REJECTED", "INVALID_SESSION_CONTEXT_RESPONSE", cancellationToken);
                        continue;
                    }
                    if (!_sessionResponses.Writer.TryWrite(message))
                    {
                        await WriteStandaloneAckAsync(pipe, message, "REJECTED", "SESSION_RESPONSE_QUEUE_FULL", cancellationToken);
                        continue;
                    }
                    await WriteStandaloneAckAsync(pipe, message, "ACCEPTED", null, cancellationToken);
                    continue;
                }
                if (!IsAllowedD3Request(message))
                {
                    await WriteStandaloneAckAsync(pipe, message, "REJECTED", "MESSAGE_NOT_ALLOWED", cancellationToken);
                    continue;
                }
                if (!_requests.Writer.TryWrite(message))
                {
                    await WriteStandaloneAckAsync(pipe, message, "REJECTED", "REQUEST_QUEUE_FULL", cancellationToken);
                    continue;
                }
                await WriteStandaloneAckAsync(pipe, message, "ACCEPTED", null, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException)
        {
            _welcomed = false;
            foreach (var pending in _pendingAcks.Values) pending.TrySetException(ex);
            try { await pipe.DisposeAsync(); } catch (IOException) { }
        }
    }

    private static bool IsAllowedD3Request(InterDaemonEnvelope message)
        => message.SourceDaemon == "RiskResponseGuard" && message.Destination == "ThreatMonitor"
            && message.MessageType == "CONTEXT_REQUEST" && message.MessageId != Guid.Empty
            && !string.IsNullOrWhiteSpace(message.CorrelationId) && message.CorrelationId.Length <= 128
            && !message.CorrelationId.Any(char.IsControl) && message.SchemaVersion == 1
            && message.TimestampUtc.Offset == TimeSpan.Zero && message.ExpiresAtUtc.Offset == TimeSpan.Zero
            && message.TimestampUtc <= DateTimeOffset.UtcNow.AddSeconds(30)
            && message.ExpiresAtUtc > DateTimeOffset.UtcNow && message.Payload.ValueKind == JsonValueKind.Object
            && message.Payload.TryGetProperty("requestedFields", out var fields) && fields.ValueKind == JsonValueKind.Array
            && fields.GetArrayLength() is > 0 and <= 4
            && fields.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String
                && x.GetString() is { } field && ThreatContextFields.All.Contains(field))
            && fields.EnumerateArray().Select(x => x.GetString()).Distinct(StringComparer.Ordinal).Count() == fields.GetArrayLength()
            && message.Payload.TryGetProperty("deadlineUtc", out var deadline) && deadline.ValueKind == JsonValueKind.String
            && deadline.TryGetDateTimeOffset(out var expires) && expires.Offset == TimeSpan.Zero
            && expires > DateTimeOffset.UtcNow && expires <= message.ExpiresAtUtc;

    private async Task WriteStandaloneAckAsync(Stream stream, InterDaemonEnvelope message, string status, string? reason, CancellationToken token)
    {
        var ack = JsonSerializer.SerializeToUtf8Bytes(new { messageId = message.MessageId.ToString("D"), status, reason }, JsonOptions);
        await _writeGate.WaitAsync(token);
        try
        {
            var header = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(header, ack.Length);
            await stream.WriteAsync(header, token); await stream.WriteAsync(ack, token); await stream.FlushAsync(token);
        }
        finally { _writeGate.Release(); }
    }

    private async Task ResetSessionAsync()
    {
        if (_sessionStop is not null)
        {
            _sessionStop.Cancel();
            if (_pipe is not null) await _pipe.DisposeAsync();
            if (_receiveLoop is not null)
            {
                try { await _receiveLoop.WaitAsync(TimeSpan.FromSeconds(1)); }
                catch (TimeoutException) { }
                catch (OperationCanceledException) { }
            }
            _sessionStop.Dispose();
        }
        else if (_pipe is not null) await _pipe.DisposeAsync();
        _sessionStop = null;
        _receiveLoop = null;
        _pipe = null;
        _welcomed = false;
    }

    private async Task WriteFrameAsync(Stream stream, InterDaemonEnvelope message, CancellationToken ct)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        if (payload.Length is <= 0 or > MaxMessageBytes) throw new InvalidDataException("Message exceeds the common 64 KiB limit.");
        await _writeGate.WaitAsync(ct);
        try
        {
            var prefix = new byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
            await stream.WriteAsync(prefix, ct);
            await stream.WriteAsync(payload, ct);
            await stream.FlushAsync(ct);
        }
        finally { _writeGate.Release(); }
    }

    private static async Task<InterDaemonEnvelope> ReadFrameAsync(Stream stream, CancellationToken ct)
    {
        var prefix = new byte[4];
        await ReadExactlyAsync(stream, prefix, ct);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (length is <= 0 or > MaxMessageBytes) throw new InvalidDataException("Invalid frame length.");
        var payload = new byte[length];
        await ReadExactlyAsync(stream, payload, ct);
        return JsonSerializer.Deserialize<InterDaemonEnvelope>(payload, JsonOptions)
            ?? throw new InvalidDataException("Guard returned invalid JSON.");
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[offset..], ct);
            if (count == 0) throw new EndOfStreamException("Guard closed the pipe before completing a frame.");
            offset += count;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _sessionGate.WaitAsync();
        try
        {
            if (_disposed) return;
            _disposed = true;
            await ResetSessionAsync();
            _requests.Writer.TryComplete();
            _sessionResponses.Writer.TryComplete();
        }
        finally
        {
            _sessionGate.Release();
            _sessionGate.Dispose();
            _writeGate.Dispose();
        }
    }
}

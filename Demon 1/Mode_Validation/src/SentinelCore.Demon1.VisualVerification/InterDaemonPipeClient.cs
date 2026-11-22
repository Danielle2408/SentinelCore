using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SentinelCore.Demon1.VisualVerification;

public sealed record InterDaemonEnvelope(
    [property: JsonPropertyName("messageId")] string MessageId,
    [property: JsonPropertyName("correlationId")] string CorrelationId,
    [property: JsonPropertyName("timestampUtc")] DateTimeOffset TimestampUtc,
    [property: JsonPropertyName("sourceDaemon")] string SourceDaemon,
    [property: JsonPropertyName("destination")] string Destination,
    [property: JsonPropertyName("messageType")] string MessageType,
    [property: JsonPropertyName("schemaVersion")] int SchemaVersion,
    [property: JsonPropertyName("expiresAtUtc")] DateTimeOffset ExpiresAtUtc,
    [property: JsonPropertyName("payload")] JsonElement Payload);

public sealed record InterDaemonAcknowledgement(
    [property: JsonPropertyName("messageId")] string MessageId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("reason")] string? Reason = null);

/// <summary>
/// D1 client for the D3-owned local Named Pipe. D3 must validate the pipe client's Windows
/// identity/ACL on its server endpoint. This class enforces message size, length framing,
/// correlation, expiry, three bounded retries, and a strict D1 message allowlist.
/// </summary>
public sealed class InterDaemonPipeClient : IAsyncDisposable
{
    public const int MaximumMessageBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> OutboundTypes = new(StringComparer.Ordinal)
    { "HELLO", "HEARTBEAT", "USER_CONTEXT", "BEHAVIOR_DEVIATION", "CONTEXT_RESPONSE", "VISUAL_IDENTITY_RESPONSE", "VISUAL_EVIDENCE_CHUNK", "MASTER_AUTH_RESULT" };
    private static readonly HashSet<string> InboundTypes = new(StringComparer.Ordinal)
    { "WELCOME", "CONTEXT_REQUEST", "VISUAL_IDENTITY_REQUEST", "VISUAL_EVIDENCE_READ_REQUEST", "MASTER_AUTH_REQUIRED" };

    private readonly NamedPipeClientStream _pipe;
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<InterDaemonAcknowledgement>> _pending = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _receivedIds = new(StringComparer.Ordinal);
    private readonly ConcurrentQueue<string> _receivedOrder = new();
    private readonly TaskCompletionSource<JsonElement> _welcome = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _shutdown = new();
    private Task? _readLoop;
    private Task? _heartbeatLoop;
    private string _daemonSessionId = "";
    private bool _connected;
    private bool _disposed;

    public event EventHandler<InterDaemonEnvelope>? MessageReceived;
    public event EventHandler<Exception>? ConnectionFailed;
    public bool IsConnectedToServer => _connected && _pipe.IsConnected && !_disposed;

    public InterDaemonPipeClient(string pipeName = "SentinelCore.Guard") : this(pipeName, allowIsolatedTestPipe: false) { }

    internal InterDaemonPipeClient(string pipeName, bool allowIsolatedTestPipe)
    {
        if (string.IsNullOrWhiteSpace(pipeName) || pipeName.Length > 128
            || pipeName.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_'))
            || (!allowIsolatedTestPipe && pipeName != "SentinelCore.Guard"))
            throw new ArgumentException("Nom de canal non autorisé par le contrat commun.", nameof(pipeName));
        _pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
    }

    public async Task<JsonElement> ConnectAndHandshakeAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _shutdown.Token);
        connectTimeout.CancelAfter(TimeSpan.FromSeconds(5));
        await _pipe.ConnectAsync(connectTimeout.Token).ConfigureAwait(false);
        _connected = true;
        _readLoop = ReadLoopAsync(_shutdown.Token);
        var now = DateTimeOffset.UtcNow;
        await SendAsync("HELLO", Guid.NewGuid().ToString("D"), new { daemonVersion = "1.0", supportedSchema = new[] { 1 } }, now.AddSeconds(10), cancellationToken).ConfigureAwait(false);
        var welcome = await _welcome.Task.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        _daemonSessionId = welcome.TryGetProperty("sessionId", out var session) ? session.GetString() ?? "" : "";
        _heartbeatLoop = HeartbeatLoopAsync(_shutdown.Token);
        return welcome;
    }

    public async Task SendAsync<TPayload>(string messageType, string correlationId, TPayload payload,
        DateTimeOffset expiresAtUtc, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_connected || !_pipe.IsConnected) throw new IOException("Le tuyau du démon 3 n’est pas connecté.");
        if (!OutboundTypes.Contains(messageType)) throw new InvalidOperationException($"Type D1->D3 interdit : {messageType}.");
        if (expiresAtUtc <= DateTimeOffset.UtcNow) throw new ArgumentOutOfRangeException(nameof(expiresAtUtc), "Le message est déjà expiré.");
        var id = Guid.NewGuid().ToString("D");
        var envelope = new InterDaemonEnvelope(id, correlationId, DateTimeOffset.UtcNow,
            "HumanBehaviorMonitor", "RiskResponseGuard", messageType, 1, expiresAtUtc,
            JsonSerializer.SerializeToElement(payload, JsonOptions));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (bytes.Length > MaximumMessageBytes) throw new InvalidDataException("Message inter-démon supérieur à 64 KiB.");

        var acknowledgement = new TaskCompletionSource<InterDaemonAcknowledgement>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(id, acknowledgement)) throw new InvalidOperationException("Identifiant de message dupliqué.");
        try
        {
            var delaysMs = new[] { 100, 250, 500 };
            for (var attempt = 0; attempt < 3; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (DateTimeOffset.UtcNow >= expiresAtUtc) throw new TimeoutException("Message inter-démon expiré.");
                await WriteFrameAsync(bytes, cancellationToken).ConfigureAwait(false);
                var ackWait = Task.Delay(TimeSpan.FromMilliseconds(800 + attempt * 400), cancellationToken);
                var completed = await Task.WhenAny(acknowledgement.Task, ackWait).ConfigureAwait(false);
                if (completed == acknowledgement.Task)
                {
                    var ack = await acknowledgement.Task.ConfigureAwait(false);
                    if (ack.Status is "ACCEPTED" or "DUPLICATE") return;
                    throw new InvalidDataException("D3 a rejeté le message : " + (ack.Reason ?? "raison non fournie"));
                }
                if (attempt < delaysMs.Length - 1) await Task.Delay(delaysMs[attempt], cancellationToken).ConfigureAwait(false);
            }
            throw new TimeoutException("Aucun ACK de D3 après trois tentatives.");
        }
        finally { _pending.TryRemove(id, out _); }
    }

    private async Task WriteFrameAsync(byte[] body, CancellationToken token)
    {
        await _writeGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            var header = new byte[sizeof(int)];
            BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
            await _pipe.WriteAsync(header, token).ConfigureAwait(false);
            await _pipe.WriteAsync(body, token).ConfigureAwait(false);
            await _pipe.FlushAsync(token).ConfigureAwait(false);
        }
        finally { _writeGate.Release(); }
    }

    private async Task ReadLoopAsync(CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested && _pipe.IsConnected)
            {
                var header = new byte[sizeof(int)];
                await _pipe.ReadExactlyAsync(header, token).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadInt32LittleEndian(header);
                if (length is <= 0 or > MaximumMessageBytes) throw new InvalidDataException("Taille de trame D3 invalide.");
                var body = new byte[length];
                await _pipe.ReadExactlyAsync(body, token).ConfigureAwait(false);
                using var document = JsonDocument.Parse(body);
                var root = document.RootElement;
                if (TryReadAck(root, out var ack))
                {
                    if (_pending.TryGetValue(ack.MessageId, out var completion)) completion.TrySetResult(ack);
                    continue;
                }
                var envelope = root.Deserialize<InterDaemonEnvelope>(JsonOptions)
                    ?? throw new InvalidDataException("Enveloppe reçue de D3 vide.");
                if (!InboundTypes.Contains(envelope.MessageType))
                {
                    await WriteAckAsync(new(envelope.MessageId, "REJECTED", "MESSAGE_TYPE_NOT_ALLOWED_FOR_D1"), token).ConfigureAwait(false);
                    continue;
                }
                if (envelope.SchemaVersion != 1 || envelope.ExpiresAtUtc <= DateTimeOffset.UtcNow
                    || envelope.SourceDaemon != "RiskResponseGuard" || envelope.Destination != "HumanBehaviorMonitor")
                {
                    var reason = envelope.SchemaVersion != 1 ? "UNKNOWN_SCHEMA"
                        : envelope.ExpiresAtUtc <= DateTimeOffset.UtcNow ? "MESSAGE_EXPIRED" : "SOURCE_OR_DESTINATION_MISMATCH";
                    await WriteAckAsync(new(envelope.MessageId, "REJECTED", reason), token).ConfigureAwait(false);
                    continue;
                }
                if (envelope.MessageType != "WELCOME" && !_receivedIds.TryAdd(envelope.MessageId, 0))
                {
                    await WriteAckAsync(new(envelope.MessageId, "DUPLICATE"), token).ConfigureAwait(false);
                    continue;
                }
                await WriteAckAsync(new(envelope.MessageId, "ACCEPTED"), token).ConfigureAwait(false);
                if (envelope.MessageType == "WELCOME") _welcome.TrySetResult(envelope.Payload.Clone());
                else
                {
                    _receivedOrder.Enqueue(envelope.MessageId);
                    while (_receivedIds.Count > 4096 && _receivedOrder.TryDequeue(out var oldest)) _receivedIds.TryRemove(oldest, out _);
                    MessageReceived?.Invoke(this, envelope);
                }
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _connected = false;
            foreach (var pending in _pending.Values) pending.TrySetException(ex);
            ConnectionFailed?.Invoke(this, ex);
        }
    }

    private async Task HeartbeatLoopAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        try
        {
            while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
            {
                var now = DateTimeOffset.UtcNow;
                await SendAsync("HEARTBEAT", _daemonSessionId, new { status = "READY" }, now.AddSeconds(10), token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex) { _connected = false; ConnectionFailed?.Invoke(this, ex); }
    }

    private async Task WriteAckAsync(InterDaemonAcknowledgement ack, CancellationToken token)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(ack, JsonOptions);
        if (bytes.Length > MaximumMessageBytes) throw new InvalidDataException("ACK trop volumineux.");
        await WriteFrameAsync(bytes, token).ConfigureAwait(false);
    }

    private static bool TryReadAck(JsonElement root, out InterDaemonAcknowledgement ack)
    {
        if (root.TryGetProperty("messageId", out var id) && root.TryGetProperty("status", out var status)
            && !root.TryGetProperty("messageType", out _))
        {
            ack = new(id.GetString() ?? string.Empty, status.GetString() ?? string.Empty,
                root.TryGetProperty("reason", out var reason) ? reason.GetString() : null);
            return true;
        }
        if (root.TryGetProperty("messageType", out var type) && type.GetString() == "ACK"
            && root.TryGetProperty("payload", out var payload)
            && payload.TryGetProperty("messageId", out id) && payload.TryGetProperty("status", out status))
        {
            ack = new(id.GetString() ?? string.Empty, status.GetString() ?? string.Empty,
                payload.TryGetProperty("reason", out var reason) ? reason.GetString() : null);
            return true;
        }
        ack = new(string.Empty, string.Empty);
        return false;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        _shutdown.Cancel();
        if (_heartbeatLoop is not null)
        {
            try { await _heartbeatLoop.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
            catch (Exception ex) when (ex is TimeoutException or IOException or OperationCanceledException or ObjectDisposedException) { }
        }
        if (_readLoop is not null)
        {
            try { await _readLoop.WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
            catch (Exception ex) when (ex is TimeoutException or IOException or OperationCanceledException or ObjectDisposedException) { }
        }
        _pipe.Dispose(); _writeGate.Dispose(); _shutdown.Dispose();
    }
}

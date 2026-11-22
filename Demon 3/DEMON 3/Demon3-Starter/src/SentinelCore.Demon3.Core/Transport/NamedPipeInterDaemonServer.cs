using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using SentinelCore.Demon3.Core.Contracts;
using SentinelCore.Demon3.Core.Validation;

namespace SentinelCore.Demon3.Core.Transport;

/// <summary>
/// Local Windows IPC host for D1 and D2. It limits Windows pipe access by SID and checks
/// the claimed daemon role against the connecting Windows identity before accepting HELLO.
/// </summary>
public sealed class NamedPipeInterDaemonServer : IAsyncDisposable
{
    public const string PipeName = "SentinelCore.Guard";
    private const int MaxClients = 8;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly EnvelopeValidator _validator;
    private readonly string _pipeName;
    private readonly string[] _additionalD1ClientSids;
    private readonly string[] _additionalD2ClientSids;
    private readonly IInboundMessageJournal? _journal;
    private readonly Channel<DaemonEnvelope> _inbound = Channel.CreateBounded<DaemonEnvelope>(new BoundedChannelOptions(512)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = false,
        SingleWriter = false
    });
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, ClientConnection> _clients = new(StringComparer.Ordinal);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> _seenIds = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> _queuedMessageIds = new();
    private readonly System.Collections.Concurrent.ConcurrentQueue<Guid> _seenOrder = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly object _startSync = new();
    private Task? _acceptLoop;
    private TaskCompletionSource? _listenerReady;
    private Exception? _listenerFailure;
    private int _clientCount;
    private bool _disposed;

    public NamedPipeInterDaemonServer(EnvelopeValidator? validator = null, string pipeName = PipeName,
        IEnumerable<string>? additionalD1ClientSids = null, IEnumerable<string>? additionalD2ClientSids = null,
        IInboundMessageJournal? journal = null)
    {
        var isolatedPipeName = Environment.GetEnvironmentVariable("SENTINELCORE_TEST_GUARD_PIPE_NAME");
        if (pipeName == PipeName && !string.IsNullOrWhiteSpace(isolatedPipeName))
            pipeName = isolatedPipeName;
        if (string.IsNullOrWhiteSpace(pipeName) || pipeName.Length > 128 || pipeName.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_')))
            throw new ArgumentException("Nom de pipe invalide.", nameof(pipeName));
        _validator = validator ?? new EnvelopeValidator();
        _pipeName = pipeName;
        _additionalD1ClientSids = NormalizeSids(additionalD1ClientSids);
        _additionalD2ClientSids = NormalizeSids(additionalD2ClientSids);
        _journal = journal;
        if (_additionalD1ClientSids.Intersect(_additionalD2ClientSids, StringComparer.OrdinalIgnoreCase).Any())
            throw new ArgumentException("Un SID de compte distinct ne peut pas être autorisé simultanément comme D1 et D2.");
        if (OperatingSystem.IsWindows()) ValidateWindowsSidTexts(_additionalD1ClientSids.Concat(_additionalD2ClientSids));
    }

    private static string[] NormalizeSids(IEnumerable<string>? values)
        => (values ?? []).Select(sid => sid?.Trim() ?? string.Empty)
            .Where(sid => sid.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    [SupportedOSPlatform("windows")]
    private static void ValidateWindowsSidTexts(IEnumerable<string> values)
    {
        foreach (var value in values) _ = new SecurityIdentifier(value);
    }

    /// <summary>Raised when the listener terminates because of an unexpected error.</summary>
    public event Action<Exception>? ListenerFailed;

    /// <summary>The original fatal listener error, if initialization or the accept loop failed.</summary>
    public Exception? ListenerFailure => Volatile.Read(ref _listenerFailure);

    /// <summary>The lifetime task of the accept loop; it faults with the original listener exception.</summary>
    public Task Completion
    {
        get { lock (_startSync) return _acceptLoop ?? Task.CompletedTask; }
    }

    /// <summary>
    /// Starts the accept loop and returns only after the first operating-system pipe listener
    /// has been created. Initialization and accept-loop failures are surfaced to the caller.
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        Task readyTask;
        Task loopTask;
        lock (_startSync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_acceptLoop is null)
            {
                _listenerReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _acceptLoop = AcceptLoopAsync(_stop.Token, _listenerReady);
            }
            readyTask = _listenerReady!.Task;
            loopTask = _acceptLoop;
        }

        var first = await Task.WhenAny(readyTask, loopTask).WaitAsync(cancellationToken).ConfigureAwait(false);
        if (first == loopTask)
        {
            await loopTask.ConfigureAwait(false);
            throw new InvalidOperationException("Le listener D3 s’est arrêté avant d’être prêt.");
        }

        await readyTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (loopTask.IsFaulted) await loopTask.ConfigureAwait(false);
    }

    /// <summary>Compatibility entry point for existing synchronous callers.</summary>
    public void Start() => StartAsync().GetAwaiter().GetResult();

    private async Task AcceptLoopAsync(CancellationToken token, TaskCompletionSource listenerReady)
    {
        try
        {
            if (_journal is not null)
            {
                foreach (var pending in await _journal.ReadPendingAsync(token).ConfigureAwait(false))
                {
                    var size = JsonSerializer.SerializeToUtf8Bytes(pending, JsonOptions).Length;
                    var validation = _validator.Validate(pending, size);
                    if (!validation.IsValid)
                    {
                        await _journal.MarkProcessedAsync(pending.MessageId, token).ConfigureAwait(false);
                        MessageRejected?.Invoke($"Message D1/D2 en attente ignoré après redémarrage : {ToReasonCode(validation.Error)} ({pending.MessageId}).");
                        continue;
                    }
                    if (_queuedMessageIds.TryAdd(pending.MessageId, 0))
                        await _inbound.Writer.WriteAsync(pending, token).ConfigureAwait(false);
                }
            }

            while (!token.IsCancellationRequested)
            {
                var pipe = CreateServerPipe();
                Task connectionTask;
                try { connectionTask = pipe.WaitForConnectionAsync(token); }
                catch { pipe.Dispose(); throw; }
                if (listenerReady.TrySetResult())
                    Console.WriteLine($"GUARD_PIPE_READY | Listener D3 créé sur \\\\.\\pipe\\{_pipeName}.");
                try { await connectionTask.ConfigureAwait(false); }
                catch { pipe.Dispose(); throw; }
                if (Interlocked.Increment(ref _clientCount) > MaxClients)
                {
                    Interlocked.Decrement(ref _clientCount);
                    pipe.Dispose();
                    continue;
                }
                _ = HandleClientAsync(pipe, token);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            listenerReady.TrySetCanceled(token);
        }
        catch (Exception exception)
        {
            listenerReady.TrySetException(exception);
            Interlocked.Exchange(ref _listenerFailure, exception);
            _inbound.Writer.TryComplete(exception);
            Console.Error.WriteLine($"GUARD_PIPE_FAILED | Erreur complète du listener local D3 :{Environment.NewLine}{exception}");
            try { ListenerFailed?.Invoke(exception); }
            catch (Exception observerError)
            {
                Console.Error.WriteLine($"D3 listener failure observer threw:{Environment.NewLine}{observerError}");
            }
            throw;
        }
        finally { _inbound.Writer.TryComplete(); }
    }

    public event Action<string>? MessageRejected;

    public async ValueTask MarkProcessedAsync(Guid messageId, CancellationToken cancellationToken = default)
    {
        if (_journal is not null) await _journal.MarkProcessedAsync(messageId, cancellationToken).ConfigureAwait(false);
        _queuedMessageIds.TryRemove(messageId, out _);
    }

    public async ValueTask SendAsync(DaemonEnvelope message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        var clientKey = message.Destination switch
        {
            DaemonNames.HumanBehaviorMonitor => DaemonNames.HumanBehaviorMonitor,
            DaemonNames.ThreatMonitor => DaemonNames.ThreatMonitor,
            _ => throw new InvalidOperationException("D3 ne peut envoyer que vers D1 ou D2 via ce canal.")
        };
        if (!_clients.TryGetValue(clientKey, out var client)) throw new IOException($"{clientKey} n'est pas connecté.");
        var validation = _validator.Validate(message, JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions).Length);
        if (!validation.IsValid) throw new InvalidDataException("Message sortant rejeté : " + validation.Error);
        var body = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        await client.WriteFrameAsync(body, cancellationToken).ConfigureAwait(false);
    }

    public IAsyncEnumerable<DaemonEnvelope> ReadAllAsync(CancellationToken cancellationToken = default)
        => _inbound.Reader.ReadAllAsync(cancellationToken);

    private NamedPipeServerStream CreateServerPipe()
    {
        if (!OperatingSystem.IsWindows()
            || _additionalD1ClientSids.Length == 0 && _additionalD2ClientSids.Length == 0)
            return new NamedPipeServerStream(_pipeName, PipeDirection.InOut, MaxClients,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly,
                inBufferSize: 64 * 1024, outBufferSize: 64 * 1024);

        // Keep the interactive owner account and explicitly configured service identities;
        // do not open the endpoint to Everyone or Authenticated Users.
        var owner = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("Impossible de déterminer le SID du compte qui héberge D3.");
        var security = new PipeSecurity();
        security.SetOwner(owner);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new PipeAccessRule(owner, PipeAccessRights.FullControl, AccessControlType.Allow));
        foreach (var sidText in _additionalD1ClientSids.Concat(_additionalD2ClientSids).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            var sid = new SecurityIdentifier(sidText);
            if (!sid.Equals(owner))
                security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.ReadWrite, AccessControlType.Allow));
        }
        return NamedPipeServerStreamAcl.Create(_pipeName, PipeDirection.InOut, MaxClients,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 64 * 1024, 64 * 1024,
            security, HandleInheritability.None, (PipeAccessRights)0);
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        ClientConnection? connection = null;
        try
        {
            while (pipe.IsConnected && !token.IsCancellationRequested)
            {
                var header = new byte[sizeof(int)];
                await pipe.ReadExactlyAsync(header, token).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadInt32LittleEndian(header);
                if (length is <= 0 or > EnvelopeValidator.MaxMessageBytes) throw new InvalidDataException("Taille de trame invalide.");
                var body = new byte[length];
                await pipe.ReadExactlyAsync(body, token).ConfigureAwait(false);
                using var document = JsonDocument.Parse(body);
                var root = document.RootElement;
                // D1 ACKs are standalone JSON objects, not protocol envelopes.
                if (root.TryGetProperty("status", out _) && !root.TryGetProperty("messageType", out _)) continue;
                var message = root.Deserialize<DaemonEnvelope>(JsonOptions) ?? throw new InvalidDataException("Enveloppe vide.");
                var result = _validator.Validate(message, length);
                if (!result.IsValid)
                {
                    await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "REJECTED", ToReasonCode(result.Error)),
                        message.CorrelationId, message.SourceDaemon == DaemonNames.ThreatMonitor, token).ConfigureAwait(false);
                    continue;
                }

                if (message.MessageType == "HELLO")
                {
                    var key = message.SourceDaemon;
                    var clientSid = GetClientSid(pipe);
                    var ownerSid = GetCurrentOwnerSid();
                    if (!IsClientAuthorized(key, clientSid, ownerSid))
                    {
                        await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "REJECTED", "CLIENT_SID_NOT_AUTHORIZED_FOR_DAEMON_ROLE"),
                            message.CorrelationId, key == DaemonNames.ThreatMonitor, token).ConfigureAwait(false);
                        return;
                    }
                    var newConnection = new ClientConnection(pipe, key, clientSid);
                    if (!_clients.TryAdd(key, newConnection))
                    {
                        await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "REJECTED", "DAEMON_ALREADY_CONNECTED"),
                            message.CorrelationId, key == DaemonNames.ThreatMonitor, token).ConfigureAwait(false);
                        return;
                    }
                    connection = newConnection;
                    // D1's client waits for a standalone ACK and then WELCOME. D2's publisher
                    // waits for WELCOME directly, so keep both established wire handshakes.
                    if (!connection.UsesEnvelopeAcknowledgements)
                        await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "ACCEPTED"),
                            message.CorrelationId, envelopeStyle: false, token).ConfigureAwait(false);
                    var now = DateTimeOffset.UtcNow;
                    var welcome = new DaemonEnvelope
                    {
                        MessageId = Guid.NewGuid(), CorrelationId = message.CorrelationId, TimestampUtc = now,
                        SourceDaemon = DaemonNames.RiskResponseGuard, Destination = key, MessageType = "WELCOME",
                        SchemaVersion = 1, ExpiresAtUtc = now.AddSeconds(15),
                        Payload = connection.UsesEnvelopeAcknowledgements
                            ? JsonSerializer.SerializeToElement(new { sessionId = Guid.NewGuid().ToString("D"), supportedSchema = 1 }, JsonOptions)
                            : JsonSerializer.SerializeToElement(new { sessionId = Guid.NewGuid().ToString("D"), supportedSchema = new[] { 1 } }, JsonOptions)
                    };
                    await connection.WriteFrameAsync(JsonSerializer.SerializeToUtf8Bytes(welcome, JsonOptions), token).ConfigureAwait(false);
                    continue;
                }

                if (connection is null || message.SourceDaemon != connection.DaemonName)
                {
                    await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "REJECTED", "HANDSHAKE_REQUIRED_OR_SOURCE_CHANGED"),
                        message.CorrelationId, connection?.UsesEnvelopeAcknowledgements ?? message.SourceDaemon == DaemonNames.ThreatMonitor, token).ConfigureAwait(false);
                    continue;
                }
                if (_journal is not null)
                {
                    var enqueueStatus = await _journal.EnqueueAsync(message, token).ConfigureAwait(false);
                    if (enqueueStatus == InboundMessageStatus.CapacityExceeded)
                    {
                        await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "REJECTED", "D3_INBOX_FULL"),
                            message.CorrelationId, connection.UsesEnvelopeAcknowledgements, token).ConfigureAwait(false);
                        continue;
                    }
                    if (enqueueStatus == InboundMessageStatus.ProcessedDuplicate
                        || !_queuedMessageIds.TryAdd(message.MessageId, 0))
                    {
                        await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "DUPLICATE"),
                            message.CorrelationId, connection.UsesEnvelopeAcknowledgements, token).ConfigureAwait(false);
                        continue;
                    }
                    try { await _inbound.Writer.WriteAsync(message, token).ConfigureAwait(false); }
                    catch { _queuedMessageIds.TryRemove(message.MessageId, out _); throw; }
                    await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "ACCEPTED"),
                        message.CorrelationId, connection.UsesEnvelopeAcknowledgements, token).ConfigureAwait(false);
                    continue;
                }
                if (!_seenIds.TryAdd(message.MessageId, 0))
                {
                    await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "DUPLICATE"),
                        message.CorrelationId, connection.UsesEnvelopeAcknowledgements, token).ConfigureAwait(false);
                    continue;
                }
                _seenOrder.Enqueue(message.MessageId);
                while (_seenIds.Count > 8192 && _seenOrder.TryDequeue(out var oldest)) _seenIds.TryRemove(oldest, out _);
                if (!_inbound.Writer.TryWrite(message))
                {
                    _seenIds.TryRemove(message.MessageId, out _);
                    await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "REJECTED", "D3_QUEUE_FULL"),
                        message.CorrelationId, connection.UsesEnvelopeAcknowledgements, token).ConfigureAwait(false);
                    continue;
                }
                await WriteAcknowledgementAsync(pipe, connection, new(message.MessageId, "ACCEPTED"),
                    message.CorrelationId, connection.UsesEnvelopeAcknowledgements, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (EndOfStreamException) { }
        catch (IOException) { }
        catch (JsonException) { }
        finally
        {
            if (connection is not null) _clients.TryRemove(new KeyValuePair<string, ClientConnection>(connection.DaemonName, connection));
            pipe.Dispose();
            Interlocked.Decrement(ref _clientCount);
        }
    }

    private static string? GetClientSid(NamedPipeServerStream pipe)
    {
        if (!OperatingSystem.IsWindows()) return null;
        return GetWindowsClientSid(pipe);
    }

    [SupportedOSPlatform("windows")]
    private static string? GetWindowsClientSid(NamedPipeServerStream pipe)
    {
        string? clientSid = null;
        pipe.RunAsClient(() => clientSid = GetWindowsCurrentSid());
        return clientSid;
    }

    private static string? GetCurrentOwnerSid()
    {
        if (!OperatingSystem.IsWindows()) return null;
        return GetWindowsCurrentSid();
    }

    [SupportedOSPlatform("windows")]
    private static string? GetWindowsCurrentSid() => WindowsIdentity.GetCurrent().User?.Value;

    private bool IsClientAuthorized(string sourceDaemon, string? clientSid, string? ownerSid)
    {
        if (!OperatingSystem.IsWindows()) return true;
        if (string.IsNullOrWhiteSpace(clientSid) || string.IsNullOrWhiteSpace(ownerSid)) return false;
        if (StringComparer.OrdinalIgnoreCase.Equals(clientSid, ownerSid)) return true;
        return IsAdditionalClientAuthorizedForRole(sourceDaemon, clientSid, _additionalD1ClientSids, _additionalD2ClientSids);
    }

    internal static bool IsAdditionalClientAuthorizedForRole(string sourceDaemon, string clientSid,
        IReadOnlyCollection<string> additionalD1ClientSids, IReadOnlyCollection<string> additionalD2ClientSids)
    {
        return sourceDaemon switch
        {
            DaemonNames.HumanBehaviorMonitor => additionalD1ClientSids.Contains(clientSid, StringComparer.OrdinalIgnoreCase),
            DaemonNames.ThreatMonitor => additionalD2ClientSids.Contains(clientSid, StringComparer.OrdinalIgnoreCase),
            _ => false
        };
    }

    private async Task WriteAcknowledgementAsync(Stream pipe, ClientConnection? connection, InterDaemonAcknowledgement ack, string correlationId,
        bool envelopeStyle, CancellationToken token)
    {
        if (envelopeStyle)
        {
            var now = DateTimeOffset.UtcNow;
            var message = new DaemonEnvelope
            {
                MessageId = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = now,
                SourceDaemon = DaemonNames.RiskResponseGuard, Destination = DaemonNames.ThreatMonitor,
                MessageType = "ACK", SchemaVersion = 1, ExpiresAtUtc = now.AddSeconds(15),
                Payload = JsonSerializer.SerializeToElement(new { messageId = ack.MessageId, status = ack.Status, reason = ack.Reason }, JsonOptions)
            };
            var validation = _validator.Validate(message, JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions).Length);
            if (!validation.IsValid) throw new InvalidDataException("ACK D2 invalide : " + validation.Error);
            await WriteFrameToPipeAsync(pipe, connection, JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions), token).ConfigureAwait(false);
            return;
        }

        await WriteFrameToPipeAsync(pipe, connection, JsonSerializer.SerializeToUtf8Bytes(ack, JsonOptions), token).ConfigureAwait(false);
    }

    private static async Task WriteFrameToPipeAsync(Stream pipe, ClientConnection? connection, byte[] body, CancellationToken token)
    {
        if (connection is not null)
        {
            await connection.WriteFrameAsync(body, token).ConfigureAwait(false);
            return;
        }
        var frame = new byte[sizeof(int) + body.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frame, body.Length);
        body.CopyTo(frame.AsSpan(sizeof(int)));
        await pipe.WriteAsync(frame, token).ConfigureAwait(false);
        await pipe.FlushAsync(token).ConfigureAwait(false);
    }

    private static string ToReasonCode(string? error)
        => string.IsNullOrWhiteSpace(error) ? "MESSAGE_REJECTED" : error.ToUpperInvariant().Replace(' ', '_').Replace('.', '_');

    public async ValueTask DisposeAsync()
    {
        lock (_startSync) _disposed = true;
        _stop.Cancel();
        foreach (var client in _clients.Values) client.Dispose();
        if (_acceptLoop is not null)
        {
            try { await _acceptLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
            catch (TimeoutException) { }
            catch (Exception) when (ListenerFailure is not null) { }
        }
        _stop.Dispose();
    }

    private sealed class ClientConnection(NamedPipeServerStream pipe, string daemonName, string? clientSid) : IDisposable
    {
        private readonly SemaphoreSlim _writeGate = new(1, 1);
        public string DaemonName { get; } = daemonName;
        public string? ClientSid { get; } = clientSid;
        public bool UsesEnvelopeAcknowledgements { get; } = daemonName == DaemonNames.ThreatMonitor;
        public async Task WriteFrameAsync(byte[] body, CancellationToken token)
        {
            await _writeGate.WaitAsync(token).ConfigureAwait(false);
            try
            {
                var header = new byte[sizeof(int)];
                BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
                await pipe.WriteAsync(header, token).ConfigureAwait(false);
                await pipe.WriteAsync(body, token).ConfigureAwait(false);
                await pipe.FlushAsync(token).ConfigureAwait(false);
            }
            finally { _writeGate.Release(); }
        }
        public void Dispose() { pipe.Dispose(); _writeGate.Dispose(); }
    }
}

public sealed record InterDaemonAcknowledgement(Guid MessageId, string Status, string? Reason = null);

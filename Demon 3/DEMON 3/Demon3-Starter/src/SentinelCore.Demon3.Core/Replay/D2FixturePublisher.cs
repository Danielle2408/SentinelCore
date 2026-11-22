using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon3.Core.Contracts;
using SentinelCore.Demon3.Core.Transport;

namespace SentinelCore.Demon3.Core.Replay;

public sealed record FixturePublishResult(int Sent, int Rejected, string PipeName, DateTimeOffset CompletedAtUtc);

/// <summary>Emits D2-shaped, synthetic findings through the exact production pipe framing.</summary>
public sealed class D2FixturePublisher
{
    private const int MaxMessageBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<FixturePublishResult> PublishAsync(string sqlitePath, string pipeName = NamedPipeInterDaemonServer.PipeName,
        CancellationToken cancellationToken = default)
    {
        if (!File.Exists(sqlitePath)) throw new FileNotFoundException("Base de scénarios D2 introuvable.", sqlitePath);
        await using var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await ConnectWithRetryAsync(pipe, cancellationToken).ConfigureAwait(false);
        var session = Guid.NewGuid().ToString("D");
        await SendAsync(pipe, Envelope(session, "HELLO", JsonSerializer.SerializeToElement(new
        {
            daemonId = "ThreatMonitor", capabilities = new[] { "findings", "context" }, supportedSchema = 1
        })), cancellationToken).ConfigureAwait(false);
        var welcome = await ReadAsync(pipe, cancellationToken).ConfigureAwait(false);
        if (!welcome.TryGetProperty("messageType", out var welcomeType) || welcomeType.GetString() != "WELCOME"
            || !welcome.TryGetProperty("sourceDaemon", out var welcomeSource) || welcomeSource.GetString() != "RiskResponseGuard")
            throw new InvalidDataException("D3 n’a pas répondu WELCOME à la simulation D2.");

        var sent = 0;
        var rejected = 0;
        await SendAsync(pipe, Envelope(session, "HEARTBEAT", JsonSerializer.SerializeToElement(new
        {
            status = "Available", queueDepth = 0, outboxDepth = 0, droppedCount = 0, lastEventUtc = (DateTimeOffset?)null
        })), cancellationToken).ConfigureAwait(false);
        _ = await ReadAsync(pipe, cancellationToken).ConfigureAwait(false);

        var cs = new SqliteConnectionStringBuilder { DataSource = Path.GetFullPath(sqlitePath), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString();
        await using var connection = new SqliteConnection(cs);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT s.scenario_id,r.report_type,r.severity,r.confidence,r.evidence_event_ids FROM scenarios s JOIN reports r ON r.scenario_id=s.scenario_id ORDER BY s.scenario_id";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var correlation = reader.GetString(0);
            var reportType = reader.GetString(1).ToUpperInvariant();
            var severity = reportType == "NEEDS_CONTEXT" ? "UNKNOWN" : reader.GetString(2).ToUpperInvariant();
            var confidence = reader.IsDBNull(3) ? (double?)null : reader.GetDouble(3);
            var evidence = ParseEvidence(reader.IsDBNull(4) ? "[]" : reader.GetString(4));
            var now = DateTimeOffset.UtcNow;
            var payload = reportType == "NEEDS_CONTEXT"
                ? JsonSerializer.SerializeToElement(new
                {
                    gapId = "FIXTURE-" + correlation, source = "D2Fixture", reason = "Fixture context is incomplete.",
                    droppedCount = 0, missingFields = new[] { "fixtureContext" }, synthetic = true
                }, JsonOptions)
                : JsonSerializer.SerializeToElement(new
                {
                    findingId = "FIXTURE-" + correlation,
                    ruleId = "FIXTURE_" + reportType,
                    ruleVersion = 1,
                    severity = severity.ToLowerInvariant(),
                    confidence = confidence ?? 0.5,
                    firstSeenUtc = now,
                    lastSeenUtc = now,
                    summary = "Synthetic D2 fixture finding; no live event was collected.",
                    facts = Array.Empty<object>(),
                    evidenceRefs = evidence,
                    missingTelemetry = Array.Empty<string>(),
                    synthetic = true
                }, JsonOptions);
            var message = Envelope(correlation, reportType == "NEEDS_CONTEXT" ? "TELEMETRY_GAP" : "THREAT_FINDING", payload);
            await SendAsync(pipe, message, cancellationToken).ConfigureAwait(false);
            var response = await ReadAsync(pipe, cancellationToken).ConfigureAwait(false);
            if (ReadStatus(response) is "ACCEPTED" or "DUPLICATE") sent++; else rejected++;
        }
        return new(sent, rejected, pipeName, DateTimeOffset.UtcNow);
    }

    private static DaemonEnvelope Envelope(string correlation, string type, JsonElement payload)
    {
        var now = DateTimeOffset.UtcNow;
        return new()
        {
            MessageId = Guid.NewGuid(), CorrelationId = correlation, TimestampUtc = now,
            SourceDaemon = DaemonNames.ThreatMonitor, Destination = DaemonNames.RiskResponseGuard,
            MessageType = type, SchemaVersion = 1, ExpiresAtUtc = now.AddSeconds(45), Payload = payload
        };
    }

    private static async Task ConnectWithRetryAsync(NamedPipeClientStream pipe, CancellationToken token)
    {
        var stopAt = DateTimeOffset.UtcNow.AddSeconds(15);
        while (true)
        {
            token.ThrowIfCancellationRequested();
            try { await pipe.ConnectAsync(500, token).ConfigureAwait(false); return; }
            catch (TimeoutException) when (DateTimeOffset.UtcNow < stopAt) { await Task.Delay(250, token).ConfigureAwait(false); }
            catch (IOException) when (DateTimeOffset.UtcNow < stopAt) { await Task.Delay(250, token).ConfigureAwait(false); }
            if (DateTimeOffset.UtcNow >= stopAt) throw new TimeoutException("D3 n’a pas ouvert son canal local dans le délai prévu.");
        }
    }

    private static async Task SendAsync(Stream stream, DaemonEnvelope envelope, CancellationToken token)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (bytes.Length > MaxMessageBytes) throw new InvalidDataException("Fixture D2 trop volumineuse.");
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }

    private static async Task<JsonElement> ReadAsync(Stream stream, CancellationToken token)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > MaxMessageBytes) throw new InvalidDataException("Réponse D3 trop volumineuse.");
        var bytes = new byte[length];
        await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(bytes);
        return doc.RootElement.Clone();
    }

    private static string? ReadStatus(JsonElement element)
    {
        if (element.TryGetProperty("payload", out var payload) && payload.ValueKind == JsonValueKind.Object)
            element = payload;
        return element.TryGetProperty("status", out var status) && status.ValueKind == JsonValueKind.String ? status.GetString() : null;
    }

    private static IReadOnlyList<string> ParseEvidence(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return [];
            return doc.RootElement.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => x.GetString()!).Where(x => !string.IsNullOrWhiteSpace(x) && x.Length <= 96
                    && x.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':')).Take(64).ToArray();
        }
        catch (JsonException) { return []; }
    }
}

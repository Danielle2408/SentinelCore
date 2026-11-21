using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Globalization;

namespace SentinelCore.Demon2.Core;

public static class InterDaemonEnvelopeFactory
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { Converters = { new JsonStringEnumConverter() } };

    public static InterDaemonEnvelope ForFinding(ThreatFinding finding, DateTimeOffset nowUtc) => Make(
        finding.CorrelationId, "THREAT_FINDING", nowUtc, finding.ExpiresAtUtc,
        new { findingId = finding.FindingId, ruleId = finding.RuleId, ruleVersion = finding.RuleVersion,
            severity = finding.Severity.ToString(), confidence = finding.Confidence, firstSeenUtc = finding.FirstSeenUtc,
            lastSeenUtc = finding.LastSeenUtc, summary = finding.Summary, facts = finding.Facts,
            evidenceRefs = finding.EvidenceRefs, missingTelemetry = finding.MissingTelemetry });

    public static InterDaemonEnvelope ForGap(TelemetryGap gap, DateTimeOffset expiresAtUtc) => Make(
        gap.GapId, "TELEMETRY_GAP", gap.ObservedAtUtc, expiresAtUtc,
        new { gapId = gap.GapId, source = gap.Source, reason = gap.Reason, droppedCount = gap.DroppedCount,
            missingFields = gap.MissingFields });

    public static InterDaemonEnvelope ForSessionContextRequest(string correlationId, IReadOnlyCollection<string> requestedFields,
        DateTimeOffset deadlineUtc)
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "sessionState", "localOrRemote", "recentAuthBand" };
        if (requestedFields.Count == 0 || requestedFields.Any(x => !allowed.Contains(x)))
            throw new ArgumentException("Only allowlisted session context fields may be requested.", nameof(requestedFields));
        return Make(correlationId, "SESSION_CONTEXT_REQUEST", DateTimeOffset.UtcNow, deadlineUtc,
            new { requestedFields = requestedFields.Distinct(StringComparer.Ordinal).ToArray(), deadlineUtc });
    }

    public static InterDaemonEnvelope Heartbeat(string correlationId, EventSourceHealth health, int outboxDepth, DateTimeOffset nowUtc) => Make(
        correlationId, "HEARTBEAT", nowUtc, nowUtc.AddSeconds(30), new { status = health.State.ToString(),
            queueDepth = health.QueueDepth, outboxDepth, lastEventUtc = health.LastEventUtc, droppedCount = health.DroppedCount });

    private static InterDaemonEnvelope Make(string correlationId, string type, DateTimeOffset timestamp, DateTimeOffset expires, object payload) =>
        new(Guid.NewGuid(), correlationId, timestamp.ToUniversalTime(), "ThreatMonitor", "RiskResponseGuard", type, 1,
            expires.ToUniversalTime(), JsonSerializer.SerializeToElement(payload, JsonOptions));
}

public static class InterDaemonEnvelopeValidator
{
    private static readonly HashSet<string> AllowedTypes = Enum.GetNames<InterDaemonMessageType>().ToHashSet(StringComparer.Ordinal);

    public static bool TryValidate(InterDaemonEnvelope message, DateTimeOffset nowUtc, out string? error)
    {
        error = null;
        if (message.MessageId == Guid.Empty || string.IsNullOrWhiteSpace(message.CorrelationId)) error = "messageId and correlationId are required.";
        else if (message.SourceDaemon != "ThreatMonitor" || message.Destination != "RiskResponseGuard") error = "Invalid D2 route.";
        else if (message.SchemaVersion != 1 || !AllowedTypes.Contains(message.MessageType)) error = "Unsupported schema or message type.";
        else if (message.TimestampUtc.Offset != TimeSpan.Zero || message.ExpiresAtUtc.Offset != TimeSpan.Zero) error = "Envelope timestamps must be UTC.";
        else if (message.ExpiresAtUtc <= message.TimestampUtc) error = "expiresAtUtc must be later than timestampUtc.";
        else if (message.ExpiresAtUtc <= nowUtc.ToUniversalTime()) error = "Message has expired.";
        else if (message.Payload.ValueKind != JsonValueKind.Object) error = "payload must be an object.";
        else if (!ValidPayload(message.MessageType, message.Payload, out error)) { }
        else if (JsonSerializer.SerializeToUtf8Bytes(message).Length > 64 * 1024) error = "Message exceeds the common 64 KiB limit.";
        return error is null;
    }

    public static bool EvidenceRefsResolve(InterDaemonEnvelope message, IReadOnlySet<string> storedEventIds, out string? error)
    {
        error = null;
        if (message.MessageType != "THREAT_FINDING") return true;
        if (!message.Payload.TryGetProperty("evidenceRefs", out var refs) || refs.ValueKind != JsonValueKind.Array) { error = "Finding evidenceRefs are unavailable."; return false; }
        var missing = refs.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).Where(x => !storedEventIds.Contains(x)).ToArray();
        if (missing.Length == 0) return true;
        error = "Finding evidenceRefs do not resolve to stored events: " + string.Join(",", missing);
        return false;
    }

    private static bool ValidPayload(string type, JsonElement p, out string? error)
    {
        error = null;
        string? payloadError = null;
        bool Str(string n) => p.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString());
        bool ArrayOfStrings(string n, bool nonempty = false) => p.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Array && (!nonempty || v.GetArrayLength() > 0) && v.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(x.GetString()));
        bool NonNegative(string n) => p.TryGetProperty(n, out var v) && v.TryGetInt64(out var x) && x >= 0;
        bool Positive(string n) => p.TryGetProperty(n, out var v) && v.TryGetInt32(out var x) && x > 0;
        bool Utc(string n) => p.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && DateTimeOffset.TryParse(v.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var d) && d.Offset == TimeSpan.Zero;
        bool Missing(bool condition, string message) { if (condition) return false; payloadError = $"Invalid {type} payload: {message}."; return true; }
        switch (type)
        {
            case "THREAT_FINDING":
                if (Missing(Str("findingId") && Str("ruleId") && Positive("ruleVersion") && Str("severity") && Enum.TryParse<ThreatSeverity>(p.GetProperty("severity").GetString(), false, out _) && p.GetProperty("confidence").ValueKind == JsonValueKind.Number && p.GetProperty("confidence").GetDouble() is >= 0 and <= 1 && Utc("firstSeenUtc") && Utc("lastSeenUtc") && Str("summary") && p.TryGetProperty("facts", out var facts) && facts.ValueKind == JsonValueKind.Array && ArrayOfStrings("evidenceRefs", true) && ArrayOfStrings("missingTelemetry"), "required finding fields, ranges, or UTC timestamps are invalid")) { error = payloadError; return false; }
                var refs = p.GetProperty("evidenceRefs").EnumerateArray().Select(x => x.GetString()!).ToArray();
                if (refs.Distinct(StringComparer.Ordinal).Count() != refs.Length) { payloadError = "Invalid THREAT_FINDING payload: duplicate evidenceRefs."; error = payloadError; return false; }
                if (DateTimeOffset.Parse(p.GetProperty("lastSeenUtc").GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind) < DateTimeOffset.Parse(p.GetProperty("firstSeenUtc").GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind)) { payloadError = "Invalid THREAT_FINDING payload: lastSeenUtc precedes firstSeenUtc."; error = payloadError; return false; }
                break;
            case "TELEMETRY_GAP": if (Missing(Str("gapId") && Str("source") && Str("reason") && NonNegative("droppedCount") && ArrayOfStrings("missingFields"), "required gap fields are invalid")) { error = payloadError; return false; } break;
            case "HEARTBEAT": if (Missing(Str("status") && NonNegative("queueDepth") && NonNegative("outboxDepth") && NonNegative("droppedCount"), "required heartbeat fields are invalid")) { error = payloadError; return false; } break;
            case "SESSION_CONTEXT_REQUEST": if (Missing(ArrayOfStrings("requestedFields", true) && Utc("deadlineUtc") && p.GetProperty("requestedFields").EnumerateArray().All(x => new[] { "sessionState", "localOrRemote", "recentAuthBand" }.Contains(x.GetString(), StringComparer.Ordinal)), "requested fields or UTC deadline are invalid")) { error = payloadError; return false; } break;
            case "HELLO": if (Missing(Str("daemonId") && Positive("supportedSchema") && ArrayOfStrings("capabilities"), "required handshake fields are invalid")) { error = payloadError; return false; } break;
            case "CONTEXT_RESPONSE": break;
        }
        error = payloadError;
        return true;
    }
}

public sealed class JsonlInterDaemonBus(string filePath) : IInterDaemonBus
{
    private static readonly SemaphoreSlim FileLock = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _filePath = filePath;

    public async ValueTask PublishAsync(InterDaemonEnvelope message, CancellationToken cancellationToken = default)
    {
        if (!InterDaemonEnvelopeValidator.TryValidate(message, DateTimeOffset.UtcNow, out var error))
            throw new InvalidOperationException(error);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(message, JsonOptions);
        if (bytes.Length > 64 * 1024) throw new InvalidOperationException("Message exceeds the common 64 KiB limit.");
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_filePath))!);
        await FileLock.WaitAsync(cancellationToken);
        try
        {
            await using var stream = new FileStream(_filePath, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, true);
            await stream.WriteAsync(bytes, cancellationToken);
            await stream.WriteAsync(Encoding.UTF8.GetBytes("\n"), cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }
        finally { FileLock.Release(); }
    }
}

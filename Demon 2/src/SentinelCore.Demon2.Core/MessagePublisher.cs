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
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        if (correlationId.Length > 128 || requestedFields.Count == 0 || requestedFields.Count > allowed.Count
            || requestedFields.Any(x => !allowed.Contains(x))
            || requestedFields.Distinct(StringComparer.Ordinal).Count() != requestedFields.Count)
            throw new ArgumentException("Only allowlisted session context fields may be requested.", nameof(requestedFields));
        var now = DateTimeOffset.UtcNow;
        deadlineUtc = deadlineUtc.ToUniversalTime();
        if (deadlineUtc <= now || deadlineUtc > now.AddMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(deadlineUtc), "Session context deadline must be within one minute.");
        return Make(correlationId, "SESSION_CONTEXT_REQUEST", now, deadlineUtc,
            new { requestedFields = requestedFields.ToArray(), deadlineUtc });
    }

    public static InterDaemonEnvelope ForThreatContextResponse(string correlationId, ThreatContextResponse response,
        DateTimeOffset nowUtc) => Make(correlationId, "CONTEXT_RESPONSE", nowUtc, nowUtc.AddSeconds(30), response);

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
        if (message.MessageId == Guid.Empty || string.IsNullOrWhiteSpace(message.CorrelationId) || message.CorrelationId.Length > 128 || message.CorrelationId.Any(char.IsControl)) error = "messageId and a bounded correlationId are required.";
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
            case "SESSION_CONTEXT_REQUEST":
                if (Missing(ArrayOfStrings("requestedFields", true) && p.GetProperty("requestedFields").GetArrayLength() <= 3
                    && Utc("deadlineUtc") && DateTimeOffset.Parse(p.GetProperty("deadlineUtc").GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind) > DateTimeOffset.UtcNow
                    && p.GetProperty("requestedFields").EnumerateArray().All(x => new[] { "sessionState", "localOrRemote", "recentAuthBand" }.Contains(x.GetString(), StringComparer.Ordinal))
                    && p.GetProperty("requestedFields").EnumerateArray().Select(x => x.GetString()).Distinct(StringComparer.Ordinal).Count() == p.GetProperty("requestedFields").GetArrayLength(),
                    "requested fields or UTC deadline are invalid")) { error = payloadError; return false; }
                break;
            case "HELLO": if (Missing(Str("daemonId") && Positive("supportedSchema") && ArrayOfStrings("capabilities"), "required handshake fields are invalid")) { error = payloadError; return false; } break;
            case "CONTEXT_RESPONSE": return ValidThreatContextResponse(p, out error);
        }
        error = payloadError;
        return true;
    }

    private static bool ValidThreatContextResponse(JsonElement payload, out string? error)
    {
        error = "Invalid CONTEXT_RESPONSE payload.";
        bool Utc(string name) => payload.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            && parsed.Offset == TimeSpan.Zero;
        if (!Utc("observedAtUtc") || !payload.TryGetProperty("found", out var found) || found.ValueKind is not (JsonValueKind.True or JsonValueKind.False)
            || !payload.TryGetProperty("requestedFields", out var requested) || requested.ValueKind != JsonValueKind.Array
            || requested.GetArrayLength() is < 1 or > 4
            || !requested.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String && x.GetString() is { } field && ThreatContextFields.All.Contains(field))
            || requested.EnumerateArray().Select(x => x.GetString()).Distinct(StringComparer.Ordinal).Count() != requested.GetArrayLength()
            || !payload.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array
            || findings.GetArrayLength() > 20 || (found.GetBoolean() != (findings.GetArrayLength() > 0)))
            return false;

        var fieldSet = requested.EnumerateArray().Select(x => x.GetString()!).ToHashSet(StringComparer.Ordinal);
        foreach (var finding in findings.EnumerateArray())
        {
            if (finding.ValueKind != JsonValueKind.Object || !HasExactProperties(finding,
                    ["findingId", "summary", "ruleDetails", "evidenceRefs", "evidenceKinds", "missingTelemetry"])) return false;
            if (!IsSafeContextToken(finding, "findingId", 96)) return false;
            if (fieldSet.Contains(ThreatContextFields.FindingSummary))
            {
                if (!IsSafeContextText(finding, "summary", 500)) return false;
            }
            else if (finding.GetProperty("summary").ValueKind != JsonValueKind.Null) return false;

            var details = finding.GetProperty("ruleDetails");
            if (fieldSet.Contains(ThreatContextFields.RuleDetails))
            {
                if (details.ValueKind != JsonValueKind.Object || !HasExactProperties(details, ["ruleId", "ruleVersion", "severity", "confidence", "facts"])
                    || !IsSafeContextToken(details, "ruleId", 64)
                    || !details.TryGetProperty("ruleVersion", out var version) || !version.TryGetInt32(out var ruleVersion) || ruleVersion < 1
                    || !details.TryGetProperty("severity", out var severity) || severity.ValueKind != JsonValueKind.String
                    || !Enum.TryParse<ThreatSeverity>(severity.GetString(), false, out var parsedSeverity) || !Enum.IsDefined(parsedSeverity)
                    || !details.TryGetProperty("confidence", out var confidence) || confidence.ValueKind != JsonValueKind.Number
                    || !double.IsFinite(confidence.GetDouble()) || confidence.GetDouble() is < 0 or > 1
                    || !details.TryGetProperty("facts", out var facts) || !ValidContextFacts(facts)) return false;
            }
            else if (details.ValueKind != JsonValueKind.Null) return false;

            var refs = finding.GetProperty("evidenceRefs");
            var kinds = finding.GetProperty("evidenceKinds");
            if (fieldSet.Contains(ThreatContextFields.EvidenceKinds))
            {
                if (!ValidContextStringArray(refs, 32, 96, IsSafeToken)
                    || refs.EnumerateArray().Select(x => x.GetString()).Distinct(StringComparer.Ordinal).Count() != refs.GetArrayLength()
                    || !ValidContextStringArray(kinds, 32, 48, (value, _) => IsThreatEventType(value))
                    || refs.GetArrayLength() != kinds.GetArrayLength()) return false;
            }
            else if (refs.ValueKind != JsonValueKind.Null || kinds.ValueKind != JsonValueKind.Null) return false;

            var missing = finding.GetProperty("missingTelemetry");
            if (fieldSet.Contains(ThreatContextFields.MissingTelemetry))
            {
                if (!ValidContextStringArray(missing, 32, 64, IsSafeToken)) return false;
            }
            else if (missing.ValueKind != JsonValueKind.Null) return false;
        }
        error = null;
        return true;
    }

    private static bool HasExactProperties(JsonElement value, params string[] expected)
        => value.EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal).SetEquals(expected)
            && value.EnumerateObject().Count() == expected.Length;

    private static bool IsSafeContextToken(JsonElement parent, string name, int maximumLength)
        => parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            && IsSafeToken(value.GetString(), maximumLength);

    private static bool IsSafeContextText(JsonElement parent, string name, int maximumLength)
        => parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            && !string.IsNullOrWhiteSpace(value.GetString()) && value.GetString()!.Length <= maximumLength
            && !value.GetString()!.Any(char.IsControl);

    private static bool ValidContextFacts(JsonElement facts)
    {
        if (facts.ValueKind != JsonValueKind.Array || facts.GetArrayLength() > 32) return false;
        foreach (var fact in facts.EnumerateArray())
        {
            if (fact.ValueKind != JsonValueKind.Object || !HasExactProperties(fact, ["name", "value"])
                || !IsSafeContextToken(fact, "name", 64) || !IsSafeContextToken(fact, "value", 64)) return false;
        }
        return true;
    }

    private static bool ValidContextStringArray(JsonElement value, int maximumCount, int maximumLength, Func<string?, int, bool> validator)
        => value.ValueKind == JsonValueKind.Array && value.GetArrayLength() <= maximumCount
            && value.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String && validator(x.GetString(), maximumLength));

    private static bool IsThreatEventType(string? value)
        => Enum.TryParse<ThreatEventType>(value, false, out var parsed) && Enum.IsDefined(parsed);

    private static bool IsSafeToken(string? value, int maximumLength = 96)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength
            && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':');
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

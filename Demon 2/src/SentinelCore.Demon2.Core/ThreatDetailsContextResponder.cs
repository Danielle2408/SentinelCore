namespace SentinelCore.Demon2.Core;

/// <summary>Consumes D3 threat-detail requests and returns a minimized, allowlisted projection.</summary>
public sealed class ThreatDetailsContextResponder(IEventStore store, IRequestReceivingInterDaemonBus bus,
    TimeProvider? timeProvider = null)
{
    private const int MaximumFindings = 10;
    private const int MaximumEvidencePerFinding = 24;
    private const int MaximumFactsPerFinding = 24;
    private static readonly IReadOnlySet<string> SafeFactNames = new HashSet<string>(StringComparer.Ordinal)
    {
        "download", "execution", "network_or_script", "unexpected_parent", "script_activity", "process",
        "persistence_change", "file_change_burst", "network_connection", "corroborating_activity",
        "repeated_dns_queries", "domain", "image_load", "signer_status_missing", "unsigned_binary",
        "execution_not_observed", "security_source_change", "sensitive_process_access"
    };
    private static readonly IReadOnlySet<string> SafeMissingFields = new HashSet<string>(StringComparer.Ordinal)
    {
        "processId/processGuid", "remoteHost", "sha256", "commandLine", "parentProcess", "networkSensor",
        "userSession", "domainReputation", "publisherContext", "initiatorContext", "imageSignerOrPath",
        "targetProcess/accessMask", "source_available", "sourceEvents", "normalizedEvent", "sourceCursor"
    };
    private static readonly IReadOnlySet<string> SafeFactValues = new HashSet<string>(StringComparer.Ordinal)
    { "observed", "synthetic", "unknown" };
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        await foreach (var request in bus.ReadRequestsAsync(cancellationToken).WithCancellation(cancellationToken))
        {
            if (!TryReadRequest(request, _clock.GetUtcNow(), out var requestedFields)) continue;
            var response = await BuildResponseAsync(request.CorrelationId, requestedFields, cancellationToken).ConfigureAwait(false);
            var now = _clock.GetUtcNow();
            var envelope = InterDaemonEnvelopeFactory.ForThreatContextResponse(request.CorrelationId, response, now);
            if (!InterDaemonEnvelopeValidator.TryValidate(envelope, now, out var error))
                throw new InvalidOperationException($"D2 generated an invalid context response: {error}");
            await bus.PublishAsync(envelope, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<ThreatContextResponse> BuildResponseAsync(string correlationId,
        IReadOnlyList<string> requestedFields, CancellationToken cancellationToken)
    {
        var now = _clock.GetUtcNow();
        var findings = await store.LoadFindingsByCorrelationAsync(correlationId, now, MaximumFindings, cancellationToken)
            .ConfigureAwait(false);
        var allEvidenceRefs = findings.SelectMany(x => x.EvidenceRefs).Distinct(StringComparer.Ordinal)
            .Take(MaximumFindings * MaximumEvidencePerFinding).ToArray();
        var events = await store.LoadEventsByIdsAsync(allEvidenceRefs, cancellationToken).ConfigureAwait(false);
        var eventById = events.ToDictionary(x => x.EventId, StringComparer.Ordinal);
        var includeSummary = requestedFields.Contains(ThreatContextFields.FindingSummary, StringComparer.Ordinal);
        var includeRuleDetails = requestedFields.Contains(ThreatContextFields.RuleDetails, StringComparer.Ordinal);
        var includeEvidence = requestedFields.Contains(ThreatContextFields.EvidenceKinds, StringComparer.Ordinal);
        var includeMissing = requestedFields.Contains(ThreatContextFields.MissingTelemetry, StringComparer.Ordinal);
        var projections = new List<ThreatFindingContextProjection>(findings.Count);

        foreach (var finding in findings)
        {
            if (!IsSafeToken(finding.FindingId, 96)) continue;
            var rule = DetectionRuleCatalog.All.FirstOrDefault(x => x.RuleId == finding.RuleId);
            if (rule is null) continue;
            var matchingEvents = finding.EvidenceRefs.Where(x => IsSafeToken(x, 96) && eventById.ContainsKey(x))
                .Distinct(StringComparer.Ordinal).Take(MaximumEvidencePerFinding).Select(x => eventById[x]).ToArray();
            var safeFacts = includeRuleDetails
                ? finding.Facts.Where(x => SafeFactNames.Contains(x.Name)).DistinctBy(x => x.Name, StringComparer.Ordinal)
                    .Take(MaximumFactsPerFinding).Select(x => new DetectionFact(x.Name,
                        SafeFactValues.Contains(x.Value) ? x.Value : "unknown")).ToArray()
                : null;
            var details = includeRuleDetails
                ? new ThreatRuleContextDetails(rule.RuleId, rule.RuleVersion, rule.Severity.ToString(), rule.Confidence,
                    safeFacts ?? [])
                : null;
            var evidenceRefs = includeEvidence ? matchingEvents.Select(x => x.EventId).ToArray() : null;
            var evidenceKinds = includeEvidence ? matchingEvents.Select(x => x.EventType.ToString()).ToArray() : null;
            var missingTelemetry = includeMissing
                ? finding.MissingTelemetry.Where(SafeMissingFields.Contains).Distinct(StringComparer.Ordinal).Take(32).ToArray()
                : null;
            projections.Add(new ThreatFindingContextProjection(finding.FindingId,
                includeSummary ? rule.Description : null, details, evidenceRefs, evidenceKinds, missingTelemetry));
        }

        return new ThreatContextResponse(now, projections.Count > 0, requestedFields.ToArray(), projections);
    }

    private static bool TryReadRequest(InterDaemonEnvelope message, DateTimeOffset nowUtc,
        out IReadOnlyList<string> requestedFields)
    {
        requestedFields = [];
        if (message.SourceDaemon != "RiskResponseGuard" || message.Destination != "ThreatMonitor"
            || message.MessageType != "CONTEXT_REQUEST" || message.MessageId == Guid.Empty
            || string.IsNullOrWhiteSpace(message.CorrelationId) || message.CorrelationId.Length > 128
            || message.CorrelationId.Any(char.IsControl) || message.SchemaVersion != 1
            || message.TimestampUtc.Offset != TimeSpan.Zero || message.ExpiresAtUtc.Offset != TimeSpan.Zero
            || message.TimestampUtc > nowUtc.AddSeconds(30) || message.ExpiresAtUtc <= nowUtc
            || message.Payload.ValueKind != System.Text.Json.JsonValueKind.Object
            || !message.Payload.TryGetProperty("requestedFields", out var fields)
            || fields.ValueKind != System.Text.Json.JsonValueKind.Array || fields.GetArrayLength() is < 1 or > 4
            || !message.Payload.TryGetProperty("deadlineUtc", out var deadline)
            || deadline.ValueKind != System.Text.Json.JsonValueKind.String
            || !deadline.TryGetDateTimeOffset(out var deadlineUtc) || deadlineUtc.Offset != TimeSpan.Zero
            || deadlineUtc <= nowUtc || deadlineUtc > message.ExpiresAtUtc)
            return false;

        var parsed = new List<string>(fields.GetArrayLength());
        foreach (var field in fields.EnumerateArray())
        {
            if (field.ValueKind != System.Text.Json.JsonValueKind.String || field.GetString() is not { } name
                || !ThreatContextFields.All.Contains(name) || parsed.Contains(name, StringComparer.Ordinal)) return false;
            parsed.Add(name);
        }
        requestedFields = parsed;
        return true;
    }

    private static bool IsSafeToken(string? value, int maximumLength)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= maximumLength
            && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':');
}

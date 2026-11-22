using System.Text.Json;
using SentinelCore.Demon3.Core.Contracts;

namespace SentinelCore.Demon3.Core.Decision;

public enum RiskLevel { UNKNOWN, LOW, GUARDED, ELEVATED, HIGH, CRITICAL }
public enum DecisionKind { MONITOR, REQUEST_CONTEXT, REQUIRE_OWNER_CONFIRMATION, RUN_BOUNDED_SCAN, CONTAINMENT_REVIEW, CAPABILITY_GAP, SAFE_DEGRADED }
public enum ProposedAction { NONE, REQUEST_D1_SESSION_CONTEXT, REQUEST_D1_VISUAL_CHECK, RUN_DEFENDER_SCAN, ISOLATE_FILE_REVIEW }

public sealed record DecisionEvidence(string SourceDaemon, string MessageType, string Severity, double? Confidence,
    string? ReasonCode, IReadOnlyList<string> EvidenceRefs, DateTimeOffset ObservedAtUtc, bool IsSynthetic = false,
    string? ContextSummary = null, IReadOnlyList<string>? AiFacts = null);

public sealed record RiskDecision(string CorrelationId, RiskLevel Risk, DecisionKind Decision,
    ProposedAction ProposedAction, string Explanation, IReadOnlyList<string> ReasonCodes,
    IReadOnlyList<string> EvidenceRefs, bool RequiresHumanApproval, bool SimulationOnly,
    DateTimeOffset DecidedAtUtc, string PolicyVersion = "d3-policy-1.1");

/// <summary>Deterministic fusion: D1 may add context, but can never erase a strong technical D2 alert.</summary>
public sealed class RiskDecisionEngine
{
    public RiskDecision Evaluate(string correlationId, IReadOnlyList<DecisionEvidence> evidence, bool degraded = false)
    {
        if (string.IsNullOrWhiteSpace(correlationId)) throw new ArgumentException("Correlation requise.", nameof(correlationId));
        ArgumentNullException.ThrowIfNull(evidence);
        var d2 = evidence.Where(x => x.SourceDaemon == DaemonNames.ThreatMonitor).ToArray();
        var d1 = evidence.Where(x => x.SourceDaemon == DaemonNames.HumanBehaviorMonitor).ToArray();
        var reasons = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in evidence) if (!string.IsNullOrWhiteSpace(item.ReasonCode)) reasons.Add(item.ReasonCode);

        var strongest = d2.Select(x => Severity(x.Severity)).DefaultIfEmpty(RiskLevel.LOW).Max();
        var risk = strongest;
        var d1Abnormal = d1.Any(x => x.MessageType == "BEHAVIOR_DEVIATION"
            && (x.ReasonCode?.Contains("DIVERGENCE_OVER_60", StringComparison.Ordinal) == true
                || x.Severity is "HIGH" or "CRITICAL"))
            || d1.Any(x => x.MessageType == "VISUAL_IDENTITY_RESPONSE" && x.Severity is "HIGH" or "CRITICAL");
        var d1Unknown = d1.Any(x => x.MessageType == "BEHAVIOR_DEVIATION"
            && (x.ReasonCode?.Contains("INCONCLUSIVE", StringComparison.Ordinal) == true
                || x.Severity == "UNKNOWN"));
        var nowUtc = DateTimeOffset.UtcNow;
        var ownerVisuallyConfirmed = d1.Any(x =>
        {
            var age = nowUtc - x.ObservedAtUtc;
            return x.MessageType == "VISUAL_IDENTITY_RESPONSE" && x.ReasonCode == "OWNER_VISUALLY_CONFIRMED_LIVE"
                && age >= TimeSpan.Zero && age <= TimeSpan.FromMinutes(1);
        });
        var familiarOwnerContext = d1.Any(x => x.MessageType is "USER_CONTEXT" or "BEHAVIOR_DEVIATION" or "CONTEXT_RESPONSE"
            && x.ReasonCode == "APPLICATION_AND_HOUR_SEEN_IN_PROFILE");

        if (d2.Any(x => x.MessageType == "TELEMETRY_GAP")) reasons.Add("D2_TELEMETRY_GAP");
        if (d2.Length == 0 && d1.Length > 0) reasons.Add("D1_ALONE_CANNOT_AUTHORIZE_DESTRUCTIVE_ACTION");
        if (d1Abnormal)
        {
            risk = Raise(risk, RiskLevel.ELEVATED);
            reasons.Add("D1_BEHAVIOR_DEVIATION_CORROBORATES_CASE");
        }
        else if (d1Unknown) reasons.Add("D1_IDENTITY_OR_BEHAVIOR_UNCERTAIN");
        if (ownerVisuallyConfirmed && d2.Length > 0)
        {
            risk = LowerOneLevel(risk);
            reasons.Add("D1_OWNER_VISUALLY_CONFIRMED_RISK_REDUCED_ONE_LEVEL");
        }
        else if (familiarOwnerContext && d2.Length > 0 && risk is RiskLevel.LOW or RiskLevel.GUARDED)
        {
            risk = LowerOneLevel(risk);
            reasons.Add("D1_LEARNED_APPLICATION_CONTEXT_REDUCED_MODERATE_RISK");
        }
        if (degraded)
        {
            reasons.Add("DAEMON_HEALTH_DEGRADED");
            if (d2.Length == 0) risk = RiskLevel.UNKNOWN;
        }
        if (evidence.Count == 0) { risk = RiskLevel.UNKNOWN; reasons.Add("NO_VALID_SIGNALS"); }

        var (kind, action, approval) = risk switch
        {
            RiskLevel.CRITICAL => (DecisionKind.CONTAINMENT_REVIEW, ProposedAction.ISOLATE_FILE_REVIEW, true),
            RiskLevel.HIGH => (DecisionKind.RUN_BOUNDED_SCAN, ProposedAction.RUN_DEFENDER_SCAN, true),
            RiskLevel.ELEVATED when ownerVisuallyConfirmed => (DecisionKind.MONITOR, ProposedAction.NONE, false),
            RiskLevel.ELEVATED when d1Unknown || d1.Length == 0 => (DecisionKind.REQUEST_CONTEXT, ProposedAction.REQUEST_D1_SESSION_CONTEXT, false),
            RiskLevel.ELEVATED => (DecisionKind.REQUIRE_OWNER_CONFIRMATION, ProposedAction.REQUEST_D1_VISUAL_CHECK, true),
            RiskLevel.UNKNOWN => (DecisionKind.SAFE_DEGRADED, ProposedAction.NONE, false),
            RiskLevel.GUARDED => (DecisionKind.MONITOR, ProposedAction.NONE, false),
            _ => (DecisionKind.MONITOR, ProposedAction.NONE, false)
        };

        if (d2.Length == 0 && (action is ProposedAction.ISOLATE_FILE_REVIEW or ProposedAction.RUN_DEFENDER_SCAN))
        {
            kind = DecisionKind.SAFE_DEGRADED; action = ProposedAction.NONE; approval = false;
        }

        var refs = evidence.SelectMany(x => x.EvidenceRefs ?? []).Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.Ordinal).Take(64).ToArray();
        var explanation = Explain(risk, kind, d1.Length, d2.Length, d1Abnormal, d1Unknown, degraded);
        return new(correlationId, risk, kind, action, explanation, reasons.Order(StringComparer.Ordinal).ToArray(),
            refs, approval, true, DateTimeOffset.UtcNow);
    }

    public static DecisionEvidence FromEnvelope(DaemonEnvelope envelope)
    {
        var payload = envelope.Payload;
        var severity = ReadString(payload, "severity") ?? ReadString(payload, "severityBand") ?? "UNKNOWN";
        var confidence = ReadDouble(payload, "confidence");
        var reason = SafeCode(ReadString(payload, "reasonCode") ?? ReadString(payload, "findingCode")
            ?? (envelope.MessageType == "THREAT_FINDING" ? ReadString(payload, "ruleId") : null));
        var observedAt = envelope.TimestampUtc;
        if (envelope.MessageType == "BEHAVIOR_DEVIATION")
        {
            var assessment = ReadString(payload, "operatorAssessment");
            var deviation = ReadDouble(payload, "deviationPercent");
            if (assessment == "BEHAVIOR_DIFFERENT" || deviation > 60) { severity = "HIGH"; reason ??= "BEHAVIOR_DIVERGENCE_OVER_60"; }
            else if (assessment == "INCONCLUSIVE") { severity = "UNKNOWN"; reason ??= "BEHAVIOR_INCONCLUSIVE"; }
            else severity = "LOW";
        }
        if (envelope.MessageType is "USER_CONTEXT" or "BEHAVIOR_DEVIATION")
        {
            var applicationContext = ReadNestedObject(payload, "applicationContext")
                ?? (ReadNestedObject(payload, "signals") is { } signals ? ReadNestedObject(signals, "applicationContext") : null);
            var familiar = applicationContext is { } context && IsFreshFamiliarApplicationContext(context);
            var contextReason = applicationContext is { } app ? SafeCode(ReadString(app, "reasonCode")) : null;
            if (familiar) reason = "APPLICATION_AND_HOUR_SEEN_IN_PROFILE";
            else if (reason is null && contextReason is not null)
                reason = contextReason == "APPLICATION_AND_HOUR_SEEN_IN_PROFILE" ? "D1_APPLICATION_CONTEXT_STALE_OR_UNVERIFIED" : contextReason;
        }
        if (envelope.MessageType == "CONTEXT_RESPONSE" && envelope.SourceDaemon == DaemonNames.HumanBehaviorMonitor)
        {
            var applicationContext = ReadNestedObject(payload, "applicationContext");
            var familiar = applicationContext is { } context && IsFreshFamiliarApplicationContext(context);
            var contextReason = SafeCode(applicationContext is { } app ? ReadString(app, "reasonCode") : null)
                ?? SafeCode(ReadString(payload, "reasonCode"));
            reason = familiar ? "APPLICATION_AND_HOUR_SEEN_IN_PROFILE"
                : contextReason == "APPLICATION_AND_HOUR_SEEN_IN_PROFILE" ? "D1_APPLICATION_CONTEXT_STALE_OR_UNVERIFIED"
                : contextReason ?? "D1_CONTEXT_RECEIVED";
            severity = familiar ? "LOW" : "UNKNOWN";
        }
        string? contextSummary = null;
        if (envelope.MessageType == "CONTEXT_RESPONSE" && envelope.SourceDaemon == DaemonNames.ThreatMonitor)
        {
            var found = ReadBool(payload, "found") == true;
            var findings = payload.TryGetProperty("findings", out var contextFindings) && contextFindings.ValueKind == JsonValueKind.Array
                ? contextFindings.EnumerateArray().Take(10).ToArray() : [];
            if (!found || findings.Length == 0) contextSummary = "D2 supplied 0 matching threat findings for this case.";
            else
            {
                var details = findings.Select(item =>
                {
                    var findingId = SafeCode(ReadString(item, "findingId")) ?? "finding";
                    var rule = ReadNestedObject(item, "ruleDetails");
                    if (rule is null) return findingId;
                    var ruleId = SafeCode(ReadString(rule.Value, "ruleId")) ?? "rule";
                    var severity = SafeCategory(ReadString(rule.Value, "severity"), "low", "medium", "high", "critical") ;
                    var confidence = ReadDouble(rule.Value, "confidence");
                    return $"{findingId}:{ruleId}/{severity}" + (confidence is { } score ? $"/{score:F2}" : string.Empty);
                }).ToArray();
                contextSummary = $"D2 supplied {details.Length} matching threat finding(s): {string.Join(", ", details)}.";
            }
            reason = found ? "D2_THREAT_CONTEXT_FOUND" : "D2_THREAT_CONTEXT_EMPTY";
            severity = "UNKNOWN";
            var contextObservedAt = ReadDateTime(payload, "observedAtUtc");
            if (contextObservedAt is { } at) observedAt = at;
        }
        if (envelope.MessageType == "TELEMETRY_GAP") { severity = "UNKNOWN"; reason ??= "TELEMETRY_GAP"; }
        var refs = new List<string>();
        if (payload.TryGetProperty("evidenceRefs", out var evidence) && evidence.ValueKind == JsonValueKind.Array)
            refs.AddRange(evidence.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).Where(IsSafeToken).Take(64));
        if (payload.TryGetProperty("evidenceRef", out var single) && single.ValueKind == JsonValueKind.String && single.GetString() is { } one && IsSafeToken(one)) refs.Add(one);
        if (envelope.MessageType == "VISUAL_IDENTITY_RESPONSE")
        {
            var status = ReadString(payload, "status")?.ToUpperInvariant();
            var liveness = ReadString(payload, "liveness")?.ToUpperInvariant();
            var profileId = ReadString(payload, "profileId");
            var visualRef = ReadString(payload, "evidenceRef");
            var faceQuality = ReadDouble(payload, "faceQuality");
            var validFrames = ReadInt(payload, "validFrames");
            reason = status == "MATCH" && liveness == "LIVE" && !string.IsNullOrWhiteSpace(profileId)
                && IsSafeToken(visualRef) && faceQuality is > 0 and <= 1 && validFrames >= 3
                ? "OWNER_VISUALLY_CONFIRMED_LIVE"
                : SafeCode(ReadString(payload, "reasonCode")) ?? "VISUAL_IDENTITY_RESULT";
            severity = status switch
            {
                "MATCH" when liveness == "LIVE" => "LOW",
                "NO_MATCH" => "HIGH",
                _ => "UNKNOWN"
            };
            confidence = ReadDouble(payload, "similarity");
            if (IsSafeToken(visualRef)) refs.Add(visualRef!);
        }
        if (envelope.MessageType == "VISUAL_IDENTITY_RESPONSE")
            observedAt = ReadDateTime(payload, "observedAtUtc") ?? envelope.TimestampUtc;
        var aiFacts = BuildAiFacts(envelope, payload);
        return new(envelope.SourceDaemon, envelope.MessageType, severity.ToUpperInvariant(), confidence, reason,
            refs.Distinct(StringComparer.Ordinal).ToArray(), observedAt, ReadBool(payload, "synthetic") == true, contextSummary, aiFacts);
    }

    private static IReadOnlyList<string> BuildAiFacts(DaemonEnvelope envelope, JsonElement payload)
    {
        var facts = new List<string>(16);
        void Add(string key, string? value)
        {
            if (value is not null && facts.Count < 16 && value.Length <= 64
                && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or '=' or ':' or '%' or ','))
                facts.Add($"{key}={value}");
        }
        void AddBand(string key, double? value, double low, double high)
            => Add(key, value is null || !double.IsFinite(value.Value) ? null : value.Value < low ? "low" : value.Value < high ? "medium" : "high");
        void AddFlag(string key, bool? value) => Add(key, value is null ? null : value.Value ? "yes" : "no");
        void AddCategories(string key, JsonElement parent, string property, int take = 5)
        {
            if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array) return;
            var values = array.EnumerateArray().Take(take).Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => SafeCode(x.GetString())).Where(x => x is not null).Cast<string>().Distinct(StringComparer.Ordinal).ToArray();
            if (values.Length > 0) Add(key, string.Join(',', values));
        }

        if (envelope.SourceDaemon == DaemonNames.HumanBehaviorMonitor)
        {
            var signals = ReadNestedObject(payload, "signals");
            Add("behaviorAssessment", SafeCategory(ReadString(payload, "operatorAssessment"), "OWNER_CONSISTENT", "BEHAVIOR_DIFFERENT", "INCONCLUSIVE"));
            AddBand("behaviorDeviation", ReadDouble(payload, "deviationPercent"), 20, 60);
            AddBand("confidence", ReadDouble(payload, "confidence"), 0.4, 0.75);
            Add("inputOrigin", SafeCategory(signals is { } so ? ReadString(so, "inputOrigin")?.ToUpperInvariant() : null,
                "HUMAN", "AUTOMATION", "SCRIPT", "UNKNOWN"));
            if (signals is { } sig)
            {
                AddBand("keyboardDeviation", ReadDouble(sig, "keyboardDeviationPercent"), 20, 60);
                AddBand("mouseDeviation", ReadDouble(sig, "mouseDeviationPercent"), 20, 60);
                var keyFeatures = ReadInt(sig, "keyboardFeatureCount");
                var mouseFeatures = ReadInt(sig, "mouseFeatureCount");
                var featureTotal = (keyFeatures ?? 0) + (mouseFeatures ?? 0);
                Add("behaviorFeatureCoverage", featureTotal >= 8 ? "full" : featureTotal >= 4 ? "partial" : "low");
            }
            var app = ReadNestedObject(payload, "applicationContext")
                ?? (signals is { } nested ? ReadNestedObject(nested, "applicationContext") : null);
            if (app is { } context)
            {
                Add("foregroundApp", SafeAppLabel(ReadString(context, "foregroundApplication")));
                AddFlag("seenInLearnedHistory", ReadBool(context, "seenInLearnedHistory"));
                AddFlag("hourCommonForApp", ReadBool(context, "hourCommonForApplication"));
                var hour = ReadInt(context, "localHour");
                Add("localTimeBand", hour is >= 0 and < 6 ? "night" : hour is >= 6 and < 12 ? "morning" : hour is >= 12 and < 18 ? "afternoon" : hour is >= 18 and < 24 ? "evening" : null);
                var day = ReadInt(context, "localDayOfWeek");
                Add("weekday", day is >= 0 and <= 6 ? ((DayOfWeek)day.Value).ToString().ToLowerInvariant() : null);
                var foregroundSeconds = ReadInt(context, "foregroundSeconds");
                Add("foregroundDuration", foregroundSeconds is null ? null : foregroundSeconds < 30 ? "brief" : foregroundSeconds < 300 ? "minutes" : "long");
                AddBand("cpuLoad", ReadDouble(context, "cpuPercent"), 35, 75);
                AddBand("systemMemoryLoad", ReadDouble(context, "systemMemoryUsedPercent"), 60, 85);
                AddBand("appMemory", ReadDouble(context, "memoryMiB"), 512, 2048);
                var samples = ReadInt(context, "sampleCount");
                Add("profileContextMaturity", samples is null ? null : samples < 10 ? "low" : samples < 50 ? "medium" : "high");
            }
        }
        else if (envelope.SourceDaemon == DaemonNames.ThreatMonitor)
        {
            Add("rule", SafeCode(ReadString(payload, "ruleId")));
            Add("ruleSeverity", SafeCategory(ReadString(payload, "severity")?.ToUpperInvariant(), "LOW", "MEDIUM", "HIGH", "CRITICAL"));
            AddBand("ruleConfidence", ReadDouble(payload, "confidence"), 0.4, 0.75);
            AddCategories("missingTelemetry", payload, "missingTelemetry");
            AddCategories("missingFields", payload, "missingFields");
            AddCategories("evidenceKinds", payload, "evidenceKinds");
            AddFactNames(payload, "facts");
            if (payload.TryGetProperty("findings", out var findings) && findings.ValueKind == JsonValueKind.Array)
            {
                foreach (var finding in findings.EnumerateArray().Take(6))
                {
                    var details = ReadNestedObject(finding, "ruleDetails");
                    if (details is not { } detail) continue;
                    Add("detailRule", SafeCode(ReadString(detail, "ruleId")));
                    Add("detailSeverity", SafeCategory(ReadString(detail, "severity")?.ToUpperInvariant(), "LOW", "MEDIUM", "HIGH", "CRITICAL"));
                    AddBand("detailConfidence", ReadDouble(detail, "confidence"), 0.4, 0.75);
                    AddCategories("detailEvidenceKinds", finding, "evidenceKinds");
                    AddCategories("detailMissingTelemetry", finding, "missingTelemetry");
                    AddFactNames(detail, "facts");
                }
            }
        }
        return facts.Distinct(StringComparer.Ordinal).Take(16).ToArray();

        void AddFactNames(JsonElement parent, string property)
        {
            if (!parent.TryGetProperty(property, out var array) || array.ValueKind != JsonValueKind.Array) return;
            foreach (var fact in array.EnumerateArray().Take(8))
            {
                var name = SafeCode(ReadString(fact, "name"));
                var value = SafeCategory(ReadString(fact, "value"), "observed", "synthetic", "unknown");
                if (name is not null && value != "unknown") Add("evidence_" + name, value);
            }
        }
    }

    private static string? SafeAppLabel(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var leaf = value.Replace('\\', '/').Split('/').LastOrDefault()?.Trim();
        if (string.IsNullOrWhiteSpace(leaf) || leaf.Length > 48 || leaf is "." or ".."
            || leaf.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))) return null;
        return leaf;
    }

    private static RiskLevel Severity(string value) => value.ToUpperInvariant() switch
    {
        "LOW" or "INFO" => RiskLevel.LOW,
        "GUARDED" => RiskLevel.GUARDED,
        "MEDIUM" or "MODERATE" => RiskLevel.GUARDED,
        "ELEVATED" => RiskLevel.ELEVATED,
        "HIGH" => RiskLevel.HIGH,
        "CRITICAL" => RiskLevel.CRITICAL,
        _ => RiskLevel.UNKNOWN
    };

    private static RiskLevel Raise(RiskLevel current, RiskLevel floor)
        => current == RiskLevel.UNKNOWN || current < floor ? floor : current;

    private static RiskLevel LowerOneLevel(RiskLevel current) => current switch
    {
        RiskLevel.CRITICAL => RiskLevel.HIGH,
        RiskLevel.HIGH => RiskLevel.ELEVATED,
        RiskLevel.ELEVATED => RiskLevel.GUARDED,
        RiskLevel.GUARDED => RiskLevel.LOW,
        _ => current
    };

    private static string? ReadString(JsonElement value, string name)
        => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String ? element.GetString() : null;

    private static JsonElement? ReadNestedObject(JsonElement value, string name)
        => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.Object ? element : null;

    private static double? ReadDouble(JsonElement value, string name)
        => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var element)
            && element.ValueKind == JsonValueKind.Number && element.TryGetDouble(out var result) && double.IsFinite(result) ? result : null;

    private static bool? ReadBool(JsonElement value, string name)
        => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var element)
            && element.ValueKind is JsonValueKind.True or JsonValueKind.False ? element.GetBoolean() : null;

    private static int? ReadInt(JsonElement value, string name)
        => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var element)
            && element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var result) ? result : null;

    private static DateTimeOffset? ReadDateTime(JsonElement value, string name)
        => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var element)
            && element.ValueKind == JsonValueKind.String && element.TryGetDateTimeOffset(out var result) ? result : null;

    private static bool IsFreshFamiliarApplicationContext(JsonElement context)
    {
        var observedAt = ReadDateTime(context, "observedAtUtc");
        var ageSeconds = ReadInt(context, "ageSeconds");
        var age = observedAt is { } at ? DateTimeOffset.UtcNow - at : TimeSpan.MaxValue;
        return ReadBool(context, "seenInLearnedHistory") == true
            && ReadBool(context, "hourCommonForApplication") == true
            && IsSafeToken(ReadString(context, "profileId"))
            && ageSeconds is >= 0 and <= 120
            && age >= TimeSpan.Zero && age <= TimeSpan.FromMinutes(2);
    }

    private static string? SafeCode(string? value)
        => IsSafeToken(value) ? value : null;

    private static string SafeCategory(string? value, params string[] allowed)
        => value is not null && allowed.Contains(value, StringComparer.Ordinal) ? value : "unknown";

    private static bool IsSafeToken(string? value)
        => !string.IsNullOrWhiteSpace(value) && value.Length <= 96
            && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':');

    private static string Explain(RiskLevel risk, DecisionKind decision, int d1, int d2, bool abnormal, bool uncertain, bool degraded)
    {
        var context = $"{d1} signal(aux) comportemental(aux) et {d2} signal(aux) technique(s) ont été pris en compte.";
        var rationale = abnormal ? "L’écart comportemental renforce le niveau de vigilance." : uncertain ? "L’identité ou le comportement reste incertain." : "Aucun écart comportemental confirmé n’a été utilisé pour réduire l’alerte technique.";
        var health = degraded ? " Un démon est indisponible ou dégradé, donc le résultat reste prudent." : string.Empty;
        return $"Risque {risk}. {context} {rationale}{health} Décision : {decision}. Toute action réelle reste à confirmer par une politique et ses autorisations.";
    }
}

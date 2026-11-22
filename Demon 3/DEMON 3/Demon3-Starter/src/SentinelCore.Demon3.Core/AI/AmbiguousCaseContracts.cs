namespace SentinelCore.Demon3.Core.AI;

public enum AdvisorStatus { Advised, Unavailable, InvalidInput, InvalidResponse }
public enum AdviceRiskBand { LOW, GUARDED, ELEVATED, HIGH, CRITICAL, UNCERTAIN }
public enum SuggestedMeasure { CONTINUE_MONITORING, REQUEST_D1_CONTEXT, REQUEST_OWNER_CONFIRMATION, RUN_DEFENDER_QUICK_SCAN, CONTAINMENT_REVIEW, CAPABILITY_GAP, NO_RECOMMENDATION }
public enum ContextRequestKind { D1_SESSION_CONTEXT, D2_THREAT_DETAILS, D1_VISUAL_IDENTITY }

/// <summary>Minimized summaries only. Never put keystrokes, passwords, face images or raw process paths here.</summary>
public sealed record SecuritySignalSummary(
    string SourceDaemon,
    string MessageType,
    string SeverityBand,
    double? Confidence,
    string Summary,
    IReadOnlyList<string> EvidenceRefs,
    IReadOnlyList<string>? Facts = null,
    DateTimeOffset? ObservedAtUtc = null);

public sealed record AmbiguousSecurityCase(
    string CorrelationId,
    IReadOnlyList<SecuritySignalSummary> Signals,
    IReadOnlyList<ContextRequestKind> AllowedContextRequests,
    string? PreviousAssessment = null,
    int Turn = 1);

public sealed record RiskAdvice(
    AdviceRiskBand RiskBand,
    double Confidence,
    string Assessment,
    IReadOnlyList<string> KeyFindings,
    IReadOnlyList<string> BenignExplanations,
    IReadOnlyList<string> ThreatHypotheses,
    IReadOnlyList<string> Uncertainties,
    IReadOnlyList<ContextRequestKind> RequestedContext,
    SuggestedMeasure SuggestedMeasure,
    string Rationale,
    IReadOnlyList<string> EvidenceRefs,
    string Summary = "",
    string? CapabilityGap = null,
    string? PlaybookDraft = null);

public sealed record AdvisorOutcome(
    AdvisorStatus Status,
    RiskAdvice? Advice,
    string Model,
    string? ErrorCode,
    DateTimeOffset CompletedAtUtc,
    double? DurationMilliseconds = null)
{
    public static AdvisorOutcome Failure(AdvisorStatus status, string model, string errorCode)
        => new(status, null, model, errorCode, DateTimeOffset.UtcNow);
}

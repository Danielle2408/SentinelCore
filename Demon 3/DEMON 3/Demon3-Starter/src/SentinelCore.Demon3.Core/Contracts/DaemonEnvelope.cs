using System.Text.Json;

namespace SentinelCore.Demon3.Core.Contracts;

public static class DaemonNames
{
    public const string HumanBehaviorMonitor = "HumanBehaviorMonitor";
    public const string ThreatMonitor = "ThreatMonitor";
    public const string RiskResponseGuard = "RiskResponseGuard";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        HumanBehaviorMonitor, ThreatMonitor, RiskResponseGuard
    };
}

public static class MessageTypes
{
    public static readonly IReadOnlySet<string> V1 = new HashSet<string>(StringComparer.Ordinal)
    {
        "HELLO", "WELCOME", "HEARTBEAT", "USER_CONTEXT", "BEHAVIOR_DEVIATION",
        "THREAT_FINDING", "TELEMETRY_GAP", "SESSION_CONTEXT_REQUEST",
        "SESSION_CONTEXT_RESPONSE", "CONTEXT_REQUEST", "CONTEXT_RESPONSE",
        "MASTER_AUTH_REQUIRED", "MASTER_AUTH_RESULT", "ACTION_REQUEST", "ACTION_RESULT",
        "VISUAL_IDENTITY_REQUEST", "VISUAL_IDENTITY_RESPONSE", "VISUAL_EVIDENCE_READ_REQUEST",
        "VISUAL_EVIDENCE_CHUNK", "ACK"
    };
}

/// <summary>V1 wire envelope. Payload remains JSON so each message type can evolve under schema control.</summary>
public sealed record DaemonEnvelope
{
    public required Guid MessageId { get; init; }
    public required string CorrelationId { get; init; }
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string SourceDaemon { get; init; }
    public required string Destination { get; init; }
    public required string MessageType { get; init; }
    public required int SchemaVersion { get; init; }
    public required DateTimeOffset ExpiresAtUtc { get; init; }
    public required JsonElement Payload { get; init; }
}

public enum AckStatus { Accepted, Rejected, Duplicate }

public sealed record AckMessage(Guid MessageId, AckStatus Status, string? Reason = null);

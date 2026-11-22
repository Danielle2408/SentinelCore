using SentinelCore.Demon3.Core.Contracts;

namespace SentinelCore.Demon3.Core.Validation;

public sealed record ValidationResult(bool IsValid, string? Error)
{
    public static ValidationResult Success() => new(true, null);
    public static ValidationResult Failure(string error) => new(false, error);
}

public sealed class EnvelopeValidator(TimeProvider? timeProvider = null)
{
    public const int MaxMessageBytes = 64 * 1024;
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public ValidationResult Validate(DaemonEnvelope? message, int serializedByteCount)
    {
        if (message is null) return ValidationResult.Failure("Message is null.");
        if (serializedByteCount <= 0 || serializedByteCount > MaxMessageBytes)
            return ValidationResult.Failure("Message size is outside the V1 limit (1..65536 bytes).");
        if (message.MessageId == Guid.Empty) return ValidationResult.Failure("messageId must be a non-empty UUID.");
        if (string.IsNullOrWhiteSpace(message.CorrelationId) || message.CorrelationId.Length > 128)
            return ValidationResult.Failure("correlationId is required and must not exceed 128 characters.");
        if (message.TimestampUtc.Offset != TimeSpan.Zero || message.ExpiresAtUtc.Offset != TimeSpan.Zero)
            return ValidationResult.Failure("Timestamps must be UTC (zero offset).");
        if (message.SchemaVersion != 1) return ValidationResult.Failure("Unsupported schemaVersion.");
        if (!DaemonNames.All.Contains(message.SourceDaemon)) return ValidationResult.Failure("Unknown sourceDaemon.");
        if (!DaemonNames.All.Contains(message.Destination)) return ValidationResult.Failure("Unknown destination.");
        if (!MessageTypes.V1.Contains(message.MessageType)) return ValidationResult.Failure("Unknown messageType.");
        if (message.ExpiresAtUtc <= _clock.GetUtcNow()) return ValidationResult.Failure("Message expired.");
        if (message.ExpiresAtUtc <= message.TimestampUtc) return ValidationResult.Failure("expiresAtUtc must be after timestampUtc.");
        if (message.Payload.ValueKind != System.Text.Json.JsonValueKind.Object)
            return ValidationResult.Failure("payload must be a JSON object.");

        if (message.MessageType is "ACTION_REQUEST" or "ACTION_RESULT")
            return ValidationResult.Failure($"{message.MessageType} is internal-only and cannot be accepted over inter-daemon transport.");
        if (!IsAllowedDirection(message.SourceDaemon, message.Destination, message.MessageType))
            return ValidationResult.Failure("Message type is not allowed for this source and destination in V1.");
        return ValidationResult.Success();
    }

    private static bool IsAllowedDirection(string source, string destination, string type)
    {
        if (source == DaemonNames.RiskResponseGuard)
            return destination switch
            {
                DaemonNames.HumanBehaviorMonitor => type is "WELCOME" or "CONTEXT_REQUEST" or "VISUAL_IDENTITY_REQUEST" or "VISUAL_EVIDENCE_READ_REQUEST" or "MASTER_AUTH_REQUIRED",
                DaemonNames.ThreatMonitor => type is "WELCOME" or "ACK" or "CONTEXT_REQUEST" or "SESSION_CONTEXT_RESPONSE",
                _ => false
            };

        if (destination != DaemonNames.RiskResponseGuard) return false;
        return source switch
        {
            DaemonNames.HumanBehaviorMonitor => type is "HELLO" or "HEARTBEAT" or "USER_CONTEXT" or "BEHAVIOR_DEVIATION"
                or "CONTEXT_RESPONSE" or "MASTER_AUTH_RESULT"
                or "VISUAL_IDENTITY_RESPONSE" or "VISUAL_EVIDENCE_CHUNK",
            DaemonNames.ThreatMonitor => type is "HELLO" or "HEARTBEAT" or "THREAT_FINDING" or "TELEMETRY_GAP"
                or "SESSION_CONTEXT_REQUEST" or "CONTEXT_RESPONSE",
            _ => false
        };
    }
}

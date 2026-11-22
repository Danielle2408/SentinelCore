using System.Text.Json;
using SentinelCore.Demon1.VisualVerification;

namespace SentinelCore.Demon1.Learning.Controller;

/// <summary>
/// D1's background-only request router. Dependencies are injected so protocol behavior can be
/// exercised with mock camera/auth services; production never grants approval without a dialog.
/// </summary>
internal sealed class Demon1BackgroundRequestProcessor(
    Func<string, string, object, DateTimeOffset, Task> send,
    Func<string?, object> createContextResponse,
    Func<VisualIdentityRequest, CancellationToken, Task<VisualIdentityResponse>> verifyVisual,
    Func<VisualEvidenceReadRequest, VisualEvidenceChunk?> readEvidence,
    Func<string, string, DateTimeOffset, CancellationToken, Task<bool>> requestOwnerApproval)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task HandleAsync(InterDaemonEnvelope message, CancellationToken cancellationToken = default)
    {
        try
        {
            switch (message.MessageType)
            {
                case "CONTEXT_REQUEST":
                {
                    var requestedProfile = message.Payload.ValueKind == JsonValueKind.Object
                        && message.Payload.TryGetProperty("profileId", out var profile)
                        && profile.ValueKind == JsonValueKind.String ? profile.GetString() : null;
                    await send("CONTEXT_RESPONSE", message.CorrelationId, createContextResponse(requestedProfile), ReplyExpiry()).ConfigureAwait(false);
                    break;
                }
                case "VISUAL_IDENTITY_REQUEST":
                {
                    var request = message.Payload.Deserialize<VisualIdentityRequest>(JsonOptions);
                    VisualIdentityResponse response;
                    if (request is null || !StringComparer.Ordinal.Equals(request.CorrelationId, message.CorrelationId)
                        || request.DeadlineUtc > message.ExpiresAtUtc)
                    {
                        response = Inconclusive(message.CorrelationId, "D1_VISUAL_REQUEST_INVALID");
                    }
                    else
                    {
                        try
                        {
                            response = await verifyVisual(request, cancellationToken).ConfigureAwait(false);
                            if (!StringComparer.Ordinal.Equals(response.CorrelationId, message.CorrelationId))
                                response = Inconclusive(message.CorrelationId, "D1_VISUAL_CORRELATION_MISMATCH");
                        }
                        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                        {
                            response = Inconclusive(message.CorrelationId, "D1_BROKER_STOPPING");
                        }
                        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                        {
                            response = Inconclusive(message.CorrelationId, "D1_VISUAL_HANDLER_ERROR_" + ex.GetType().Name.ToUpperInvariant());
                        }
                    }
                    await send("VISUAL_IDENTITY_RESPONSE", message.CorrelationId, response, ReplyExpiry()).ConfigureAwait(false);
                    break;
                }
                case "VISUAL_EVIDENCE_READ_REQUEST":
                {
                    var request = message.Payload.Deserialize<VisualEvidenceReadRequest>(JsonOptions);
                    var chunk = request is null ? null : readEvidence(request);
                    chunk ??= new VisualEvidenceChunk(request?.EvidenceRef ?? "", Math.Max(0, request?.Offset ?? 0), 0, string.Empty, true);
                    await send("VISUAL_EVIDENCE_CHUNK", message.CorrelationId, chunk, ReplyExpiry()).ConfigureAwait(false);
                    break;
                }
                case "MASTER_AUTH_REQUIRED":
                {
                    var payload = message.Payload;
                    var challengeId = ReadString(payload, "challengeId");
                    var actionId = ReadString(payload, "actionId");
                    var deadline = ReadDate(payload, "deadlineUtc");
                    var valid = challengeId is { Length: > 0 and <= 96 }
                        && actionId == "RUN_DEFENDER_SCAN"
                        && deadline > DateTimeOffset.UtcNow
                        && deadline <= DateTimeOffset.UtcNow.AddMinutes(2);
                    var approved = valid && await requestOwnerApproval(challengeId!, actionId!, deadline, cancellationToken).ConfigureAwait(false);
                    var payloadResult = new
                    {
                        challengeId = challengeId ?? "invalid-challenge",
                        actionId = actionId ?? "UNKNOWN",
                        approved,
                        verifiedAtUtc = approved ? DateTimeOffset.UtcNow : (DateTimeOffset?)null,
                        reasonCode = approved ? "OWNER_MASTER_PASSWORD_CONFIRMED"
                            : valid ? "OWNER_DENIED_OR_AUTHENTICATION_FAILED" : "MASTER_AUTH_REQUEST_INVALID_OR_EXPIRED"
                    };
                    await send("MASTER_AUTH_RESULT", message.CorrelationId, payloadResult, ReplyExpiry()).ConfigureAwait(false);
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or ArgumentException)
        {
            if (message.MessageType == "VISUAL_IDENTITY_REQUEST")
                await send("VISUAL_IDENTITY_RESPONSE", message.CorrelationId,
                    Inconclusive(message.CorrelationId, "D1_VISUAL_REQUEST_INVALID"), ReplyExpiry()).ConfigureAwait(false);
        }
    }

    private static VisualIdentityResponse Inconclusive(string correlationId, string reason)
        => new(correlationId, "INDETERMINATE", null, "INDETERMINATE", null, 0, 0, null, DateTimeOffset.UtcNow, reason);

    private static DateTimeOffset ReplyExpiry() => DateTimeOffset.UtcNow.AddSeconds(30);

    private static string? ReadString(JsonElement payload, string name)
        => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static DateTimeOffset ReadDate(JsonElement payload, string name)
        => payload.ValueKind == JsonValueKind.Object && payload.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String && value.TryGetDateTimeOffset(out var parsed)
            ? parsed : DateTimeOffset.MinValue;
}

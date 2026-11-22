using System.Text.Json.Serialization;

namespace SentinelCore.Demon1.VisualVerification;

/// <summary>Typed payloads for the message envelopes owned and transported by Demon 3.</summary>
public sealed record VisualIdentityRequest(
    [property: JsonPropertyName("correlationId")] string CorrelationId,
    [property: JsonPropertyName("purpose")] string Purpose,
    [property: JsonPropertyName("requestedAtUtc")] DateTimeOffset RequestedAtUtc,
    [property: JsonPropertyName("deadlineUtc")] DateTimeOffset DeadlineUtc,
    [property: JsonPropertyName("requiredLiveness")] bool RequiredLiveness = true);

public sealed record VisualIdentityResponse(
    [property: JsonPropertyName("correlationId")] string CorrelationId,
    [property: JsonPropertyName("status")] string Status,
    [property: JsonPropertyName("profileId")] string? ProfileId,
    [property: JsonPropertyName("liveness")] string Liveness,
    [property: JsonPropertyName("similarity")] double? Similarity,
    [property: JsonPropertyName("faceQuality")] double FaceQuality,
    [property: JsonPropertyName("validFrames")] int ValidFrames,
    [property: JsonPropertyName("evidenceRef")] string? EvidenceRef,
    [property: JsonPropertyName("observedAtUtc")] DateTimeOffset ObservedAtUtc,
    [property: JsonPropertyName("reasonCode")] string ReasonCode);

public sealed record VisualEvidenceReadRequest(
    [property: JsonPropertyName("evidenceRef")] string EvidenceRef,
    [property: JsonPropertyName("offset")] int Offset,
    [property: JsonPropertyName("maxBytes")] int MaxBytes);

public sealed record VisualEvidenceChunk(
    [property: JsonPropertyName("evidenceRef")] string EvidenceRef,
    [property: JsonPropertyName("offset")] int Offset,
    [property: JsonPropertyName("totalBytes")] int TotalBytes,
    [property: JsonPropertyName("chunkBase64")] string ChunkBase64,
    [property: JsonPropertyName("isFinal")] bool IsFinal);

public interface IVisualIdentityVerifier
{
    Task<VisualCheckResult> VerifyAlertAsync(string correlationId, CancellationToken cancellationToken = default);
    byte[]? ReadEvidence(string evidenceRef);
}

/// <summary>
/// D1-side request handler. The caller receives requests from D3's bus adapter; D1 does not
/// create a second pipe or make risk decisions. No prompt is shown for each configured alert.
/// </summary>
public sealed class Demon1VisualRequestHandler(IVisualIdentityVerifier verifier, Func<bool> isConfigured, VisualEvidenceReader? evidenceReader = null)
{
    private const int MaximumDeadlineSeconds = 60;
    private const int MaximumEvidenceChunkBytes = 24 * 1024;

    public async Task<VisualIdentityResponse> HandleAsync(VisualIdentityRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.CorrelationId) || request.CorrelationId.Length > 128)
            return Result(request.CorrelationId, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, "VISUAL_CORRELATION_ID_INVALID");
        if (request.Purpose is not ("ALERT" or "SUSPICION" or "REPORT"))
            return Result(request.CorrelationId, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, "VISUAL_REQUEST_PURPOSE_NOT_ALLOWED");
        if (!isConfigured()) return Result(request.CorrelationId, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, "VISUAL_VERIFICATION_NOT_CONFIGURED");
        var now = DateTimeOffset.UtcNow;
        if (request.RequestedAtUtc > now.AddSeconds(5) || request.DeadlineUtc <= request.RequestedAtUtc)
            return Result(request.CorrelationId, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, "VISUAL_REQUEST_TIMING_INVALID");
        if (request.DeadlineUtc <= now) return Result(request.CorrelationId, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, "VISUAL_REQUEST_EXPIRED");
        var remaining = request.DeadlineUtc - now;
        if (remaining > TimeSpan.FromSeconds(MaximumDeadlineSeconds)) remaining = TimeSpan.FromSeconds(MaximumDeadlineSeconds);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(remaining);
        var result = await verifier.VerifyAlertAsync(request.CorrelationId, deadline.Token).ConfigureAwait(false);
        if (!StringComparer.Ordinal.Equals(result.CorrelationId, request.CorrelationId))
            return Result(request.CorrelationId, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, "VISUAL_CORRELATION_MISMATCH");
        if (result.Match == VisualMatch.MATCH
            && (result.Liveness != LivenessResult.LIVE || string.IsNullOrWhiteSpace(result.ProfileId)))
            return Result(request.CorrelationId, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, "VISUAL_MATCH_INVARIANT_REJECTED");
        return new(result.CorrelationId, result.Match.ToString(), result.ProfileId, result.Liveness.ToString(), result.Similarity,
            result.FaceQuality, result.ValidFrames, string.IsNullOrWhiteSpace(result.EvidenceRef) ? null : result.EvidenceRef,
            result.CapturedAtUtc, result.ReasonCode);
    }

    /// <summary>Serves only an encrypted-at-rest evidence item previously issued by this D1 instance.</summary>
    public VisualEvidenceChunk? ReadEvidenceChunk(VisualEvidenceReadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Offset < 0 || request.MaxBytes is < 1 or > MaximumEvidenceChunkBytes) return null;
        var image = evidenceReader?.ReadEvidence(request.EvidenceRef) ?? verifier.ReadEvidence(request.EvidenceRef);
        if (image is null || request.Offset > image.Length) return null;
        var length = Math.Min(request.MaxBytes, image.Length - request.Offset);
        var data = image.AsSpan(request.Offset, length).ToArray();
        return new(request.EvidenceRef, request.Offset, image.Length, Convert.ToBase64String(data), request.Offset + length >= image.Length);
    }

    private static VisualIdentityResponse Result(string correlationId, VisualMatch match, LivenessResult live, string reason)
        => new(correlationId, match.ToString(), null, live.ToString(), null, 0, 0, null, DateTimeOffset.UtcNow, reason);
}

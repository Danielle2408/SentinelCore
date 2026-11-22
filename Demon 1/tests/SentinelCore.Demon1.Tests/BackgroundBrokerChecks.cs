using System.Text.Json;
using SentinelCore.Demon1.Learning.Controller;
using SentinelCore.Demon1.VisualVerification;

internal static class BackgroundBrokerChecks
{
    public static async Task RunAsync(Action<bool, string> check)
    {
        var sent = new List<(string Type, string Correlation, object Payload)>();
        var verifyCalls = 0;
        var approvalCalls = 0;
        var processor = new Demon1BackgroundRequestProcessor(
            (type, correlation, payload, _) =>
            {
                sent.Add((type, correlation, payload));
                return Task.CompletedTask;
            },
            profile => new { status = "AVAILABLE", requestedProfile = profile },
            (request, _) =>
            {
                verifyCalls++;
                return Task.FromResult(new VisualIdentityResponse(request.CorrelationId, "MATCH", "PROFIL_1", "LIVE",
                    .72, .84, 7, "evidence-1", DateTimeOffset.UtcNow, "PROFILE_MATCH_AND_LIVENESS_CONFIRMED"));
            },
            request => new VisualEvidenceChunk(request.EvidenceRef, request.Offset, 0, string.Empty, true),
            (_, _, deadline, _) =>
            {
                approvalCalls++;
                return Task.FromResult(deadline > DateTimeOffset.UtcNow);
            });

        var now = DateTimeOffset.UtcNow;
        await processor.HandleAsync(Envelope("CONTEXT_REQUEST", "context-1", new { profileId = "PROFIL_1" }, now));
        check(sent[^1].Type == "CONTEXT_RESPONSE" && sent[^1].Correlation == "context-1", "broker answers D3 context request with correlation preserved");
        check(JsonSerializer.Serialize(sent[^1].Payload).Contains("PROFIL_1", StringComparison.Ordinal), "broker uses requested configured profile context");

        await processor.HandleAsync(Envelope("VISUAL_IDENTITY_REQUEST", "visual-mismatch", new VisualIdentityRequest(
            "different-correlation", "ALERT", now, now.AddSeconds(30)), now));
        check(verifyCalls == 0 && ReadString(sent[^1].Payload, "reasonCode") == "D1_VISUAL_REQUEST_INVALID", "broker rejects visual correlation mismatch without camera call");

        await processor.HandleAsync(Envelope("VISUAL_IDENTITY_REQUEST", "visual-ok", new VisualIdentityRequest(
            "visual-ok", "ALERT", now, now.AddSeconds(30)), now));
        check(verifyCalls == 1 && ReadString(sent[^1].Payload, "status") == "MATCH", "broker delegates valid visual request and returns result");
        check(sent[^1].Correlation == "visual-ok", "visual response preserves D3 correlation id");

        await processor.HandleAsync(Envelope("VISUAL_EVIDENCE_READ_REQUEST", "evidence-1", new VisualEvidenceReadRequest("evidence-1", 0, 4096), now));
        check(sent[^1].Type == "VISUAL_EVIDENCE_CHUNK" && sent[^1].Correlation == "evidence-1", "broker routes encrypted evidence chunk requests");

        var validDeadline = DateTimeOffset.UtcNow.AddSeconds(20);
        await processor.HandleAsync(Envelope("MASTER_AUTH_REQUIRED", "approval-1", new
        {
            challengeId = "challenge-1", actionId = "RUN_DEFENDER_SCAN", deadlineUtc = validDeadline
        }, validDeadline));
        check(approvalCalls == 1 && ReadBoolean(sent[^1].Payload, "approved"), "broker asks owner before approved Defender action");

        await processor.HandleAsync(Envelope("MASTER_AUTH_REQUIRED", "approval-expired", new
        {
            challengeId = "challenge-expired", actionId = "RUN_DEFENDER_SCAN", deadlineUtc = DateTimeOffset.UtcNow.AddSeconds(-1)
        }, DateTimeOffset.UtcNow.AddSeconds(-1)));
        check(approvalCalls == 1 && !ReadBoolean(sent[^1].Payload, "approved"), "broker refuses expired owner approval without prompting");

        var beforeUnknown = sent.Count;
        await processor.HandleAsync(Envelope("UNKNOWN_MESSAGE", "unknown-1", new { ignored = true }, now));
        check(sent.Count == beforeUnknown, "broker ignores unsupported message types");
    }

    private static InterDaemonEnvelope Envelope(string type, string correlation, object payload, DateTimeOffset now)
        => new(Guid.NewGuid().ToString("D"), correlation, now, "RiskResponseGuard", "HumanBehaviorMonitor", type,
            1, now.AddMinutes(1), JsonSerializer.SerializeToElement(payload));

    private static string? ReadString(object payload, string name)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(payload));
        return document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private static bool ReadBoolean(object payload, string name)
    {
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(payload));
        return document.RootElement.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
    }
}

using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using SentinelCore.Demon3.Core.AI;
using SentinelCore.Demon3.Core.Actions;
using SentinelCore.Demon3.Core.Contracts;
using SentinelCore.Demon3.Core.Decision;
using SentinelCore.Demon3.Core.Reports;
using SentinelCore.Demon3.Core.Transport;

namespace SentinelCore.Demon3.Core.Runtime;

/// <summary>Runs the D3 receive, correlate, decide and report loop. System actions remain simulated.</summary>
public sealed class Demon3Host(NamedPipeInterDaemonServer bus, RiskDecisionEngine engine,
    RiskReportStore reports, IAmbiguousCaseAdvisor advisor, ActionCatalog actions, Demon3HostOptions? options = null,
    SessionActivityReportService? sessionActivityReports = null)
{
    private readonly Demon3HostOptions _options = (options ?? Demon3HostOptions.Default).Validate();
    private readonly ConcurrentDictionary<string, CaseBuffer> _cases = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _heartbeats = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _visualRequests = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _visualCompleted = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _contextRequests = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _d2ContextRequests = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SessionContextProjection> _d1SessionContexts = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<SessionContextProjection>> _d1SessionContextWaiters = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _d2SessionContextRelays = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, int> _aiTurns = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _aiAssessments = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _aiInFlight = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _pendingAiRefresh = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _contextCompleted = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _d2ContextCompleted = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, VisualTransfer> _visualTransfers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Task, byte> _aiJobs = new();
    private readonly ConcurrentDictionary<string, byte> _actionRequests = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, PendingOwnerApproval> _ownerApprovals = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Task, byte> _requestJobs = new();
    private readonly ConcurrentDictionary<Task, byte> _actionJobs = new();
    private readonly SemaphoreSlim _aiSlots = new(2, 2);

    public event Action<RiskReport>? ReportCreated;
    public event Action<string>? OperationalNotice;

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        bus.MessageRejected += OnInboundMessageRejected;
        using var periodicSnapshotStop = new CancellationTokenSource();
        Task? periodicSnapshotTask = null;
        var sessionStarted = false;
        try
        {
        await bus.StartAsync(cancellationToken).ConfigureAwait(false);
        if (sessionActivityReports is not null)
        {
            try
            {
                await sessionActivityReports.BeginSessionAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
                sessionStarted = true;
                periodicSnapshotTask = RunPeriodicActivitySnapshotsAsync(periodicSnapshotStop.Token);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                OperationalNotice?.Invoke($"Rapport de session indisponible au démarrage : {exception.GetType().Name}.");
            }
        }
        await foreach (var envelope in bus.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            if (envelope.MessageType is "HEARTBEAT" or "HELLO")
            {
                _heartbeats[envelope.SourceDaemon] = envelope.TimestampUtc;
                if (envelope.MessageType == "HEARTBEAT" && !IsSyntheticEnvelope(envelope)
                    && sessionActivityReports is not null)
                {
                    try { await sessionActivityReports.RecordHeartbeatAsync(envelope.SourceDaemon, envelope.TimestampUtc, cancellationToken).ConfigureAwait(false); }
                    catch (Exception exception) when (exception is not OperationCanceledException)
                    { OperationalNotice?.Invoke($"Battement de session non enregistré : {exception.GetType().Name}."); }
                }
                await bus.MarkProcessedAsync(envelope.MessageId, cancellationToken).ConfigureAwait(false);
                continue;
            }
            if (envelope.SourceDaemon == DaemonNames.ThreatMonitor && envelope.MessageType == "SESSION_CONTEXT_REQUEST")
            {
                TrackJob(_requestJobs, HandleD2SessionContextRequestAsync(envelope, cancellationToken));
                continue;
            }
            if (envelope.MessageType == "VISUAL_EVIDENCE_CHUNK")
            {
                await HandleVisualChunkAsync(envelope, cancellationToken).ConfigureAwait(false);
                await bus.MarkProcessedAsync(envelope.MessageId, cancellationToken).ConfigureAwait(false);
                continue;
            }
            if (envelope.MessageType == "MASTER_AUTH_RESULT" && envelope.SourceDaemon == DaemonNames.HumanBehaviorMonitor)
            {
                HandleOwnerApprovalResult(envelope);
                await bus.MarkProcessedAsync(envelope.MessageId, cancellationToken).ConfigureAwait(false);
                continue;
            }
            if (envelope.MessageType is not ("USER_CONTEXT" or "BEHAVIOR_DEVIATION" or "THREAT_FINDING" or "TELEMETRY_GAP" or "VISUAL_IDENTITY_RESPONSE" or "CONTEXT_RESPONSE"))
            {
                await bus.MarkProcessedAsync(envelope.MessageId, cancellationToken).ConfigureAwait(false);
                continue;
            }

            if (envelope.SourceDaemon == DaemonNames.HumanBehaviorMonitor)
            {
                if (envelope.MessageType == "CONTEXT_RESPONSE")
                {
                    CompleteRequest(_contextRequests, envelope.CorrelationId);
                    _contextCompleted.TryAdd(envelope.CorrelationId, 0);
                    var sessionContext = ReadD1SessionContext(envelope);
                    _d1SessionContexts[envelope.CorrelationId] = sessionContext;
                    if (_d1SessionContextWaiters.TryGetValue(envelope.CorrelationId, out var waiter))
                        waiter.TrySetResult(sessionContext);
                }
                if (envelope.MessageType == "VISUAL_IDENTITY_RESPONSE")
                {
                    _visualCompleted.TryAdd(envelope.CorrelationId, 0);
                    CompleteRequest(_visualRequests, envelope.CorrelationId);
                }
            }
            if (envelope.SourceDaemon == DaemonNames.ThreatMonitor && envelope.MessageType == "CONTEXT_RESPONSE")
            {
                CompleteRequest(_d2ContextRequests, envelope.CorrelationId);
                _d2ContextCompleted.TryAdd(envelope.CorrelationId, 0);
            }

            var item = RiskDecisionEngine.FromEnvelope(envelope);
            var buffer = _cases.GetOrAdd(envelope.CorrelationId, _ => new CaseBuffer(DateTimeOffset.UtcNow));
            buffer.Add(item);
            var related = buffer.Snapshot();
            var syntheticCase = related.Any(x => x.IsSynthetic);
            var degraded = IsDegraded(envelope.TimestampUtc);
            var decision = engine.Evaluate(envelope.CorrelationId, related, degraded);
            var savedReport = await reports.SaveAsync(decision, related, cancellationToken: cancellationToken).ConfigureAwait(false);
            if (!syntheticCase && sessionActivityReports is not null)
            {
                try
                {
                    await sessionActivityReports.RecordActivityAsync(item.SourceDaemon, item.MessageType, item.Severity,
                        item.ReasonCode, envelope.CorrelationId, item.ObservedAtUtc, cancellationToken).ConfigureAwait(false);
                    await sessionActivityReports.RecordDecisionAsync(decision.Risk.ToString(), decision.Decision.ToString(),
                        envelope.CorrelationId, decision.DecidedAtUtc, cancellationToken).ConfigureAwait(false);
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                { OperationalNotice?.Invoke($"Activité de session non enregistrée : {exception.GetType().Name}."); }
            }
            // The deterministic decision is durable before the D2 sender is told this delivery is complete.
            // Side effects and model calls start only after this idempotency checkpoint.
            await bus.MarkProcessedAsync(envelope.MessageId, cancellationToken).ConfigureAwait(false);
            ReportCreated?.Invoke(savedReport);
            // Deterministic evidence gathering does not depend on the model being available.
            // For real high-risk cases, ask D2 for its matching rule details and D1 for fresh
            // learned-session context plus visual identity. Synthetic fixtures never trigger sensors.
            if (!syntheticCase)
            {
                if (related.Any(x => x.SourceDaemon == DaemonNames.ThreatMonitor && x.MessageType == "THREAT_FINDING")
                    && !_d2ContextCompleted.ContainsKey(envelope.CorrelationId)
                    && _d2ContextRequests.TryAdd(envelope.CorrelationId, new CancellationTokenSource()))
                    await RequestD2ThreatDetailsAsync(envelope.CorrelationId, cancellationToken).ConfigureAwait(false);
                if (decision.Risk is RiskLevel.HIGH or RiskLevel.CRITICAL)
                {
                    if (!_contextCompleted.ContainsKey(envelope.CorrelationId)
                        && _contextRequests.TryAdd(envelope.CorrelationId, new CancellationTokenSource()))
                        await RequestSessionContextAsync(envelope.CorrelationId, cancellationToken).ConfigureAwait(false);
                    if (!_visualCompleted.ContainsKey(envelope.CorrelationId)
                        && _visualRequests.TryAdd(envelope.CorrelationId, new CancellationTokenSource()))
                        await RequestVisualCheckAsync(envelope.CorrelationId, cancellationToken).ConfigureAwait(false);
                }
            }
            var needsAi = ShouldAskAi(decision, related);
            TryStartAiAnalysis(envelope.CorrelationId, decision, related,
                envelope.MessageType is "CONTEXT_RESPONSE" or "VISUAL_IDENTITY_RESPONSE", cancellationToken);
            var actionKey = envelope.CorrelationId + "|" + decision.ProposedAction;
            var hardCritical = related.Any(x => x.SourceDaemon == DaemonNames.ThreatMonitor
                && x.MessageType == "THREAT_FINDING" && x.Severity == "CRITICAL");
            if ((!needsAi || hardCritical) && decision.ProposedAction != ProposedAction.NONE && _actionRequests.TryAdd(actionKey, 0))
                TrackJob(_actionJobs, ExecuteActionInBackgroundAsync(envelope.CorrelationId, decision, related, savedReport, cancellationToken));
            if (envelope.MessageType == "VISUAL_IDENTITY_RESPONSE"
                && envelope.Payload.TryGetProperty("evidenceRef", out var evidenceRefElement)
                && evidenceRefElement.ValueKind == JsonValueKind.String
                && evidenceRefElement.GetString() is { Length: > 0 and <= 96 } evidenceRef
                && _visualTransfers.TryAdd(envelope.CorrelationId, new VisualTransfer(evidenceRef)))
                await RequestVisualEvidenceChunkAsync(envelope.CorrelationId, evidenceRef, 0, cancellationToken).ConfigureAwait(false);
            RemoveExpiredCases();
        }
        }
        catch (ChannelClosedException) when (!cancellationToken.IsCancellationRequested)
        {
            await bus.Completion.ConfigureAwait(false);
            throw new InvalidOperationException("La boucle d’écoute Named Pipe D3 s’est terminée sans erreur signalée.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        finally
        {
        periodicSnapshotStop.Cancel();
        if (periodicSnapshotTask is not null)
        {
            try { await periodicSnapshotTask.ConfigureAwait(false); }
            catch (OperationCanceledException) when (periodicSnapshotStop.IsCancellationRequested) { }
        }
        if (sessionStarted && sessionActivityReports is not null)
        {
            var stopTrigger = cancellationToken.IsCancellationRequested ? "SESSION_END" : "D3_STOPPED";
            try { await sessionActivityReports.FinalizeSessionAsync(stopTrigger, CancellationToken.None).ConfigureAwait(false); }
            catch (Exception exception) { OperationalNotice?.Invoke($"Rapport final de session non enregistré : {exception.GetType().Name}."); }
        }
        bus.MessageRejected -= OnInboundMessageRejected;
        if (!_aiJobs.IsEmpty)
        {
            try { await Task.WhenAll(_aiJobs.Keys.ToArray()).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        }
        if (!_actionJobs.IsEmpty)
        {
            try { await Task.WhenAll(_actionJobs.Keys.ToArray()).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        }
        foreach (var transfer in _visualTransfers.Values) transfer.Dispose();
        _visualTransfers.Clear();
        CancelRequests(_contextRequests);
        CancelRequests(_d2ContextRequests);
        CancelRequests(_visualRequests);
        if (!_requestJobs.IsEmpty)
        {
            try { await Task.WhenAll(_requestJobs.Keys.ToArray()).ConfigureAwait(false); }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        }
        }
    }

    private async Task RunPeriodicActivitySnapshotsAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try { await sessionActivityReports!.CreateSnapshotAsync("PERIODIC", cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
                catch (Exception exception) { OperationalNotice?.Invoke($"Rapport périodique non enregistré : {exception.GetType().Name}."); }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
    }

    private static bool IsSyntheticEnvelope(DaemonEnvelope envelope)
        => envelope.Payload.ValueKind == JsonValueKind.Object
            && envelope.Payload.TryGetProperty("synthetic", out var synthetic)
            && synthetic.ValueKind == JsonValueKind.True;

    private void OnInboundMessageRejected(string notice) => OperationalNotice?.Invoke(notice);

    private async Task ExecuteActionInBackgroundAsync(string correlationId, RiskDecision decision,
        IReadOnlyList<DecisionEvidence> related, RiskReport report, CancellationToken token)
    {
        try
        {
            var synthetic = related.Any(x => x.IsSynthetic);
            var ownerApproved = false;
            if (!synthetic && decision.ProposedAction == ProposedAction.RUN_DEFENDER_SCAN && actions.RequiresOwnerApprovalForEnabledActions)
                ownerApproved = await RequestOwnerApprovalAsync(correlationId, decision.ProposedAction, token).ConfigureAwait(false);
            var result = await actions.ExecuteAsync(decision, related, token, forceSimulation: synthetic, ownerApproved: ownerApproved).ConfigureAwait(false);
            await reports.UpdateActionResultAsync(report.ReportId, result, token).ConfigureAwait(false);
            ReportCreated?.Invoke(report with { ActionResult = result, Decision = decision with { SimulationOnly = result.SimulationOnly } });
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception)
        {
            var failed = new ActionExecutionResult(decision.ProposedAction.ToString(), ActionExecutionStatus.FAILED,
                "Le catalogue de mesures a rencontré une erreur; aucune commande libre n’a été exécutée.",
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, true);
            await reports.UpdateActionResultAsync(report.ReportId, failed, token).ConfigureAwait(false);
        }
    }

    private async Task<bool> RequestOwnerApprovalAsync(string correlationId, ProposedAction action, CancellationToken token)
    {
        var challengeId = Guid.NewGuid().ToString("N");
        var requestedAt = DateTimeOffset.UtcNow;
        var deadline = requestedAt.AddSeconds(45);
        var pending = new PendingOwnerApproval(challengeId, action.ToString(), requestedAt, deadline);
        if (!_ownerApprovals.TryAdd(correlationId, pending)) return false;
        var request = new DaemonEnvelope
        {
            MessageId = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = requestedAt,
            SourceDaemon = DaemonNames.RiskResponseGuard, Destination = DaemonNames.HumanBehaviorMonitor,
            MessageType = "MASTER_AUTH_REQUIRED", SchemaVersion = 1, ExpiresAtUtc = deadline,
            Payload = JsonSerializer.SerializeToElement(new
            {
                challengeId, actionId = action.ToString(), requestedAtUtc = requestedAt,
                deadlineUtc = deadline, purpose = "AUTHORIZE_SECURITY_MEASURE"
            })
        };
        try
        {
            OperationalNotice?.Invoke($"D3 demande l’accord du propriétaire pour {action} ({correlationId}).");
            await bus.SendAsync(request, token).ConfigureAwait(false);
            return await pending.Completion.Task.WaitAsync(deadline - DateTimeOffset.UtcNow, token).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            OperationalNotice?.Invoke($"Aucun accord du propriétaire reçu à temps pour {action} ({correlationId}); mesure bloquée.");
            return false;
        }
        catch (IOException)
        {
            OperationalNotice?.Invoke($"D1 indisponible pour l’authentification du propriétaire; {action} bloquée.");
            return false;
        }
        finally { _ownerApprovals.TryRemove(new KeyValuePair<string, PendingOwnerApproval>(correlationId, pending)); }
    }

    private void HandleOwnerApprovalResult(DaemonEnvelope envelope)
    {
        if (!_ownerApprovals.TryGetValue(envelope.CorrelationId, out var pending))
        {
            OperationalNotice?.Invoke($"Réponse d’approbation D1 sans demande active ignorée ({envelope.CorrelationId}).");
            return;
        }
        var payload = envelope.Payload;
        var challenge = payload.TryGetProperty("challengeId", out var challengeElement) && challengeElement.ValueKind == JsonValueKind.String
            ? challengeElement.GetString() : null;
        var actionId = payload.TryGetProperty("actionId", out var actionElement) && actionElement.ValueKind == JsonValueKind.String
            ? actionElement.GetString() : null;
        var approved = payload.TryGetProperty("approved", out var approvedElement)
            && approvedElement.ValueKind is JsonValueKind.True or JsonValueKind.False && approvedElement.GetBoolean();
        var verifiedAt = payload.TryGetProperty("verifiedAtUtc", out var verifiedElement)
            && verifiedElement.ValueKind == JsonValueKind.String && verifiedElement.TryGetDateTimeOffset(out var parsedVerifiedAt)
            ? parsedVerifiedAt : (DateTimeOffset?)null;
        var valid = StringComparer.Ordinal.Equals(challenge, pending.ChallengeId)
            && StringComparer.Ordinal.Equals(actionId, pending.ActionId)
            && envelope.TimestampUtc <= pending.DeadlineUtc
            && DateTimeOffset.UtcNow <= pending.DeadlineUtc
            && (!approved || verifiedAt is { } at && at >= pending.RequestedAtUtc && at <= pending.DeadlineUtc && at <= DateTimeOffset.UtcNow);
        pending.Completion.TrySetResult(valid && approved);
        if (!valid || !approved)
            OperationalNotice?.Invoke($"Accord du propriétaire refusé, invalide ou expiré pour {pending.ActionId} ({envelope.CorrelationId}).");
        else
            OperationalNotice?.Invoke($"Accord du propriétaire confirmé pour {pending.ActionId} ({envelope.CorrelationId}).");
    }

    private async Task RequestVisualEvidenceChunkAsync(string correlationId, string evidenceRef, int offset, CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow;
        var message = new DaemonEnvelope
        {
            MessageId = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = now,
            SourceDaemon = DaemonNames.RiskResponseGuard, Destination = DaemonNames.HumanBehaviorMonitor,
            MessageType = "VISUAL_EVIDENCE_READ_REQUEST", SchemaVersion = 1, ExpiresAtUtc = now.AddSeconds(20),
            Payload = JsonSerializer.SerializeToElement(new { evidenceRef, offset, maxBytes = 24 * 1024 })
        };
        try { await bus.SendAsync(message, token).ConfigureAwait(false); }
        catch (IOException) { _visualTransfers.TryRemove(correlationId, out _); }
    }

    private async Task HandleVisualChunkAsync(DaemonEnvelope envelope, CancellationToken token)
    {
        if (!_visualTransfers.TryGetValue(envelope.CorrelationId, out var transfer)) return;
        var payload = envelope.Payload;
        if (!payload.TryGetProperty("evidenceRef", out var refElement) || refElement.ValueKind != JsonValueKind.String || refElement.GetString() != transfer.EvidenceRef
            || !payload.TryGetProperty("offset", out var offsetElement) || !offsetElement.TryGetInt32(out var offset)
            || !payload.TryGetProperty("totalBytes", out var totalElement) || !totalElement.TryGetInt32(out var total)
            || !payload.TryGetProperty("chunkBase64", out var dataElement) || dataElement.ValueKind != JsonValueKind.String
            || !payload.TryGetProperty("isFinal", out var finalElement) || finalElement.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        { _visualTransfers.TryRemove(envelope.CorrelationId, out _); return; }

        byte[] chunk;
        try { chunk = Convert.FromBase64String(dataElement.GetString() ?? string.Empty); }
        catch (FormatException) { _visualTransfers.TryRemove(envelope.CorrelationId, out _); return; }
        if (chunk.Length > 24 * 1024 || total is < 1 or > 10 * 1024 * 1024 || offset != transfer.Buffer.Length
            || offset + chunk.Length > total || transfer.TotalBytes is not null && transfer.TotalBytes != total)
        { _visualTransfers.TryRemove(envelope.CorrelationId, out _); return; }
        transfer.TotalBytes = total;
        await transfer.Buffer.WriteAsync(chunk, token).ConfigureAwait(false);
        if (finalElement.GetBoolean())
        {
            _visualTransfers.TryRemove(envelope.CorrelationId, out _);
            if (transfer.Buffer.Length == total)
                await reports.AttachVisualEvidenceAsync(envelope.CorrelationId, transfer.EvidenceRef, transfer.Buffer.ToArray(), token).ConfigureAwait(false);
            transfer.Dispose();
            return;
        }
        if (transfer.Buffer.Length >= total)
        { _visualTransfers.TryRemove(envelope.CorrelationId, out _); transfer.Dispose(); return; }
        await RequestVisualEvidenceChunkAsync(envelope.CorrelationId, transfer.EvidenceRef, checked((int)transfer.Buffer.Length), token).ConfigureAwait(false);
    }

    private void TryStartAiAnalysis(string correlationId, RiskDecision decision,
        IReadOnlyList<DecisionEvidence> related, bool contextChanged, CancellationToken token)
    {
        if (!ShouldAskAi(decision, related)) return;
        var turn = _aiTurns.GetValueOrDefault(correlationId);
        if (turn >= 3) return;
        if (turn > 0 && !contextChanged) return;
        if (!_aiInFlight.TryAdd(correlationId, 0))
        {
            if (contextChanged) _pendingAiRefresh.TryAdd(correlationId, 0);
            return;
        }
        turn++;
        _aiTurns[correlationId] = turn;
        var previous = _aiAssessments.GetValueOrDefault(correlationId);
        TrackJob(_aiJobs, AskAiInBackgroundAsync(correlationId, decision, related, turn, previous, token));
    }

    private async Task AskAiInBackgroundAsync(string correlationId, RiskDecision decision,
        IReadOnlyList<DecisionEvidence> related, int turn, string? previousAssessment, CancellationToken token)
    {
        await _aiSlots.WaitAsync(token).ConfigureAwait(false);
        try
        {
            if (_cases.TryGetValue(correlationId, out var latestBuffer)) related = latestBuffer.Snapshot();
            var allowedContext = new List<ContextRequestKind>();
            if (turn < 3)
            {
                if (!_contextCompleted.ContainsKey(correlationId)) allowedContext.Add(ContextRequestKind.D1_SESSION_CONTEXT);
                if (!_d2ContextCompleted.ContainsKey(correlationId)) allowedContext.Add(ContextRequestKind.D2_THREAT_DETAILS);
                if (!_visualCompleted.ContainsKey(correlationId)) allowedContext.Add(ContextRequestKind.D1_VISUAL_IDENTITY);
            }
            var aiCase = new AmbiguousSecurityCase(correlationId,
                related.OrderBy(x => x.ObservedAtUtc).TakeLast(20).Select(x => new SecuritySignalSummary(x.SourceDaemon, x.MessageType, x.Severity,
                    x.Confidence, x.ContextSummary ?? x.ReasonCode ?? "Signal reçu; contexte à préciser.", x.EvidenceRefs.Take(8).ToArray(), x.AiFacts, x.ObservedAtUtc)).ToArray(),
                allowedContext,
                previousAssessment, turn);
            var advice = await advisor.AnalyzeAsync(aiCase, token).ConfigureAwait(false);
            if (advice.Advice is { } assessment)
                _aiAssessments[correlationId] = assessment.Summary.Length > 0 ? assessment.Summary : assessment.Assessment;
            if (advice.Advice is { } recommendation && related.All(x => !x.IsSynthetic))
            {
                var requestedUsefulContext = false;
                if ((recommendation.RequestedContext.Contains(ContextRequestKind.D1_SESSION_CONTEXT)
                        || recommendation.SuggestedMeasure == SuggestedMeasure.REQUEST_D1_CONTEXT)
                    && !_contextCompleted.ContainsKey(correlationId)
                    && allowedContext.Contains(ContextRequestKind.D1_SESSION_CONTEXT)
                    && _contextRequests.TryAdd(correlationId, new CancellationTokenSource()))
                {
                    await RequestSessionContextAsync(correlationId, token).ConfigureAwait(false);
                    requestedUsefulContext = true;
                }
                if (recommendation.RequestedContext.Contains(ContextRequestKind.D1_VISUAL_IDENTITY)
                    && !_visualCompleted.ContainsKey(correlationId)
                    && allowedContext.Contains(ContextRequestKind.D1_VISUAL_IDENTITY)
                    && _visualRequests.TryAdd(correlationId, new CancellationTokenSource()))
                {
                    await RequestVisualCheckAsync(correlationId, token).ConfigureAwait(false);
                    requestedUsefulContext = true;
                }
                if (recommendation.RequestedContext.Contains(ContextRequestKind.D2_THREAT_DETAILS)
                    && !_d2ContextCompleted.ContainsKey(correlationId)
                    && allowedContext.Contains(ContextRequestKind.D2_THREAT_DETAILS)
                    && _d2ContextRequests.TryAdd(correlationId, new CancellationTokenSource()))
                {
                    await RequestD2ThreatDetailsAsync(correlationId, token).ConfigureAwait(false);
                    requestedUsefulContext = true;
                }
                if (recommendation.SuggestedMeasure == SuggestedMeasure.REQUEST_OWNER_CONFIRMATION
                    && !_visualCompleted.ContainsKey(correlationId)
                    && allowedContext.Contains(ContextRequestKind.D1_VISUAL_IDENTITY)
                    && _visualRequests.TryAdd(correlationId, new CancellationTokenSource()))
                {
                    await RequestVisualCheckAsync(correlationId, token).ConfigureAwait(false);
                    requestedUsefulContext = true;
                }
                // A pending question is not yet a verdict: wait for the correlated D1/D2 answer and analyze again.
                if (requestedUsefulContext)
                {
                    await reports.UpdateLatestAiAdviceAsync(correlationId, advice, token).ConfigureAwait(false);
                    return;
                }

                var finalDecision = CreateDecisionFromAdvice(correlationId, recommendation, related, decision);
                var finalReport = await reports.UpdateLatestDecisionAsync(correlationId, finalDecision, related, advice, token).ConfigureAwait(false);
                if (finalReport is not null)
                {
                    if (sessionActivityReports is not null && related.All(x => !x.IsSynthetic))
                    {
                        try { await sessionActivityReports.RecordDecisionAsync(finalDecision.Risk.ToString(), finalDecision.Decision.ToString(), correlationId, finalDecision.DecidedAtUtc, token).ConfigureAwait(false); }
                        catch (Exception exception) when (exception is not OperationCanceledException)
                        { OperationalNotice?.Invoke($"Décision IA non ajoutée au rapport de session : {exception.GetType().Name}."); }
                    }
                    ReportCreated?.Invoke(finalReport);
                    if (finalDecision.ProposedAction != ProposedAction.NONE
                        && _actionRequests.TryAdd(correlationId + "|AI|" + finalDecision.ProposedAction, 0))
                        TrackJob(_actionJobs, ExecuteActionInBackgroundAsync(correlationId, finalDecision, related, finalReport, token));
                }
            }
            else
            {
                await reports.UpdateLatestAiAdviceAsync(correlationId, advice, token).ConfigureAwait(false);
                await PublishLatestReportAsync(correlationId, token).ConfigureAwait(false);
                // Ollama failure uses the established, bounded policy fallback; arbitrary commands are never run.
                await ScheduleDeterministicFallbackActionAsync(correlationId, decision, related, token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (IOException)
        {
            var failed = AdvisorOutcome.Failure(AdvisorStatus.Unavailable, OllamaAdvisorOptions.Default.Model, "OLLAMA_IO_FAILURE");
            await reports.UpdateLatestAiAdviceAsync(correlationId, failed, token).ConfigureAwait(false);
            await PublishLatestReportAsync(correlationId, token).ConfigureAwait(false);
            await ScheduleDeterministicFallbackActionAsync(correlationId, decision, related, token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            var failed = AdvisorOutcome.Failure(AdvisorStatus.Unavailable, OllamaAdvisorOptions.Default.Model, "AI_ADVISOR_INTERNAL_ERROR");
            await reports.UpdateLatestAiAdviceAsync(correlationId, failed, token).ConfigureAwait(false);
            await PublishLatestReportAsync(correlationId, token).ConfigureAwait(false);
            await ScheduleDeterministicFallbackActionAsync(correlationId, decision, related, token).ConfigureAwait(false);
        }
        finally
        {
            _aiSlots.Release();
            _aiInFlight.TryRemove(correlationId, out _);
            if (_pendingAiRefresh.TryRemove(correlationId, out _)
                && _cases.TryGetValue(correlationId, out var buffer))
            {
                var updated = buffer.Snapshot();
                TryStartAiAnalysis(correlationId, engine.Evaluate(correlationId, updated, IsDegraded(DateTimeOffset.UtcNow)), updated, true, token);
            }
        }
    }

    private async Task PublishLatestReportAsync(string correlationId, CancellationToken token)
    {
        var report = await reports.ReadLatestForCorrelationAsync(correlationId, token).ConfigureAwait(false);
        if (report is not null) ReportCreated?.Invoke(report);
    }

    private async Task ScheduleDeterministicFallbackActionAsync(string correlationId, RiskDecision decision,
        IReadOnlyList<DecisionEvidence> related, CancellationToken token)
    {
        if (decision.ProposedAction == ProposedAction.NONE
            || !_actionRequests.TryAdd(correlationId + "|FALLBACK|" + decision.ProposedAction, 0)) return;
        var latest = await reports.ReadLatestForCorrelationAsync(correlationId, token).ConfigureAwait(false);
        if (latest is not null)
            TrackJob(_actionJobs, ExecuteActionInBackgroundAsync(correlationId, decision, related, latest, token));
    }

    private static RiskDecision CreateDecisionFromAdvice(string correlationId, RiskAdvice advice,
        IReadOnlyList<DecisionEvidence> signals, RiskDecision fallback)
    {
        var risk = advice.RiskBand switch
        {
            AdviceRiskBand.LOW => RiskLevel.LOW,
            AdviceRiskBand.GUARDED => RiskLevel.GUARDED,
            AdviceRiskBand.ELEVATED => RiskLevel.ELEVATED,
            AdviceRiskBand.HIGH => RiskLevel.HIGH,
            AdviceRiskBand.CRITICAL => RiskLevel.CRITICAL,
            _ => RiskLevel.UNKNOWN
        };
        var hasTechnicalFinding = signals.Any(x => x.SourceDaemon == DaemonNames.ThreatMonitor && x.MessageType == "THREAT_FINDING");
        var now = DateTimeOffset.UtcNow;
        var ownerVisuallyConfirmed = signals.Any(x =>
        {
            var age = now - x.ObservedAtUtc;
            return x.SourceDaemon == DaemonNames.HumanBehaviorMonitor
                && x.MessageType == "VISUAL_IDENTITY_RESPONSE"
                && x.ReasonCode == "OWNER_VISUALLY_CONFIRMED_LIVE"
                && age >= TimeSpan.Zero && age <= TimeSpan.FromMinutes(1);
        });
        var technicalSeverity = signals.Where(x => x.SourceDaemon == DaemonNames.ThreatMonitor
                && x.MessageType == "THREAT_FINDING")
            .Select(x => x.Severity)
            .Select(value => value == "CRITICAL" ? RiskLevel.CRITICAL : value == "HIGH" ? RiskLevel.HIGH : RiskLevel.UNKNOWN)
            .DefaultIfEmpty(RiskLevel.UNKNOWN).Max();
        var technicalFloor = technicalSeverity switch
        {
            RiskLevel.CRITICAL when ownerVisuallyConfirmed => RiskLevel.HIGH,
            RiskLevel.HIGH when ownerVisuallyConfirmed => RiskLevel.ELEVATED,
            _ => technicalSeverity
        };
        var floorApplied = technicalFloor > risk;
        if (floorApplied) risk = technicalFloor;

        var action = ProposedAction.NONE;
        var kind = DecisionKind.MONITOR;
        var requiresApproval = false;
        switch (advice.SuggestedMeasure)
        {
            case SuggestedMeasure.RUN_DEFENDER_QUICK_SCAN when hasTechnicalFinding && risk == RiskLevel.HIGH:
                action = ProposedAction.RUN_DEFENDER_SCAN;
                kind = DecisionKind.RUN_BOUNDED_SCAN;
                requiresApproval = true;
                break;
            case SuggestedMeasure.CONTAINMENT_REVIEW when hasTechnicalFinding && risk == RiskLevel.CRITICAL:
                action = ProposedAction.ISOLATE_FILE_REVIEW;
                kind = DecisionKind.CONTAINMENT_REVIEW;
                requiresApproval = true;
                break;
            case SuggestedMeasure.REQUEST_D1_CONTEXT:
                kind = DecisionKind.REQUEST_CONTEXT;
                break;
            case SuggestedMeasure.REQUEST_OWNER_CONFIRMATION:
                kind = DecisionKind.REQUIRE_OWNER_CONFIRMATION;
                requiresApproval = true;
                break;
            case SuggestedMeasure.CAPABILITY_GAP:
                kind = DecisionKind.CAPABILITY_GAP;
                break;
            case SuggestedMeasure.NO_RECOMMENDATION:
                kind = risk == RiskLevel.UNKNOWN ? DecisionKind.SAFE_DEGRADED : DecisionKind.MONITOR;
                break;
        }

        // A strong D2 finding cannot be cleared by a short model answer or familiar D1 activity.
        // A fresh, live D1 owner match may reduce it by one level, matching the deterministic policy.
        if (floorApplied && hasTechnicalFinding)
        {
            if (risk == RiskLevel.CRITICAL)
            {
                action = ProposedAction.ISOLATE_FILE_REVIEW;
                kind = DecisionKind.CONTAINMENT_REVIEW;
                requiresApproval = true;
            }
            else if (risk == RiskLevel.HIGH)
            {
                action = ProposedAction.RUN_DEFENDER_SCAN;
                kind = DecisionKind.RUN_BOUNDED_SCAN;
                requiresApproval = true;
            }
        }

        // A model can propose only a closed action set; a typed action still has to satisfy D3's capability policy.
        var reasonCodes = signals.Select(x => x.ReasonCode).Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>().Where(IsSafeReasonCode).Distinct(StringComparer.Ordinal).ToList();
        if (floorApplied) reasonCodes.Add(ownerVisuallyConfirmed ? "AI_RESULT_RAISED_TO_OWNER_VERIFIED_D2_FLOOR" : "AI_RESULT_RAISED_TO_D2_TECHNICAL_FLOOR");
        var validEvidence = signals.SelectMany(x => x.EvidenceRefs).ToHashSet(StringComparer.Ordinal);
        // The model may cite only known evidence, and it cannot remove D1/D2 evidence from D3's final audit.
        var evidenceRefs = validEvidence.Concat(advice.EvidenceRefs.Where(validEvidence.Contains))
            .Distinct(StringComparer.Ordinal).Take(64).ToArray();
        var explanation = $"Analyse Ollama : {advice.Assessment} (confiance {advice.Confidence:P0}). {advice.Rationale}";
        if (advice.SuggestedMeasure == SuggestedMeasure.CAPABILITY_GAP)
            explanation += " Aucune capacité correspondante n’est installée; le playbook éventuel reste un texte à examiner, jamais une commande exécutée.";
        return new RiskDecision(correlationId, risk, kind, action, explanation, reasonCodes.Distinct(StringComparer.Ordinal).Take(32).ToArray(), evidenceRefs,
            requiresApproval, fallback.SimulationOnly, DateTimeOffset.UtcNow);
    }

    private static bool IsSafeReasonCode(string value)
        => value.Length <= 96 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');

    private async Task RequestVisualCheckAsync(string correlationId, CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow;
        var deadline = now.AddSeconds(55);
        var payload = JsonSerializer.SerializeToElement(new
        {
            correlationId,
            purpose = "ALERT",
            requestedAtUtc = now,
            deadlineUtc = deadline,
            requiredLiveness = true
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var request = new DaemonEnvelope
        {
            MessageId = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = now,
            SourceDaemon = DaemonNames.RiskResponseGuard, Destination = DaemonNames.HumanBehaviorMonitor,
            MessageType = "VISUAL_IDENTITY_REQUEST", SchemaVersion = 1, ExpiresAtUtc = deadline, Payload = payload
        };
        try
        {
            await bus.SendAsync(request, token).ConfigureAwait(false);
            StartRequestTimeout(correlationId, "VISUAL_IDENTITY_RESPONSE", _visualRequests, _options.VisualResponseTimeout, token);
        }
        catch (IOException)
        {
            _visualCompleted.TryAdd(correlationId, 0);
            CompleteRequest(_visualRequests, correlationId);
            await RecordContextUnavailableAsync(correlationId, DaemonNames.HumanBehaviorMonitor, "VISUAL_IDENTITY_RESPONSE", "D1_VISUAL_REQUEST_UNAVAILABLE", token).ConfigureAwait(false);
        }
    }

    private async Task HandleD2SessionContextRequestAsync(DaemonEnvelope request, CancellationToken token)
    {
        try
        {
        var correlationId = request.CorrelationId;
        if (!_d2SessionContextRelays.TryAdd(correlationId, 0)) return;

        if (!TryValidateD2SessionContextRequest(request, DateTimeOffset.UtcNow, out var deadline))
        {
            await SendSessionContextResponseToD2Async(correlationId, SessionContextProjection.Unavailable(DateTimeOffset.UtcNow), token).ConfigureAwait(false);
            return;
        }

        if (_d1SessionContexts.TryGetValue(correlationId, out var cached) && IsFreshSessionContext(cached, DateTimeOffset.UtcNow))
        {
            await SendSessionContextResponseToD2Async(correlationId, cached, token).ConfigureAwait(false);
            return;
        }
        if (_contextCompleted.ContainsKey(correlationId))
        {
            await SendSessionContextResponseToD2Async(correlationId, SessionContextProjection.Unavailable(DateTimeOffset.UtcNow), token).ConfigureAwait(false);
            return;
        }

        var waiter = _d1SessionContextWaiters.GetOrAdd(correlationId,
            _ => new TaskCompletionSource<SessionContextProjection>(TaskCreationOptions.RunContinuationsAsynchronously));
        if (_contextRequests.TryAdd(correlationId, new CancellationTokenSource()))
            await RequestSessionContextAsync(correlationId, token).ConfigureAwait(false);

        if (_contextCompleted.ContainsKey(correlationId) && !_d1SessionContexts.ContainsKey(correlationId))
            waiter.TrySetResult(SessionContextProjection.Unavailable(DateTimeOffset.UtcNow));

        var remaining = deadline - DateTimeOffset.UtcNow;
        if (remaining > TimeSpan.FromSeconds(2)) remaining = TimeSpan.FromSeconds(2);
        if (remaining <= TimeSpan.Zero)
        {
            await SendSessionContextResponseToD2Async(correlationId, SessionContextProjection.Unavailable(DateTimeOffset.UtcNow), token).ConfigureAwait(false);
            return;
        }

        SessionContextProjection result;
        try { result = await waiter.Task.WaitAsync(remaining, token).ConfigureAwait(false); }
        catch (TimeoutException) { result = SessionContextProjection.Unavailable(DateTimeOffset.UtcNow); }
        catch (OperationCanceledException) when (!token.IsCancellationRequested)
        { result = SessionContextProjection.Unavailable(DateTimeOffset.UtcNow); }

        if (!IsFreshSessionContext(result, DateTimeOffset.UtcNow))
            result = SessionContextProjection.Unavailable(DateTimeOffset.UtcNow);
        await SendSessionContextResponseToD2Async(correlationId, result, token).ConfigureAwait(false);
        }
        finally { await bus.MarkProcessedAsync(request.MessageId, token).ConfigureAwait(false); }
    }

    private async Task SendSessionContextResponseToD2Async(string correlationId, SessionContextProjection projection, CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow;
        object payload = projection.Available
            ? new
            {
                status = "AVAILABLE",
                observedAtUtc = projection.ObservedAtUtc,
                context = new
                {
                    sessionState = projection.SessionState,
                    localOrRemote = projection.LocalOrRemote,
                    recentAuthBand = projection.RecentAuthBand
                }
            }
            : new { status = "NOT_AVAILABLE", observedAtUtc = now, context = (object?)null };
        var response = new DaemonEnvelope
        {
            MessageId = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = now,
            SourceDaemon = DaemonNames.RiskResponseGuard, Destination = DaemonNames.ThreatMonitor,
            MessageType = "SESSION_CONTEXT_RESPONSE", SchemaVersion = 1, ExpiresAtUtc = now.AddSeconds(10),
            Payload = JsonSerializer.SerializeToElement(payload)
        };
        try { await bus.SendAsync(response, token).ConfigureAwait(false); }
        catch (IOException) { OperationalNotice?.Invoke($"Réponse de contexte de session non remise à D2 pour {correlationId}."); }
    }

    private static SessionContextProjection ReadD1SessionContext(DaemonEnvelope response)
    {
        var payload = response.Payload;
        if (payload.ValueKind != JsonValueKind.Object
            || !payload.TryGetProperty("status", out var status) || status.ValueKind != JsonValueKind.String
            || status.GetString() != "AVAILABLE"
            || !payload.TryGetProperty("sessionContext", out var context) || context.ValueKind != JsonValueKind.Object)
            return SessionContextProjection.Unavailable(DateTimeOffset.UtcNow);

        var observedAt = response.TimestampUtc;
        if (payload.TryGetProperty("sessionContextObservedAtUtc", out var observed)
            && observed.ValueKind == JsonValueKind.String && observed.TryGetDateTimeOffset(out var parsed)) observedAt = parsed;
        if (observedAt.Offset != TimeSpan.Zero
            || !ReadAllowedCategory(context, "sessionState", ["ACTIVE", "IDLE", "LOCKED", "UNKNOWN"], out var sessionState)
            || !ReadAllowedCategory(context, "localOrRemote", ["LOCAL", "REMOTE", "UNKNOWN"], out var localOrRemote)
            || !ReadAllowedCategory(context, "recentAuthBand", ["RECENT", "NOT_RECENT", "UNKNOWN"], out var recentAuthBand))
            return SessionContextProjection.Unavailable(DateTimeOffset.UtcNow);
        return new(true, observedAt, sessionState, localOrRemote, recentAuthBand);
    }

    private static bool ReadAllowedCategory(JsonElement parent, string name, string[] allowed, out string value)
    {
        value = "UNKNOWN";
        if (!parent.TryGetProperty(name, out var element) || element.ValueKind != JsonValueKind.String) return false;
        var candidate = element.GetString();
        if (candidate is null || !allowed.Contains(candidate, StringComparer.Ordinal)) return false;
        value = candidate;
        return true;
    }

    private static bool TryValidateD2SessionContextRequest(DaemonEnvelope request, DateTimeOffset now, out DateTimeOffset deadline)
    {
        deadline = default;
        if (request.SourceDaemon != DaemonNames.ThreatMonitor || request.Destination != DaemonNames.RiskResponseGuard
            || request.MessageType != "SESSION_CONTEXT_REQUEST" || request.Payload.ValueKind != JsonValueKind.Object
            || !request.Payload.TryGetProperty("requestedFields", out var fields) || fields.ValueKind != JsonValueKind.Array
            || fields.GetArrayLength() != 3
            || !fields.EnumerateArray().All(x => x.ValueKind == JsonValueKind.String
                && x.GetString() is "sessionState" or "localOrRemote" or "recentAuthBand")
            || fields.EnumerateArray().Select(x => x.GetString()).Distinct(StringComparer.Ordinal).Count() != 3
            || !request.Payload.TryGetProperty("deadlineUtc", out var deadlineElement)
            || deadlineElement.ValueKind != JsonValueKind.String
            || !deadlineElement.TryGetDateTimeOffset(out deadline)
            || deadline.Offset != TimeSpan.Zero || deadline <= now || deadline > request.ExpiresAtUtc)
            return false;
        return true;
    }

    private static bool IsFreshSessionContext(SessionContextProjection projection, DateTimeOffset now)
        => projection.Available && projection.ObservedAtUtc <= now.AddSeconds(5)
            && now - projection.ObservedAtUtc <= TimeSpan.FromMinutes(2);

    private async Task RequestSessionContextAsync(string correlationId, CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow;
        var deadline = now.AddSeconds(20);
        var request = new DaemonEnvelope
        {
            MessageId = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = now,
            SourceDaemon = DaemonNames.RiskResponseGuard, Destination = DaemonNames.HumanBehaviorMonitor,
            MessageType = "CONTEXT_REQUEST", SchemaVersion = 1, ExpiresAtUtc = deadline,
            Payload = JsonSerializer.SerializeToElement(new
            {
                requestedAtUtc = now,
                deadlineUtc = deadline,
                requestedFields = new[] { "applicationContext", "sessionContext" }
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web))
        };
        try
        {
            await bus.SendAsync(request, token).ConfigureAwait(false);
            StartRequestTimeout(correlationId, "CONTEXT_RESPONSE", _contextRequests, _options.ContextResponseTimeout, token);
        }
        catch (IOException)
        {
            CompleteRequest(_contextRequests, correlationId);
            _contextCompleted.TryAdd(correlationId, 0);
            await RecordContextUnavailableAsync(correlationId, DaemonNames.HumanBehaviorMonitor, "CONTEXT_RESPONSE", "D1_CONTEXT_REQUEST_UNAVAILABLE", token).ConfigureAwait(false);
        }
    }

    private async Task RequestD2ThreatDetailsAsync(string correlationId, CancellationToken token)
    {
        var now = DateTimeOffset.UtcNow;
        var deadline = now.AddSeconds(20);
        var request = new DaemonEnvelope
        {
            MessageId = Guid.NewGuid(), CorrelationId = correlationId, TimestampUtc = now,
            SourceDaemon = DaemonNames.RiskResponseGuard, Destination = DaemonNames.ThreatMonitor,
            MessageType = "CONTEXT_REQUEST", SchemaVersion = 1, ExpiresAtUtc = deadline,
            Payload = JsonSerializer.SerializeToElement(new
            {
                requestedAtUtc = now, deadlineUtc = deadline,
                requestedFields = new[] { "findingSummary", "ruleDetails", "evidenceKinds", "missingTelemetry" }
            })
        };
        try
        {
            await bus.SendAsync(request, token).ConfigureAwait(false);
            StartRequestTimeout(correlationId, "D2_CONTEXT_RESPONSE", _d2ContextRequests, _options.ContextResponseTimeout, token);
        }
        catch (IOException)
        {
            CompleteRequest(_d2ContextRequests, correlationId);
            _d2ContextCompleted.TryAdd(correlationId, 0);
            await RecordContextUnavailableAsync(correlationId, DaemonNames.ThreatMonitor, "CONTEXT_RESPONSE", "D2_CONTEXT_REQUEST_UNAVAILABLE", token).ConfigureAwait(false);
        }
    }

    private void StartRequestTimeout(string correlationId, string expectedMessageType,
        ConcurrentDictionary<string, CancellationTokenSource> requests, TimeSpan timeout, CancellationToken hostToken)
    {
        if (!requests.TryGetValue(correlationId, out var request)) return;
        TrackJob(_requestJobs, ObserveRequestTimeoutAsync(correlationId, expectedMessageType, requests, request, timeout, hostToken));
    }

    private static void TrackJob(ConcurrentDictionary<Task, byte> jobs, Task job)
    {
        jobs.TryAdd(job, 0);
        _ = job.ContinueWith(completed =>
        {
            _ = completed.Exception;
            jobs.TryRemove(completed, out var ignored);
        }, CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    private async Task ObserveRequestTimeoutAsync(string correlationId, string expectedMessageType,
        ConcurrentDictionary<string, CancellationTokenSource> requests, CancellationTokenSource request,
        TimeSpan timeout, CancellationToken hostToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(request.Token, hostToken);
        try { await Task.Delay(timeout, linked.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (linked.IsCancellationRequested) { return; }
        if (!requests.TryRemove(new KeyValuePair<string, CancellationTokenSource>(correlationId, request))) return;
        request.Dispose();
        if (expectedMessageType == "VISUAL_IDENTITY_RESPONSE") _visualCompleted.TryAdd(correlationId, 0);
        var isD2 = expectedMessageType.StartsWith("D2_", StringComparison.Ordinal);
        if (isD2) _d2ContextCompleted.TryAdd(correlationId, 0);
        else if (expectedMessageType == "CONTEXT_RESPONSE") _contextCompleted.TryAdd(correlationId, 0);
        await RecordContextUnavailableAsync(correlationId,
            isD2 ? DaemonNames.ThreatMonitor : DaemonNames.HumanBehaviorMonitor,
            expectedMessageType == "D2_CONTEXT_RESPONSE" ? "CONTEXT_RESPONSE" : expectedMessageType,
            expectedMessageType switch
            {
                "VISUAL_IDENTITY_RESPONSE" => "D1_VISUAL_RESPONSE_TIMEOUT",
                "D2_CONTEXT_RESPONSE" => "D2_CONTEXT_RESPONSE_TIMEOUT",
                _ => "D1_CONTEXT_RESPONSE_TIMEOUT"
            }, hostToken).ConfigureAwait(false);
    }

    private static void CompleteRequest(ConcurrentDictionary<string, CancellationTokenSource> requests, string correlationId)
    {
        if (!requests.TryRemove(correlationId, out var request)) return;
        request.Cancel();
        request.Dispose();
    }

    private static void CancelRequests(ConcurrentDictionary<string, CancellationTokenSource> requests)
    {
        foreach (var pair in requests)
            if (requests.TryRemove(pair))
            {
                pair.Value.Cancel();
                pair.Value.Dispose();
            }
    }

    private async Task RecordContextUnavailableAsync(string correlationId, string sourceDaemon, string messageType, string reasonCode, CancellationToken token)
    {
        if (!_cases.TryGetValue(correlationId, out var buffer)) return;
        buffer.Add(new DecisionEvidence(sourceDaemon, messageType, "UNKNOWN", null,
            reasonCode, [], DateTimeOffset.UtcNow));
        var related = buffer.Snapshot();
        if (sessionActivityReports is not null && related.All(x => !x.IsSynthetic))
        {
            try { await sessionActivityReports.RecordActivityAsync(sourceDaemon, messageType, "UNKNOWN", reasonCode, correlationId, DateTimeOffset.UtcNow, token).ConfigureAwait(false); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            { OperationalNotice?.Invoke($"Absence de contexte non ajoutée au rapport de session : {exception.GetType().Name}."); }
        }
        var decision = engine.Evaluate(correlationId, related, IsDegraded(DateTimeOffset.UtcNow));
        var report = await reports.SaveAsync(decision, related, cancellationToken: token).ConfigureAwait(false);
        if (sessionActivityReports is not null && related.All(x => !x.IsSynthetic))
        {
            try { await sessionActivityReports.RecordDecisionAsync(decision.Risk.ToString(), decision.Decision.ToString(), correlationId, decision.DecidedAtUtc, token).ConfigureAwait(false); }
            catch (Exception exception) when (exception is not OperationCanceledException)
            { OperationalNotice?.Invoke($"Décision de repli non ajoutée au rapport de session : {exception.GetType().Name}."); }
        }
        ReportCreated?.Invoke(report);
        TryStartAiAnalysis(correlationId, decision, related, true, token);
    }

    private bool IsDegraded(DateTimeOffset now)
        => new[] { DaemonNames.HumanBehaviorMonitor, DaemonNames.ThreatMonitor }
            .Any(name => !_heartbeats.TryGetValue(name, out var last) || now - last > TimeSpan.FromSeconds(30));

    private static bool ShouldAskAi(RiskDecision decision, IReadOnlyList<DecisionEvidence> signals)
        => decision.Risk is RiskLevel.UNKNOWN or RiskLevel.ELEVATED
            || signals.Any(x => x.SourceDaemon == DaemonNames.ThreatMonitor
                && x.MessageType is "THREAT_FINDING" or "TELEMETRY_GAP")
            || signals.Any(x => x.SourceDaemon == DaemonNames.HumanBehaviorMonitor
                && x.MessageType is "BEHAVIOR_DEVIATION" or "VISUAL_IDENTITY_RESPONSE")
            || (signals.Any(x => x.SourceDaemon == DaemonNames.HumanBehaviorMonitor)
                && signals.Any(x => x.SourceDaemon == DaemonNames.ThreatMonitor)
                && signals.Any(x => x.Severity is "HIGH" or "CRITICAL")
                && signals.Any(x => x.Severity is "LOW" or "UNKNOWN"));

    private void RemoveExpiredCases()
    {
        var cutoff = DateTimeOffset.UtcNow.AddMinutes(-10);
        foreach (var pair in _cases)
            if (pair.Value.CreatedAtUtc < cutoff && _cases.TryRemove(pair.Key, out _))
            {
                _aiTurns.TryRemove(pair.Key, out _); _aiAssessments.TryRemove(pair.Key, out _);
                _aiInFlight.TryRemove(pair.Key, out _); _pendingAiRefresh.TryRemove(pair.Key, out _);
                _contextCompleted.TryRemove(pair.Key, out _); _d2ContextCompleted.TryRemove(pair.Key, out _);
                _visualCompleted.TryRemove(pair.Key, out _);
                _d1SessionContexts.TryRemove(pair.Key, out _); _d2SessionContextRelays.TryRemove(pair.Key, out _);
                foreach (var actionKey in _actionRequests.Keys.Where(key => key.StartsWith(pair.Key + "|", StringComparison.Ordinal)))
                    _actionRequests.TryRemove(actionKey, out _);
                if (_d1SessionContextWaiters.TryRemove(pair.Key, out var waiter))
                    waiter.TrySetResult(SessionContextProjection.Unavailable(DateTimeOffset.UtcNow));
            }
    }

    private sealed record SessionContextProjection(bool Available, DateTimeOffset ObservedAtUtc,
        string SessionState, string LocalOrRemote, string RecentAuthBand)
    {
        public static SessionContextProjection Unavailable(DateTimeOffset observedAtUtc)
            => new(false, observedAtUtc, "UNKNOWN", "UNKNOWN", "UNKNOWN");
    }

    private sealed class CaseBuffer(DateTimeOffset createdAtUtc)
    {
        private readonly object _gate = new();
        private readonly List<DecisionEvidence> _items = [];
        public DateTimeOffset CreatedAtUtc { get; } = createdAtUtc;
        public void Add(DecisionEvidence value)
        {
            lock (_gate)
            {
                _items.RemoveAll(x => x.SourceDaemon == value.SourceDaemon && x.MessageType == value.MessageType
                    && value.ObservedAtUtc - x.ObservedAtUtc > TimeSpan.FromMinutes(10));
                _items.Add(value);
                if (_items.Count > 100) _items.RemoveRange(0, _items.Count - 100);
            }
        }
        public IReadOnlyList<DecisionEvidence> Snapshot() { lock (_gate) return _items.ToArray(); }
    }

    private sealed class VisualTransfer(string evidenceRef) : IDisposable
    {
        public string EvidenceRef { get; } = evidenceRef;
        public int? TotalBytes { get; set; }
        public MemoryStream Buffer { get; } = new();
        public void Dispose() => Buffer.Dispose();
    }

    private sealed record PendingOwnerApproval(string ChallengeId, string ActionId, DateTimeOffset RequestedAtUtc,
        DateTimeOffset DeadlineUtc)
    {
        public TaskCompletionSource<bool> Completion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
}

public sealed record Demon3HostOptions(TimeSpan ContextResponseTimeout, TimeSpan VisualResponseTimeout)
{
    public static Demon3HostOptions Default { get; } = new(TimeSpan.FromSeconds(20), TimeSpan.FromSeconds(50));

    internal Demon3HostOptions Validate()
    {
        if (ContextResponseTimeout <= TimeSpan.Zero || ContextResponseTimeout > TimeSpan.FromSeconds(50)
            || VisualResponseTimeout <= TimeSpan.Zero || VisualResponseTimeout > TimeSpan.FromSeconds(50))
            throw new ArgumentOutOfRangeException(nameof(ContextResponseTimeout), "Les délais de réponse D1 doivent être compris entre 1 ms et 50 secondes.");
        return this;
    }
}

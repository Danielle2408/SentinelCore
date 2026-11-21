namespace SentinelCore.Demon2.Core;

public sealed class ThreatMonitorPipeline(
    IEventSource<SysmonRecord> source,
    IEventSourceHealthProvider sourceHealth,
    IEventNormalizer<SysmonRecord> normalizer,
    IEventStore store,
    DetectionEngine detection,
    IInterDaemonBus bus,
    TimeProvider? timeProvider = null)
{
    private TimeProvider Clock { get; } = timeProvider ?? TimeProvider.System;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (store is SqliteEventStore sqlite) await sqlite.InitializeAsync(cancellationToken);
        await store.PruneExpiredAsync(Clock.GetUtcNow(), cancellationToken);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var token = lifetime.Token;
        var publisher = PublishLoopAsync(token);
        var heartbeat = HeartbeatLoopAsync(token);
        var healthTask = HealthLoopAsync(token);
        var retentionTask = RetentionLoopAsync(token);
        try
        {
            await foreach (var raw in source.ReadAllAsync(token).WithCancellation(token))
            {
                if (raw.SourceError is { } sourceError)
                {
                    var gap = new TelemetryGap(Guid.NewGuid().ToString("N"), source.Name, Clock.GetUtcNow(),
                        sourceError, 0, ["source_available"]);
                    await PublishGapAsync(gap, Clock.GetUtcNow().AddMinutes(1), token);
                    continue;
                }
                CanonicalEvent? item;
                string? rejected;
                bool normalized;
                try { normalized = normalizer.TryNormalize(raw, out item, out rejected); }
                catch (Exception ex)
                {
                    item = null;
                    rejected = $"Normalizer failed: {ex.Message}";
                    normalized = false;
                }
                if (!normalized || item is null)
                {
                    Console.Error.WriteLine($"Sysmon event rejected: {rejected}");
                    var poisonIdentity = raw.BookmarkXml ?? Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes(raw.Xml))).ToLowerInvariant();
                    var gapId = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes($"{source.Name}|malformed|{poisonIdentity}"))).ToLowerInvariant();
                    await PublishGapAsync(new TelemetryGap(gapId, source.Name, Clock.GetUtcNow(),
                        $"Observed source record was rejected during normalization: {rejected ?? "unknown validation error"}", 0, ["normalizedEvent"]),
                        Clock.GetUtcNow().AddMinutes(1), token);
                    if (raw.BookmarkXml is { Length: > 0 } rejectedCursor)
                    {
                        await store.SaveCursorAsync(source.Name, rejectedCursor, token);
                        if (source is IEventCursorSource rejectedCursorSource) rejectedCursorSource.CommitCursor(rejectedCursor);
                    }
                    continue;
                }
                var isNew = await store.SaveEventAsync(item, token);
                if (item.SourceCursor is not null)
                {
                    await store.SaveCursorAsync(source.Name, item.SourceCursor, token);
                    if (source is IEventCursorSource cursorSource) cursorSource.CommitCursor(item.SourceCursor);
                }
                if (!isNew) continue;
                var recent = await new TemporalCorrelator(store).GetRelatedEventsAsync(item, token);
                var result = detection.Evaluate(item, recent, Clock.GetUtcNow());
                foreach (var finding in result.Findings)
                {
                    var evidenceEvents = await store.LoadEventsByIdsAsync(finding.EvidenceRefs, token);
                    var evidenceIds = evidenceEvents.Select(x => x.EventId).ToHashSet(StringComparer.Ordinal);
                    if (evidenceIds.Count != finding.EvidenceRefs.Distinct(StringComparer.Ordinal).Count())
                    {
                        var unresolved = finding.EvidenceRefs.Where(x => !evidenceIds.Contains(x));
                        Console.Error.WriteLine($"Finding {finding.FindingId} not persisted: unresolved evidenceRefs: {string.Join(",", unresolved)}");
                        continue;
                    }
                    if (await store.SaveFindingAsync(finding, token))
                    {
                        var message = InterDaemonEnvelopeFactory.ForFinding(finding, Clock.GetUtcNow());
                        if (!InterDaemonEnvelopeValidator.EvidenceRefsResolve(message, evidenceIds, out var evidenceError))
                        {
                            Console.Error.WriteLine($"Finding {finding.FindingId} not queued: {evidenceError}");
                            continue;
                        }
                        await EnqueueAsync(message, token);
                    }
                }
                foreach (var gap in result.Gaps)
                    await PublishGapAsync(gap, Clock.GetUtcNow().AddMinutes(1), token);
            }
        }
        finally
        {
            lifetime.Cancel();
            try { await Task.WhenAll(publisher, heartbeat, healthTask, retentionTask); }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        }
    }

    private async Task PublishLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        while (true)
        {
            var now = Clock.GetUtcNow();
            var expired = await store.ExpireMessagesAsync(now, ct);
            foreach (var message in expired.Where(x => x.MessageType == "THREAT_FINDING"))
            {
                var gap = new TelemetryGap(Guid.NewGuid().ToString("N"), "GuardDelivery", now,
                    $"Le Guard n’a pas acquitté le message de type {message.MessageType} avant son expiration.", 0, ["guard_ack"]);
                await PublishGapAsync(gap, now.AddHours(24), ct);
            }
            var pending = await store.LoadPendingMessagesAsync(now, 32, ct);
            foreach (var message in pending)
            {
                try
                {
                    await bus.PublishAsync(message, ct);
                    await store.MarkMessageDeliveredAsync(message.MessageId, ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Guard delivery failed for {message.MessageId}: {ex.Message}");
                    await store.ScheduleMessageRetryAsync(message.MessageId, ex.Message, Clock.GetUtcNow().AddMilliseconds(250), ct);
                }
            }
            await timer.WaitForNextTickAsync(ct);
        }
    }

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(10));
        while (await timer.WaitForNextTickAsync(ct))
        {
            var health = sourceHealth.GetHealth();
            var outboxDepth = await store.GetPendingMessageCountAsync(ct);
            var heartbeat = InterDaemonEnvelopeFactory.Heartbeat(Guid.NewGuid().ToString(), health, outboxDepth, Clock.GetUtcNow());
            await EnqueueAsync(heartbeat, ct);
        }
    }

    private async Task HealthLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        string? lastGapSignature = null;
        while (await timer.WaitForNextTickAsync(ct))
        {
            var health = sourceHealth.GetHealth();
            var gap = new TelemetryHealthMonitor().Evaluate(source.Name, health, Clock.GetUtcNow());
            if (gap is null) { lastGapSignature = null; continue; }
            var signature = $"{health.State}|{health.Error}|{health.DroppedCount}|{health.LastEventUtc}|{health.StartedAtUtc}";
            if (signature == lastGapSignature) continue;
            lastGapSignature = signature;
            await PublishGapAsync(gap, Clock.GetUtcNow().AddMinutes(1), ct);
        }
    }

    private async Task RetentionLoopAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        while (await timer.WaitForNextTickAsync(ct)) await store.PruneExpiredAsync(Clock.GetUtcNow(), ct);
    }

    private async ValueTask EnqueueAsync(InterDaemonEnvelope message, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!await store.EnqueueMessageAsync(message, ct))
            Console.Error.WriteLine($"Bounded durable outbox is full; message {message.MessageId} was not queued.");
    }

    private async ValueTask PublishGapAsync(TelemetryGap gap, DateTimeOffset expiresAtUtc, CancellationToken ct)
    {
        if (!await store.SaveTelemetryGapAsync(gap, ct)) return;
        await EnqueueAsync(InterDaemonEnvelopeFactory.ForGap(gap, expiresAtUtc), ct);
    }
}

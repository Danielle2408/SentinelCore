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
        var sourceOutages = new SourceOutageEpisodes();
        var publisher = PublishLoopAsync(token);
        var heartbeat = HeartbeatLoopAsync(token);
        var healthTask = HealthLoopAsync(token, sourceOutages);
        var retentionTask = RetentionLoopAsync(token);
        var requestTask = bus is IRequestReceivingInterDaemonBus requestBus
            ? new ThreatDetailsContextResponder(store, requestBus, Clock).RunAsync(token)
            : Task.CompletedTask;
        var sessionRelay = bus is ISessionContextResponseReceivingInterDaemonBus sessionResponseBus
            ? new SessionContextRelay(store, sessionResponseBus, Clock)
            : null;
        var sessionResponseTask = sessionRelay?.RunAsync(token) ?? Task.CompletedTask;
        try
        {
            await foreach (var raw in source.ReadAllAsync(token).WithCancellation(token))
            {
                if (raw.SourceError is { } sourceError)
                {
                    var gap = new TelemetryGap(Guid.NewGuid().ToString("N"), raw.SourceName, Clock.GetUtcNow(),
                        "Telemetry source reported temporary unavailability.", 0, ["source_available"]);
                    var firstGapForEpisode = sourceOutages.TryBegin(gap);
                    if (firstGapForEpisode is not null)
                        await PublishGapAsync(firstGapForEpisode, Clock.GetUtcNow().AddMinutes(1), token);
                    continue;
                }
                sourceOutages.MarkRecovered();
                CanonicalEvent? item;
                string? rejected;
                bool normalized;
                try { normalized = normalizer.TryNormalize(raw, out item, out rejected); }
                catch (Exception ex)
                {
                    item = null;
                    rejected = $"Normalizer failed: {ex.GetType().Name}";
                    normalized = false;
                }
                if (!normalized || item is null)
                {
                    Console.Error.WriteLine($"{raw.SourceName} event rejected during normalization.");
                    var bookmarkIsBounded = raw.BookmarkXml is { Length: > 0 and <= SysmonEventNormalizer.MaxBookmarkCharacters };
                    var poisonIdentity = bookmarkIsBounded ? raw.BookmarkXml! : Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes(raw.Xml))).ToLowerInvariant();
                    var gapId = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes($"{raw.SourceName}|malformed|{poisonIdentity}"))).ToLowerInvariant();
                    var missingFields = bookmarkIsBounded || raw.BookmarkXml is null ? new[] { "normalizedEvent" } : new[] { "normalizedEvent", "sourceCursor" };
                    await PublishGapAsync(new TelemetryGap(gapId, raw.SourceName, Clock.GetUtcNow(),
                        "Observed source record was rejected during normalization.", 0, missingFields),
                        Clock.GetUtcNow().AddMinutes(1), token);
                    if (bookmarkIsBounded && raw.BookmarkXml is { } rejectedCursor)
                    {
                        await store.SaveCursorAsync(raw.SourceName, rejectedCursor, token);
                        CommitCursor(raw.SourceName, rejectedCursor);
                    }
                    continue;
                }
                var isNew = await store.SaveEventAsync(item, token);
                if (item.SourceCursor is not null)
                {
                    await store.SaveCursorAsync(raw.SourceName, item.SourceCursor, token);
                    CommitCursor(raw.SourceName, item.SourceCursor);
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
                        if (sessionRelay is not null && finding.MissingTelemetry.Count > 0)
                            await sessionRelay.RequestForFindingAsync(finding, token);
                    }
                }
                foreach (var gap in result.Gaps)
                    await PublishGapAsync(gap, Clock.GetUtcNow().AddMinutes(1), token);
            }
        }
        finally
        {
            lifetime.Cancel();
            try { await Task.WhenAll(publisher, heartbeat, healthTask, retentionTask, requestTask, sessionResponseTask); }
            catch (OperationCanceledException) when (lifetime.IsCancellationRequested) { }
        }

        void CommitCursor(string sourceName, string cursor)
        {
            if (source is IMultiEventCursorSource multiSource) multiSource.CommitCursor(sourceName, cursor);
            else if (source is IEventCursorSource cursorSource) cursorSource.CommitCursor(cursor);
        }
    }


    private async Task PublishLoopAsync(CancellationToken ct)
    {
        var guardAvailable = false;
        var failureReported = false;
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
                    if (!guardAvailable)
                        Console.WriteLine($"GUARD_DELIVERY_OK | ACK reçu pour le message {message.MessageId}.");
                    guardAvailable = true;
                    failureReported = false;
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    if (guardAvailable || !failureReported)
                        Console.Error.WriteLine($"GUARD_DELIVERY_FAILED | messageId={message.MessageId} | {ex.GetType().Name}: {ex.Message}");
                    guardAvailable = false;
                    failureReported = true;
                    await store.ScheduleMessageRetryAsync(message.MessageId, ex.GetType().Name, Clock.GetUtcNow().AddMilliseconds(250), ct);
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

    private async Task HealthLoopAsync(CancellationToken ct, SourceOutageEpisodes sourceOutages)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        var healthMonitor = new TelemetryHealthMonitor();
        var sourceSessionId = Guid.NewGuid().ToString("N");
        long reportedDroppedCount = 0;
        while (await timer.WaitForNextTickAsync(ct))
        {
            var health = sourceHealth.GetHealth();
            if (health.DroppedCount > reportedDroppedCount)
            {
                var droppedDelta = health.DroppedCount - reportedDroppedCount;
                reportedDroppedCount = health.DroppedCount;
                var dropKey = $"{source.Name}|{sourceSessionId}|drops|{reportedDroppedCount}";
                var gapId = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(dropKey))).ToLowerInvariant();
                await PublishGapAsync(new TelemetryGap(gapId, source.Name, Clock.GetUtcNow(),
                    "The bounded collector queue discarded telemetry records.", droppedDelta, ["sourceEvents"]),
                    Clock.GetUtcNow().AddMinutes(1), ct);
            }

            // Loss totals are reported as deltas above. Evaluate only the current source state here,
            // so a historical drop does not keep a recovered source in an outage episode.
            var gap = healthMonitor.Evaluate(source.Name, health with { DroppedCount = 0 }, Clock.GetUtcNow());
            if (gap is null) { sourceOutages.MarkRecovered(); continue; }
            var firstGapForEpisode = sourceOutages.TryBegin(gap);
            if (firstGapForEpisode is not null)
                await PublishGapAsync(firstGapForEpisode, Clock.GetUtcNow().AddMinutes(1), ct);
        }
    }

    private sealed class SourceOutageEpisodes
    {
        private readonly object _gate = new();
        private bool _active;

        public TelemetryGap? TryBegin(TelemetryGap gap)
        {
            lock (_gate)
            {
                if (_active) return null;
                _active = true;
                return gap;
            }
        }

        public void MarkRecovered()
        {
            lock (_gate) _active = false;
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

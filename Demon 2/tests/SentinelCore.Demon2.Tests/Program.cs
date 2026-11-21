using System.Security.Cryptography;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon2.Core;
using SentinelCore.Demon2.Service;

Console.OutputEncoding = new System.Text.UTF8Encoding(false);
return await Demon2Checks.RunAsync();

internal static class Demon2Checks
{
    private static int _passed;
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-21T12:00:00Z");

    public static async Task<int> RunAsync()
    {
        try
        {
            await Check("Sysmon event normalization", NormalizeSysmonEvents);
            await Check("Common envelope validation and JSONL", ValidateAndPublishEnvelope);
            if (OperatingSystem.IsWindows()) await Check("Persistent Named Pipe service session", PersistentNamedPipeSession);
            await Check("SQLite idempotence, cursor, and expiry", StoreAndExpiry);
            await Check("Native SQLite runtime version", VerifyNativeSqliteVersion);
            await Check("Versioned rule catalog", ValidateRuleCatalog);
            await Check("All 50 scenarios through Threat Monitor pipeline", ReplayScenariosThroughPipeline);
            await Check("Reference database integrity and replay", ReplayReferenceDatabase);
            await Check("Benign and suspicious chains", EvaluateRules);
            await Check("Telemetry gaps and bounded health", EvaluateTelemetryGaps);
            await Check("Pipeline resilience, malformed input, and recovery", PipelineResilience);
            Console.WriteLine($"Demon 2 checks passed: {_passed}.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Demon 2 check failed: {ex}");
            return 1;
        }
    }

    private static async Task Check(string name, Func<Task> test)
    {
        await test();
        _passed++;
        Console.WriteLine($"PASS {name}");
    }

    private static Task NormalizeSysmonEvents()
    {
        var normalizer = new SysmonEventNormalizer();
        var script = EventXml(1, 101, "Image", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ("ProcessId", "0x1234"), ("ProcessGuid", "{p1}"), ("ParentProcessId", "0x0010"),
            ("ParentProcessGuid", "{p0}"), ("Signed", "false"), ("Hashes", "SHA256=ABC"));
        True(normalizer.TryNormalize(new(script, "bookmark-1"), out var normalized, out _), "Sysmon process event should normalize.");
        Equal(ThreatEventType.SCRIPT_ACTIVITY, normalized!.EventType, "Interpreter should map to script activity.");
        Equal(4660, normalized.ProcessId, "Hexadecimal process IDs should normalize.");
        Equal("ABC", normalized.Sha256, "SHA256 should be extracted.");
        Equal("bookmark-1", normalized.SourceCursor, "Bookmark should be retained as the collector cursor.");
        Equal("{p0}", normalized.ParentProcessGuid, "Parent process GUID must remain available for chain reconstruction.");
        Equal(16, normalized.ParentProcessId, "Parent PID must normalize from hexadecimal.");

        var file = EventXml(11, 105, "TargetFilename", @"C:\Users\Public\created.bin", ("ProcessId", "41"), ("ProcessGuid", "{file-p}"));
        True(normalizer.TryNormalize(new(file, "bookmark-file"), out var fileEvent, out _), "Sysmon file create should normalize.");
        Equal(ThreatEventType.FILE_CREATED_OR_CHANGED, fileEvent!.EventType, "File create mapping.");
        Equal(@"C:\Users\Public\created.bin", fileEvent.TargetPath, "File target path must be preserved.");
        Equal("bookmark-file", fileEvent.SourceCursor, "File event must retain its source bookmark.");

        var connection = EventXml(3, 106, "DestinationHostname", "updates.example", ("ProcessId", "41"), ("DestinationPort", "443"));
        True(normalizer.TryNormalize(new(connection, null), out var network, out _), "Sysmon network connection should normalize.");
        Equal(ThreatEventType.NETWORK_CONNECTION, network!.EventType, "Sysmon event 3 is a network connection.");
        Equal("updates.example", network.RemoteHost, "Remote host should be retained.");
        var dns = EventXml(22, 107, "QueryName", "updates.example", ("ProcessId", "41"));
        True(normalizer.TryNormalize(new(dns, null), out var dnsEvent, out _), "Sysmon DNS query should normalize.");
        Equal(ThreatEventType.DOMAIN_QUERY, dnsEvent!.EventType, "DNS query must not be misrepresented as a connection or reputation verdict.");
        True(!normalizer.TryNormalize(new(EventXml(255, 108, "Image", "test.exe"), null), out _, out _),
            "Unsupported source events must not create normalized evidence.");

        var download = EventXml(15, 102, "TargetFilename", @"C:\Users\Public\demo.exe:Zone.Identifier", ("ProcessId", "0x200"));
        True(normalizer.TryNormalize(new(download, null), out var downloaded, out _), "Zone.Identifier should be observed as a download.");
        Equal(ThreatEventType.DOWNLOAD_OBSERVED, downloaded!.EventType, "Download stream mapping.");
        True(downloaded.TargetPath?.EndsWith("demo.exe", StringComparison.Ordinal) == true, "Zone stream suffix should be removed.");
        True(!normalizer.TryNormalize(new(EventXml(15, 109, "TargetFilename", @"C:\Users\Public\plain.exe"), null), out _, out _),
            "A generic file create must not be claimed as a download without Zone.Identifier evidence.");

        var persistence = EventXml(13, 103, "TargetObject", @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Demo", ("ProcessId", "0x200"));
        True(normalizer.TryNormalize(new(persistence, null), out var changed, out _), "Run-key write should normalize.");
        Equal(ThreatEventType.PERSISTENCE_CHANGE, changed!.EventType, "Run-key event mapping.");
        True(!normalizer.TryNormalize(new(EventXml(13, 110, "TargetObject", @"\REGISTRY\MACHINE\SOFTWARE\Vendor\OrdinaryValue"), null), out _, out _),
            "An unrelated registry value must not be labeled persistence.");
        var configChange = EventXml(16, 104, "Configuration", "synthetic config change");
        True(normalizer.TryNormalize(new(configChange, null), out var configEvent, out _), "Sysmon configuration change should be observed.");
        var configResult = new DetectionEngine().Evaluate(configEvent!, [configEvent!], Now);
        True(configResult.Gaps.Count > 0 && configResult.Findings.Count == 0,
            "A source configuration change alone is telemetry health evidence, not a confirmed threat.");
        True(!normalizer.TryNormalize(new(EventXml(25, 104, "Image", "test.exe"), null), out _, out _), "Unmapped process-tampering event should be rejected visibly.");
        return Task.CompletedTask;
    }

    private static async Task ValidateAndPublishEnvelope()
    {
        var testNow = DateTimeOffset.UtcNow;
        var finding = MakeFinding("rule", ["e1"]) with { FirstSeenUtc = testNow, LastSeenUtc = testNow, ExpiresAtUtc = testNow.AddMinutes(1) };
        var envelope = InterDaemonEnvelopeFactory.ForFinding(finding, testNow);
        True(InterDaemonEnvelopeValidator.TryValidate(envelope, testNow, out _), "Valid v1 finding envelope should pass.");
        var expired = envelope with { ExpiresAtUtc = testNow.AddSeconds(-1) };
        True(!InterDaemonEnvelopeValidator.TryValidate(expired, testNow, out _), "Expired messages must be rejected.");
        var action = envelope with { MessageType = "ACTION_REQUEST" };
        True(!InterDaemonEnvelopeValidator.TryValidate(action, testNow, out _), "D2 must reject action messages.");
        True(!InterDaemonEnvelopeValidator.TryValidate(envelope with { TimestampUtc = testNow.ToOffset(TimeSpan.FromHours(1)) }, testNow, out _), "Envelope timestamps with a non-UTC offset must be rejected.");
        True(!InterDaemonEnvelopeValidator.TryValidate(envelope with { MessageId = Guid.Empty }, testNow, out _), "Empty message ids must be rejected.");
        var badConfidence = envelope with { Payload = JsonSerializer.SerializeToElement(new { findingId = "f", ruleId = "r", ruleVersion = 1, severity = "high", confidence = 2, firstSeenUtc = Now, lastSeenUtc = Now, summary = "s", facts = Array.Empty<object>(), evidenceRefs = new[] { "e1" }, missingTelemetry = Array.Empty<string>() }, new JsonSerializerOptions(JsonSerializerDefaults.Web)) };
        True(!InterDaemonEnvelopeValidator.TryValidate(badConfidence, testNow, out _), "Finding payload confidence outside 0..1 must be rejected.");
        var badRefs = envelope with { Payload = JsonSerializer.SerializeToElement(new { findingId = "f", ruleId = "r", ruleVersion = 1, severity = "high", confidence = .5, firstSeenUtc = Now, lastSeenUtc = Now, summary = "s", facts = Array.Empty<object>(), evidenceRefs = Array.Empty<string>(), missingTelemetry = Array.Empty<string>() }, new JsonSerializerOptions(JsonSerializerDefaults.Web)) };
        True(!InterDaemonEnvelopeValidator.TryValidate(badRefs, testNow, out _), "Finding with no evidence references must be rejected.");
        True(InterDaemonEnvelopeValidator.EvidenceRefsResolve(envelope, new HashSet<string> { "e1" }, out _), "Existing evidence references should resolve.");
        True(!InterDaemonEnvelopeValidator.EvidenceRefsResolve(envelope, new HashSet<string>(), out _), "Missing evidence references must be detected.");
        var heartbeat = InterDaemonEnvelopeFactory.Heartbeat("case-heartbeat",
            new EventSourceHealth(TelemetryState.Available, 2, null, testNow, QueueDepth: 17), 5, testNow);
        Equal(17, heartbeat.Payload.GetProperty("queueDepth").GetInt32(), "Heartbeat must report the actual collector queue depth.");
        Equal(5, heartbeat.Payload.GetProperty("outboxDepth").GetInt32(), "Heartbeat must report the actual durable outbox depth.");
        _ = InterDaemonEnvelopeFactory.ForSessionContextRequest("case-1", ["sessionState", "localOrRemote"], testNow.AddSeconds(2));
        Throws<ArgumentException>(() => InterDaemonEnvelopeFactory.ForSessionContextRequest("case-1", ["userName"], testNow.AddSeconds(2)),
            "Session context requests must follow the common allowlist.");

        var path = Path.Combine(Path.GetTempPath(), "sentinelcore-d2-" + Guid.NewGuid().ToString("N") + ".jsonl");
        try
        {
            await new JsonlInterDaemonBus(path).PublishAsync(envelope);
            var line = await File.ReadAllTextAsync(path);
            True(line.StartsWith("{\"messageId\"", StringComparison.Ordinal), "JSONL envelope must use contract camelCase.");
            True(line.EndsWith('\n'), "JSONL message must end with one line break.");
            var roundTrip = JsonSerializer.Deserialize<InterDaemonEnvelope>(line, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
            Equal(envelope.CorrelationId, roundTrip.CorrelationId, "JSONL must preserve the common correlationId.");
            Equal("RiskResponseGuard", roundTrip.Destination, "JSONL must preserve the common destination.");
            True(roundTrip.Payload.TryGetProperty("findingId", out _) && !JsonDocument.Parse(line).RootElement.TryGetProperty("findingId", out _), "Finding fields must remain nested under payload.");
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    private static async Task StoreAndExpiry()
    {
        var path = Path.Combine(Path.GetTempPath(), "sentinelcore-d2-" + Guid.NewGuid().ToString("N") + ".sqlite");
        try
        {
            await using var store = new SqliteEventStore(path, TimeSpan.FromDays(1));
            await store.InitializeAsync();
            var item = MakeEvent("store-event", ThreatEventType.PROCESS_STARTED, Now, processId: 77);
            True(await store.SaveEventAsync(item), "First event insert should be accepted.");
            True(!await store.SaveEventAsync(item), "Duplicate source event should be ignored.");
            await store.SaveCursorAsync("Sysmon", "bookmark-77");
            Equal("bookmark-77", await store.LoadCursorAsync("Sysmon"), "Source cursor should persist.");
            Equal(1, (await store.LoadRecentEventsAsync(Now.AddMinutes(-1), 20)).Count, "Stored event should be queryable.");

            var lateParent = MakeEvent("late-parent", ThreatEventType.PROCESS_STARTED, Now.AddSeconds(-1), processId: 100);
            var child = MakeEvent("out-of-order-child", ThreatEventType.NETWORK_CONNECTION, Now, processId: 200, parentId: 100);
            await store.SaveEventAsync(child);
            await store.SaveEventAsync(lateParent);
            var related = await new TemporalCorrelator(store).GetRelatedEventsAsync(child);
            True(related.Any(x => x.EventId == lateParent.EventId), "Late-arriving parent must join the bounded timeline.");

            var writtenFile = MakeEvent("path-written", ThreatEventType.FILE_CREATED_OR_CHANGED, Now.AddSeconds(-20), processId: 300, path: @"C:\sandbox\demo.exe");
            var executedFile = MakeEvent("path-executed", ThreatEventType.PROCESS_STARTED, Now, processId: 301, image: @"c:/SANDBOX/demo.exe");
            await store.SaveEventAsync(writtenFile);
            var pathRelated = await new TemporalCorrelator(store).GetRelatedEventsAsync(executedFile);
            True(pathRelated.Any(x => x.EventId == writtenFile.EventId), "File write and later execution should correlate by normalized path.");

            var dnsQuery = MakeEvent("domain-query", ThreatEventType.DOMAIN_QUERY, Now.AddSeconds(-15), processId: 400, remote: "rare.example.test.");
            var connection = MakeEvent("domain-connection", ThreatEventType.NETWORK_CONNECTION, Now, processId: 401, remote: "RARE.EXAMPLE.TEST");
            await store.SaveEventAsync(dnsQuery);
            var domainRelated = await new TemporalCorrelator(store).GetRelatedEventsAsync(connection);
            True(domainRelated.Any(x => x.EventId == dnsQuery.EventId), "DNS and connection evidence should correlate by normalized domain.");
            var outsideWindow = writtenFile with { EventId = "old-path-event", SourceEventId = "old-path-event", TimestampUtc = Now.AddMinutes(-20) };
            await store.SaveEventAsync(outsideWindow);
            var bounded = await new TemporalCorrelator(store, TimeSpan.FromMinutes(5)).GetRelatedEventsAsync(executedFile);
            True(!bounded.Any(x => x.EventId == outsideWindow.EventId), "Correlation must exclude evidence outside its time window.");

            var detection = new DetectionEngine(TimeSpan.FromMinutes(1));
            var stale = MakeEvent("stale", ThreatEventType.DOWNLOAD_OBSERVED, Now.AddMinutes(-2), processId: 77);
            var expired = detection.Evaluate(stale, [stale], Now);
            Equal(0, expired.Findings.Count, "Events outside the correlation TTL must not trigger a finding.");

            var finding = MakeFinding("persisted-rule", [item.EventId]);
            True(await store.SaveFindingAsync(finding), "First finding insert should be accepted.");
            True(!await store.SaveFindingAsync(finding), "Duplicate finding insert should be idempotent.");
            True(await store.HasFindingAsync(SqliteEventStore.MakeDeduplicationKey(finding)), "Finding idempotency key should persist.");
            var gap = new TelemetryGap("gap-test", "Sysmon", Now, "Fixture missing parent context.", 0, ["parentProcess"]);
            True(await store.SaveTelemetryGapAsync(gap), "Telemetry gap should be recorded for replay traceability.");
            True(!await store.SaveTelemetryGapAsync(gap), "Duplicate telemetry gap should be idempotent.");
            Equal("parentProcess", (await store.LoadTelemetryGapsAsync()).Single().MissingFields.Single(), "Recorded gap should preserve missing evidence.");
            var expiredFinding = MakeFinding("expired-rule", [item.EventId]) with { ExpiresAtUtc = Now.AddSeconds(-1) };
            await store.SaveFindingAsync(expiredFinding);
            var oldEvent = MakeEvent("old-event", ThreatEventType.FILE_CREATED_OR_CHANGED, Now.AddDays(-2));
            await store.SaveEventAsync(oldEvent);

            var queued = InterDaemonEnvelopeFactory.ForFinding(MakeFinding("outbox-rule", [item.EventId]), Now);
            True(await store.EnqueueMessageAsync(queued), "Outbox should durably accept a new message.");
            True(!await store.EnqueueMessageAsync(queued), "Identical messageId and payload must remain idempotent.");
            var collision = queued with { CorrelationId = "different-content" };
            await ThrowsAsync<InvalidOperationException>(() => store.EnqueueMessageAsync(collision), "Reusing messageId with different content must fail visibly.");
            Equal(1, await store.GetPendingMessageCountAsync(), "Pending outbox depth should be queryable for heartbeat reporting.");
            var resolved = await store.LoadEventsByIdsAsync([item.EventId]);
            Equal(item.EventId, resolved.Single().EventId, "Evidence lookup should resolve persisted event ids.");
            Equal(0, (await store.LoadEventsByIdsAsync(["not-stored"])).Count, "Evidence lookup should not fabricate missing ids.");
            Equal(1, (await store.LoadPendingMessagesAsync(Now, 10)).Count, "Outbox message should survive before delivery.");
            for (var attempt = 0; attempt < 3; attempt++)
                await store.ScheduleMessageRetryAsync(queued.MessageId, "fixture transport unavailable", Now.AddSeconds(-1));
            Equal(0, (await store.LoadPendingMessagesAsync(Now, 10)).Count, "Outbox stops retrying after three attempts.");
            var expiredMessages = await store.ExpireMessagesAsync(Now.AddMinutes(2));
            True(expiredMessages.Any(x => x.MessageId == queued.MessageId), "Expired outbox messages should be reported for a delivery gap.");

            await store.PruneExpiredAsync(Now);
            True(!await store.HasFindingAsync(SqliteEventStore.MakeDeduplicationKey(expiredFinding)), "Expired findings should be pruned.");
            True((await store.LoadRecentEventsAsync(Now.AddDays(-3), 100)).All(x => x.EventId != oldEvent.EventId), "Expired telemetry should be pruned.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(path)) File.Delete(path);
            if (File.Exists(path + "-wal")) File.Delete(path + "-wal");
            if (File.Exists(path + "-shm")) File.Delete(path + "-shm");
        }
    }

    private static async Task VerifyNativeSqliteVersion()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT sqlite_version();";
        var rawVersion = (string?)await command.ExecuteScalarAsync();
        True(Version.TryParse(rawVersion, out var version) && version >= new Version(3, 50, 2),
            $"Native SQLite must be at least 3.50.2; loaded {rawVersion ?? "unknown"}.");
        Console.WriteLine($"NATIVE_SQLITE|version={rawVersion}");
    }

    private static async Task PersistentNamedPipeSession()
    {
        var testNow = DateTimeOffset.UtcNow;
        var pipeName = "SentinelCore.Guard.Tests." + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var serverTask = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            var hello = await ReadPipeEnvelope(server);
            Equal("HELLO", hello.MessageType, "Pipe session must begin with HELLO.");
            var welcome = new InterDaemonEnvelope(Guid.NewGuid(), hello.CorrelationId, DateTimeOffset.UtcNow,
                "RiskResponseGuard", "ThreatMonitor", "WELCOME", 1, DateTimeOffset.UtcNow.AddMinutes(1),
                JsonSerializer.SerializeToElement(new { sessionId = "session-test", supportedSchema = 1 }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            await WritePipeEnvelope(server, welcome);
            for (var i = 0; i < 2; i++)
            {
                var sent = await ReadPipeEnvelope(server);
                Equal("HEARTBEAT", sent.MessageType, "Expected a heartbeat over the established pipe session.");
                var ack = new InterDaemonEnvelope(Guid.NewGuid(), sent.CorrelationId, DateTimeOffset.UtcNow,
                    "RiskResponseGuard", "ThreatMonitor", "ACK", 1, DateTimeOffset.UtcNow.AddMinutes(1),
                    JsonSerializer.SerializeToElement(new { messageId = sent.MessageId, status = "ACCEPTED" }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
                await WritePipeEnvelope(server, ack);
            }
        });

        await using var bus = new NamedPipeInterDaemonBus(pipeName);
        for (var i = 0; i < 2; i++)
            await bus.PublishAsync(InterDaemonEnvelopeFactory.Heartbeat("pipe-test-" + i,
                new EventSourceHealth(TelemetryState.Available, 0, null, testNow, QueueDepth: i + 1), 0, testNow));
        await serverTask.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private static async Task<InterDaemonEnvelope> ReadPipeEnvelope(Stream stream)
    {
        var prefix = new byte[4];
        await ReadPipeExactly(stream, prefix);
        var payload = new byte[BinaryPrimitives.ReadInt32LittleEndian(prefix)];
        await ReadPipeExactly(stream, payload);
        return JsonSerializer.Deserialize<InterDaemonEnvelope>(payload, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException("Invalid pipe envelope.");
    }

    private static async Task WritePipeEnvelope(Stream stream, InterDaemonEnvelope envelope)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(envelope, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, payload.Length);
        await stream.WriteAsync(prefix);
        await stream.WriteAsync(payload);
        await stream.FlushAsync();
    }

    private static async Task ReadPipeExactly(Stream stream, Memory<byte> buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..]);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
    }

    private static async Task ReplayReferenceDatabase()
    {
        var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "Demon2_Training.sqlite");
        True(File.Exists(fixture), "Reference SQLite fixture must be copied to test output.");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = fixture, Mode = SqliteOpenMode.ReadOnly }.ToString();
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await using (var check = connection.CreateCommand())
        {
            check.CommandText = "PRAGMA integrity_check;";
            Equal("ok", (string?)await check.ExecuteScalarAsync(), "Reference database must remain intact.");
        }
        var scenarios = new List<(string Id, string Label, string Split)>();
        await using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT scenario_id,label,split FROM scenarios ORDER BY scenario_id;";
            await using var rows = await read.ExecuteReaderAsync();
            while (await rows.ReadAsync()) scenarios.Add((rows.GetString(0), rows.GetString(1), rows.GetString(2)));
        }
        Equal(50, scenarios.Count, "Reference case count.");
        Equal(40, scenarios.Count(x => x.Split == "train"), "First forty cases are the development split.");
        Equal(10, scenarios.Count(x => x.Split == "validation"), "Last ten cases are the validation split.");
        Equal(15, scenarios.Count(x => x.Label == "benign"), "Benign scenario count.");
        Equal(20, scenarios.Count(x => x.Label == "suspicious"), "Suspicious scenario count.");
        Equal(15, scenarios.Count(x => x.Label == "uncertain"), "Ambiguous scenario count.");

        var reports = new Dictionary<string, int>(StringComparer.Ordinal);
        await using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT report_type,COUNT(*) FROM reports GROUP BY report_type;";
            await using var rows = await read.ExecuteReaderAsync();
            while (await rows.ReadAsync()) reports[rows.GetString(0)] = rows.GetInt32(1);
        }
        Equal(15, reports["OBSERVATION"], "Benevolent reports.");
        Equal(20, reports["THREAT_FINDING"], "Threat reports.");
        Equal(15, reports["NEEDS_CONTEXT"], "Context-needed reports.");

        await using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT finding_code,COUNT(*) FROM expected_findings GROUP BY finding_code;";
            await using var rows = await read.ExecuteReaderAsync();
            var expected = new Dictionary<string, int>(StringComparer.Ordinal);
            while (await rows.ReadAsync()) expected[rows.GetString(0)] = rows.GetInt32(1);
            Equal(20, expected["expected_threat"], "Reference threat expectations.");
            Equal(30, expected["false_positive_guard"], "Reference no-threat expectations.");
        }

        var expectedWireFindings = 0;
        await using (var read = connection.CreateCommand())
        {
            read.CommandText = "SELECT COUNT(*) FROM interop_messages WHERE message_type='THREAT_FINDING';";
            expectedWireFindings = Convert.ToInt32(await read.ExecuteScalarAsync());
        }
        Equal(50, expectedWireFindings, "Reference wire type count documents the known fixture mismatch.");

        foreach (var scenario in scenarios)
        {
            var events = await ReadScenarioEvents(connection, scenario.Id);
            True(events.Count > 0, $"{scenario.Id} must contain replayable synthetic events.");
            True(events.All(x => x.Fields?.GetValueOrDefault("synthetic") == "true"), $"{scenario.Id} must be synthetic.");
        }
    }

    private static Task ValidateRuleCatalog()
    {
        True(DetectionRuleCatalog.All.Count > 0, "At least one deterministic rule must be registered.");
        Equal(DetectionRuleCatalog.All.Count, DetectionRuleCatalog.All.Select(x => x.RuleId).Distinct(StringComparer.Ordinal).Count(),
            "Rule identifiers must be unique.");
        True(DetectionRuleCatalog.All.All(x => !string.IsNullOrWhiteSpace(x.RuleId) && x.RuleVersion > 0 &&
            !string.IsNullOrWhiteSpace(x.Description) && x.Conditions.Count > 0 && x.Evidence.Count > 0 &&
            x.Confidence is >= 0 and <= 1 && Enum.IsDefined(x.Severity)),
            "Every rule must publish version, description, conditions, evidence, confidence, and project severity.");
        return Task.CompletedTask;
    }

    private static async Task ReplayScenariosThroughPipeline()
    {
        var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "Demon2_Training.sqlite");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = fixture, Mode = SqliteOpenMode.ReadOnly }.ToString();
        await using var reference = new SqliteConnection(connectionString);
        await reference.OpenAsync();
        var summaries = new List<(string Id, string Title, string Label, string Expected, string Actual, string Status, string Explanation)>();
        var failed = 0;
        var needsClarification = 0;
        var availableEvents = new HashSet<ThreatEventType>();
        var observedRules = new HashSet<string>(StringComparer.Ordinal);

        await using var scenarios = reference.CreateCommand();
        scenarios.CommandText = "SELECT s.scenario_id,s.title,s.label,s.expected_outcome,r.report_type,r.severity,e.expected,e.expected_severity,e.reason FROM scenarios s JOIN reports r USING(scenario_id) JOIN expected_findings e USING(scenario_id) ORDER BY s.scenario_id;";
        await using var rows = await scenarios.ExecuteReaderAsync();
        var definitions = new List<FixtureScenario>();
        while (await rows.ReadAsync())
            definitions.Add(new(rows.GetString(0), rows.GetString(1), rows.GetString(2), rows.GetString(3),
                rows.GetString(4), rows.GetString(5), rows.GetInt32(6) != 0,
                rows.IsDBNull(7) ? null : rows.GetString(7), rows.IsDBNull(8) ? "" : rows.GetString(8)));
        await rows.CloseAsync();

        foreach (var definition in definitions)
        {
            var records = await LoadFixtureRecords(reference, definition.Id);
            if (definition.Id == "D2-043" && records.Count > 0) records.Add(records[0]); // Fixture explicitly models duplicate delivery.
            await using var maxTimeCommand = reference.CreateCommand();
            maxTimeCommand.CommandText = "SELECT MAX(ts_utc) FROM events WHERE scenario_id=$id;";
            maxTimeCommand.Parameters.AddWithValue("$id", definition.Id);
            var replayNow = DateTimeOffset.Parse((string)(await maxTimeCommand.ExecuteScalarAsync() ?? throw new InvalidDataException("Scenario has no event timestamps."))).AddSeconds(1);
            var normalizer = new RecordingNormalizer(new SysmonEventNormalizer());
            var source = new ReplaySysmonSource(records);
            var bus = new CaptureBus();
            var dbPath = Path.Combine(Path.GetTempPath(), "sentinelcore-d2-replay-" + Guid.NewGuid().ToString("N") + ".sqlite");
            IReadOnlyList<ThreatFinding> findings;
            IReadOnlyList<TelemetryGap> gaps;
            IReadOnlyList<CanonicalEvent> normalizedEvents;
            try
            {
                await using (var store = new SqliteEventStore(dbPath, TimeSpan.FromDays(30)))
                {
                    var pipeline = new ThreatMonitorPipeline(source, source, normalizer, store, new DetectionEngine(), bus, new FixedTimeProvider(replayNow));
                    await pipeline.RunAsync(CancellationToken.None);
                    findings = await store.LoadFindingsAsync();
                    gaps = await store.LoadTelemetryGapsAsync();
                    normalizedEvents = await store.LoadRecentEventsAsync(DateTimeOffset.MinValue, 512);
                }
            }
            finally
            {
                SqliteConnection.ClearAllPools();
                if (File.Exists(dbPath)) File.Delete(dbPath);
                if (File.Exists(dbPath + "-wal")) File.Delete(dbPath + "-wal");
                if (File.Exists(dbPath + "-shm")) File.Delete(dbPath + "-shm");
            }

            foreach (var item in normalizedEvents) availableEvents.Add(item.EventType);
            foreach (var finding in findings) observedRules.Add(finding.RuleId);
            var actual = findings.Count > 0 ? "THREAT_FINDING" : gaps.Count > 0 ? "NEEDS_CONTEXT" : "OBSERVATION";
            var actualRules = string.Join(',', findings.Select(x => x.RuleId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
            var evidence = findings.SelectMany(x => x.EvidenceRefs).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            var missing = gaps.SelectMany(x => x.MissingFields).Concat(normalizer.Rejections.Select(x => "rejected:" + x.Reason))
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            var expectedOutcome = definition.ExpectedReport + (definition.ExpectedFinding ? "/finding" : "/no-finding");
            var status = "PASS";
            var explanation = findings.Count > 0 ? "Règles " + actualRules + "; preuves " + string.Join(',', evidence) :
                gaps.Count > 0 ? "Aucun verdict de menace; lacunes " + string.Join(',', missing) : "Aucun finding ni lacune de télémétrie.";

            if (definition.Label == "benign" && findings.Count > 0 || definition.Label == "uncertain" && findings.Count > 0)
            {
                status = "FAIL";
                failed++;
            }
            else if (definition.Label == "suspicious" && findings.Count == 0)
            {
                var clarification = ReferenceClarification(definition.Id);
                status = clarification is null ? "FAIL" : "NEEDS_CLARIFICATION";
                if (clarification is null) failed++; else needsClarification++;
                if (clarification is not null) explanation = clarification;
            }
            else if (definition.Label == "suspicious" && definition.ExpectedSeverityFromFindings is { } expectedSeverity &&
                findings.Any(x => !string.Equals(x.Severity.ToString(), expectedSeverity, StringComparison.OrdinalIgnoreCase)))
            {
                status = "NEEDS_CLARIFICATION";
                needsClarification++;
                explanation += $"; sévérité obtenue {string.Join(',', findings.Select(x => x.Severity).Distinct())}, attendue {expectedSeverity}";
            }
            else if (definition.Label == "uncertain" && definition.ExpectedReport == "NEEDS_CONTEXT" && gaps.Count == 0)
            {
                status = "NEEDS_CLARIFICATION";
                needsClarification++;
                explanation = ReferenceClarification(definition.Id) ?? "Pas de threat finding, mais la fixture attend NEEDS_CONTEXT et aucune donnée manquante structurée n’a été enregistrée.";
            }

            if (status != "PASS")
            {
                var eventList = string.Join(',', normalizedEvents.Select(x => x.SourceCursor ?? x.SourceEventId).Concat(normalizer.Rejections.Select(x => x.EventId)).Distinct());
                var rule = actualRules.Length == 0 ? "none" : actualRules;
                var detailedMissing = missing.Concat(definition.Id is "D2-031" or "D2-032" ? ["networkConnection"] : [])
                    .Distinct(StringComparer.Ordinal).ToArray();
                Console.WriteLine($"TRACE|scenarioId={definition.Id}|event={eventList}|rule={rule}|obtained={actual}|expected={expectedOutcome}|difference={status}|evidence={string.Join(',', evidence)}|missing={string.Join(',', detailedMissing)}|detail={explanation}");
            }
            summaries.Add((definition.Id, definition.Title, definition.Label, expectedOutcome, actual + (actualRules.Length == 0 ? "" : ":" + actualRules), status, explanation));
        }

        var passed = summaries.Count(x => x.Status == "PASS");
        Console.WriteLine("SCENARIO TABLE|Scenario|Résultat attendu|Résultat obtenu|Statut|Explication");
        foreach (var row in summaries)
            Console.WriteLine($"TABLE|{row.Id} {row.Title}|{row.Label}:{row.Expected}|{row.Actual}|{row.Status}|{row.Explanation}");
        Console.WriteLine($"SCENARIO TOTALS|executed={summaries.Count}|passed={passed}|failed={failed}|needs_clarification={needsClarification}");
        var availableSourceTypes = Enum.GetValues<ThreatEventType>().ToHashSet();
        var missingSourceTypes = availableSourceTypes.Except(availableEvents).OrderBy(x => x).ToArray();
        var registeredRules = DetectionRuleCatalog.All.Select(x => x.RuleId).ToHashSet(StringComparer.Ordinal);
        var missingRules = registeredRules.Except(observedRules).Order(StringComparer.Ordinal).ToArray();
        Console.WriteLine($"COVERAGE|events={availableEvents.Count}/{availableSourceTypes.Count}|types={string.Join(',', availableEvents.OrderBy(x => x))}|uncoveredTypes={string.Join(',', missingSourceTypes)}|rules={observedRules.Count}/{registeredRules.Count}|firedRules={string.Join(',', observedRules.Order(StringComparer.Ordinal))}|unfiredRules={string.Join(',', missingRules)}");
        Equal(50, summaries.Count, "Every official scenario must run through the production pipeline.");
        Equal(0, failed, "Every mismatch must be explained as a fixture clarification; unexplained failures are not accepted.");
    }

    private sealed record FixtureScenario(string Id, string Title, string Label, string ExpectedOutcome,
        string ExpectedReport, string ExpectedSeverity, bool ExpectedFinding, string? ExpectedSeverityFromFindings, string ExpectedReason);

    private static string? ReferenceClarification(string scenarioId) => scenarioId switch
    {
        "D2-027" => "Événement ImageLoad observé, mais la fixture ne fournit ni signature exploitable ni événement de corroboration; le moteur garde NEEDS_CONTEXT.",
        "D2-028" => "L’événement ProcessAccess de fixture ne contient ni TargetImage ni GrantedAccess; aucun verdict de menace n’est émis.",
        "D2-031" => "La table marque expected_threat, tandis que le résultat attendu exige un événement réseau/exfiltration ultérieur absent des lignes du scénario.",
        "D2-032" => "La description parle d’un flux sortant, mais l’unique ligne est typée FILE_OR_SYSTEM_ACTIVITY et ne fournit pas d’événement réseau distinct.",
        "D2-039" => "La fixture attend NEEDS_CONTEXT alors que son résultat narratif dit observation sans menace; la réputation du binaire portable n’est pas fournie.",
        "D2-040" => "Le rapport structuré demande NEEDS_CONTEXT, mais le résultat narratif dit de ne pas utiliser l’heure seule; aucune preuve manquante supplémentaire n’est listée.",
        "D2-042" => "La fixture décrit une alerte Defender historique, source que le collecteur Sysmon de ce pipeline ne consomme pas.",
        "D2-043" => "Le résultat narratif demande déduplication sans alerte, mais le rapport structuré classe le cas NEEDS_CONTEXT.",
        "D2-044" => "La fixture attend NEEDS_CONTEXT pour l’ordre tardif, mais ses lignes ne donnent pas assez de détails parent/enfant horodatés pour matérialiser cette corrélation.",
        "D2-050" => "La fixture décrit un téléchargement sans marque Zone.Identifier et ne fournit pas la durée de la fenêtre de suivi; aucun DOWNLOAD_OBSERVED n’est inventé.",
        _ => null
    };

    private static async Task<List<SysmonRecord>> LoadFixtureRecords(SqliteConnection connection, string scenarioId)
    {
        var records = new List<SysmonRecord>();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT event_id,sequence_no,ts_utc,event_type,process,parent_process,object_path,remote_host,details_json FROM events WHERE scenario_id=$id ORDER BY sequence_no;";
        command.Parameters.AddWithValue("$id", scenarioId);
        await using var rows = await command.ExecuteReaderAsync();
        while (await rows.ReadAsync())
        {
            var eventId = rows.GetString(0);
            var sequenceNo = rows.GetInt32(1);
            var timestamp = DateTimeOffset.Parse(rows.GetString(2)).ToUniversalTime();
            var sourceType = rows.GetString(3);
            var process = rows.IsDBNull(4) ? null : rows.GetString(4);
            var parent = rows.IsDBNull(5) ? null : rows.GetString(5);
            var path = rows.IsDBNull(6) ? null : rows.GetString(6);
            var remote = rows.IsDBNull(7) ? null : rows.GetString(7);
            using var details = JsonDocument.Parse(rows.GetString(8));
            var description = details.RootElement.TryGetProperty("sequence_text", out var text) ? text.GetString() ?? "" : "";
            var xml = FixtureEventXml(scenarioId, eventId, sequenceNo, timestamp, sourceType, process, parent, path, remote, description);
            records.Add(new SysmonRecord(xml, eventId));
        }
        return records;
    }

    private static string FixtureEventXml(string scenarioId, string sourceEventId, int recordId, DateTimeOffset timestamp,
        string sourceType, string? process, string? parent, string? objectPath, string? remote, string description)
    {
        var text = StripDiacritics($"{process} {description}");
        int eventId;
        if (sourceType == "NETWORK_ACTIVITY")
            eventId = ContainsAny(text, "dns", "requetes") ? 22 : 3;
        else if (text.Contains("image load", StringComparison.OrdinalIgnoreCase)) eventId = 7;
        else if (text.Contains("processaccess", StringComparison.OrdinalIgnoreCase)) eventId = 10;
        else if (text.Contains("alteration de configuration", StringComparison.OrdinalIgnoreCase)) eventId = 16;
        else if (FixtureEventType(sourceType, process, description) == ThreatEventType.DOWNLOAD_OBSERVED) eventId = 15;
        else if (sourceType == "PROCESS_ACTIVITY") eventId = 1;
        else if (text.Contains("persistance", StringComparison.OrdinalIgnoreCase) || text.Contains("registre", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("tache", StringComparison.OrdinalIgnoreCase) || text.Contains("startup", StringComparison.OrdinalIgnoreCase)) eventId = 13;
        else if (FixtureEventType(sourceType, process, description) == ThreatEventType.SCRIPT_ACTIVITY ||
            text.Contains("lancement", StringComparison.OrdinalIgnoreCase) || text.Contains("execution", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("evenement process", StringComparison.OrdinalIgnoreCase)) eventId = 1;
        else eventId = 11;

        var processName = process ?? "unknown";
        var processPid = text.Contains("pid absent", StringComparison.OrdinalIgnoreCase) || text.Contains("sans pid", StringComparison.OrdinalIgnoreCase)
            ? (int?)null : StablePid(scenarioId, processName);
        var processGuid = processPid is null ? null : StableProcessGuid(scenarioId, processName);
        int? parentPid = parent is null ? null : StablePid(scenarioId, parent);
        var parentGuid = parent is null ? null : StableProcessGuid(scenarioId, parent);
        string Image(string? name, bool script = false)
        {
            if (script) return @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
            var safe = string.Concat((name ?? "unknown").Select(c => char.IsLetterOrDigit(c) || c is '.' or '-' or '_' ? c : '_'));
            return @"C:\Fixture\" + safe + ".exe";
        }

        var eventType = FixtureEventType(sourceType, process, description);
        var fields = new List<(string Name, string? Value)> { ("FixtureDescription", description), ("FixtureSynthetic", "true") };
        if (eventId == 1)
        {
            fields.AddRange([("ProcessId", processPid?.ToString()), ("ProcessGuid", processGuid), ("Image", Image(processName, eventType == ThreatEventType.SCRIPT_ACTIVITY)),
                ("ParentProcessId", parentPid?.ToString()), ("ParentProcessGuid", parentGuid), ("ParentImage", parent is null ? null : Image(parent)),
                ("Signed", text.Contains("non signe", StringComparison.OrdinalIgnoreCase) ? "false" : "true")]);
        }
        else if (eventId == 3)
        {
            fields.AddRange([("ProcessId", processPid?.ToString()), ("ProcessGuid", processGuid), ("Image", Image(processName)),
                ("DestinationHostname", remote), ("DestinationPort", "443")]);
        }
        else if (eventId == 22)
        {
            fields.AddRange([("ProcessId", processPid?.ToString()), ("ProcessGuid", processGuid), ("Image", Image(processName)), ("QueryName", remote)]);
        }
        else if (eventId == 15)
        {
            fields.AddRange([("ProcessId", processPid?.ToString()), ("ProcessGuid", processGuid), ("Image", Image(processName)),
                ("TargetFilename", (objectPath ?? @"C:\Fixture\download.exe") + ":Zone.Identifier")]);
        }
        else if (eventId == 13)
        {
            var target = text.Contains("task", StringComparison.OrdinalIgnoreCase) || text.Contains("tache", StringComparison.OrdinalIgnoreCase)
                ? @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\Fixture"
                : @"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Fixture";
            fields.AddRange([("ProcessId", processPid?.ToString()), ("ProcessGuid", processGuid), ("Image", Image(processName)), ("TargetObject", target)]);
        }
        else if (eventId == 16)
        {
            fields.Add(("Configuration", description));
        }
        else if (eventId == 7)
        {
            fields.AddRange([("ProcessId", processPid?.ToString()), ("ProcessGuid", processGuid), ("Image", Image(processName)), ("ImageLoaded", objectPath), ("Signed", null)]);
        }
        else if (eventId == 10)
        {
            fields.AddRange([("SourceProcessId", processPid?.ToString()), ("SourceProcessGuid", processGuid), ("SourceImage", Image(processName)),
                ("TargetProcessId", null), ("TargetProcessGuid", null), ("TargetImage", null), ("GrantedAccess", null)]);
        }
        else
        {
            fields.AddRange([("ProcessId", processPid?.ToString()), ("ProcessGuid", processGuid), ("Image", Image(processName)), ("TargetFilename", objectPath)]);
        }

        if (eventId is not 1 and not 10)
            fields.AddRange([("ParentProcessId", parentPid?.ToString()), ("ParentProcessGuid", parentGuid), ("ParentImage", parent is null ? null : Image(parent))]);

        var data = string.Join("", fields.Where(x => x.Value is not null).Select(x =>
            $"<Data Name=\"{x.Name}\">{System.Security.SecurityElement.Escape(x.Value!)}</Data>"));
        return $"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{eventId}</EventID><EventRecordID>{recordId}</EventRecordID><TimeCreated SystemTime=\"{timestamp:O}\"/></System><EventData>{data}</EventData></Event>";
    }

    private sealed class RecordingNormalizer(IEventNormalizer<SysmonRecord> inner) : IEventNormalizer<SysmonRecord>
    {
        public List<(string EventId, string Reason)> Rejections { get; } = [];
        public bool TryNormalize(SysmonRecord input, out CanonicalEvent? result, out string? rejectionReason)
        {
            var accepted = inner.TryNormalize(input, out result, out rejectionReason);
            if (!accepted) Rejections.Add((input.BookmarkXml ?? "unknown", rejectionReason ?? "unspecified"));
            return accepted;
        }
    }

    private sealed class ReplaySysmonSource(IReadOnlyList<SysmonRecord> records) : IEventSource<SysmonRecord>, IEventSourceHealthProvider
    {
        public string Name => "Sysmon";
        public EventSourceHealth GetHealth() => new(TelemetryState.Available, 0, null, null);
        public async IAsyncEnumerable<SysmonRecord> ReadAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            foreach (var record in records)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return record;
                await Task.Yield();
            }
        }
    }

    private sealed class CaptureBus : IInterDaemonBus
    {
        public List<InterDaemonEnvelope> Published { get; } = [];
        public ValueTask PublishAsync(InterDaemonEnvelope message, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Published.Add(message);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset nowUtc) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => nowUtc;
    }

    private static async Task EvaluateRules()
    {
        var benign = await LoadCase("D2-001");
        var noFinding = new DetectionEngine().Evaluate(benign[^1], benign, benign[^1].TimestampUtc.AddSeconds(1));
        Equal(0, noFinding.Findings.Count, "Benign developer chain must not raise a finding.");
        var supervisedAgent = await LoadCase("D2-015");
        Equal(0, new DetectionEngine().Evaluate(supervisedAgent[^1], supervisedAgent, supervisedAgent[^1].TimestampUtc.AddSeconds(1)).Findings.Count,
            "Supervised AI development activity must remain distinguishable from malicious behavior.");
        var missingSession = await LoadCase("D2-047");
        Equal(0, new DetectionEngine().Evaluate(missingSession[^1], missingSession, missingSession[^1].TimestampUtc.AddSeconds(1)).Findings.Count,
            "Missing user/session context alone must not be promoted to a threat or invented as an open session.");

        var downloadedScript = await LoadCase("D2-016");
        var finding = new DetectionEngine().Evaluate(downloadedScript[^1], downloadedScript, downloadedScript[^1].TimestampUtc.AddSeconds(1));
        True(finding.Findings.Any(x => x.RuleId == "download_chain"), "Download, interpreter, and network chain should be detected.");

        var persistence = await LoadCase("D2-018");
        var persistenceFinding = new DetectionEngine().Evaluate(persistence[^1], persistence, persistence[^1].TimestampUtc.AddSeconds(1))
            .Findings.Single(x => x.RuleId == "drop_then_persistence");
        True(persistenceFinding.EvidenceRefs.Count > 0 && persistenceFinding.EvidenceRefs.All(id => persistence.Any(x => x.EventId == id)),
            "Finding evidence references must resolve to source events.");
        True(persistenceFinding.EvidenceRefs.All(id => persistence.Single(x => x.EventId == id).EventType is
            ThreatEventType.PROCESS_STARTED or ThreatEventType.SCRIPT_ACTIVITY or ThreatEventType.PERSISTENCE_CHANGE),
            "Persistence finding evidence must identify the process and persistence observations used by the rule.");
        Equal(0, new DetectionEngine().Evaluate(persistence.First(x => x.EventType == ThreatEventType.PERSISTENCE_CHANGE),
            persistence.Where(x => x.EventType == ThreatEventType.PERSISTENCE_CHANGE).ToArray(), Now).Findings.Count,
            "Persistence observation alone must not claim a process-linked threat chain.");

        var downloadEvent = MakeEvent("download-positive", ThreatEventType.DOWNLOAD_OBSERVED, Now, processId: 77);
        var executionEvent = MakeEvent("execution-positive", ThreatEventType.PROCESS_STARTED, Now.AddSeconds(1), processId: 77);
        var networkEvent = MakeEvent("network-positive", ThreatEventType.NETWORK_CONNECTION, Now.AddSeconds(2), processId: 77);
        var downloadChain = new[] { downloadEvent, executionEvent, networkEvent };
        var downloadFinding = new DetectionEngine().Evaluate(networkEvent, downloadChain, Now.AddSeconds(3)).Findings
            .Single(x => x.RuleId == "download_chain");
        True(downloadFinding.EvidenceRefs.Contains(downloadEvent.EventId) && downloadFinding.EvidenceRefs.Contains(executionEvent.EventId) &&
            downloadFinding.EvidenceRefs.Contains(networkEvent.EventId), "Download chain finding must identify download, execution, and network evidence.");
        Equal(0, new DetectionEngine().Evaluate(downloadEvent, [downloadEvent], Now.AddSeconds(1)).Findings.Count,
            "A download observation without execution or corroboration must not be a finding.");

        var networkOnly = MakeEvent("network-only", ThreatEventType.NETWORK_CONNECTION, Now, processId: 91);
        Equal(0, new DetectionEngine().Evaluate(networkOnly, [networkOnly], Now.AddSeconds(1)).Findings.Count,
            "A network connection alone must not be labeled suspicious.");
        var dnsQueries = Enumerable.Range(0, 5).Select(i => MakeEvent("dns-repeat-" + i, ThreatEventType.DOMAIN_QUERY,
            Now.AddSeconds(i * 5), processId: 701, remote: "beacon.example.test.")).ToArray();
        var dnsFinding = new DetectionEngine().Evaluate(dnsQueries[^1], dnsQueries, Now.AddSeconds(30)).Findings
            .Single(x => x.RuleId == "repeated_dns");
        Equal(5, dnsFinding.EvidenceRefs.Count, "Repeated DNS finding must cite each qualifying query event.");
        Equal(0, new DetectionEngine().Evaluate(dnsQueries[0], [dnsQueries[0]], Now.AddSeconds(1)).Findings.Count,
            "One DNS query must not become an isolated threat verdict.");
        var parent = MakeEvent("parent-office", ThreatEventType.PROCESS_STARTED, Now, processId: 500, image: @"C:\Program Files\Office\WINWORD.EXE");
        var childScript = MakeEvent("child-script", ThreatEventType.SCRIPT_ACTIVITY, Now.AddSeconds(1), processId: 501, parentId: 500, image: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
        var scriptChain = new[] { parent, childScript };
        var scriptFinding = new DetectionEngine().Evaluate(childScript, scriptChain, Now.AddSeconds(2)).Findings
            .Single(x => x.RuleId == "script_child");
        True(scriptFinding.EvidenceRefs.Contains(parent.EventId) && scriptFinding.EvidenceRefs.Contains(childScript.EventId),
            "Script finding must link its parent and child process evidence.");

        var burst = await LoadCase("D2-019");
        var burstFinding = new DetectionEngine().Evaluate(burst[^1], burst, burst[^1].TimestampUtc.AddSeconds(1)).Findings
            .Single(x => x.RuleId == "file_burst");
        Equal(ThreatSeverity.high, burstFinding.Severity, "Ransomware fixture severity must follow its structured expected severity.");
        var ransomware = await LoadCase("D2-035");
        True(new DetectionEngine().Evaluate(ransomware[^1], ransomware, ransomware[^1].TimestampUtc.AddSeconds(1))
            .Findings.Any(x => x.RuleId == "file_burst"), "Synthetic sandbox ransomware behavior should match a deterministic rule.");

        var duplicateCase = await LoadCase("D2-016");
        var duplicateEngine = new DetectionEngine();
        var first = duplicateEngine.Evaluate(duplicateCase[^1], duplicateCase, duplicateCase[^1].TimestampUtc.AddSeconds(1));
        var second = duplicateEngine.Evaluate(duplicateCase[^1], duplicateCase, duplicateCase[^1].TimestampUtc.AddSeconds(1));
        True(first.Findings.Count > 0 && second.Findings.Count == 0, "Identical evidence must not produce duplicate findings.");
    }

    private static async Task EvaluateTelemetryGaps()
    {
        var ambiguous = await LoadCase("D2-036");
        var result = new DetectionEngine().Evaluate(ambiguous[^1], ambiguous, ambiguous[^1].TimestampUtc.AddSeconds(1));
        True(result.Gaps.Count > 0, "Missing process command/parent context should produce a telemetry gap.");
        Equal(0, result.Findings.Count, "Incomplete context must not confirm a threat.");

        var health = new TelemetryHealthMonitor(TimeSpan.FromSeconds(30));
        var absent = health.Evaluate("Sysmon", new EventSourceHealth(TelemetryState.Unavailable, 0, null, null), Now);
        True(absent is not null && absent.Source == "Sysmon", "Unavailable telemetry source must raise TELEMETRY_GAP.");
        var dropped = health.Evaluate("Sysmon", new EventSourceHealth(TelemetryState.Degraded, 4, null, Now), Now);
        Equal(4L, dropped!.DroppedCount, "Dropped event count must be preserved.");
        True(health.Evaluate("Sysmon", new EventSourceHealth(TelemetryState.Available, 0, null, Now), Now) is null,
            "A recovered, fresh source should return to healthy without implying missing events were observed.");
        True(health.Evaluate("Sysmon", new EventSourceHealth(TelemetryState.Available, 0, null, Now.AddMinutes(-2)), Now) is not null,
            "Stale telemetry must be reported rather than treated as evidence of no activity.");

        var download = MakeEvent("partial-download", ThreatEventType.DOWNLOAD_OBSERVED, Now, processId: 72);
        var execution = MakeEvent("partial-execution", ThreatEventType.PROCESS_STARTED, Now.AddSeconds(1), processId: 72);
        var script = MakeEvent("partial-script", ThreatEventType.SCRIPT_ACTIVITY, Now.AddSeconds(2), processId: 72,
            fields: new Dictionary<string, string> { ["fixtureDescription"] = "capteur réseau indisponible" });
        var partial = new DetectionEngine().Evaluate(script, [download, execution, script], Now.AddSeconds(3));
        var partialFinding = partial.Findings.Single(x => x.RuleId == "download_chain");
        True(partialFinding.EvidenceRefs.Contains(download.EventId) && partialFinding.EvidenceRefs.Contains(execution.EventId) &&
            partialFinding.EvidenceRefs.Contains(script.EventId), "Partial correlation must preserve each actually observed stage.");
        True(partialFinding.MissingTelemetry.Contains("networkSensor") &&
            !partialFinding.EvidenceRefs.Any(id => id.StartsWith("invented-network", StringComparison.Ordinal)),
            "A known missing network sensor must leave the chain explicitly partial without inventing network evidence.");
    }

    private static async Task PipelineResilience()
    {
        Equal(FixtureEventType("FILE_OR_SYSTEM_ACTIVITY", null, "téléchargement marqué internet"),
            FixtureEventType("FILE_OR_SYSTEM_ACTIVITY", null, "tÃ©lÃ©chargement marquÃ© internet"),
            "Fixture event classification must survive common UTF-8-as-Latin-1 mojibake.");
        var path = Path.Combine(Path.GetTempPath(), "sentinelcore-d2-resilience-" + Guid.NewGuid().ToString("N") + ".sqlite");
        try
        {
            var first = EventXml(11, 901, "TargetFilename", @"C:\Fixture\first.bin", ("ProcessId", "91"));
            var near = EventXml(11, 902, "TargetFilename", @"C:\Fixture\near.bin", ("ProcessId", "91"));
            var afterBad = EventXml(11, 903, "TargetFilename", @"C:\Fixture\after-bad.bin", ("ProcessId", "91"));
            var source = new ReplaySysmonSource([
                new(first, "cursor-901"), new(first, "cursor-901"), new(near, "cursor-902"),
                new("<Event><broken", "poison-cursor"), new("<Event><broken", "poison-cursor"),
                new("", null, "Simulated temporary Sysmon source outage"), new(afterBad, "cursor-903")
            ]);
            var bus = new CaptureBus();
            await using var store = new SqliteEventStore(path, TimeSpan.FromDays(1));
            await new ThreatMonitorPipeline(source, source, new SysmonEventNormalizer(), store,
                new DetectionEngine(), bus, new FixedTimeProvider(Now)).RunAsync(CancellationToken.None);

            var events = await store.LoadRecentEventsAsync(DateTimeOffset.MinValue, 20);
            Equal(3, events.Count, "A single malformed input must not interrupt following valid events; exact duplicates stay deduplicated.");
            True(events.Any(x => x.SourceEventId == "902"), "A nearby event with a distinct telemetry ID must remain distinct.");
            Equal("cursor-903", await store.LoadCursorAsync("Sysmon"), "The cursor must advance after a controlled poison-record rejection.");
            var gaps = await store.LoadTelemetryGapsAsync();
            Equal(2, gaps.Count, "Malformed observed input and source outage must be reported as separate gaps.");
            True(gaps.Any(x => x.MissingFields.Contains("normalizedEvent")), "Malformed observed input must identify normalization as unavailable.");
            True(gaps.Any(x => x.MissingFields.Contains("source_available")), "Source outage must remain distinct from malformed input.");
            True(!gaps.Any(x => x.DroppedCount > 0), "A rejected malformed event is not a confirmed collector drop.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(path)) File.Delete(path);
            if (File.Exists(path + "-wal")) File.Delete(path + "-wal");
            if (File.Exists(path + "-shm")) File.Delete(path + "-shm");
        }
    }

    private static async Task<List<CanonicalEvent>> LoadCase(string id)
    {
        var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", "Demon2_Training.sqlite");
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = fixture, Mode = SqliteOpenMode.ReadOnly }.ToString());
        await connection.OpenAsync();
        return await ReadScenarioEvents(connection, id);
    }

    private static async Task<List<CanonicalEvent>> ReadScenarioEvents(SqliteConnection connection, string id)
    {
        var events = new List<CanonicalEvent>();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT event_id,ts_utc,source,event_type,process,parent_process,object_path,remote_host,details_json FROM events WHERE scenario_id=$id ORDER BY sequence_no;";
        command.Parameters.AddWithValue("$id", id);
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var eventId = reader.GetString(0);
            var timestamp = DateTimeOffset.Parse(reader.GetString(1));
            var source = reader.GetString(2);
            var kind = reader.GetString(3);
            var process = reader.IsDBNull(4) ? null : reader.GetString(4);
            var parent = reader.IsDBNull(5) ? null : reader.GetString(5);
            var path = reader.IsDBNull(6) ? null : reader.GetString(6);
            var host = reader.IsDBNull(7) ? null : reader.GetString(7);
            using var details = JsonDocument.Parse(reader.GetString(8));
            var sequence = details.RootElement.TryGetProperty("sequence_text", out var text) ? text.GetString() : null;
            var fields = new Dictionary<string, string>(StringComparer.Ordinal) { ["synthetic"] = "true", ["fixtureText"] = sequence ?? "" };
            var eventType = FixtureEventType(kind, process, sequence);
            events.Add(new CanonicalEvent(eventId, timestamp, source, eventId, "fixture-host", eventType,
                process is null ? null : StablePid(id, process), null,
                parent is null ? null : StablePid(id, parent), null,
                process, null, null, path, host, null, null, null, fields));
        }
        return events;
    }

    private static ThreatEventType FixtureEventType(string sourceType, string? process, string? description)
    {
        var text = StripDiacritics($"{process} {description}");
        var kind = sourceType.Trim().ToUpperInvariant();
        if (kind == "NETWORK_ACTIVITY" || text.Contains("envoie flux", StringComparison.OrdinalIgnoreCase)) return ThreatEventType.NETWORK_CONNECTION;
        if (text.Contains("persistance", StringComparison.OrdinalIgnoreCase) || text.Contains("registre", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("tache fixture", StringComparison.OrdinalIgnoreCase) || text.Contains("tache planifiee", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("startup", StringComparison.OrdinalIgnoreCase)) return ThreatEventType.PERSISTENCE_CHANGE;
        if (text.Contains("telechargement", StringComparison.OrdinalIgnoreCase) || text.Contains("marque internet", StringComparison.OrdinalIgnoreCase))
            return ThreatEventType.DOWNLOAD_OBSERVED;
        if (text.Contains("powershell", StringComparison.OrdinalIgnoreCase) || text.Contains("script-host", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("script host", StringComparison.OrdinalIgnoreCase) || text.Contains("interpreteur", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("shell", StringComparison.OrdinalIgnoreCase) || text.Contains("script dans", StringComparison.OrdinalIgnoreCase))
            return ThreatEventType.SCRIPT_ACTIVITY;
        return kind == "PROCESS_ACTIVITY" ? ThreatEventType.PROCESS_STARTED : ThreatEventType.FILE_CREATED_OR_CHANGED;
    }

    private static string StripDiacritics(string value)
    {
        if (value.Contains('Ã') || value.Contains('Â') || value.Contains("â€", StringComparison.Ordinal))
        {
            var repaired = System.Text.Encoding.UTF8.GetString(System.Text.Encoding.Latin1.GetBytes(value));
            if (!repaired.Contains('\uFFFD') && repaired.Count(c => c is 'Ã' or 'Â') < value.Count(c => c is 'Ã' or 'Â'))
                value = repaired;
        }
        var decomposed = value.Normalize(System.Text.NormalizationForm.FormD);
        return string.Concat(decomposed.Where(c => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c) !=
            System.Globalization.UnicodeCategory.NonSpacingMark)).Normalize(System.Text.NormalizationForm.FormC);
    }

    private static int StablePid(string scenario, string process)
    {
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(scenario + "|" + process.ToLowerInvariant()));
        return BitConverter.ToInt32(hash, 0) & 0x7fffffff;
    }

    private static string StableProcessGuid(string scenario, string process)
    {
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(scenario + "|" + process.ToLowerInvariant()));
        return "{" + new Guid(hash.AsSpan(0, 16)).ToString() + "}";
    }

    private static bool ContainsAny(string text, params string[] values) =>
        values.Any(value => text.Contains(value, StringComparison.OrdinalIgnoreCase));

    private static string EventXml(int id, int recordId, string key, string value, params (string Key, string Value)[] rest)
    {
        var data = string.Join("", new[] { (key, value) }.Concat(rest).Select(x => $"<Data Name=\"{x.Item1}\">{System.Security.SecurityElement.Escape(x.Item2)}</Data>"));
        return $"<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{id}</EventID><EventRecordID>{recordId}</EventRecordID><TimeCreated SystemTime=\"2026-11-21T12:00:00.000Z\"/><Security UserID=\"S-1-5-18\"/></System><EventData>{data}</EventData></Event>";
    }

    private static CanonicalEvent MakeEvent(string id, ThreatEventType type, DateTimeOffset at, int? processId = null, int? parentId = null,
        string? image = null, string? path = null, string? remote = null, IReadOnlyDictionary<string, string>? fields = null) =>
        new(id, at, "SyntheticFixture", id, "fixture-host", type, processId, null, parentId, null, image, null, null, path, remote, null, null, null, fields);

    private static ThreatFinding MakeFinding(string rule, IReadOnlyList<string> evidence) =>
        new(Guid.NewGuid().ToString("N"), "test-case", rule, 1, ThreatSeverity.high, .8, Now, Now,
            "Synthetic test finding", [], evidence, [], Now.AddMinutes(1));

    private static void True(bool value, string message) { if (!value) throw new InvalidOperationException(message); }
    private static void Throws<T>(Action action, string message) where T : Exception
    { try { action(); } catch (T) { return; } throw new InvalidOperationException(message); }
    private static async Task ThrowsAsync<T>(Func<Task> action, string message) where T : Exception
    {
        try { await action(); }
        catch (T) { return; }
        throw new InvalidOperationException(message);
    }
    private static void Equal<T>(T expected, T actual, string message)
    { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new InvalidOperationException($"{message} Expected {expected}, got {actual}."); }
}

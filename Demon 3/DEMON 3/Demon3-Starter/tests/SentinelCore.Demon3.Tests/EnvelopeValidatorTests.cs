using System.Text.Json;
using System.Text;
using System.Buffers.Binary;
using System.IO.Pipes;
using System.Net;
using System.Threading.Channels;
using SentinelCore.Demon2.Core;
using SentinelCore.Demon2.Service;
using D1PipeClient = SentinelCore.Demon1.VisualVerification.InterDaemonPipeClient;
using D1Envelope = SentinelCore.Demon1.VisualVerification.InterDaemonEnvelope;
using SentinelCore.Demon3.Core.Contracts;
using SentinelCore.Demon3.Core.Validation;
using SentinelCore.Demon3.Core.Decision;
using SentinelCore.Demon3.Core.Reports;
using SentinelCore.Demon3.Core.Actions;
using SentinelCore.Demon3.Core.Replay;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon3.Core.AI;
using SentinelCore.Demon3.Core.Runtime;
using SentinelCore.Demon3.Core.Transport;
using Xunit;
using Xunit.Abstractions;

namespace SentinelCore.Demon3.Tests;

public sealed class EnvelopeValidatorTests
{
    private readonly ITestOutputHelper _output;
    public EnvelopeValidatorTests(ITestOutputHelper output) => _output = output;

    private static readonly DateTimeOffset Now = new(2026, 11, 21, 9, 0, 0, TimeSpan.Zero);
    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private static DaemonEnvelope Valid() => new()
    {
        MessageId = Guid.NewGuid(), CorrelationId = "D3-TEST-001", TimestampUtc = Now,
        SourceDaemon = DaemonNames.ThreatMonitor, Destination = DaemonNames.RiskResponseGuard,
        MessageType = "THREAT_FINDING", SchemaVersion = 1, ExpiresAtUtc = Now.AddMinutes(1),
        Payload = JsonDocument.Parse("{\"synthetic\":true}").RootElement.Clone()
    };

    [Fact]
    public void VisualIdentityNullMeasurementsAreAcceptedAsUnavailable()
    {
        using var payload = JsonDocument.Parse("""
            {"status":"INDETERMINATE","liveness":"NOT_CONFIRMED","similarity":null,
             "faceQuality":null,"validFrames":0,"observedAtUtc":"2026-11-21T09:00:00Z",
             "profileId":"test-profile","evidenceRef":null,"reasonCode":"CAMERA_UNAVAILABLE"}
            """);
        var envelope = Valid() with
        {
            SourceDaemon = DaemonNames.HumanBehaviorMonitor,
            MessageType = "VISUAL_IDENTITY_RESPONSE",
            Payload = payload.RootElement.Clone()
        };

        var result = RiskDecisionEngine.FromEnvelope(envelope);

        Assert.Null(result.Confidence);
        Assert.Equal("CAMERA_UNAVAILABLE", result.ReasonCode);
        Assert.Equal("UNKNOWN", result.Severity);
    }

    [Fact]
    public void AdditionalD2ServiceSidCannotClaimD1IdentityOrOwnerApproval()
    {
        const string d2ServiceSid = "S-1-5-80-123456789-123456789-123456789-123456789-123456789";
        var d1Sids = Array.Empty<string>();
        var d2Sids = new[] { d2ServiceSid };

        Assert.True(SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.IsAdditionalClientAuthorizedForRole(
            DaemonNames.ThreatMonitor, d2ServiceSid, d1Sids, d2Sids));
        Assert.False(SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.IsAdditionalClientAuthorizedForRole(
            DaemonNames.HumanBehaviorMonitor, d2ServiceSid, d1Sids, d2Sids));
    }

    [Fact]
    public async Task SqliteInboundJournalReplaysUnprocessedMessagesAcrossInstancesAndDeduplicatesProcessedOnes()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-inbox-" + Guid.NewGuid().ToString("N"));
        var database = Path.Combine(folder, "inbox.sqlite3");
        try
        {
            var envelope = Valid() with { MessageId = Guid.NewGuid(), CorrelationId = "D3-INBOX-RESTART-001" };
            var firstRun = new SqliteInboundMessageJournal(database);
            Assert.Equal(InboundMessageStatus.Inserted, await firstRun.EnqueueAsync(envelope));
            Assert.Equal(InboundMessageStatus.PendingDuplicate, await firstRun.EnqueueAsync(envelope));

            // A new journal instance represents D3 starting again after it had ACKed but before handling the message.
            var afterRestart = new SqliteInboundMessageJournal(database);
            var pending = await afterRestart.ReadPendingAsync();
            var recovered = Assert.Single(pending);
            Assert.Equal(envelope.MessageId, recovered.MessageId);
            Assert.Equal(envelope.CorrelationId, recovered.CorrelationId);

            await afterRestart.MarkProcessedAsync(envelope.MessageId);
            Assert.Empty(await new SqliteInboundMessageJournal(database).ReadPendingAsync());
            Assert.Equal(InboundMessageStatus.ProcessedDuplicate, await afterRestart.EnqueueAsync(envelope));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task OllamaAllocationFailureIsReportedAsResourceIssue()
    {
        using var http = new HttpClient(new StaticResponseHandler(HttpStatusCode.InternalServerError,
            "{\"error\":\"memory layout cannot be allocated\"}"));
        var advisor = new OllamaAmbiguousCaseAdvisor(http, new OllamaAdvisorOptions(
            new Uri("http://127.0.0.1:11434/"), "test-model", TimeSpan.FromSeconds(2), ContextWindow: 512));
        var input = new AmbiguousSecurityCase("D3-AI-RESOURCE-TEST",
            [new("ThreatMonitor", "THREAT_FINDING", "MEDIUM", 0.6, "Synthetic test", ["D2-TEST-1"])], []);

        var result = await advisor.AnalyzeAsync(input);

        Assert.Equal(AdvisorStatus.Unavailable, result.Status);
        Assert.Equal("OLLAMA_RESOURCE_ALLOCATION_FAILED", result.ErrorCode);
        Assert.True(result.DurationMilliseconds is >= 0);
    }

    [Fact]
    public async Task OllamaCannotTreatNotRequestedVisualCheckAsMissingOrFailedEvidence()
    {
        var adviceJson = JsonSerializer.Serialize(new
        {
            riskBand = "HIGH", confidence = 0.9, assessment = "L'absence de vérification visuelle confirme une attaque.",
            keyFindings = new[] { "L'absence de vérification visuelle" }, benignExplanations = Array.Empty<string>(),
            threatHypotheses = Array.Empty<string>(), uncertainties = Array.Empty<string>(),
            summary = "L'absence de vérification visuelle est suspecte.", requestedContext = Array.Empty<string>(),
            suggestedMeasure = "NO_RECOMMENDATION", rationale = "L'absence visuelle indique une attaque.",
            evidenceRefs = new[] { "D1-VISUAL-STATE" }, capabilityGap = "", playbookDraft = ""
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var responseJson = JsonSerializer.Serialize(new
        {
            model = "test-model", done = true,
            message = new { role = "assistant", content = adviceJson }
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        using var http = new HttpClient(new StaticResponseHandler(HttpStatusCode.OK, responseJson));
        var advisor = new OllamaAmbiguousCaseAdvisor(http, new OllamaAdvisorOptions(
            new Uri("http://127.0.0.1:11434/"), "test-model", TimeSpan.FromSeconds(2), ContextWindow: 512));
        var input = new AmbiguousSecurityCase("D3-AI-VISUAL-STATE-TEST",
            [new("HumanBehaviorMonitor", "USER_CONTEXT", "LOW", 0.7, "synthetic", ["D1-VISUAL-STATE"], ["visualStatus=NOT_REQUESTED"])],
            [ContextRequestKind.D1_VISUAL_IDENTITY]);

        var result = await advisor.AnalyzeAsync(input);

        Assert.Equal(AdvisorStatus.InvalidResponse, result.Status);
        Assert.Equal("OLLAMA_UNSUPPORTED_VISUAL_INFERENCE", result.ErrorCode);
        Assert.True(result.DurationMilliseconds is >= 0);
    }

    private sealed class StaticResponseHandler(HttpStatusCode statusCode, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(statusCode) { Content = new StringContent(body) });
    }

    private sealed class CapturingResponseHandler(string body) : HttpMessageHandler
    {
        public string? RequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        }
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    [Theory]
    [InlineData("qwen3-coder:480b-cloud")]
    [InlineData("gemma4:cloud")]
    public async Task OllamaRejectsCloudModelsBeforeAnyNetworkCall(string model)
    {
        var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var advisor = new OllamaAmbiguousCaseAdvisor(http, new OllamaAdvisorOptions(
            new Uri("http://127.0.0.1:11434/"), model, TimeSpan.FromSeconds(2)));
        var input = new AmbiguousSecurityCase("D3-AI-CLOUD-TEST",
            [new("ThreatMonitor", "THREAT_FINDING", "MEDIUM", 0.6, "Synthetic test", ["D2-TEST-1"])], []);

        var result = await advisor.AnalyzeAsync(input);

        Assert.Equal(AdvisorStatus.InvalidInput, result.Status);
        Assert.Equal("OLLAMA_CLOUD_MODEL_REJECTED", result.ErrorCode);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task OllamaRequestUsesTheDocumentedSnakeCaseGenerationOptions()
    {
        const string advice = """
            {"riskBand":"ELEVATED","confidence":0.8,"assessment":"Analyse synthétique.","keyFindings":["Fait synthétique"],"benignExplanations":[],"threatHypotheses":[],"uncertainties":[],"summary":"Risque à examiner.","requestedContext":[],"suggestedMeasure":"CONTINUE_MONITORING","rationale":"Une donnée manque.","evidenceRefs":["D2-TEST-1"],"capabilityGap":"","playbookDraft":""}
            """;
        var response = JsonSerializer.Serialize(new
        {
            model = "test-model", done = true,
            message = new { role = "assistant", content = advice }
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var handler = new CapturingResponseHandler(response);
        using var http = new HttpClient(handler);
        var advisor = new OllamaAmbiguousCaseAdvisor(http, new OllamaAdvisorOptions(
            new Uri("http://127.0.0.1:11434/"), "test-model", TimeSpan.FromSeconds(2), ContextWindow: 3072));
        var input = new AmbiguousSecurityCase("D3-AI-OPTIONS-TEST",
            [new("ThreatMonitor", "THREAT_FINDING", "MEDIUM", 0.6, "Synthetic test", ["D2-TEST-1"])], []);

        var result = await advisor.AnalyzeAsync(input);

        Assert.Equal(AdvisorStatus.Advised, result.Status);
        using var request = JsonDocument.Parse(handler.RequestBody!);
        var root = request.RootElement;
        Assert.Equal("5m", root.GetProperty("keep_alive").GetString());
        var options = root.GetProperty("options");
        Assert.Equal(3072, options.GetProperty("num_ctx").GetInt32());
        Assert.Equal(1800, options.GetProperty("num_predict").GetInt32());
        Assert.False(options.TryGetProperty("numCtx", out _));
        Assert.False(options.TryGetProperty("numPredict", out _));
    }

    [Fact] public void AcceptsValidV1Envelope() => Assert.True(new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(Valid(), 100).IsValid);
    [Fact] public void RejectsExpiredMessage() => Assert.Equal("Message expired.", new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(Valid() with { ExpiresAtUtc = Now }, 100).Error!);
    [Fact] public void RejectsOversizedMessage() => Assert.False(new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(Valid(), 65537).IsValid);
    [Fact] public void RejectsUnknownSource() => Assert.False(new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(Valid() with { SourceDaemon = "Unknown" }, 100).IsValid);
    [Fact] public void RejectsInterDaemonActionRequest() => Assert.Contains("internal-only", new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(Valid() with { MessageType = "ACTION_REQUEST" }, 100).Error!);
    [Fact] public void AcceptsDemon1VisualIdentityResponse()
    {
        var message = Valid() with { SourceDaemon = DaemonNames.HumanBehaviorMonitor, MessageType = "VISUAL_IDENTITY_RESPONSE" };
        Assert.True(new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(message, 100).IsValid);
    }
    [Fact] public void RejectsThreatFindingSentByDemon1()
    {
        var message = Valid() with { SourceDaemon = DaemonNames.HumanBehaviorMonitor, MessageType = "THREAT_FINDING" };
        Assert.Contains("not allowed", new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(message, 100).Error!);
    }
    [Fact] public void AcceptsDemon2ContextRequest()
    {
        var message = Valid() with { MessageType = "SESSION_CONTEXT_REQUEST" };
        Assert.True(new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(message, 100).IsValid);
    }
    [Fact] public void AcceptsGuardSessionContextResponseToDemon2()
    {
        var message = Valid() with
        {
            SourceDaemon = DaemonNames.RiskResponseGuard,
            Destination = DaemonNames.ThreatMonitor,
            MessageType = "SESSION_CONTEXT_RESPONSE"
        };
        Assert.True(new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(message, 100).IsValid);
    }
    [Fact] public void RejectsDemon1SessionContextResponseDirection()
    {
        var message = Valid() with
        {
            SourceDaemon = DaemonNames.HumanBehaviorMonitor,
            Destination = DaemonNames.RiskResponseGuard,
            MessageType = "SESSION_CONTEXT_RESPONSE"
        };
        Assert.Contains("not allowed", new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(message, 100).Error!);
    }
    [Fact] public void RejectsVisualRequestFromDemon2()
    {
        var message = Valid() with { MessageType = "VISUAL_IDENTITY_REQUEST" };
        Assert.Contains("not allowed", new EnvelopeValidator(new FixedTimeProvider(Now)).Validate(message, 100).Error!);
    }

    [Fact]
    public async Task NamedPipeServerHandshakesAndReceivesDemon1Message()
    {
        if (!OperatingSystem.IsWindows()) return;
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".test-" + Guid.NewGuid().ToString("N");
        await using var server = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
        server.Start();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        await using var received = server.ReadAllAsync(deadline.Token).GetAsyncEnumerator(deadline.Token);
        using var client = new NamedPipeClientStream(".", pipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(deadline.Token);

        var hello = Envelope("HumanBehaviorMonitor", "HELLO", "RiskResponseGuard");
        await WriteFrame(client, hello, deadline.Token);
        using var helloAck = await ReadFrame(client, deadline.Token);
        Assert.True(helloAck.RootElement.GetProperty("status").GetString() == "ACCEPTED", helloAck.RootElement.ToString());
        using var welcome = await ReadFrame(client, deadline.Token);
        Assert.Equal("WELCOME", welcome.RootElement.GetProperty("messageType").GetString());

        var context = Envelope("HumanBehaviorMonitor", "USER_CONTEXT", "RiskResponseGuard");
        await WriteFrame(client, context, deadline.Token);
        using var contextAck = await ReadFrame(client, deadline.Token);
        Assert.Equal("ACCEPTED", contextAck.RootElement.GetProperty("status").GetString());
        Assert.True(await received.MoveNextAsync());
        Assert.Equal("USER_CONTEXT", received.Current.MessageType);

        using var threatClient = new NamedPipeClientStream(".", pipeName,
            PipeDirection.InOut, PipeOptions.Asynchronous);
        await threatClient.ConnectAsync(deadline.Token);
        var threatHello = Envelope("ThreatMonitor", "HELLO", "RiskResponseGuard") with
        {
            Payload = JsonSerializer.SerializeToElement(new { daemonId = "ThreatMonitor", capabilities = new[] { "findings", "context" }, supportedSchema = 1 })
        };
        await WriteFrame(threatClient, threatHello, deadline.Token);
        using var threatWelcome = await ReadFrame(threatClient, deadline.Token);
        Assert.Equal("WELCOME", threatWelcome.RootElement.GetProperty("messageType").GetString());
        var finding = Envelope("ThreatMonitor", "THREAT_FINDING", "RiskResponseGuard") with
        {
            Payload = JsonSerializer.SerializeToElement(new { severity = "CRITICAL", confidence = 0.97, evidenceRefs = new[] { "D2-CASE-1" } }, new JsonSerializerOptions(JsonSerializerDefaults.Web))
        };
        await WriteFrame(threatClient, finding, deadline.Token);
        using var findingAck = await ReadFrame(threatClient, deadline.Token);
        Assert.Equal("ACK", findingAck.RootElement.GetProperty("messageType").GetString());
        Assert.Equal("ACCEPTED", findingAck.RootElement.GetProperty("payload").GetProperty("status").GetString());
        Assert.True(await received.MoveNextAsync());
        Assert.Equal("THREAT_FINDING", received.Current.MessageType);
    }

    [Fact]
    public async Task AwaitableStartReturnsOnlyAfterTheNamedPipeListenerCanAcceptAClient()
    {
        var pipeName = NamedPipeInterDaemonServer.PipeName + ".readiness-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeInterDaemonServer(pipeName: pipeName);

        await server.StartAsync();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(timeout.Token);
        Assert.Null(server.ListenerFailure);
    }

    [Fact]
    public async Task AwaitableStartPropagatesAndReportsJournalInitializationFailure()
    {
        var expected = new InvalidOperationException("injected journal startup failure");
        var pipeName = NamedPipeInterDaemonServer.PipeName + ".failed-start-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeInterDaemonServer(
            pipeName: pipeName, journal: new FailingStartupJournal(expected));
        Exception? observedFailure = null;
        server.ListenerFailed += exception => observedFailure = exception;

        var propagated = await Assert.ThrowsAsync<InvalidOperationException>(() => server.StartAsync());

        Assert.Same(expected, propagated);
        Assert.Same(expected, server.ListenerFailure);
        Assert.Same(expected, observedFailure);
        Assert.False(server.Completion.IsCompletedSuccessfully);
    }

    private sealed class FailingStartupJournal(Exception failure) : IInboundMessageJournal
    {
        public Task<InboundMessageStatus> EnqueueAsync(DaemonEnvelope message, CancellationToken cancellationToken = default)
            => Task.FromResult(InboundMessageStatus.Inserted);

        public Task<IReadOnlyList<DaemonEnvelope>> ReadPendingAsync(CancellationToken cancellationToken = default)
            => Task.FromException<IReadOnlyList<DaemonEnvelope>>(failure);

        public Task MarkProcessedAsync(Guid messageId, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }

    [Fact]
    public async Task D2SessionContextRequestIsRelayedThroughD1AndReducedToCategories()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-session-relay-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".session-relay-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        Task? hostTask = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(
                pipeName: pipeName, additionalD2ClientSids: ["S-1-5-18"]);
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), new RiskReportStore(reportFolder),
                new ImmediateUnavailableAdvisor(), new ActionCatalog());
            hostTask = host.RunAsync(stop.Token);

            var d1Messages = Channel.CreateUnbounded<D1Envelope>();
            await using var d1 = new D1PipeClient(pipeName, allowIsolatedTestPipe: true);
            d1.MessageReceived += (_, message) => d1Messages.Writer.TryWrite(message);
            await d1.ConnectAndHandshakeAsync(stop.Token);

            await using var d2 = new SentinelCore.Demon2.Service.NamedPipeInterDaemonBus(pipeName);
            await using var responses = d2.ReadSessionContextResponsesAsync(stop.Token).GetAsyncEnumerator(stop.Token);
            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D3-SESSION-RELAY-001";
            var request = InterDaemonEnvelopeFactory.ForSessionContextRequest(correlationId,
                ["sessionState", "localOrRemote", "recentAuthBand"], now.AddSeconds(10));
            await d2.PublishAsync(request, stop.Token);

            D1Envelope? contextRequest = null;
            while (contextRequest is null)
            {
                var message = await d1Messages.Reader.ReadAsync(stop.Token);
                if (message.MessageType == "CONTEXT_REQUEST") contextRequest = message;
            }
            Assert.Equal(correlationId, contextRequest.CorrelationId);

            var observedAt = DateTimeOffset.UtcNow;
            await d1.SendAsync("CONTEXT_RESPONSE", correlationId, new
            {
                status = "AVAILABLE",
                applicationStatus = "AVAILABLE",
                observedAtUtc = observedAt,
                sessionId = "1",
                applicationContext = (object?)null,
                expiresAtUtc = observedAt.AddSeconds(30),
                sessionContext = new { sessionState = "ACTIVE", localOrRemote = "REMOTE", recentAuthBand = "UNKNOWN" },
                sessionContextObservedAtUtc = observedAt
            }, observedAt.AddSeconds(30), stop.Token);

            Assert.True(await responses.MoveNextAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(4), stop.Token));
            var reply = responses.Current;
            Assert.Equal("SESSION_CONTEXT_RESPONSE", reply.MessageType);
            Assert.Equal(correlationId, reply.CorrelationId);
            Assert.True(SessionContextResponseValidator.TryValidate(reply, DateTimeOffset.UtcNow, out var parsed, out var error), error);
            Assert.Equal(SessionContextAvailability.AVAILABLE, parsed!.Status);
            Assert.Equal(SessionStateCategory.ACTIVE, parsed.Context!.SessionState);
            Assert.Equal(SessionLocationCategory.REMOTE, parsed.Context.LocalOrRemote);
            Assert.Equal(RecentAuthenticationCategory.UNKNOWN, parsed.Context.RecentAuthBand);
            Assert.Equal(new[] { "context", "observedAtUtc", "status" }, reply.Payload.EnumerateObject().Select(x => x.Name).Order(StringComparer.Ordinal).ToArray());
        }
        finally
        {
            stop.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            await DeleteTemporaryDirectoryAsync(reportFolder);
        }
    }

    private static async Task DeleteTemporaryDirectoryAsync(string path)
    {
        for (var attempt = 0; attempt < 20; attempt++)
        {
            if (!Directory.Exists(path)) return;
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 19)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(100));
            }
        }

        if (Directory.Exists(path)) Directory.Delete(path, recursive: true);
    }

    private static DaemonEnvelope Envelope(string source, string type, string destination)
    {
        var now = DateTimeOffset.UtcNow;
        return new()
        {
            MessageId = Guid.NewGuid(), CorrelationId = Guid.NewGuid().ToString("D"), TimestampUtc = now,
            SourceDaemon = source, Destination = destination, MessageType = type, SchemaVersion = 1,
            ExpiresAtUtc = now.AddSeconds(20), Payload = JsonDocument.Parse("{}").RootElement.Clone()
        };
    }

    private static async Task WriteFrame(Stream stream, DaemonEnvelope envelope, CancellationToken token)
    {
        var data = JsonSerializer.SerializeToUtf8Bytes(envelope, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, data.Length);
        await stream.WriteAsync(prefix, token);
        await stream.WriteAsync(data, token);
        await stream.FlushAsync(token);
    }

    private static async Task<JsonDocument> ReadFrame(Stream stream, CancellationToken token)
    {
        var prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix, token);
        var length = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        Assert.InRange(length, 1, 65536);
        var data = new byte[length];
        await stream.ReadExactlyAsync(data, token);
        return JsonDocument.Parse(data);
    }

    [Fact]
    public void OrdinaryOwnerConsistentBehaviorDoesNotReduceCriticalTechnicalFinding()
    {
        var engine = new RiskDecisionEngine();
        var signals = new DecisionEvidence[]
        {
            new("ThreatMonitor", "THREAT_FINDING", "CRITICAL", 0.99, "EXFILTRATION", ["D2-E1"], Now),
            new("HumanBehaviorMonitor", "BEHAVIOR_DEVIATION", "LOW", 0.95, "BEHAVIOR_WITHIN_OWNER_BASELINE", ["D1-E1"], Now)
        };
        var decision = engine.Evaluate("case-critical", signals);
        Assert.Equal(RiskLevel.CRITICAL, decision.Risk);
        Assert.Equal(DecisionKind.CONTAINMENT_REVIEW, decision.Decision);
        Assert.True(decision.RequiresHumanApproval);
        Assert.True(decision.SimulationOnly);
    }

    [Fact]
    public void HumanSignalAloneCannotCauseDestructiveAction()
    {
        var decision = new RiskDecisionEngine().Evaluate("case-d1-only",
            [new("HumanBehaviorMonitor", "BEHAVIOR_DEVIATION", "HIGH", 0.9, "BEHAVIOR_DIVERGENCE_OVER_60", [], Now)]);
        Assert.False(new[] { ProposedAction.ISOLATE_FILE_REVIEW, ProposedAction.RUN_DEFENDER_SCAN }.Contains(decision.ProposedAction));
        Assert.True(decision.SimulationOnly);
    }

    [Fact]
    public void LiveVisualOwnerMatchReducesRiskOneLevelButPreservesTechnicalFinding()
    {
        var engine = new RiskDecisionEngine();
        var now = DateTimeOffset.UtcNow;
        var critical = new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "CRITICAL", 0.99, "EXFILTRATION", ["D2-E1"], now);
        var ownerMatch = new DecisionEvidence("HumanBehaviorMonitor", "VISUAL_IDENTITY_RESPONSE", "LOW", 0.9,
            "OWNER_VISUALLY_CONFIRMED_LIVE", ["D1-VISUAL-1"], now);
        var decision = engine.Evaluate("case-visual-owner", [critical, ownerMatch]);
        Assert.Equal(RiskLevel.HIGH, decision.Risk);
        Assert.Equal(DecisionKind.RUN_BOUNDED_SCAN, decision.Decision);
        Assert.Contains("EXFILTRATION", decision.ReasonCodes);
        Assert.Contains("D1_OWNER_VISUALLY_CONFIRMED_RISK_REDUCED_ONE_LEVEL", decision.ReasonCodes);
        Assert.Contains("D2-E1", decision.EvidenceRefs);
    }

    [Fact]
    public void StaleOrNonLiveVisualMatchDoesNotReduceCriticalTechnicalFinding()
    {
        var now = DateTimeOffset.UtcNow;
        var critical = new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "CRITICAL", 0.99, "EXFILTRATION", ["D2-E1"], now);
        var staleOwnerMatch = new DecisionEvidence("HumanBehaviorMonitor", "VISUAL_IDENTITY_RESPONSE", "LOW", 0.95,
            "OWNER_VISUALLY_CONFIRMED_LIVE", ["D1-VISUAL-1"], now.AddMinutes(-2));

        var decision = new RiskDecisionEngine().Evaluate("case-stale-visual", [critical, staleOwnerMatch]);

        Assert.Equal(RiskLevel.CRITICAL, decision.Risk);
        Assert.DoesNotContain("D1_OWNER_VISUALLY_CONFIRMED_RISK_REDUCED_ONE_LEVEL", decision.ReasonCodes);
    }

    [Fact]
    public void ReadsDemon1LiveVisualResponseContract()
    {
        var now = DateTimeOffset.UtcNow;
        var payload = JsonSerializer.SerializeToElement(new
        {
            status = "MATCH", liveness = "LIVE", similarity = 0.61, observedAtUtc = now,
            profileId = "owner-1", faceQuality = 0.82, validFrames = 5,
            evidenceRef = "D1-EVIDENCE-4", reasonCode = "PROFILE_MATCH_AND_LIVENESS_CONFIRMED"
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var envelope = Envelope("HumanBehaviorMonitor", "VISUAL_IDENTITY_RESPONSE", "RiskResponseGuard") with { Payload = payload };
        var evidence = RiskDecisionEngine.FromEnvelope(envelope);
        Assert.Equal("OWNER_VISUALLY_CONFIRMED_LIVE", evidence.ReasonCode);
        Assert.Equal("LOW", evidence.Severity);
        Assert.Equal("D1-EVIDENCE-4", Assert.Single(evidence.EvidenceRefs));
    }

    [Fact]
    public void LearnedKnownApplicationAndUsualHourReduceOnlyModerateTechnicalRisk()
    {
        var now = DateTimeOffset.UtcNow;
        var d1Payload = JsonSerializer.SerializeToElement(new
        {
            schemaVersion = 1,
            applicationContext = new
            {
                profileId = "PROFIL_1", observedAtUtc = now, ageSeconds = 0,
                seenInLearnedHistory = true, hourCommonForApplication = true,
                reasonCode = "APPLICATION_AND_HOUR_SEEN_IN_PROFILE"
            }
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var d1 = Envelope("HumanBehaviorMonitor", "USER_CONTEXT", "RiskResponseGuard") with { Payload = d1Payload };
        var d2 = new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "MEDIUM", 0.7, "UNUSUAL_ACTIVITY", ["D2-E1"], now);
        var d1Evidence = RiskDecisionEngine.FromEnvelope(d1);
        Assert.Equal("APPLICATION_AND_HOUR_SEEN_IN_PROFILE", d1Evidence.ReasonCode);
        var decision = new RiskDecisionEngine().Evaluate("known-app", [d1Evidence, d2]);
        Assert.Equal(RiskLevel.LOW, decision.Risk);
        Assert.Contains("D1_LEARNED_APPLICATION_CONTEXT_REDUCED_MODERATE_RISK", decision.ReasonCodes);
    }

    [Fact]
    public void FreshDemon1ContextResponseCanReduceModerateRiskButStaleContextCannot()
    {
        var now = DateTimeOffset.UtcNow;
        var threat = new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "MEDIUM", 0.7,
            "known_rule", ["D2-E1"], now);
        var freshPayload = JsonSerializer.SerializeToElement(new
        {
            schemaVersion = 1, observedAtUtc = now, sessionId = "session-test",
            applicationContext = new
            {
                profileId = "PROFIL_1", observedAtUtc = now, ageSeconds = 3,
                foregroundApplication = "IDE", seenInLearnedHistory = true,
                hourCommonForApplication = true, reasonCode = "APPLICATION_AND_HOUR_SEEN_IN_PROFILE"
            }
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var template = Envelope("HumanBehaviorMonitor", "CONTEXT_RESPONSE", "RiskResponseGuard");
        var fresh = RiskDecisionEngine.FromEnvelope(template with { Payload = freshPayload });
        var lowered = new RiskDecisionEngine().Evaluate("context-fresh", [threat, fresh]);
        Assert.Equal("APPLICATION_AND_HOUR_SEEN_IN_PROFILE", fresh.ReasonCode);
        Assert.Equal(RiskLevel.LOW, lowered.Risk);

        var staleAt = now.AddMinutes(-5);
        var stalePayload = JsonSerializer.SerializeToElement(new
        {
            schemaVersion = 1, observedAtUtc = staleAt, sessionId = "session-test",
            applicationContext = new
            {
                profileId = "PROFIL_1", observedAtUtc = staleAt, ageSeconds = 300,
                foregroundApplication = "IDE", seenInLearnedHistory = true,
                hourCommonForApplication = true, reasonCode = "APPLICATION_AND_HOUR_SEEN_IN_PROFILE"
            }
        }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var stale = RiskDecisionEngine.FromEnvelope(template with { Payload = stalePayload });
        var unchanged = new RiskDecisionEngine().Evaluate("context-stale", [threat, stale]);
        Assert.NotEqual("APPLICATION_AND_HOUR_SEEN_IN_PROFILE", stale.ReasonCode);
        Assert.Equal(RiskLevel.GUARDED, unchanged.Risk);
    }

    [Fact]
    public async Task ActionCatalogSimulatesQuickScanAndBlocksUnapprovedContainment()
    {
        var catalog = new ActionCatalog();
        var engine = new RiskDecisionEngine();
        var signals = new[] { new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "HIGH", 0.9, "SUSPICIOUS_CHAIN", ["D2-E1"], DateTimeOffset.UtcNow) };
        var high = engine.Evaluate("scan-case", signals);
        var scan = await catalog.ExecuteAsync(high, signals);
        Assert.Equal(ActionExecutionStatus.SIMULATED, scan.Status);
        Assert.True(scan.SimulationOnly);

        var criticalSignals = new[] { new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "CRITICAL", 0.99, "EXFILTRATION", ["D2-E2"], DateTimeOffset.UtcNow) };
        var critical = engine.Evaluate("containment-case", criticalSignals);
        var blocked = await catalog.ExecuteAsync(critical, criticalSignals);
        Assert.Equal(ActionExecutionStatus.BLOCKED_POLICY, blocked.Status);

        var runner = new RecordingDefenderRunner();
        var enabled = new ActionCatalog(ActionCatalogMode.DefenderQuickScanEnabled, runner);
        var denied = await enabled.ExecuteAsync(high, signals);
        Assert.Equal(ActionExecutionStatus.BLOCKED_POLICY, denied.Status);
        Assert.Equal(0, runner.CallCount);
        var allowed = await enabled.ExecuteAsync(high with { CorrelationId = "scan-approved" }, signals, ownerApproved: true);
        Assert.Equal(ActionExecutionStatus.COMPLETED, allowed.Status);
        Assert.Equal(1, runner.CallCount);
    }

    private sealed class RecordingDefenderRunner : IDefenderQuickScanRunner
    {
        private int _callCount;
        public int CallCount => _callCount;
        public Task<ActionExecutionResult> RunAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _callCount);
            var now = DateTimeOffset.UtcNow;
            return Task.FromResult(new ActionExecutionResult("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.COMPLETED,
                "Simulation de test du moteur Defender.", now, now, false));
        }
    }

    [Fact]
    public async Task D2FixtureReplaySeparatesBenignSuspiciousAndUncertainMappings()
    {
        var path = Path.Combine(Path.GetTempPath(), "SentinelCore-D2-" + Guid.NewGuid().ToString("N") + ".sqlite");
        try
        {
            await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false }.ToString()))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE scenarios(scenario_id TEXT PRIMARY KEY,category TEXT,title TEXT,label TEXT);
                    CREATE TABLE reports(scenario_id TEXT PRIMARY KEY,report_type TEXT,severity TEXT,confidence REAL,evidence_event_ids TEXT);
                    INSERT INTO scenarios VALUES('B1','Bénin','Compteur normal','benign');
                    INSERT INTO scenarios VALUES('S1','Suspect','Chaîne suspecte','suspicious');
                    INSERT INTO scenarios VALUES('U1','Ambigu','Parent absent','uncertain');
                    INSERT INTO reports VALUES('B1','OBSERVATION','low',0.3,'["B1-E1"]');
                    INSERT INTO reports VALUES('S1','THREAT_FINDING','high',0.9,'["S1-E1"]');
                    INSERT INTO reports VALUES('U1','NEEDS_CONTEXT','low',0.3,'["U1-E1"]');
                    """;
                await command.ExecuteNonQueryAsync();
            }
            var report = await new D2FixtureReplayService().ReplayAsync(path);
            Assert.Equal(3, report.Total);
            Assert.Equal(3, report.Consistent);
            Assert.Equal(1, report.Scenarios.Count(x => x.AiConsultSuggested));
        }
        finally { if (File.Exists(path)) File.Delete(path); }
    }

    [Fact]
    public async Task D2FixturePublisherRunsThroughLiveD3PipeIntoReports()
    {
        var database = Path.Combine(Path.GetTempPath(), "SentinelCore-D2-wire-" + Guid.NewGuid().ToString("N") + ".sqlite");
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-live-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".test-" + Guid.NewGuid().ToString("N");
        CancellationTokenSource? stop = null;
        Task? hostTask = null;
        try
        {
            await using (var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Pooling = false }.ToString()))
            {
                await connection.OpenAsync();
                await using var command = connection.CreateCommand();
                command.CommandText = """
                    CREATE TABLE scenarios(scenario_id TEXT PRIMARY KEY,category TEXT,title TEXT,label TEXT);
                    CREATE TABLE reports(scenario_id TEXT PRIMARY KEY,report_type TEXT,severity TEXT,confidence REAL,evidence_event_ids TEXT);
                    INSERT INTO scenarios VALUES('D2-B','Bénin','Routine','benign');
                    INSERT INTO scenarios VALUES('D2-S','Suspect','Finding élevé','suspicious');
                    INSERT INTO scenarios VALUES('D2-U','Ambigu','Rapport incomplet','uncertain');
                    INSERT INTO reports VALUES('D2-B','OBSERVATION','low',0.3,'["D2-B-E1"]');
                    INSERT INTO reports VALUES('D2-S','THREAT_FINDING','high',0.9,'["D2-S-E1"]');
                    INSERT INTO reports VALUES('D2-U','NEEDS_CONTEXT','low',0.3,'["D2-U-E1"]');
                    """;
                await command.ExecuteNonQueryAsync();
            }

            stop = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            await using var bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
            var advisor = new ImmediateUnavailableAdvisor();
            var reports = new RiskReportStore(reportFolder);
            var host = new Demon3Host(bus, new RiskDecisionEngine(), reports, advisor, new ActionCatalog());
            hostTask = host.RunAsync(stop.Token);

            using var d1Client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await d1Client.ConnectAsync(stop.Token);
            await WriteFrame(d1Client, Envelope("HumanBehaviorMonitor", "HELLO", "RiskResponseGuard"), stop.Token);
            using var d1Ack = await ReadFrame(d1Client, stop.Token);
            Assert.Equal("ACCEPTED", d1Ack.RootElement.GetProperty("status").GetString());
            using var d1Welcome = await ReadFrame(d1Client, stop.Token);
            Assert.Equal("WELCOME", d1Welcome.RootElement.GetProperty("messageType").GetString());

            var publish = await new D2FixturePublisher().PublishAsync(database, pipeName, stop.Token);
            Assert.Equal(3, publish.Sent);
            Assert.Equal(0, publish.Rejected);

            IReadOnlyList<RiskReport> saved = [];
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (saved.Count < 3 && DateTimeOffset.UtcNow < deadline)
            {
                saved = await reports.ReadRecentAsync(10, stop.Token);
                if (saved.Count < 3) await Task.Delay(50, stop.Token);
            }
            Assert.Equal(3, saved.Count);
            Assert.Equal(RiskLevel.LOW, saved.Single(x => x.Decision.CorrelationId == "D2-B").Decision.Risk);
            Assert.Equal(RiskLevel.HIGH, saved.Single(x => x.Decision.CorrelationId == "D2-S").Decision.Risk);
            Assert.Equal(RiskLevel.UNKNOWN, saved.Single(x => x.Decision.CorrelationId == "D2-U").Decision.Risk);
            Assert.InRange(advisor.CallCount, 1, 9); // Up to three AI turns per ambiguous correlation.
            using var noSyntheticCameraRequest = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await ReadFrame(d1Client, noSyntheticCameraRequest.Token));
            stop.Cancel();
            await hostTask;
        }
        finally
        {
            stop?.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            stop?.Dispose();
            if (File.Exists(database)) File.Delete(database);
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    [Fact]
    public async Task ActualDemon2NamedPipeBusHandshakesAndDeliversFindingToD3()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-actual-D2-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".actual-d2-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        Task? hostTask = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
            var reports = new RiskReportStore(reportFolder);
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), reports,
                new ImmediateUnavailableAdvisor(), new ActionCatalog());
            hostTask = host.RunAsync(stop.Token);

            await using var d2Bus = new NamedPipeInterDaemonBus(pipeName);
            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D2-ACTUAL-BUS-001";
            await d2Bus.PublishAsync(InterDaemonEnvelopeFactory.Heartbeat(correlationId,
                new EventSourceHealth(TelemetryState.Available, 0, null, now), 0, now), stop.Token);
            var finding = new ThreatFinding("FINDING-INTEGRATION-1", correlationId, "critical_test_rule", 1,
                ThreatSeverity.critical, 0.99, now, now, "Synthetic integration-test finding.",
                [new DetectionFact("test", "synthetic")], ["D2-INTEGRATION-EVIDENCE"], [], now.AddMinutes(2));
            await d2Bus.PublishAsync(InterDaemonEnvelopeFactory.ForFinding(finding, now), stop.Token);

            IReadOnlyList<RiskReport> saved = [];
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            RiskReport? report = null;
            while (report?.ActionResult is null && DateTimeOffset.UtcNow < deadline)
            {
                saved = await reports.ReadRecentAsync(10, stop.Token);
                report = saved.FirstOrDefault(x => x.Decision.CorrelationId == correlationId && x.ActionResult is not null);
                if (report is null) await Task.Delay(50, stop.Token);
            }
            Assert.NotNull(report);
            Assert.Equal(correlationId, report!.Decision.CorrelationId);
            Assert.Equal(RiskLevel.CRITICAL, report.Decision.Risk);
            Assert.Contains("D2-INTEGRATION-EVIDENCE", report.Decision.EvidenceRefs);
            Assert.Contains("critical_test_rule", report.Decision.ReasonCodes);
            Assert.Equal(ActionExecutionStatus.BLOCKED_POLICY, report.ActionResult!.Status);
            stop.Cancel();
            await hostTask;
        }
        finally
        {
            stop.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    [Fact]
    public async Task ActualDemon1AndDemon2ClientsCompleteContextAndVisualReportCycle()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-D1-D2-" + Guid.NewGuid().ToString("N"));
        // Use D1's production pipe client on an isolated test pipe. Never connect to the user's live D1 app.
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".full-integration-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task? hostTask = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(
                pipeName: pipeName, additionalD2ClientSids: ["S-1-5-18"]);
            var reports = new RiskReportStore(reportFolder);
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), reports,
                new ImmediateUnavailableAdvisor(), new ActionCatalog());
            hostTask = host.RunAsync(stop.Token);

            var d1Messages = Channel.CreateUnbounded<D1Envelope>();
            await using var d1 = new D1PipeClient(pipeName, allowIsolatedTestPipe: true);
            d1.MessageReceived += (_, message) => d1Messages.Writer.TryWrite(message);
            await d1.ConnectAndHandshakeAsync(stop.Token);

            await using var d2 = new NamedPipeInterDaemonBus(pipeName);
            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D1-D2-FULL-001";
            await d2.PublishAsync(InterDaemonEnvelopeFactory.Heartbeat(correlationId,
                new EventSourceHealth(TelemetryState.Available, 0, null, now), 0, now), stop.Token);
            var finding = new ThreatFinding("FINDING-FULL-1", correlationId, "critical_test_rule", 1,
                ThreatSeverity.critical, 0.99, now, now, "Synthetic end-to-end finding.",
                [new DetectionFact("test", "synthetic")], ["D2-FULL-EVIDENCE"], [], now.AddMinutes(2));
            await d2.PublishAsync(InterDaemonEnvelopeFactory.ForFinding(finding, now), stop.Token);

            InterDaemonEnvelope? d2ContextRequest = null;
            using (var requestDeadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
            {
                requestDeadline.CancelAfter(TimeSpan.FromSeconds(3));
                await foreach (var request in d2.ReadRequestsAsync(requestDeadline.Token))
                {
                    if (request.MessageType == "CONTEXT_REQUEST") { d2ContextRequest = request; break; }
                }
            }
            Assert.NotNull(d2ContextRequest);
            var d2ContextPayload = JsonSerializer.SerializeToElement(new
            {
                observedAtUtc = DateTimeOffset.UtcNow, found = false,
                requestedFields = new[] { "findingSummary", "ruleDetails", "evidenceKinds", "missingTelemetry" },
                findings = Array.Empty<object>()
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            var d2ContextResponse = new InterDaemonEnvelope(Guid.NewGuid(), correlationId, DateTimeOffset.UtcNow,
                "ThreatMonitor", "RiskResponseGuard", "CONTEXT_RESPONSE", 1, DateTimeOffset.UtcNow.AddSeconds(20), d2ContextPayload);
            await d2.PublishAsync(d2ContextResponse, stop.Token);

            var d1Requests = new Dictionary<string, D1Envelope>(StringComparer.Ordinal);
            while (d1Requests.Count < 2)
            {
                var request = await d1Messages.Reader.ReadAsync(stop.Token);
                if (request.MessageType is "CONTEXT_REQUEST" or "VISUAL_IDENTITY_REQUEST") d1Requests[request.MessageType] = request;
            }
            Assert.Contains("CONTEXT_REQUEST", d1Requests.Keys);
            Assert.Contains("VISUAL_IDENTITY_REQUEST", d1Requests.Keys);

            var contextObservedAt = DateTimeOffset.UtcNow;
            await d1.SendAsync("CONTEXT_RESPONSE", correlationId, new
            {
                schemaVersion = 1, observedAtUtc = contextObservedAt,
                    sessionId = "session-test", applicationContext = new { profileId = "PROFIL_1", observedAtUtc = contextObservedAt,
                        ageSeconds = 1, foregroundApplication = "IDE", seenInLearnedHistory = true,
                        hourCommonForApplication = true, reasonCode = "APPLICATION_AND_HOUR_SEEN_IN_PROFILE" }
            }, DateTimeOffset.UtcNow.AddSeconds(20), stop.Token);

            var visualObservedAt = DateTimeOffset.UtcNow;
            await d1.SendAsync("VISUAL_IDENTITY_RESPONSE", correlationId, new
            {
                status = "MATCH", liveness = "LIVE", similarity = 0.61,
                observedAtUtc = visualObservedAt, profileId = "owner-1", faceQuality = 0.82, validFrames = 5,
                evidenceRef = "D1-FULL-EVIDENCE", reasonCode = "PROFILE_MATCH_AND_LIVENESS_CONFIRMED"
            }, DateTimeOffset.UtcNow.AddSeconds(20), stop.Token);

            var evidenceRequest = await d1Messages.Reader.ReadAsync(stop.Token);
            Assert.Equal("VISUAL_EVIDENCE_READ_REQUEST", evidenceRequest.MessageType);
            await d1.SendAsync("VISUAL_EVIDENCE_CHUNK", correlationId, new
            {
                evidenceRef = "D1-FULL-EVIDENCE", offset = 0, totalBytes = 4,
                chunkBase64 = Convert.ToBase64String([0xFF, 0xD8, 0xFF, 0xD9]), isFinal = true
            }, DateTimeOffset.UtcNow.AddSeconds(20), stop.Token);

            RiskReport? finalReport = null;
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (DateTimeOffset.UtcNow < deadline)
            {
                var found = (await reports.ReadRecentAsync(20, stop.Token))
                    .Where(x => x.Decision.CorrelationId == correlationId)
                    .OrderByDescending(x => x.CreatedAtUtc).FirstOrDefault();
                if (found?.Decision.Risk == RiskLevel.HIGH && found.Attachments?.Count > 0)
                { finalReport = found; break; }
                await Task.Delay(50, stop.Token);
            }

            Assert.NotNull(finalReport);
            Assert.Contains("critical_test_rule", finalReport!.Decision.ReasonCodes);
            Assert.Contains("D2-FULL-EVIDENCE", finalReport.Decision.EvidenceRefs);
            Assert.Contains("D1-FULL-EVIDENCE", finalReport.Decision.EvidenceRefs);
            Assert.Contains("D1_OWNER_VISUALLY_CONFIRMED_RISK_REDUCED_ONE_LEVEL", finalReport.Decision.ReasonCodes);
            Assert.Contains(finalReport.Signals, x => x.SourceDaemon == "ThreatMonitor"
                && x.MessageType == "CONTEXT_RESPONSE" && x.ContextSummary!.Contains("0 matching threat findings", StringComparison.Ordinal));
            stop.Cancel();
            await hostTask;
        }
        finally
        {
            stop.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    [Fact]
    public async Task D2AcknowledgedMessageIsReplayedFromDurableInboxAfterD3PipeRestart()
    {
        if (!OperatingSystem.IsWindows()) return;
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-inbox-pipe-" + Guid.NewGuid().ToString("N"));
        var database = Path.Combine(folder, "inbox.sqlite3");
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".inbox-restart-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        var journal = new SqliteInboundMessageJournal(database);
        SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer? firstServer = null;
        SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer? restartedServer = null;
        try
        {
            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D3-INBOX-PIPE-RESTART-001";
            var envelope = InterDaemonEnvelopeFactory.Heartbeat(correlationId,
                new EventSourceHealth(TelemetryState.Available, 0, null, now), 0, now);
            firstServer = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName, journal: journal);
            firstServer.Start();
            await using var d2 = new NamedPipeInterDaemonBus(pipeName);
            await d2.PublishAsync(envelope, stop.Token); // D2 receives ACCEPTED only after the SQLite insert commits.

            var firstRead = firstServer.ReadAllAsync(stop.Token).GetAsyncEnumerator(stop.Token);
            Assert.True(await firstRead.MoveNextAsync());
            Assert.Equal(envelope.MessageId, firstRead.Current.MessageId);
            await firstRead.DisposeAsync();

            await firstServer.DisposeAsync();
            firstServer = null; // Simulate a D3 crash after the sender was acknowledged but before processing completed.

            restartedServer = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName, journal: journal);
            restartedServer.Start();
            var replayRead = restartedServer.ReadAllAsync(stop.Token).GetAsyncEnumerator(stop.Token);
            Assert.True(await replayRead.MoveNextAsync());
            Assert.Equal(envelope.MessageId, replayRead.Current.MessageId);
            Assert.Equal(correlationId, replayRead.Current.CorrelationId);
            await replayRead.DisposeAsync();

            await restartedServer.MarkProcessedAsync(envelope.MessageId, stop.Token);
            Assert.Empty(await journal.ReadPendingAsync(stop.Token));
        }
        finally
        {
            stop.Cancel();
            if (firstServer is not null) await firstServer.DisposeAsync();
            if (restartedServer is not null) await restartedServer.DisposeAsync();
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "LiveOllama")]
    public async Task LiveOllamaReceivesRealD1D2PipeContextAndWritesAuditedReport()
    {
        // Opt-in: this test requires the local Ollama service and gemma3:1b.
        if (Environment.GetEnvironmentVariable("SENTINELCORE_LIVE_OLLAMA_TEST") != "1") return;
        if (!OperatingSystem.IsWindows()) return;

        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-live-ollama-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".live-ollama-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(110));
        Task? hostTask = null;
        Task? d1Responder = null;
        Task? d2Responder = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
            var reports = new RiskReportStore(reportFolder);
            using var ollamaHttp = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
            var advisor = new OllamaAmbiguousCaseAdvisor(ollamaHttp, OllamaAdvisorOptions.Default);
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), reports, advisor, new ActionCatalog());
            hostTask = host.RunAsync(stop.Token);

            var d1Messages = Channel.CreateUnbounded<D1Envelope>();
            await using var d1 = new D1PipeClient(pipeName, allowIsolatedTestPipe: true);
            d1.MessageReceived += (_, message) => d1Messages.Writer.TryWrite(message);
            await d1.ConnectAndHandshakeAsync(stop.Token);
            await using var d2 = new NamedPipeInterDaemonBus(pipeName);

            // The production D1 and D2 clients are connected to D3's real named-pipe server;
            // responders below return fixed protocol messages and never access camera or host actions.
            d1Responder = Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    var request = await d1Messages.Reader.ReadAsync(stop.Token);
                    if (request.MessageType == "CONTEXT_REQUEST")
                    {
                        var observedAt = DateTimeOffset.UtcNow;
                        await d1.SendAsync("CONTEXT_RESPONSE", request.CorrelationId, new
                        {
                            schemaVersion = 1, observedAtUtc = observedAt, sessionId = "live-ollama-test",
                            applicationContext = new { profileId = "test-profile", observedAtUtc = observedAt, ageSeconds = 1,
                                foregroundApplication = "IDE", seenInLearnedHistory = true, hourCommonForApplication = true,
                                reasonCode = "APPLICATION_AND_HOUR_SEEN_IN_PROFILE" }
                        }, DateTimeOffset.UtcNow.AddSeconds(20), stop.Token);
                    }
                    else if (request.MessageType == "VISUAL_IDENTITY_REQUEST")
                    {
                        var observedAt = DateTimeOffset.UtcNow;
                        await d1.SendAsync("VISUAL_IDENTITY_RESPONSE", request.CorrelationId, new
                        {
                            status = "INDETERMINATE", liveness = "NOT_CONFIRMED", similarity = (double?)null,
                            observedAtUtc = observedAt, profileId = "test-profile", faceQuality = (double?)null,
                            validFrames = 0, evidenceRef = (string?)null, reasonCode = "LIVE_TEST_NO_CAMERA"
                        }, DateTimeOffset.UtcNow.AddSeconds(20), stop.Token);
                    }
                }
            }, stop.Token);

            d2Responder = Task.Run(async () =>
            {
                await foreach (var request in d2.ReadRequestsAsync(stop.Token))
                {
                    if (request.MessageType != "CONTEXT_REQUEST") continue;
                    var observedAt = DateTimeOffset.UtcNow;
                    var payload = JsonSerializer.SerializeToElement(new
                    {
                        observedAtUtc = observedAt, found = false,
                        requestedFields = new[] { "findingSummary", "ruleDetails", "evidenceKinds", "missingTelemetry" },
                        findings = Array.Empty<object>()
                    }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
                    await d2.PublishAsync(new InterDaemonEnvelope(Guid.NewGuid(), request.CorrelationId, observedAt,
                        "ThreatMonitor", "RiskResponseGuard", "CONTEXT_RESPONSE", 1, observedAt.AddSeconds(20), payload), stop.Token);
                }
            }, stop.Token);

            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D1-D2-OLLAMA-LIVE-001";
            await d2.PublishAsync(InterDaemonEnvelopeFactory.Heartbeat(correlationId,
                new EventSourceHealth(TelemetryState.Available, 0, null, now), 0, now), stop.Token);
            var finding = new ThreatFinding("FINDING-OLLAMA-LIVE-1", correlationId, "suspicious_download_chain", 1,
                ThreatSeverity.high, 0.82, now, now, "Potentially suspicious download and process launch; corroboration requested.",
                [new DetectionFact("chain", "download followed by process start")], ["D2-OLLAMA-LIVE-EVIDENCE"], [], now.AddMinutes(2));
            await d2.PublishAsync(InterDaemonEnvelopeFactory.ForFinding(finding, now), stop.Token);

            RiskReport? latest = null;
            var deadline = DateTimeOffset.UtcNow.AddSeconds(95);
            while (DateTimeOffset.UtcNow < deadline)
            {
                latest = (await reports.ReadRecentAsync(30, stop.Token))
                    .Where(x => x.Decision.CorrelationId == correlationId)
                    .OrderByDescending(x => x.CreatedAtUtc).FirstOrDefault();
                if (latest?.AiAdvice?.DurationMilliseconds is > 0
                    && latest.AiAdvice.Status is AdvisorStatus.Advised or AdvisorStatus.InvalidResponse)
                    break;
                await Task.Delay(250, stop.Token);
            }

            Assert.NotNull(latest?.AiAdvice);
            Assert.Equal(OllamaAdvisorOptions.Default.Model, latest!.AiAdvice!.Model);
            Assert.True(latest.AiAdvice.DurationMilliseconds > 0);
            _output.WriteLine($"Ollama model={latest.AiAdvice.Model}; outcome={latest.AiAdvice.Status}; inferenceMs={latest.AiAdvice.DurationMilliseconds:F0}; risk={latest.Decision.Risk}; requestedContext={string.Join(",", latest.AiAdvice.Advice?.RequestedContext ?? [])}");
            Assert.Contains(latest.Signals, x => x.SourceDaemon == "ThreatMonitor" && x.MessageType == "THREAT_FINDING");
            Assert.Contains("D2-OLLAMA-LIVE-EVIDENCE", latest.Decision.EvidenceRefs);
            Assert.NotEmpty(Directory.EnumerateFiles(reportFolder, "*.txt"));
        }
        finally
        {
            stop.Cancel();
            foreach (var task in new[] { d1Responder, d2Responder, hostTask }.Where(x => x is not null))
            {
                try { await task!; }
                catch (OperationCanceledException) { }
            }
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    [Fact]
    public async Task D1RequestTimeoutsAreRecordedWithoutLoweringTechnicalRisk()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-D1-timeout-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".d1-timeout-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task? hostTask = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
            var reports = new RiskReportStore(reportFolder);
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), reports,
                new ImmediateUnavailableAdvisor(), new ActionCatalog(),
                new Demon3HostOptions(TimeSpan.FromMilliseconds(200), TimeSpan.FromMilliseconds(250)));
            hostTask = host.RunAsync(stop.Token);

            await using var d1 = new D1PipeClient(pipeName, allowIsolatedTestPipe: true);
            await d1.ConnectAndHandshakeAsync(stop.Token);
            await using var d2 = new NamedPipeInterDaemonBus(pipeName);
            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D1-REQUEST-TIMEOUT-001";
            await d2.PublishAsync(InterDaemonEnvelopeFactory.Heartbeat(correlationId,
                new EventSourceHealth(TelemetryState.Available, 0, null, now), 0, now), stop.Token);
            var finding = new ThreatFinding("FINDING-TIMEOUT-1", correlationId, "critical_test_rule", 1,
                ThreatSeverity.critical, 0.99, now, now, "Synthetic timeout-test finding.",
                [new DetectionFact("test", "synthetic")], ["D2-TIMEOUT-EVIDENCE"], [], now.AddMinutes(2));
            await d2.PublishAsync(InterDaemonEnvelopeFactory.ForFinding(finding, now), stop.Token);

            IReadOnlyList<RiskReport> saved = [];
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (DateTimeOffset.UtcNow < deadline)
            {
                saved = await reports.ReadRecentAsync(20, stop.Token);
                var caseReports = saved.Where(x => x.Decision.CorrelationId == correlationId).ToArray();
                var reasons = caseReports.SelectMany(x => x.Signals).Select(x => x.ReasonCode).ToHashSet(StringComparer.Ordinal);
                if (reasons.Contains("D1_CONTEXT_RESPONSE_TIMEOUT") && reasons.Contains("D1_VISUAL_RESPONSE_TIMEOUT")) break;
                await Task.Delay(50, stop.Token);
            }
            var latest = saved.Where(x => x.Decision.CorrelationId == correlationId).OrderByDescending(x => x.CreatedAtUtc).First();
            var allReasons = saved.Where(x => x.Decision.CorrelationId == correlationId).SelectMany(x => x.Signals)
                .Select(x => x.ReasonCode).ToHashSet(StringComparer.Ordinal);
            Assert.Contains("D1_CONTEXT_RESPONSE_TIMEOUT", allReasons);
            Assert.Contains("D1_VISUAL_RESPONSE_TIMEOUT", allReasons);
            Assert.Equal(RiskLevel.CRITICAL, latest.Decision.Risk);
            Assert.Contains("D2-TIMEOUT-EVIDENCE", latest.Decision.EvidenceRefs);
        }
        finally
        {
            stop.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    [Fact]
    public async Task LowAiConclusionCannotDowngradeHighD2Finding()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-AI-floor-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".ai-floor-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task? hostTask = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
            var reports = new RiskReportStore(reportFolder);
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), reports, new LowRiskNoContextAdvisor(), new ActionCatalog(),
                new Demon3HostOptions(TimeSpan.FromMilliseconds(250), TimeSpan.FromMilliseconds(250)));
            hostTask = host.RunAsync(stop.Token);

            await using var d1 = new D1PipeClient(pipeName, allowIsolatedTestPipe: true);
            await d1.ConnectAndHandshakeAsync(stop.Token);
            await using var d2 = new NamedPipeInterDaemonBus(pipeName);
            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D3-AI-TECHNICAL-FLOOR-001";
            await d2.PublishAsync(InterDaemonEnvelopeFactory.Heartbeat(correlationId,
                new EventSourceHealth(TelemetryState.Available, 0, null, now), 0, now), stop.Token);
            var finding = new ThreatFinding("D2-AI-FLOOR-FINDING", correlationId, "high_test_rule", 1,
                ThreatSeverity.high, 0.94, now, now, "Synthetic high technical finding.",
                [new DetectionFact("test", "synthetic")], ["D2-AI-FLOOR-EVIDENCE"], [], now.AddMinutes(2));
            await d2.PublishAsync(InterDaemonEnvelopeFactory.ForFinding(finding, now), stop.Token);

            RiskReport? latest = null;
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (DateTimeOffset.UtcNow < deadline)
            {
                latest = (await reports.ReadRecentAsync(20, stop.Token))
                    .Where(x => x.Decision.CorrelationId == correlationId)
                    .OrderByDescending(x => x.CreatedAtUtc).FirstOrDefault();
                if (latest?.AiAdvice?.Advice?.RiskBand == AdviceRiskBand.LOW
                    && latest.ActionResult is not null) break;
                await Task.Delay(40, stop.Token);
            }

            Assert.NotNull(latest);
            Assert.Equal(AdviceRiskBand.LOW, latest!.AiAdvice!.Advice!.RiskBand);
            Assert.Equal(RiskLevel.HIGH, latest.Decision.Risk);
            Assert.Equal(ProposedAction.RUN_DEFENDER_SCAN, latest.Decision.ProposedAction);
            Assert.Contains("D2-AI-FLOOR-EVIDENCE", latest.Decision.EvidenceRefs);
            Assert.Contains(latest.Signals, signal => signal.EvidenceRefs.Contains("D2-AI-FLOOR-EVIDENCE"));
            Assert.True(latest.Decision.RequiresHumanApproval);
            Assert.Contains("AI_RESULT_RAISED_TO_D2_TECHNICAL_FLOOR", latest.Decision.ReasonCodes);
            Assert.Equal(ActionExecutionStatus.SIMULATED, latest.ActionResult!.Status);
        }
        finally
        {
            stop.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    [Fact]
    public async Task AiReassessesAfterRequestedD1ContextAndOwnsFinalVerdict()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-AI-context-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".ai-context-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task? hostTask = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
            var reports = new RiskReportStore(reportFolder);
            var advisor = new ContextThenLowRiskAdvisor();
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), reports, advisor, new ActionCatalog());
            hostTask = host.RunAsync(stop.Token);

            var d1Messages = Channel.CreateUnbounded<D1Envelope>();
            await using var d1 = new D1PipeClient(pipeName, allowIsolatedTestPipe: true);
            d1.MessageReceived += (_, message) => d1Messages.Writer.TryWrite(message);
            await d1.ConnectAndHandshakeAsync(stop.Token);
            const string correlationId = "D3-AI-CONTEXT-REASSESS-001";
            var observed = DateTimeOffset.UtcNow;
            await d1.SendAsync("BEHAVIOR_DEVIATION", correlationId, new
            {
                schemaVersion = 1, observedAtUtc = observed, sid = "TEST-SID", sessionId = "test-session",
                operatorAssessment = "BEHAVIOR_DIFFERENT", deviationPercent = 72.0, confidence = 0.86,
                signals = new { keyboardDeviationPercent = 68.0, mouseDeviationPercent = 20.0, keyboardFeatureCount = 4, mouseFeatureCount = 4 },
                reasonCodes = new[] { "DIVERGENCE_OVER_60" }, evidenceRefs = new[] { "D1-AI-CONTEXT-EVIDENCE" }
            }, observed.AddSeconds(20), stop.Token);

            var contextRequest = await d1Messages.Reader.ReadAsync(stop.Token);
            Assert.Equal("CONTEXT_REQUEST", contextRequest.MessageType);
            Assert.Equal(correlationId, contextRequest.CorrelationId);
            var contextObserved = DateTimeOffset.UtcNow;
            await d1.SendAsync("CONTEXT_RESPONSE", correlationId, new
            {
                schemaVersion = 1, observedAtUtc = contextObserved, sessionId = "session-test",
                applicationContext = new
                {
                    profileId = "PROFILE_TEST", observedAtUtc = contextObserved, ageSeconds = 1,
                    foregroundApplication = "IDE.exe", foregroundSeconds = 420, localHour = 10, localDayOfWeek = 2,
                    seenInLearnedHistory = true, hourCommonForApplication = true, cpuPercent = 31.4,
                    memoryMiB = 612.0, systemMemoryUsedPercent = 48.0, sampleCount = 68,
                    reasonCode = "APPLICATION_AND_HOUR_SEEN_IN_PROFILE"
                }
            }, contextObserved.AddSeconds(20), stop.Token);

            RiskReport? final = null;
            var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
            while (DateTimeOffset.UtcNow < deadline)
            {
                final = (await reports.ReadRecentAsync(20, stop.Token))
                    .FirstOrDefault(x => x.Decision.CorrelationId == correlationId && x.AiAdvice?.Advice?.RiskBand == AdviceRiskBand.LOW);
                if (final is not null) break;
                await Task.Delay(40, stop.Token);
            }

            Assert.NotNull(final);
            Assert.Equal(2, advisor.CallCount);
            Assert.Equal(RiskLevel.LOW, final!.Decision.Risk);
            Assert.Equal(DecisionKind.MONITOR, final.Decision.Decision);
            Assert.Contains("Analyse Ollama", final.Decision.Explanation, StringComparison.Ordinal);
            Assert.Equal("CHANGED", final.Comparison.Result);
            Assert.Equal(RiskLevel.UNKNOWN, final.Comparison.PreviousRisk);
            var readableFinal = Directory.GetFiles(reportFolder, "*.txt")
                .Select(File.ReadAllText).FirstOrDefault(x => x.Contains("Évaluation IA retenue", StringComparison.Ordinal));
            Assert.NotNull(readableFinal);
            Assert.Contains("Fait reformulé par l’IA", readableFinal, StringComparison.Ordinal);
            Assert.Contains("durée 1234 ms", readableFinal, StringComparison.Ordinal);
            var learnedContext = Assert.Single(advisor.ReceivedCases[1].Signals, x => x.MessageType == "CONTEXT_RESPONSE");
            Assert.Contains("foregroundApp=IDE.exe", learnedContext.Facts!);
            Assert.Contains("seenInLearnedHistory=yes", learnedContext.Facts!);
        }
        finally
        {
            stop.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    [Fact]
    public async Task EnabledDefenderScanRequiresFreshD1MasterPasswordApproval()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-owner-approval-" + Guid.NewGuid().ToString("N"));
        var pipeName = SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer.PipeName + ".owner-approval-" + Guid.NewGuid().ToString("N");
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(12));
        Task? hostTask = null;
        try
        {
            await using var d3Bus = new SentinelCore.Demon3.Core.Transport.NamedPipeInterDaemonServer(pipeName: pipeName);
            var reports = new RiskReportStore(reportFolder);
            var runner = new RecordingDefenderRunner();
            var host = new Demon3Host(d3Bus, new RiskDecisionEngine(), reports,
                new ThrowingIOExceptionAdvisor(), new ActionCatalog(ActionCatalogMode.DefenderQuickScanEnabled, runner));
            hostTask = host.RunAsync(stop.Token);

            var d1Messages = Channel.CreateUnbounded<D1Envelope>();
            await using var d1 = new D1PipeClient(pipeName, allowIsolatedTestPipe: true);
            d1.MessageReceived += (_, message) => d1Messages.Writer.TryWrite(message);
            await d1.ConnectAndHandshakeAsync(stop.Token);
            await using var d2 = new NamedPipeInterDaemonBus(pipeName);
            var now = DateTimeOffset.UtcNow;
            const string correlationId = "D3-OWNER-APPROVAL-001";
            await d2.PublishAsync(InterDaemonEnvelopeFactory.Heartbeat(correlationId,
                new EventSourceHealth(TelemetryState.Available, 0, null, now), 0, now), stop.Token);
            var finding = new ThreatFinding("FINDING-OWNER-APPROVAL", correlationId, "high_test_rule", 1,
                ThreatSeverity.high, 0.92, now, now, "Synthetic high finding for approval test.",
                [new DetectionFact("test", "synthetic")], ["D2-APPROVAL-EVIDENCE"], [], now.AddMinutes(2));
            await d2.PublishAsync(InterDaemonEnvelopeFactory.ForFinding(finding, now), stop.Token);

            D1Envelope? approval = null;
            while (approval is null)
            {
                var message = await d1Messages.Reader.ReadAsync(stop.Token);
                if (message.MessageType == "MASTER_AUTH_REQUIRED") approval = message;
            }
            var challengeId = approval.Payload.GetProperty("challengeId").GetString();
            var actionId = approval.Payload.GetProperty("actionId").GetString();
            var deadline = approval.Payload.GetProperty("deadlineUtc").GetDateTimeOffset();
            Assert.Equal("RUN_DEFENDER_SCAN", actionId);
            Assert.True(deadline > DateTimeOffset.UtcNow);

            await d1.SendAsync("MASTER_AUTH_RESULT", correlationId, new
            {
                challengeId, actionId, approved = true, verifiedAtUtc = DateTimeOffset.UtcNow,
                reasonCode = "OWNER_MASTER_PASSWORD_CONFIRMED"
            }, DateTimeOffset.UtcNow.AddSeconds(10), stop.Token);

            RiskReport? completed = null;
            var reportDeadline = DateTimeOffset.UtcNow.AddSeconds(4);
            while (DateTimeOffset.UtcNow < reportDeadline)
            {
                completed = (await reports.ReadRecentAsync(20, stop.Token))
                    .FirstOrDefault(x => x.Decision.CorrelationId == correlationId && x.ActionResult?.Status == ActionExecutionStatus.COMPLETED);
                if (completed is not null) break;
                await Task.Delay(40, stop.Token);
            }
            Assert.NotNull(completed);
            Assert.Equal(1, runner.CallCount);
            Assert.False(completed!.ActionResult!.SimulationOnly);
            Assert.Equal("RUN_DEFENDER_QUICK_SCAN", completed.ActionResult.ActionId);
            Assert.Equal("OLLAMA_IO_FAILURE", completed.AiAdvice?.ErrorCode);
        }
        finally
        {
            stop.Cancel();
            if (hostTask is not null)
            {
                try { await hostTask; }
                catch (OperationCanceledException) { }
            }
            if (Directory.Exists(reportFolder)) Directory.Delete(reportFolder, recursive: true);
        }
    }

    private sealed class ImmediateUnavailableAdvisor : IAmbiguousCaseAdvisor
    {
        private int _callCount;
        public int CallCount => _callCount;
        public Task<AdvisorOutcome> AnalyzeAsync(AmbiguousSecurityCase securityCase, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _callCount);
            return Task.FromResult(AdvisorOutcome.Failure(AdvisorStatus.Unavailable, "test-model", "TEST_OFFLINE"));
        }
    }

    private sealed class LowRiskNoContextAdvisor : IAmbiguousCaseAdvisor
    {
        public Task<AdvisorOutcome> AnalyzeAsync(AmbiguousSecurityCase securityCase, CancellationToken cancellationToken = default)
        {
            var evidence = securityCase.Signals.SelectMany(x => x.EvidenceRefs).Distinct(StringComparer.Ordinal).ToArray();
            var advice = new RiskAdvice(AdviceRiskBand.LOW, 0.99, "Réponse synthétique de test.", [], [], [], [], [],
                SuggestedMeasure.CONTINUE_MONITORING, "Réponse de test volontairement rassurante.", evidence,
                "Test de garde contre une baisse de risque.");
            return Task.FromResult(new AdvisorOutcome(AdvisorStatus.Advised, advice, "test-low-model", null, DateTimeOffset.UtcNow));
        }
    }

    private sealed class ThrowingIOExceptionAdvisor : IAmbiguousCaseAdvisor
    {
        public Task<AdvisorOutcome> AnalyzeAsync(AmbiguousSecurityCase securityCase, CancellationToken cancellationToken = default)
            => Task.FromException<AdvisorOutcome>(new IOException("Synthetic transport failure."));
    }

    private sealed class ContextThenLowRiskAdvisor : IAmbiguousCaseAdvisor
    {
        private int _callCount;
        private readonly System.Collections.Concurrent.ConcurrentQueue<AmbiguousSecurityCase> _received = new();
        public int CallCount => _callCount;
        public IReadOnlyList<AmbiguousSecurityCase> ReceivedCases => _received.ToArray();

        public Task<AdvisorOutcome> AnalyzeAsync(AmbiguousSecurityCase securityCase, CancellationToken cancellationToken = default)
        {
            _received.Enqueue(securityCase);
            var call = Interlocked.Increment(ref _callCount);
            var evidenceRefs = securityCase.Signals.SelectMany(x => x.EvidenceRefs).Distinct(StringComparer.Ordinal).ToArray();
            var advice = call == 1
                ? new RiskAdvice(AdviceRiskBand.ELEVATED, 0.52, "Le comportement diffère; il faut vérifier le contexte applicatif.",
                    ["Écart agrégé élevé"], ["Une session de développement peut expliquer l’écart"], ["Changement d’opérateur possible"],
                    ["Application active non confirmée"], [], SuggestedMeasure.REQUEST_D1_CONTEXT,
                    "Comparer à l’habitude de l’application au moment observé.", evidenceRefs, "Contexte D1 nécessaire.")
                : new RiskAdvice(AdviceRiskBand.LOW, 0.94, "IDE.exe est habituel à cette heure et correspond au profil appris.",
                    ["Application connue", "Heure habituelle"], ["Développement assisté attendu"], [], [], [],
                    SuggestedMeasure.CONTINUE_MONITORING, "Le contexte récent D1 explique l’écart sans signal technique corroborant.",
                    evidenceRefs, "Activité cohérente après contextualisation.");
            return Task.FromResult(new AdvisorOutcome(AdvisorStatus.Advised, advice, "test-advisor", null, DateTimeOffset.UtcNow, 1234.5));
        }
    }

    [Fact]
    public async Task ReportStoreKeepsReadableReportsAndComparesPriorDecision()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new RiskReportStore(folder);
            var engine = new RiskDecisionEngine();
            var signals = new[] { new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "LOW", 0.7, "OBSERVATION", ["E1"], Now) };
            var first = await store.SaveAsync(engine.Evaluate("same-case", signals), signals);
            var changedSignals = signals.Append(new DecisionEvidence("HumanBehaviorMonitor", "BEHAVIOR_DEVIATION", "HIGH", 0.9, "BEHAVIOR_DIVERGENCE_OVER_60", [], Now)).ToArray();
            var changed = engine.Evaluate("same-case", changedSignals);
            var second = await store.SaveAsync(changed, changedSignals);
            Assert.Equal("CHANGED", second.Comparison.Result);
            var actionAt = DateTimeOffset.UtcNow;
            var actionResult = new ActionExecutionResult("TEST_ACTION", ActionExecutionStatus.SIMULATED,
                "Résultat de mesure attaché à son rapport exact.", actionAt, actionAt, true);
            Assert.True(await store.UpdateActionResultAsync(first.ReportId, actionResult));
            var afterActionUpdate = await store.ReadRecentAsync();
            Assert.Equal(ActionExecutionStatus.SIMULATED, afterActionUpdate.Single(x => x.ReportId == first.ReportId).ActionResult!.Status);
            Assert.Null(afterActionUpdate.Single(x => x.ReportId == second.ReportId).ActionResult);
            var similar = engine.Evaluate("another-case", signals);
            var third = await store.SaveAsync(similar, signals);
            Assert.Equal("UNCHANGED", third.Comparison.Result);
            Assert.Equal("SIMILAR_SIGNAL_PATTERN", third.Comparison.Basis);
            if (OperatingSystem.IsWindows())
            {
                Assert.True(await store.AttachVisualEvidenceAsync("another-case", "D1-VISUAL-1", [0xFF, 0xD8, 0xFF, 0xD9]));
                var reportWithImage = (await store.ReadRecentAsync()).First(x => x.Decision.CorrelationId == "another-case");
                Assert.Single(reportWithImage.Attachments!);
                Assert.EndsWith(".jpg.dpapi", reportWithImage.Attachments![0].EncryptedPath, StringComparison.Ordinal);
            }
            Assert.Equal(3, (await store.ReadRecentAsync()).Count);
            Assert.Equal(3, Directory.GetFiles(folder, "*.txt").Length);
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public async Task ReportStoreExportsStructurallyValidPdfAndEmbedsDecryptableImage()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-PdfStore-" + Guid.NewGuid().ToString("N"));
        var exportFolder = Path.Combine(Path.GetTempPath(), "SentinelCore-D3-PdfExport-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new RiskReportStore(folder);
            var signals = new[]
            {
                new DecisionEvidence("ThreatMonitor", "THREAT_FINDING", "HIGH", 0.91, "TEST_PDF_REPORT",
                    ["test-evidence-reference"], Now)
            };
            var decision = new RiskDecisionEngine().Evaluate("pdf-export-case", signals);
            var report = await store.SaveAsync(decision, signals);
            var image = Convert.FromBase64String(TinyJpegBase64);
            var includeImage = OperatingSystem.IsWindows();
            if (includeImage)
                Assert.True(await store.AttachVisualEvidenceAsync("pdf-export-case", "D1-VISUAL-PDF-TEST", image));

            var pdfPath = Path.Combine(exportFolder, "risk-report.pdf");
            Assert.True(await store.ExportPdfAsync(report.ReportId, pdfPath));
            var bytes = await File.ReadAllBytesAsync(pdfPath);
            var pdf = Encoding.Latin1.GetString(bytes);

            Assert.StartsWith("%PDF-1.4", pdf, StringComparison.Ordinal);
            Assert.Contains("SENTINELCORE - RAPPORT DE RISQUE", pdf, StringComparison.Ordinal);
            Assert.Contains("%%EOF", pdf, StringComparison.Ordinal);
            var startXrefMarker = pdf.LastIndexOf("startxref\n", StringComparison.Ordinal);
            Assert.True(startXrefMarker >= 0);
            var xrefLineStart = startXrefMarker + "startxref\n".Length;
            var xrefLineEnd = pdf.IndexOf('\n', xrefLineStart);
            Assert.True(xrefLineEnd > xrefLineStart);
            Assert.True(int.TryParse(pdf[xrefLineStart..xrefLineEnd], out var xrefOffset));
            Assert.StartsWith("xref\n", pdf[xrefOffset..], StringComparison.Ordinal);

            if (includeImage)
            {
                Assert.Contains("/Subtype /Image", pdf, StringComparison.Ordinal);
                Assert.Contains("/Filter /DCTDecode", pdf, StringComparison.Ordinal);
                Assert.Contains("/Count 2", pdf, StringComparison.Ordinal);
                var reportWithImage = Assert.Single(await store.ReadRecentAsync(), x => x.ReportId == report.ReportId);
                Assert.Single(reportWithImage.Attachments!);
                Assert.DoesNotContain(reportWithImage.Attachments![0].EncryptedPath, pdf, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(".jpg.dpapi", pdf, StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                Assert.Contains("/Count 1", pdf, StringComparison.Ordinal);
                Assert.DoesNotContain("/Subtype /Image", pdf, StringComparison.Ordinal);
            }
        }
        finally
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
            if (Directory.Exists(exportFolder)) Directory.Delete(exportFolder, recursive: true);
        }
    }

    private const string TinyJpegBase64 = "/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wAARCAACAAIDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD8qqKKKAP/2Q==";
}

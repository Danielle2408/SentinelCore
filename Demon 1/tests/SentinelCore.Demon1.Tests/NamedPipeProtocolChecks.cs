using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using SentinelCore.Demon1.VisualVerification;

internal static class NamedPipeProtocolChecks
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static async Task RunAsync()
    {
        // Never contend with the real D3 listener: tests may run while the product is active.
        var testPipeName = $"SentinelCore.Guard.Test.{Guid.NewGuid():N}";
        await using var server = new NamedPipeServerStream(testPipeName, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        await using var client = new InterDaemonPipeClient(testPipeName, allowIsolatedTestPipe: true);
        var visualRequestReceived = new TaskCompletionSource<InterDaemonEnvelope>(TaskCreationOptions.RunContinuationsAsynchronously);
        client.MessageReceived += (_, envelope) =>
        {
            if (envelope.MessageType == "VISUAL_IDENTITY_REQUEST") visualRequestReceived.TrySetResult(envelope);
        };

        var mockD3 = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            var hello = await ReadEnvelopeAsync(server);
            Require(hello.MessageType == "HELLO" && hello.SourceDaemon == "HumanBehaviorMonitor", "mock D3 receives D1 HELLO");
            await WriteJsonFrameAsync(server, new InterDaemonAcknowledgement(hello.MessageId, "ACCEPTED"));
            var now = DateTimeOffset.UtcNow;
            await WriteJsonFrameAsync(server, new InterDaemonEnvelope("mock-welcome", hello.CorrelationId, now,
                "RiskResponseGuard", "HumanBehaviorMonitor", "WELCOME", 1, now.AddSeconds(30),
                JsonSerializer.SerializeToElement(new { sessionId = "mock-session" }, JsonOptions)));
            var welcomeAck = await ReadJsonAsync(server);
            Require(welcomeAck.RootElement.GetProperty("status").GetString() == "ACCEPTED", "D1 acknowledges D3 WELCOME");

            var context = await ReadEnvelopeAsync(server);
            Require(context.MessageType == "USER_CONTEXT", "D1 sends its allowed USER_CONTEXT message");
            await WriteJsonFrameAsync(server, new InterDaemonAcknowledgement(context.MessageId, "ACCEPTED"));

            var sentAt = DateTimeOffset.UtcNow;
            var request = new VisualIdentityRequest("mock-visual-correlation", "SUSPICION", sentAt,
                sentAt.AddSeconds(30), true);
            await WriteJsonFrameAsync(server, new InterDaemonEnvelope("mock-visual-request", request.CorrelationId,
                sentAt, "RiskResponseGuard", "HumanBehaviorMonitor", "VISUAL_IDENTITY_REQUEST", 1,
                sentAt.AddSeconds(30), JsonSerializer.SerializeToElement(request, JsonOptions)));
            var requestAck = await ReadJsonAsync(server);
            Require(requestAck.RootElement.GetProperty("messageId").GetString() == "mock-visual-request"
                && requestAck.RootElement.GetProperty("status").GetString() == "ACCEPTED", "D1 accepts D3 visual request");

            var response = await ReadEnvelopeAsync(server);
            Require(response.MessageType == "VISUAL_IDENTITY_RESPONSE"
                && response.CorrelationId == request.CorrelationId, "D1 sends a correlated visual response");
            await WriteJsonFrameAsync(server, new InterDaemonAcknowledgement(response.MessageId, "ACCEPTED"));
        });

        var welcomePayload = await client.ConnectAndHandshakeAsync().WaitAsync(TimeSpan.FromSeconds(8));
        Require(welcomePayload.GetProperty("sessionId").GetString() == "mock-session", "D1 completes the HELLO/WELCOME handshake");
        await client.SendAsync("USER_CONTEXT", "mock-context-correlation", new { profileId = "OWNER_1" },
            DateTimeOffset.UtcNow.AddSeconds(30));
        var incoming = await visualRequestReceived.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var parsedRequest = incoming.Payload.Deserialize<VisualIdentityRequest>(JsonOptions);
        Require(parsedRequest?.CorrelationId == incoming.CorrelationId, "D3 visual request payload preserves correlation");
        await client.SendAsync("VISUAL_IDENTITY_RESPONSE", incoming.CorrelationId,
            new VisualIdentityResponse(incoming.CorrelationId, "INDETERMINATE", null, "LIVE", null,
                .8, 4, null, DateTimeOffset.UtcNow, "NO_ENROLLED_VISUAL_PROFILE"),
            DateTimeOffset.UtcNow.AddSeconds(30));
        await mockD3.WaitAsync(TimeSpan.FromSeconds(5));
    }

    private static async Task<InterDaemonEnvelope> ReadEnvelopeAsync(Stream stream)
    {
        using var json = await ReadJsonAsync(stream);
        return json.RootElement.Deserialize<InterDaemonEnvelope>(JsonOptions)
            ?? throw new InvalidDataException("Mock D3 received an empty envelope.");
    }

    private static async Task<JsonDocument> ReadJsonAsync(Stream stream)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > InterDaemonPipeClient.MaximumMessageBytes)
            throw new InvalidDataException("Mock D3 received an invalid frame length.");
        var body = new byte[length];
        await stream.ReadExactlyAsync(body);
        return JsonDocument.Parse(body);
    }

    private static async Task WriteJsonFrameAsync(Stream stream, object value)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(value, JsonOptions);
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, body.Length);
        await stream.WriteAsync(header);
        await stream.WriteAsync(body);
        await stream.FlushAsync();
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new Exception("FAIL " + message);
        Console.WriteLine("PASS " + message);
    }
}

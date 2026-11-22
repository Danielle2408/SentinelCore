namespace SentinelCore.Demon2.Core;

/// <summary>Requests only coarse session categories for ambiguous findings and stores a validated, correlation-linked reply.</summary>
public sealed class SessionContextRelay(IEventStore store, ISessionContextResponseReceivingInterDaemonBus bus,
    TimeProvider? timeProvider = null)
{
    private static readonly string[] RequestedFields = ["sessionState", "localOrRemote", "recentAuthBand"];
    private static readonly TimeSpan ResponseDeadline = TimeSpan.FromSeconds(15);
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<bool> RequestForFindingAsync(ThreatFinding finding, CancellationToken cancellationToken = default)
    {
        if (finding.MissingTelemetry.Count == 0) return false;
        var deadline = _clock.GetUtcNow().ToUniversalTime().Add(ResponseDeadline);
        var request = InterDaemonEnvelopeFactory.ForSessionContextRequest(finding.CorrelationId, RequestedFields, deadline);
        if (!InterDaemonEnvelopeValidator.TryValidate(request, _clock.GetUtcNow(), out var error))
            throw new InvalidOperationException($"D2 generated an invalid session-context request: {error}");
        return await store.TryEnqueueSessionContextRequestAsync(request, finding.FindingId, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        await foreach (var message in bus.ReadSessionContextResponsesAsync(cancellationToken)
            .WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            var now = _clock.GetUtcNow();
            if (!SessionContextResponseValidator.TryValidate(message, now, out var response, out _)
                || response is null) continue;
            await store.SaveSessionContextResponseAsync(message.CorrelationId, response, now, cancellationToken)
                .ConfigureAwait(false);
        }
    }
}

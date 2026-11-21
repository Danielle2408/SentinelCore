namespace SentinelCore.Demon2.Core;

public sealed class TelemetryHealthMonitor(TimeSpan? staleAfter = null)
{
    private readonly TimeSpan _staleAfter = staleAfter ?? TimeSpan.FromSeconds(30);

    public static TelemetryState ClassifySourceState(bool watcherEnabled, string? activeError) =>
        !watcherEnabled ? TelemetryState.Unavailable
        : activeError is not null ? TelemetryState.Degraded
        : TelemetryState.Available;

    public TelemetryGap? Evaluate(string source, EventSourceHealth health, DateTimeOffset nowUtc)
    {
        var lastKnown = health.LastEventUtc ?? health.StartedAtUtc;
        var stale = lastKnown is { } last && nowUtc - last > _staleAfter;
        if (health.State == TelemetryState.Available && !stale) return null;
        var reason = health.Error ?? (health.DroppedCount > 0
            ? "La file de collecte bornée a perdu des événements."
            : stale ? "Aucun événement reçu dans le délai de santé." : "La source de télémétrie est dégradée ou indisponible.");
        return new(Guid.NewGuid().ToString("N"), source, nowUtc.ToUniversalTime(), reason, health.DroppedCount, []);
    }
}

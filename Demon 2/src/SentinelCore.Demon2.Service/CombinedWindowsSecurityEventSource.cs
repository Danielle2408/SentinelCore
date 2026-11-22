using System.Runtime.Versioning;
using System.Threading.Channels;
using SentinelCore.Demon2.Core;

namespace SentinelCore.Demon2.Service;

[SupportedOSPlatform("windows")]
public sealed class CombinedWindowsSecurityEventSource : IEventSource<SysmonRecord>, IEventSourceHealthProvider,
    IMultiEventCursorSource, IAsyncDisposable
{
    private readonly IReadOnlyList<IEventSource<SysmonRecord>> _sources;
    private readonly Channel<SysmonRecord> _records = Channel.CreateBounded<SysmonRecord>(new BoundedChannelOptions(4096)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
        SingleWriter = false
    });
    private bool _started;
    private int _disposeStarted;

    public CombinedWindowsSecurityEventSource(params IEventSource<SysmonRecord>[] sources)
    {
        if (sources.Length == 0 || sources.Select(source => source.Name).Distinct(StringComparer.Ordinal).Count() != sources.Length)
            throw new ArgumentException("At least one source with a unique name is required.", nameof(sources));
        _sources = sources;
    }

    public string Name => "WindowsSecurity";

    public async IAsyncEnumerable<SysmonRecord> ReadAllAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (_started) throw new InvalidOperationException("A combined source instance can only be consumed once.");
        _started = true;
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pumps = _sources.Select(source => PumpAsync(source, lifetime.Token)).ToArray();
        var completion = CompleteWriterWhenPumpsFinishAsync(pumps);
        try
        {
            await foreach (var record in _records.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
                yield return record;
        }
        finally
        {
            lifetime.Cancel();
            await completion.ConfigureAwait(false);
        }
    }

    private async Task PumpAsync(IEventSource<SysmonRecord> source, CancellationToken token)
    {
        try
        {
            await foreach (var record in source.ReadAllAsync(token).WithCancellation(token).ConfigureAwait(false))
                await _records.Writer.WriteAsync(record, token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        catch (Exception ex)
        {
            try { await _records.Writer.WriteAsync(new SysmonRecord("", null,
                $"Windows event source stopped ({ex.GetType().Name}).", source.Name), token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { }
        }
    }

    private async Task CompleteWriterWhenPumpsFinishAsync(Task[] pumps)
    {
        try { await Task.WhenAll(pumps).ConfigureAwait(false); }
        finally { _records.Writer.TryComplete(); }
    }

    public EventSourceHealth GetHealth()
    {
        var states = _sources.Select(source => (source.Name, Health: (source as IEventSourceHealthProvider)?.GetHealth()))
            .ToArray();
        var healthyCount = states.Count(x => x.Health?.State == TelemetryState.Available);
        var allHealthy = healthyCount == states.Length;
        var state = allHealthy ? TelemetryState.Available
            : healthyCount > 0 ? TelemetryState.Degraded : TelemetryState.Unavailable;
        var unavailable = states.Where(x => x.Health?.State != TelemetryState.Available)
            .Select(x => x.Name + ": " + (x.Health?.Error ?? "health not reported"));
        var errors = unavailable.ToArray();
        var known = states.Where(x => x.Health is not null).Select(x => x.Health!).ToArray();
        var lastEvent = known.Where(x => x.LastEventUtc.HasValue).Select(x => x.LastEventUtc!.Value)
            .DefaultIfEmpty().Max();
        var startedAt = known.Where(x => x.StartedAtUtc.HasValue).Select(x => x.StartedAtUtc!.Value)
            .DefaultIfEmpty().Min();
        return new(state, known.Sum(x => x.DroppedCount), errors.Length == 0 ? null : string.Join("; ", errors),
            lastEvent == default ? null : lastEvent,
            known.Sum(x => x.QueueDepth), startedAt == default ? null : startedAt);
    }

    public void CommitCursor(string cursor) => CommitCursor("Sysmon", cursor);

    public void CommitCursor(string sourceName, string cursor)
    {
        var source = _sources.FirstOrDefault(item => string.Equals(item.Name, sourceName, StringComparison.Ordinal));
        if (source is IEventCursorSource cursorSource) cursorSource.CommitCursor(cursor);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0) return;
        _records.Writer.TryComplete();
        foreach (var source in _sources.OfType<IAsyncDisposable>())
            await source.DisposeAsync().ConfigureAwait(false);
    }
}

using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Threading.Channels;
using SentinelCore.Demon2.Core;

namespace SentinelCore.Demon2.Service;

[SupportedOSPlatform("windows")]
public sealed class PowerShellScriptBlockEventSource(string? bookmarkXml = null)
    : IEventSource<SysmonRecord>, IEventSourceHealthProvider, IEventCursorSource, IAsyncDisposable
{
    public const string ChannelName = "Microsoft-Windows-PowerShell/Operational";
    private const string EventFilter = "*[System[(EventID=4104)]]";
    private readonly Channel<SysmonRecord> _records = Channel.CreateBounded<SysmonRecord>(new BoundedChannelOptions(1024)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
        SingleWriter = false
    });
    private readonly CancellationTokenSource _disposeStop = new();
    private EventLogWatcher? _watcher;
    private TaskCompletionSource? _watcherFailure;
    private Task? _watchTask;
    private volatile string? _bookmarkXml = bookmarkXml;
    private long _dropped;
    private int _queueDepth;
    private DateTimeOffset? _lastEventUtc;
    private DateTimeOffset? _startedAtUtc;
    private string? _error;
    private int _disposeStarted;
    private bool _started;
    private volatile bool _disposed;

    public string Name => "PowerShell";

    public async IAsyncEnumerable<SysmonRecord> ReadAllAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("PowerShell Operational Event Log requires Windows.");
        if (_started) throw new InvalidOperationException("A PowerShell source instance can only be consumed once.");
        _started = true;
        using var watchStop = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _disposeStop.Token);
        _watchTask = WatchLoopAsync(watchStop.Token);
        try
        {
            await foreach (var record in _records.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                Interlocked.Decrement(ref _queueDepth);
                yield return record;
            }
        }
        finally
        {
            watchStop.Cancel();
            if (_watchTask is not null) await _watchTask.ConfigureAwait(false);
        }
    }

    public EventSourceHealth GetHealth()
    {
        var state = TelemetryHealthMonitor.ClassifySourceState(_watcher?.Enabled == true, _error);
        return new(state, Interlocked.Read(ref _dropped), _error, _lastEventUtc,
            Volatile.Read(ref _queueDepth), _startedAtUtc);
    }

    private async Task WatchLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && !_disposed)
        {
            try
            {
                var query = new EventLogQuery(ChannelName, PathType.LogName, EventFilter);
                var bookmark = string.IsNullOrWhiteSpace(_bookmarkXml) ? null : new EventBookmark(_bookmarkXml);
                _watcherFailure = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _watcher = new EventLogWatcher(query, bookmark, readExistingEvents: bookmark is not null);
                _watcher.EventRecordWritten += OnEventRecordWritten;
                _watcher.Enabled = true;
                _startedAtUtc = DateTimeOffset.UtcNow;
                _error = null;
                await _watcherFailure.Task.WaitAsync(ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _error = $"PowerShell Operational Event Log unavailable ({ex.GetType().Name}).";
                _startedAtUtc ??= DateTimeOffset.UtcNow;
                QueueSourceError(_error);
            }
            finally
            {
                if (_watcher is not null)
                {
                    _watcher.EventRecordWritten -= OnEventRecordWritten;
                    _watcher.Dispose();
                    _watcher = null;
                }
            }
            if (!_disposed && !ct.IsCancellationRequested)
            {
                try { await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            }
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            _error = $"PowerShell Event Log watcher failed ({e.EventException.GetType().Name}).";
            QueueSourceError(_error);
            _watcherFailure?.TrySetResult();
            return;
        }
        if (e.EventRecord is not { } record) return;
        using (record)
        {
            try
            {
                var entry = new SysmonRecord(record.ToXml(), record.Bookmark?.BookmarkXml, SourceName: Name);
                Interlocked.Increment(ref _queueDepth);
                if (_records.Writer.TryWrite(entry))
                {
                    _lastEventUtc = DateTimeOffset.UtcNow;
                    if (_watcher?.Enabled == true) _error = null;
                }
                else
                {
                    Interlocked.Decrement(ref _queueDepth);
                    Interlocked.Increment(ref _dropped);
                    _error = "PowerShell event queue is full; a telemetry record was dropped.";
                }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _dropped);
                _error = $"PowerShell event could not be read ({ex.GetType().Name}).";
                QueueSourceError(_error);
            }
        }
    }

    private void QueueSourceError(string message)
    {
        Interlocked.Increment(ref _queueDepth);
        if (!_records.Writer.TryWrite(new SysmonRecord("", null, message, Name)))
            Interlocked.Decrement(ref _queueDepth);
    }

    public void CommitCursor(string cursor) => _bookmarkXml = cursor;

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0) return;
        _disposed = true;
        _disposeStop.Cancel();
        _records.Writer.TryComplete();
        _watcher?.Dispose();
        try { if (_watchTask is not null) await _watchTask.ConfigureAwait(false); }
        finally { _disposeStop.Dispose(); }
    }
}

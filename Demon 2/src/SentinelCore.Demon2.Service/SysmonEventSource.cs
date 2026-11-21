using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Threading.Channels;
using SentinelCore.Demon2.Core;

namespace SentinelCore.Demon2.Service;

[SupportedOSPlatform("windows")]
public sealed class SysmonEventSource(string? bookmarkXml = null) : IEventSource<SysmonRecord>, IEventSourceHealthProvider, IEventCursorSource, IAsyncDisposable
{
    public const string ChannelName = "Microsoft-Windows-Sysmon/Operational";
    private readonly Channel<SysmonRecord> _records = Channel.CreateBounded<SysmonRecord>(new BoundedChannelOptions(2048)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
        SingleWriter = false
    });
    private EventLogWatcher? _watcher;
    private TaskCompletionSource? _watcherFailure;
    private Task? _watchTask;
    private volatile string? _bookmarkXml = bookmarkXml;
    private long _dropped;
    private int _queueDepth;
    private DateTimeOffset? _lastEventUtc;
    private DateTimeOffset? _startedAtUtc;
    private string? _error;
    private bool _started;
    private volatile bool _disposed;

    public string Name => "Sysmon";

    public async IAsyncEnumerable<SysmonRecord> ReadAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Sysmon Event Log collection requires Windows.");
        if (_started) throw new InvalidOperationException("A Sysmon source instance can only be consumed once.");
        _started = true;
        _watchTask = WatchLoopAsync(cancellationToken);
        await foreach (var record in _records.Reader.ReadAllAsync(cancellationToken))
        {
            Interlocked.Decrement(ref _queueDepth);
            yield return record;
        }
        if (_watchTask is not null) await _watchTask;
    }

    public EventSourceHealth GetHealth()
    {
        var watching = _watcher?.Enabled == true;
        var state = !watching ? TelemetryState.Unavailable
            : _error is not null || Interlocked.Read(ref _dropped) > 0 ? TelemetryState.Degraded
            : TelemetryState.Available;
        return new(state, Interlocked.Read(ref _dropped), _error, _lastEventUtc, Volatile.Read(ref _queueDepth), _startedAtUtc);
    }

    private async Task WatchLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && !_disposed)
        {
            try
            {
                var query = new EventLogQuery(ChannelName, PathType.LogName);
                var bookmark = string.IsNullOrWhiteSpace(_bookmarkXml) ? null : new EventBookmark(_bookmarkXml);
                _watcherFailure = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _watcher = new EventLogWatcher(query, bookmark, true);
                _watcher.EventRecordWritten += OnEventRecordWritten;
                _watcher.Enabled = true;
                _startedAtUtc = DateTimeOffset.UtcNow;
                _error = null;
                await _watcherFailure.Task.WaitAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _error = $"Sysmon Event Log unavailable: {ex.Message}";
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
            if (!_disposed && !ct.IsCancellationRequested) await Task.Delay(TimeSpan.FromSeconds(2), ct);
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventException is not null)
        {
            _error = e.EventException.Message;
            QueueSourceError($"Sysmon Event Log watcher failed: {e.EventException.Message}");
            _watcherFailure?.TrySetResult();
            return;
        }
        if (e.EventRecord is not { } record) return;
        using (record)
        {
            try
            {
                var entry = new SysmonRecord(record.ToXml(), record.Bookmark?.BookmarkXml);
                Interlocked.Increment(ref _queueDepth);
                if (_records.Writer.TryWrite(entry))
                {
                    _lastEventUtc = DateTimeOffset.UtcNow;
                    if (_watcher?.Enabled == true) _error = null;
                }
                else { Interlocked.Decrement(ref _queueDepth); Interlocked.Increment(ref _dropped); }
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref _dropped);
                _error = $"Sysmon event could not be read: {ex.Message}";
                QueueSourceError(_error);
            }
        }
    }

    private void QueueSourceError(string message)
    {
        Interlocked.Increment(ref _queueDepth);
        if (!_records.Writer.TryWrite(new SysmonRecord("", null, message)))
        {
            Interlocked.Decrement(ref _queueDepth);
        }
    }

    public void CommitCursor(string cursor) => _bookmarkXml = cursor;

    public ValueTask DisposeAsync()
    {
        _disposed = true;
        _records.Writer.TryComplete();
        _watcher?.Dispose();
        return ValueTask.CompletedTask;
    }
}

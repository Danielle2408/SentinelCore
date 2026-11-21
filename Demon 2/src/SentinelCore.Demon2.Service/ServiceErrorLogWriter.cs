using System.Text;
using System.Text.RegularExpressions;

namespace SentinelCore.Demon2.Service;

/// <summary>Persists the service's error diagnostics while retaining interactive stderr output.</summary>
internal sealed class ServiceErrorLogWriter : TextWriter
{
    private const long MaximumDailyLogBytes = 10 * 1024 * 1024;
    private const int MaximumLogLineCharacters = 8_192;
    private readonly object _gate = new();
    private readonly TextWriter _console;
    private readonly string _directory;
    private StreamWriter _file;
    private DateOnly _fileDate;
    private bool _fileAtLimit;
    private bool _limitWarningWritten;

    public ServiceErrorLogWriter(string directory, TextWriter console)
    {
        _directory = Path.GetFullPath(directory);
        Directory.CreateDirectory(_directory);
        _console = console;
        _fileDate = DateOnly.FromDateTime(DateTime.UtcNow);
        _file = OpenDailyFile(_fileDate);
    }

    public override Encoding Encoding => new UTF8Encoding(false);

    public override void WriteLine(string? value)
    {
        lock (_gate)
        {
            var timestamp = DateTimeOffset.UtcNow;
            var safeValue = Sanitize(value);
            _console.WriteLine(safeValue);
            EnsureDailyFile(timestamp);
            if (_fileAtLimit) { WarnLimitOnce(); return; }
            var line = $"{timestamp:O} {safeValue}";
            var bytes = Encoding.UTF8.GetByteCount(line) + Encoding.UTF8.GetByteCount(Environment.NewLine);
            if (_file.BaseStream.Length + bytes > MaximumDailyLogBytes)
            {
                _fileAtLimit = true;
                WarnLimitOnce();
                return;
            }
            try { _file.WriteLine(line); }
            catch (IOException) { _fileAtLimit = true; WarnLimitOnce(); }
            catch (UnauthorizedAccessException) { _fileAtLimit = true; WarnLimitOnce(); }
        }
    }

    public override void Write(string? value)
    {
        lock (_gate)
        {
            var timestamp = DateTimeOffset.UtcNow;
            var safeValue = Sanitize(value);
            _console.Write(safeValue);
            EnsureDailyFile(timestamp);
            if (_fileAtLimit) { WarnLimitOnce(); return; }
            var bytes = Encoding.UTF8.GetByteCount(safeValue);
            if (_file.BaseStream.Length + bytes > MaximumDailyLogBytes)
            {
                _fileAtLimit = true;
                WarnLimitOnce();
                return;
            }
            try { _file.Write(safeValue); }
            catch (IOException) { _fileAtLimit = true; WarnLimitOnce(); }
            catch (UnauthorizedAccessException) { _fileAtLimit = true; WarnLimitOnce(); }
        }
    }

    public override void Write(char value)
    {
        lock (_gate)
        {
            _console.Write(value);
            EnsureDailyFile(DateTimeOffset.UtcNow);
            if (!_fileAtLimit)
            {
                try
                {
                    if (_file.BaseStream.Length + Encoding.UTF8.GetByteCount(value.ToString()) > MaximumDailyLogBytes)
                    {
                        _fileAtLimit = true;
                        WarnLimitOnce();
                        return;
                    }
                    _file.Write(value);
                }
                catch (IOException) { _fileAtLimit = true; WarnLimitOnce(); }
                catch (UnauthorizedAccessException) { _fileAtLimit = true; WarnLimitOnce(); }
            }
        }
    }

    public override void Flush()
    {
        lock (_gate)
        {
            _console.Flush();
            EnsureDailyFile(DateTimeOffset.UtcNow);
            if (!_fileAtLimit)
            {
                try
                {
                    _file.Flush();
                    _fileAtLimit = _file.BaseStream.Length >= MaximumDailyLogBytes;
                }
                catch (IOException) { _fileAtLimit = true; }
                catch (UnauthorizedAccessException) { _fileAtLimit = true; }
            }
        }
    }

    private StreamWriter OpenDailyFile(DateOnly date)
    {
        var path = Path.Combine(_directory, $"threat-monitor-{date:yyyyMMdd}.log");
        var writer = new StreamWriter(new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite), new UTF8Encoding(false))
        {
            AutoFlush = true
        };
        _fileAtLimit = writer.BaseStream.Length >= MaximumDailyLogBytes;
        _limitWarningWritten = false;
        return writer;
    }

    private void EnsureDailyFile(DateTimeOffset nowUtc)
    {
        var date = DateOnly.FromDateTime(nowUtc.UtcDateTime);
        if (date == _fileDate) return;
        _file.Dispose();
        _fileDate = date;
        _file = OpenDailyFile(date);
    }

    private void WarnLimitOnce()
    {
        if (_limitWarningWritten) return;
        _limitWarningWritten = true;
        _console.WriteLine($"{DateTimeOffset.UtcNow:O} Threat Monitor daily log reached its 10 MiB limit; persistent logging is paused until the next UTC day.");
    }

    private static string Sanitize(string? value)
    {
        if (string.IsNullOrEmpty(value)) return string.Empty;
        var redacted = Regex.Replace(value,
            "(?i)\\b(password|passwd|secret|token|api[_-]?key|authorization)\\b(\\s*[:=]\\s*)(\\\"[^\\\"]*\\\"|'[^']*'|[^,\\s;\\\"}]+)",
            "$1$2[REDACTED]");
        return redacted.Length <= MaximumLogLineCharacters ? redacted : redacted[..MaximumLogLineCharacters] + " [truncated]";
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _file.Dispose();
        base.Dispose(disposing);
    }
}

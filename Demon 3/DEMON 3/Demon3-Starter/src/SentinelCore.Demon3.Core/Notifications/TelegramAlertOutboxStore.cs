using System.Text.Json;

namespace SentinelCore.Demon3.Core.Notifications;

public sealed record TelegramAlertOutboxEntry(Guid ReportId, string CorrelationId,
    DateTimeOffset QueuedAtUtc, int Attempts, DateTimeOffset NextAttemptAtUtc, bool Delivered);

/// <summary>Small local retry ledger; it stores report identifiers only, never the token or report contents.</summary>
public sealed class TelegramAlertOutboxStore(string? filePath = null)
{
    private const int MaximumEntries = 256;
    private static readonly TimeSpan PendingRetention = TimeSpan.FromDays(7);
    private static readonly TimeSpan DeliveredRetention = TimeSpan.FromDays(1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly object _gate = new();
    private readonly string _filePath = filePath ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon3", "telegram-alert-outbox.json");

    public IReadOnlyList<TelegramAlertOutboxEntry> ReadAll()
    {
        lock (_gate)
        {
            var entries = ReadUnsafe();
            var retained = entries.Where(IsRetained).ToArray();
            if (retained.Length != entries.Count) WriteUnsafe(retained);
            return retained;
        }
    }

    public bool TryEnqueue(Guid reportId, string correlationId)
    {
        if (reportId == Guid.Empty || string.IsNullOrWhiteSpace(correlationId) || correlationId.Length > 128) return false;
        lock (_gate)
        {
            var entries = ReadUnsafe().Where(IsRetained).ToList();
            if (entries.Any(x => x.CorrelationId.Equals(correlationId, StringComparison.Ordinal))) return false;
            if (entries.Count >= MaximumEntries) return false;
            var now = DateTimeOffset.UtcNow;
            entries.Add(new(reportId, correlationId, now, 0, now, false));
            WriteUnsafe(entries);
            return true;
        }
    }

    public bool MarkDelivered(Guid reportId)
        => Update(reportId, entry => entry with { Delivered = true, NextAttemptAtUtc = DateTimeOffset.MaxValue });

    public bool ScheduleRetry(Guid reportId, int attempts, DateTimeOffset nextAttemptAtUtc)
        => Update(reportId, entry => entry with { Attempts = Math.Clamp(attempts, 0, 100_000), NextAttemptAtUtc = nextAttemptAtUtc });

    public void RemovePending()
    {
        lock (_gate) WriteUnsafe(ReadUnsafe().Where(x => x.Delivered).ToArray());
    }

    private bool Update(Guid reportId, Func<TelegramAlertOutboxEntry, TelegramAlertOutboxEntry> update)
    {
        lock (_gate)
        {
            var entries = ReadUnsafe();
            var index = entries.FindIndex(x => x.ReportId == reportId && !x.Delivered);
            if (index < 0) return false;
            entries[index] = update(entries[index]);
            WriteUnsafe(entries);
            return true;
        }
    }

    private List<TelegramAlertOutboxEntry> ReadUnsafe()
    {
        if (!File.Exists(_filePath)) return [];
        try
        {
            var info = new FileInfo(_filePath);
            if (info.Length is <= 0 or > 1024 * 1024) return [];
            var entries = JsonSerializer.Deserialize<List<TelegramAlertOutboxEntry>>(File.ReadAllText(_filePath), JsonOptions);
            return entries?.Where(x => x.ReportId != Guid.Empty && !string.IsNullOrWhiteSpace(x.CorrelationId)
                && x.CorrelationId.Length <= 128 && x.Attempts is >= 0 and <= 100_000).Take(MaximumEntries).ToList() ?? [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or ArgumentException)
        {
            return [];
        }
    }

    private void WriteUnsafe(IReadOnlyCollection<TelegramAlertOutboxEntry> entries)
    {
        var fullPath = Path.GetFullPath(_filePath);
        var directory = Path.GetDirectoryName(fullPath) ?? throw new InvalidOperationException("Dossier Outbox invalide.");
        Directory.CreateDirectory(directory);
        var tempPath = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(tempPath, JsonSerializer.Serialize(entries, JsonOptions));
            File.Move(tempPath, fullPath, overwrite: true);
        }
        finally { if (File.Exists(tempPath)) File.Delete(tempPath); }
    }

    private static bool IsRetained(TelegramAlertOutboxEntry entry)
        => DateTimeOffset.UtcNow - entry.QueuedAtUtc <= (entry.Delivered ? DeliveredRetention : PendingRetention);
}

using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon3.Core.Contracts;

namespace SentinelCore.Demon3.Core.Transport;

public enum InboundMessageStatus { Inserted, PendingDuplicate, ProcessedDuplicate, CapacityExceeded }

/// <summary>Durable D3 inbox: accepted daemon messages survive a process restart until D3 records them.</summary>
public interface IInboundMessageJournal
{
    Task<InboundMessageStatus> EnqueueAsync(DaemonEnvelope message, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<DaemonEnvelope>> ReadPendingAsync(CancellationToken cancellationToken = default);
    Task MarkProcessedAsync(Guid messageId, CancellationToken cancellationToken = default);
}

/// <summary>SQLite-backed, idempotent local inbox for D1/D2 protocol messages.</summary>
public sealed class SqliteInboundMessageJournal(string databasePath) : IInboundMessageJournal
{
    private const int MaximumPendingMessages = 4096;
    private static readonly TimeSpan ProcessedMessageRetention = TimeSpan.FromDays(30);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _databasePath = Path.GetFullPath(databasePath ?? throw new ArgumentNullException(nameof(databasePath)));

    public async Task<InboundMessageStatus> EnqueueAsync(DaemonEnvelope message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            await using (var find = connection.CreateCommand())
            {
                find.Transaction = transaction;
                find.CommandText = "SELECT processed FROM inbound_messages WHERE message_id=$id";
                find.Parameters.AddWithValue("$id", message.MessageId.ToString("D"));
                var processed = await find.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
                if (processed is not null)
                    return Convert.ToInt32(processed, System.Globalization.CultureInfo.InvariantCulture) == 0
                        ? InboundMessageStatus.PendingDuplicate : InboundMessageStatus.ProcessedDuplicate;
            }

            var now = DateTimeOffset.UtcNow;
            await using (var prune = connection.CreateCommand())
            {
                prune.Transaction = transaction;
                prune.CommandText = "DELETE FROM inbound_messages WHERE processed=1 AND processed_at_utc < $cutoff";
                prune.Parameters.AddWithValue("$cutoff", now.Subtract(ProcessedMessageRetention).ToString("O"));
                await prune.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await using (var count = connection.CreateCommand())
            {
                count.Transaction = transaction;
                count.CommandText = "SELECT COUNT(*) FROM inbound_messages WHERE processed=0";
                if (Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false), System.Globalization.CultureInfo.InvariantCulture)
                    >= MaximumPendingMessages)
                {
                    await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
                    return InboundMessageStatus.CapacityExceeded;
                }
            }
            await using (var insert = connection.CreateCommand())
            {
                insert.Transaction = transaction;
                insert.CommandText = "INSERT INTO inbound_messages(message_id, received_at_utc, payload_json, processed) VALUES($id,$received,$payload,0)";
                insert.Parameters.AddWithValue("$id", message.MessageId.ToString("D"));
                insert.Parameters.AddWithValue("$received", now.ToString("O"));
                insert.Parameters.AddWithValue("$payload", JsonSerializer.Serialize(message, JsonOptions));
                await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return InboundMessageStatus.Inserted;
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<DaemonEnvelope>> ReadPendingAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT payload_json FROM inbound_messages WHERE processed=0 ORDER BY received_at_utc, message_id";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            var messages = new List<DaemonEnvelope>();
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var message = JsonSerializer.Deserialize<DaemonEnvelope>(reader.GetString(0), JsonOptions)
                    ?? throw new InvalidDataException("Enveloppe vide dans la file locale D3.");
                messages.Add(message);
            }
            return messages;
        }
        finally { _gate.Release(); }
    }

    public async Task MarkProcessedAsync(Guid messageId, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE inbound_messages SET processed=1, processed_at_utc=$processed WHERE message_id=$id";
            command.Parameters.AddWithValue("$id", messageId.ToString("D"));
            command.Parameters.AddWithValue("$processed", DateTimeOffset.UtcNow.ToString("O"));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    private async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken)
    {
        var folder = Path.GetDirectoryName(_databasePath);
        if (!string.IsNullOrWhiteSpace(folder)) Directory.CreateDirectory(folder);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false
        }.ToString());
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS inbound_messages(message_id TEXT PRIMARY KEY, received_at_utc TEXT NOT NULL, payload_json TEXT NOT NULL, processed INTEGER NOT NULL DEFAULT 0, processed_at_utc TEXT);";
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }
}

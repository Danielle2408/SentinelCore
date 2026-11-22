using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon3.Core.Contracts;

namespace SentinelCore.Demon3.Core.Reports;

public sealed record SessionActivityItem(DateTimeOffset ObservedAtUtc, string SourceDaemon, string MessageType,
    string Severity, string Summary, string CorrelationId);

public sealed record ManualActivitySnapshotResult(SessionActivityReport Report, bool SessionInitializedForSnapshot);

public sealed record SessionActivityReport(Guid ReportId, string SessionId, DateTimeOffset SessionStartedAtUtc,
    DateTimeOffset ComputerBootAtUtc, DateTimeOffset CapturedAtUtc, DateTimeOffset? SessionEndedAtUtc, string Trigger, bool IsFinal,
    int TotalActivityCount, int D1ActivityCount, int D2ActivityCount, int ThreatCount, int TelemetryGapCount,
    int D1HeartbeatCount, int D2HeartbeatCount, DateTimeOffset? D1LastSeenAtUtc,
    DateTimeOffset? D2LastSeenAtUtc, int DecisionCount, string SessionState,
    IReadOnlyDictionary<string, int> ActivityCounts, IReadOnlyList<SessionActivityItem> RecentActivities,
    string Summary, string JsonPath, string TextPath);

/// <summary>
/// Keeps a compact local journal of D1/D2 signals observed by D3 and produces activity snapshots.
/// It stores only message type, severity, reason code and correlation ID; it never stores raw payloads.
/// </summary>
public sealed class SessionActivityReportService
{
    private const int MaximumRecentActivities = 100;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string _directory;
    private readonly string _databasePath;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SessionActivityReportService(string? directory = null)
    {
        _directory = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelCore", "Demon3", "reports");
        _databasePath = Path.Combine(_directory, "session-activity.sqlite3");
    }

    /// <summary>Starts a new SentinelCore session, writes its startup report and recovers an unclosed session.</summary>
    public async Task<SessionActivityReport> BeginSessionAsync(DateTimeOffset? computerBootAtUtc = null,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(_directory);
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;
            var previousSession = await ReadActiveSessionIdAsync(connection, cancellationToken).ConfigureAwait(false);
            string? interruptedId = null;
            await using (var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
            {
                if (previousSession is not null)
                {
                    interruptedId = previousSession;
                    await using var recover = connection.CreateCommand();
                    recover.Transaction = (SqliteTransaction)transaction;
                    recover.CommandText = "UPDATE sessions SET ended_at_utc=$ended, state='INTERRUPTED' WHERE session_id=$id AND ended_at_utc IS NULL";
                    recover.Parameters.AddWithValue("$ended", Format(now));
                    recover.Parameters.AddWithValue("$id", interruptedId);
                    await recover.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }

                var sessionId = Guid.NewGuid().ToString("N");
                var bootTime = (computerBootAtUtc ?? EstimateComputerBootTime()).ToUniversalTime();
                await using var insert = connection.CreateCommand();
                insert.Transaction = (SqliteTransaction)transaction;
                insert.CommandText = "INSERT INTO sessions(session_id, started_at_utc, computer_boot_at_utc, state) VALUES($id,$started,$boot,'ACTIVE')";
                insert.Parameters.AddWithValue("$id", sessionId);
                insert.Parameters.AddWithValue("$started", Format(now));
                insert.Parameters.AddWithValue("$boot", Format(bootTime));
                await insert.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

                if (interruptedId is not null)
                    await SaveSnapshotCoreAsync(connection, interruptedId, "INTERRUPTED_AFTER_RESTART", true, now, cancellationToken).ConfigureAwait(false);
                return await SaveSnapshotCoreAsync(connection, sessionId, "STARTUP", false, null, cancellationToken).ConfigureAwait(false);
            }
        }
        finally { _gate.Release(); }
    }

    /// <summary>Updates D1/D2 coverage without writing every heartbeat as a separate activity row.</summary>
    public async Task RecordHeartbeatAsync(string sourceDaemon, DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        var isD1 = sourceDaemon == DaemonNames.HumanBehaviorMonitor;
        var isD2 = sourceDaemon == DaemonNames.ThreatMonitor;
        if (!isD1 && !isD2) throw new ArgumentOutOfRangeException(nameof(sourceDaemon), "Seuls D1 et D2 publient ces battements.");
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            var column = isD1 ? "d1_heartbeat_count" : "d2_heartbeat_count";
            var lastSeenColumn = isD1 ? "d1_last_seen_utc" : "d2_last_seen_utc";
            await using var command = connection.CreateCommand();
            command.CommandText = $"UPDATE sessions SET {column}={column}+1, {lastSeenColumn}=$seen WHERE session_id=(SELECT session_id FROM sessions WHERE state='ACTIVE' ORDER BY started_at_utc DESC LIMIT 1)";
            command.Parameters.AddWithValue("$seen", Format(observedAtUtc));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Records a minimized D1/D2 signal; payload fields and raw process/user data are deliberately omitted.</summary>
    public async Task RecordActivityAsync(string sourceDaemon, string messageType, string severity,
        string? reasonCode, string? correlationId, DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        if (sourceDaemon is not (DaemonNames.HumanBehaviorMonitor or DaemonNames.ThreatMonitor))
            throw new ArgumentOutOfRangeException(nameof(sourceDaemon), "Un rapport de session ne journalise que les signaux D1 et D2.");
        if (!IsSafeCode(messageType, 64)) throw new ArgumentException("Type de signal invalide.", nameof(messageType));
        if (!IsSafeCode(severity, 32)) severity = "UNKNOWN";
        var safeReason = IsSafeCode(reasonCode, 96) ? reasonCode! : "UNSPECIFIED";
        var safeCorrelation = IsSafeCorrelation(correlationId) ? correlationId! : string.Empty;
        var summary = $"Signal {messageType}; niveau {severity}; motif {safeReason}.";

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            var sessionId = await ReadActiveSessionIdAsync(connection, cancellationToken).ConfigureAwait(false);
            if (sessionId is null) return;
            await using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO activities(activity_id,session_id,observed_at_utc,source_daemon,message_type,severity,summary,correlation_id) VALUES($activity,$session,$observed,$source,$type,$severity,$summary,$correlation)";
            command.Parameters.AddWithValue("$activity", Guid.NewGuid().ToString("N"));
            command.Parameters.AddWithValue("$session", sessionId);
            command.Parameters.AddWithValue("$observed", Format(observedAtUtc));
            command.Parameters.AddWithValue("$source", sourceDaemon);
            command.Parameters.AddWithValue("$type", messageType);
            command.Parameters.AddWithValue("$severity", severity);
            command.Parameters.AddWithValue("$summary", summary);
            command.Parameters.AddWithValue("$correlation", safeCorrelation);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Counts one durable D3 risk decision in the current session report.</summary>
    public async Task RecordDecisionAsync(string risk, string decision, string? correlationId,
        DateTimeOffset observedAtUtc, CancellationToken cancellationToken = default)
    {
        if (!IsSafeCode(risk, 32)) risk = "UNKNOWN";
        if (!IsSafeCode(decision, 48)) decision = "UNSPECIFIED";
        var safeCorrelation = IsSafeCorrelation(correlationId) ? correlationId! : string.Empty;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            var sessionId = await ReadActiveSessionIdAsync(connection, cancellationToken).ConfigureAwait(false);
            if (sessionId is null) return;
            await using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO activities(activity_id,session_id,observed_at_utc,source_daemon,message_type,severity,summary,correlation_id) VALUES($activity,$session,$observed,$source,'RISK_DECISION',$severity,$summary,$correlation)";
            command.Parameters.AddWithValue("$activity", Guid.NewGuid().ToString("N"));
            command.Parameters.AddWithValue("$session", sessionId);
            command.Parameters.AddWithValue("$observed", Format(observedAtUtc));
            command.Parameters.AddWithValue("$source", DaemonNames.RiskResponseGuard);
            command.Parameters.AddWithValue("$severity", risk);
            command.Parameters.AddWithValue("$summary", $"Décision D3 {decision}, niveau {risk}.");
            command.Parameters.AddWithValue("$correlation", safeCorrelation);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    /// <summary>Creates an on-demand or periodic snapshot for the latest SentinelCore session.</summary>
    public async Task<SessionActivityReport> CreateSnapshotAsync(string trigger = "MANUAL",
        CancellationToken cancellationToken = default)
    {
        if (!IsSafeCode(trigger, 48)) throw new ArgumentException("Déclencheur invalide; utiliser un code court en lettres, chiffres et underscore.", nameof(trigger));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            var sessionId = await ReadLatestSessionIdAsync(connection, cancellationToken).ConfigureAwait(false)
                ?? throw new InvalidOperationException("Aucune session SentinelCore n’a encore été ouverte par D3.");
            return await SaveSnapshotCoreAsync(connection, sessionId, trigger, IsFinalTrigger(trigger), null, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Creates an on-demand report even when an older D3 build has not opened the activity journal yet.
    /// The new journal starts at this moment; it does not claim to contain activity from before initialization.
    /// </summary>
    public async Task<ManualActivitySnapshotResult> CreateManualSnapshotAsync(CancellationToken cancellationToken = default)
    {
        var initializedForSnapshot = !await HasActiveSessionAsync(cancellationToken).ConfigureAwait(false);
        if (initializedForSnapshot)
            await BeginSessionAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        var report = await CreateSnapshotAsync("MANUAL", cancellationToken).ConfigureAwait(false);
        return new(report, initializedForSnapshot);
    }

    private async Task<bool> HasActiveSessionAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            return await ReadActiveSessionIdAsync(connection, cancellationToken).ConfigureAwait(false) is not null;
        }
        finally { _gate.Release(); }
    }

    /// <summary>Marks the active session as closed and writes its final report.</summary>
    public async Task<SessionActivityReport> FinalizeSessionAsync(string trigger = "SESSION_END",
        CancellationToken cancellationToken = default)
    {
        if (!IsSafeCode(trigger, 48)) throw new ArgumentException("Déclencheur invalide.", nameof(trigger));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            var sessionId = await ReadActiveSessionIdAsync(connection, cancellationToken).ConfigureAwait(false);
            if (sessionId is null)
            {
                var latest = await ReadLatestReportForTriggerAsync(connection, trigger, cancellationToken).ConfigureAwait(false);
                if (latest is not null) return latest;
                throw new InvalidOperationException("Aucune session active à clôturer.");
            }
            var endedAt = DateTimeOffset.UtcNow;
            await using (var command = connection.CreateCommand())
            {
                command.CommandText = "UPDATE sessions SET ended_at_utc=$ended,state='FINAL' WHERE session_id=$id AND ended_at_utc IS NULL";
                command.Parameters.AddWithValue("$ended", Format(endedAt));
                command.Parameters.AddWithValue("$id", sessionId);
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }
            return await SaveSnapshotCoreAsync(connection, sessionId, trigger, true, endedAt, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<SessionActivityReport>> ReadRecentAsync(int maximum = 100,
        CancellationToken cancellationToken = default)
    {
        if (maximum is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximum));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_databasePath)) return [];
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT report_json FROM session_reports ORDER BY captured_at_utc DESC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", maximum);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            var reports = new List<SessionActivityReport>();
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                try { if (JsonSerializer.Deserialize<SessionActivityReport>(reader.GetString(0), JsonOptions) is { } report) reports.Add(report); }
                catch (JsonException) { }
            }
            return reports;
        }
        finally { _gate.Release(); }
    }

    public async Task<SessionActivityReport?> ReadByIdAsync(Guid reportId, CancellationToken cancellationToken = default)
    {
        if (reportId == Guid.Empty) throw new ArgumentException("Identifiant de rapport requis.", nameof(reportId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_databasePath)) return null;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT report_json FROM session_reports WHERE report_id=$id";
            command.Parameters.AddWithValue("$id", reportId.ToString("D"));
            var json = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
            return json is null ? null : JsonSerializer.Deserialize<SessionActivityReport>(json, JsonOptions);
        }
        finally { _gate.Release(); }
    }

    private async Task<SessionActivityReport> SaveSnapshotCoreAsync(SqliteConnection connection, string sessionId,
        string trigger, bool isFinal, DateTimeOffset? endedAt, CancellationToken token)
    {
        var state = await ReadSessionAsync(connection, sessionId, token).ConfigureAwait(false)
            ?? throw new InvalidOperationException("Session introuvable.");
        var dedupeKey = trigger switch
        {
            "STARTUP" => "STARTUP",
            "SESSION_END" or "SHUTDOWN" or "INTERRUPTED_AFTER_RESTART" => "FINAL",
            "PERIODIC" => "PERIODIC_" + DateTimeOffset.UtcNow.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture),
            _ => trigger + "_" + Guid.NewGuid().ToString("N")
        };
        if (await ReadReportByDedupeAsync(connection, sessionId, dedupeKey, token).ConfigureAwait(false) is { } existing)
            return existing;

        var counts = await ReadActivityCountsAsync(connection, sessionId, token).ConfigureAwait(false);
        var recent = await ReadRecentActivitiesAsync(connection, sessionId, token).ConfigureAwait(false);
        var reportId = Guid.NewGuid();
        var capturedAt = DateTimeOffset.UtcNow;
        var jsonPath = Path.Combine(_directory, $"session_{capturedAt:yyyyMMddTHHmmssfffZ}_{reportId:N}.json");
        var textPath = Path.ChangeExtension(jsonPath, ".txt");
        var ended = endedAt ?? state.EndedAtUtc;
        var total = counts.Values.Sum();
        var d1Count = counts.Where(x => x.Key.StartsWith("HumanBehaviorMonitor/", StringComparison.Ordinal)).Sum(x => x.Value);
        var d2Count = counts.Where(x => x.Key.StartsWith("ThreatMonitor/", StringComparison.Ordinal)).Sum(x => x.Value);
        var decisionCount = counts.GetValueOrDefault("RiskResponseGuard/RISK_DECISION");
        var threatCount = counts.GetValueOrDefault("ThreatMonitor/THREAT_FINDING");
        var gapCount = counts.GetValueOrDefault("ThreatMonitor/TELEMETRY_GAP");
        var summary = $"Session SentinelCore démarrée le {state.StartedAtUtc.ToLocalTime():dd/MM/yyyy HH:mm:ss} – {total} activité(s) enregistrée(s) : {d1Count} signal(aux) D1, {d2Count} signal(aux) D2, {decisionCount} décision(s) D3; {threatCount} menace(s) et {gapCount} lacune(s) de télémétrie signalée(s). Couverture : D1 {FormatCoverage(state.D1LastSeenAtUtc)}, D2 {FormatCoverage(state.D2LastSeenAtUtc)}.";
        var report = new SessionActivityReport(reportId, sessionId, state.StartedAtUtc, state.ComputerBootAtUtc, capturedAt, ended, trigger,
            isFinal, total, d1Count, d2Count, threatCount, gapCount, state.D1HeartbeatCount, state.D2HeartbeatCount,
            state.D1LastSeenAtUtc, state.D2LastSeenAtUtc, decisionCount,
            state.State, counts, recent, summary, jsonPath, textPath);
        var reportJson = JsonSerializer.Serialize(report, JsonOptions);
        await using var transaction = await connection.BeginTransactionAsync(token).ConfigureAwait(false);
        await using (var command = connection.CreateCommand())
        {
            command.Transaction = (SqliteTransaction)transaction;
            command.CommandText = "INSERT INTO session_reports(report_id,session_id,captured_at_utc,trigger,is_final,dedupe_key,json_path,text_path,report_json) VALUES($id,$session,$captured,$trigger,$final,$dedupe,$jsonPath,$textPath,$json)";
            command.Parameters.AddWithValue("$id", reportId.ToString("D"));
            command.Parameters.AddWithValue("$session", sessionId);
            command.Parameters.AddWithValue("$captured", Format(capturedAt));
            command.Parameters.AddWithValue("$trigger", trigger);
            command.Parameters.AddWithValue("$final", isFinal ? 1 : 0);
            command.Parameters.AddWithValue("$dedupe", dedupeKey);
            command.Parameters.AddWithValue("$jsonPath", jsonPath);
            command.Parameters.AddWithValue("$textPath", textPath);
            command.Parameters.AddWithValue("$json", reportJson);
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }
        await transaction.CommitAsync(token).ConfigureAwait(false);
        await WriteAtomicAsync(jsonPath, reportJson, token).ConfigureAwait(false);
        await WriteAtomicAsync(textPath, ToFrenchText(report), token).ConfigureAwait(false);
        return report;
    }

    private async Task<SqliteConnection> OpenDatabaseAsync(CancellationToken token)
    {
        Directory.CreateDirectory(_directory);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath, Mode = SqliteOpenMode.ReadWriteCreate, Cache = SqliteCacheMode.Shared,
            Pooling = false, DefaultTimeout = 5
        }.ToString());
        try
        {
            await connection.OpenAsync(token).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;"
                + "CREATE TABLE IF NOT EXISTS sessions(session_id TEXT PRIMARY KEY,started_at_utc TEXT NOT NULL,computer_boot_at_utc TEXT NOT NULL,ended_at_utc TEXT NULL,state TEXT NOT NULL,d1_heartbeat_count INTEGER NOT NULL DEFAULT 0,d2_heartbeat_count INTEGER NOT NULL DEFAULT 0,d1_last_seen_utc TEXT NULL,d2_last_seen_utc TEXT NULL);"
                + "CREATE TABLE IF NOT EXISTS activities(activity_id TEXT PRIMARY KEY,session_id TEXT NOT NULL,observed_at_utc TEXT NOT NULL,source_daemon TEXT NOT NULL,message_type TEXT NOT NULL,severity TEXT NOT NULL,summary TEXT NOT NULL,correlation_id TEXT NOT NULL,FOREIGN KEY(session_id) REFERENCES sessions(session_id));"
                + "CREATE INDEX IF NOT EXISTS ix_session_activity_time ON activities(session_id,observed_at_utc DESC);"
                + "CREATE TABLE IF NOT EXISTS session_reports(report_id TEXT PRIMARY KEY,session_id TEXT NOT NULL,captured_at_utc TEXT NOT NULL,trigger TEXT NOT NULL,is_final INTEGER NOT NULL,dedupe_key TEXT NOT NULL,json_path TEXT NOT NULL,text_path TEXT NOT NULL,report_json TEXT NOT NULL,FOREIGN KEY(session_id) REFERENCES sessions(session_id),UNIQUE(session_id,dedupe_key));"
                + "CREATE INDEX IF NOT EXISTS ix_session_report_time ON session_reports(captured_at_utc DESC);";
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            return connection;
        }
        catch { await connection.DisposeAsync().ConfigureAwait(false); throw; }
    }

    private static async Task<string?> ReadActiveSessionIdAsync(SqliteConnection connection, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT session_id FROM sessions WHERE state='ACTIVE' AND ended_at_utc IS NULL ORDER BY started_at_utc DESC LIMIT 1";
        return await command.ExecuteScalarAsync(token).ConfigureAwait(false) as string;
    }

    private static async Task<string?> ReadLatestSessionIdAsync(SqliteConnection connection, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT session_id FROM sessions ORDER BY started_at_utc DESC LIMIT 1";
        return await command.ExecuteScalarAsync(token).ConfigureAwait(false) as string;
    }

    private static async Task<SessionState?> ReadSessionAsync(SqliteConnection connection, string sessionId, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT started_at_utc,computer_boot_at_utc,ended_at_utc,state,d1_heartbeat_count,d2_heartbeat_count,d1_last_seen_utc,d2_last_seen_utc FROM sessions WHERE session_id=$id";
        command.Parameters.AddWithValue("$id", sessionId);
        await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
        if (!await reader.ReadAsync(token).ConfigureAwait(false)) return null;
        return new(Parse(reader.GetString(0)), Parse(reader.GetString(1)), reader.IsDBNull(2) ? null : Parse(reader.GetString(2)), reader.GetString(3),
            reader.GetInt32(4), reader.GetInt32(5), reader.IsDBNull(6) ? null : Parse(reader.GetString(6)),
            reader.IsDBNull(7) ? null : Parse(reader.GetString(7)));
    }

    private static async Task<Dictionary<string, int>> ReadActivityCountsAsync(SqliteConnection connection, string sessionId, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT source_daemon || '/' || message_type,COUNT(*) FROM activities WHERE session_id=$id GROUP BY source_daemon,message_type";
        command.Parameters.AddWithValue("$id", sessionId);
        await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        while (await reader.ReadAsync(token).ConfigureAwait(false)) counts[reader.GetString(0)] = reader.GetInt32(1);
        return counts;
    }

    private static async Task<IReadOnlyList<SessionActivityItem>> ReadRecentActivitiesAsync(SqliteConnection connection, string sessionId, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT observed_at_utc,source_daemon,message_type,severity,summary,correlation_id FROM activities WHERE session_id=$id ORDER BY observed_at_utc DESC LIMIT $limit";
        command.Parameters.AddWithValue("$id", sessionId);
        command.Parameters.AddWithValue("$limit", MaximumRecentActivities);
        await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
        var rows = new List<SessionActivityItem>();
        while (await reader.ReadAsync(token).ConfigureAwait(false))
            rows.Add(new(Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4), reader.GetString(5)));
        return rows;
    }

    private static async Task<SessionActivityReport?> ReadReportByDedupeAsync(SqliteConnection connection, string sessionId,
        string dedupeKey, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT report_json FROM session_reports WHERE session_id=$session AND dedupe_key=$dedupe";
        command.Parameters.AddWithValue("$session", sessionId);
        command.Parameters.AddWithValue("$dedupe", dedupeKey);
        var json = await command.ExecuteScalarAsync(token).ConfigureAwait(false) as string;
        return json is null ? null : JsonSerializer.Deserialize<SessionActivityReport>(json, JsonOptions);
    }

    private static async Task<SessionActivityReport?> ReadLatestReportForTriggerAsync(SqliteConnection connection, string trigger, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT report_json FROM session_reports WHERE trigger=$trigger AND is_final=1 ORDER BY captured_at_utc DESC LIMIT 1";
        command.Parameters.AddWithValue("$trigger", trigger);
        var json = await command.ExecuteScalarAsync(token).ConfigureAwait(false) as string;
        return json is null ? null : JsonSerializer.Deserialize<SessionActivityReport>(json, JsonOptions);
    }

    private static async Task WriteAtomicAsync(string path, string contents, CancellationToken token)
    {
        var temp = path + ".tmp";
        await File.WriteAllTextAsync(temp, contents, new UTF8Encoding(false), token).ConfigureAwait(false);
        File.Move(temp, path, overwrite: true);
    }

    private static DateTimeOffset EstimateComputerBootTime()
        => DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

    private static DateTimeOffset Parse(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
    private static string Format(DateTimeOffset value) => value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
    private static bool IsFinalTrigger(string trigger) => trigger is "SESSION_END" or "SHUTDOWN" or "INTERRUPTED_AFTER_RESTART";
    private static string FormatCoverage(DateTimeOffset? seen) => seen is { } value ? $"vu à {value.ToLocalTime():HH:mm:ss}" : "non observé";
    private static bool IsSafeCode(string? value, int max) => !string.IsNullOrWhiteSpace(value) && value.Length <= max
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
    private static bool IsSafeCorrelation(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 128
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private static string ToFrenchText(SessionActivityReport report)
    {
        var b = new StringBuilder();
        b.AppendLine("RAPPORT D’ACTIVITÉ SENTINELCORE");
        b.AppendLine($"Session : {report.SessionId}");
        b.AppendLine($"Début de la session : {report.SessionStartedAtUtc:O}");
        b.AppendLine($"Démarrage estimé de Windows : {report.ComputerBootAtUtc:O} (calculé à partir de la durée de fonctionnement du système)");
        b.AppendLine($"Instant du rapport : {report.CapturedAtUtc:O}");
        b.AppendLine($"Déclencheur : {report.Trigger} — rapport final : {(report.IsFinal ? "oui" : "non")}");
        if (report.SessionEndedAtUtc is { } ended) b.AppendLine($"Fin de la session : {ended:O}");
        b.AppendLine(report.Summary);
        b.AppendLine($"Battements reçus : D1 {report.D1HeartbeatCount}, D2 {report.D2HeartbeatCount}");
        b.AppendLine("Dernières activités (contenu brut non conservé) :");
        if (report.RecentActivities.Count == 0) b.AppendLine("- Aucune activité D1/D2 observée pendant cette session.");
        foreach (var item in report.RecentActivities)
            b.AppendLine($"- {item.ObservedAtUtc:O} | {item.SourceDaemon} | {item.MessageType} | {item.Severity} | {item.Summary} | corrélation {item.CorrelationId}");
        b.AppendLine("Ces données indiquent ce que SentinelCore a observé; elles ne prouvent pas l’absence d’activité non collectée.");
        return b.ToString();
    }

    private sealed record SessionState(DateTimeOffset StartedAtUtc, DateTimeOffset ComputerBootAtUtc, DateTimeOffset? EndedAtUtc, string State,
        int D1HeartbeatCount, int D2HeartbeatCount, DateTimeOffset? D1LastSeenAtUtc, DateTimeOffset? D2LastSeenAtUtc);
}

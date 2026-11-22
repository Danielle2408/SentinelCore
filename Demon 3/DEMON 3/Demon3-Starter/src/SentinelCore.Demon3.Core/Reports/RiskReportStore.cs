using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon3.Core.Actions;
using SentinelCore.Demon3.Core.AI;
using SentinelCore.Demon3.Core.Decision;

namespace SentinelCore.Demon3.Core.Reports;

public sealed record DecisionComparison(string Result, RiskLevel? PreviousRisk, DecisionKind? PreviousDecision,
    string Explanation, string Basis = "NONE");

public sealed record RiskReport(Guid ReportId, DateTimeOffset CreatedAtUtc, RiskDecision Decision,
    IReadOnlyList<DecisionEvidence> Signals, DecisionComparison Comparison, AdvisorOutcome? AiAdvice = null,
    IReadOnlyList<ReportAttachment>? Attachments = null, ActionExecutionResult? ActionResult = null);
public sealed record ReportAttachment(string Type, string EvidenceRef, string EncryptedPath, string Sha256);

/// <summary>Append-only local reports: structured JSON plus a French-readable text copy.</summary>
public sealed class RiskReportStore
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string _directory;
    private string DatabasePath => Path.Combine(_directory, "decision-history.sqlite3");
    private readonly SemaphoreSlim _gate = new(1, 1);

    public RiskReportStore(string? directory = null)
    {
        _directory = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon3", "reports");
    }

    public async Task<RiskReport> SaveAsync(RiskDecision decision, IReadOnlyList<DecisionEvidence> signals,
        AdvisorOutcome? aiAdvice = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(signals);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(_directory);
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            var patternKey = PatternKey(signals);
            var previous = await FindPreviousAsync(connection, decision.CorrelationId, patternKey, cancellationToken).ConfigureAwait(false);
            var comparison = CompareWithPrevious(previous, decision);
            var report = new RiskReport(Guid.NewGuid(), DateTimeOffset.UtcNow, decision, signals.ToArray(), comparison, aiAdvice);
            var stem = $"{report.CreatedAtUtc:yyyyMMddTHHmmssfffZ}_{report.ReportId:N}";
            var reportJson = JsonSerializer.Serialize(report, JsonOptions);
            await using (var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false))
            {
                await using var command = connection.CreateCommand();
                command.Transaction = (SqliteTransaction)transaction;
                command.CommandText = "INSERT INTO reports(report_id, correlation_id, pattern_key, created_at_utc, risk, decision, report_json) VALUES($id,$case,$pattern,$created,$risk,$decision,$json)";
                command.Parameters.AddWithValue("$id", report.ReportId.ToString("D"));
                command.Parameters.AddWithValue("$case", decision.CorrelationId);
                command.Parameters.AddWithValue("$pattern", patternKey);
                command.Parameters.AddWithValue("$created", report.CreatedAtUtc.ToString("O"));
                command.Parameters.AddWithValue("$risk", decision.Risk.ToString());
                command.Parameters.AddWithValue("$decision", decision.Decision.ToString());
                command.Parameters.AddWithValue("$json", reportJson);
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            }
            await File.WriteAllTextAsync(Path.Combine(_directory, stem + ".json"), reportJson, new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
            await File.WriteAllTextAsync(Path.Combine(_directory, stem + ".txt"), ToFrenchText(report), new UTF8Encoding(false), cancellationToken).ConfigureAwait(false);
            return report;
        }
        finally { _gate.Release(); }
    }

    public async Task<IReadOnlyList<RiskReport>> ReadRecentAsync(int maximum = 100, CancellationToken cancellationToken = default)
    {
        if (maximum is < 1 or > 1000) throw new ArgumentOutOfRangeException(nameof(maximum));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!Directory.Exists(_directory)) return [];
            if (!File.Exists(DatabasePath)) return [];
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT report_json FROM reports ORDER BY created_at_utc DESC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", maximum);
            var reports = new List<RiskReport>();
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                try { if (JsonSerializer.Deserialize<RiskReport>(reader.GetString(0), JsonOptions) is { } report) reports.Add(report); }
                catch (JsonException) { }
            }
            return reports;
        }
        finally { _gate.Release(); }
    }

    public async Task<RiskReport?> ReadByIdAsync(Guid reportId, CancellationToken cancellationToken = default)
    {
        if (reportId == Guid.Empty) throw new ArgumentException("Identifiant de rapport requis.", nameof(reportId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(DatabasePath)) return null;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT report_json FROM reports WHERE report_id=$id";
            command.Parameters.AddWithValue("$id", reportId.ToString("D"));
            var json = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
            if (json is null) return null;
            var report = JsonSerializer.Deserialize<RiskReport>(json, JsonOptions);
            return report?.ReportId == reportId ? report : null;
        }
        finally { _gate.Release(); }
    }

    /// <summary>
    /// Builds a PDF for a saved report in memory. Any attached owner-verification JPEG is
    /// decrypted only for PDF composition; the store never writes an unencrypted photo/PDF copy.
    /// A caller that needs a file must explicitly choose a destination and protect its lifecycle.
    /// </summary>
    public async Task<byte[]?> CreatePdfAsync(Guid reportId, CancellationToken cancellationToken = default)
    {
        if (reportId == Guid.Empty) throw new ArgumentException("Identifiant de rapport requis.", nameof(reportId));
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        byte[]? visualEvidence = null;
        try
        {
            if (!File.Exists(DatabasePath)) return null;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT report_json FROM reports WHERE report_id=$id";
            command.Parameters.AddWithValue("$id", reportId.ToString("D"));
            var json = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
            if (json is null) return null;
            RiskReport? report;
            try { report = JsonSerializer.Deserialize<RiskReport>(json, JsonOptions); }
            catch (JsonException) { return null; }
            if (report is null || report.ReportId != reportId) return null;

            visualEvidence = TryReadVisualEvidence(report);
            return RiskReportPdfWriter.Create(report, visualEvidence);
        }
        finally
        {
            if (visualEvidence is not null) CryptographicOperations.ZeroMemory(visualEvidence);
            _gate.Release();
        }
    }

    /// <summary>
    /// Writes a PDF copy to the caller-selected location. If the report has a decryptable
    /// verification JPEG, the exported PDF contains that image in clear form; choose a protected
    /// destination and manage the exported copy's retention explicitly.
    /// </summary>
    public async Task<bool> ExportPdfAsync(Guid reportId, string destinationPath,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(destinationPath)) throw new ArgumentException("Destination requise.", nameof(destinationPath));
        var pdf = await CreatePdfAsync(reportId, cancellationToken).ConfigureAwait(false);
        if (pdf is null) return false;
        try
        {
            var fullPath = Path.GetFullPath(destinationPath);
            var directory = Path.GetDirectoryName(fullPath);
            if (string.IsNullOrWhiteSpace(directory)) throw new ArgumentException("Destination PDF invalide.", nameof(destinationPath));
            Directory.CreateDirectory(directory);
            await File.WriteAllBytesAsync(fullPath, pdf, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally { CryptographicOperations.ZeroMemory(pdf); }
    }

    private byte[]? TryReadVisualEvidence(RiskReport report)
    {
        if (!OperatingSystem.IsWindows() || report.Attachments is not { Count: > 0 }) return null;
        var expectedDirectory = Path.GetFullPath(_directory);
        var pathComparer = OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal;
        var entropy = SHA256.HashData(Encoding.UTF8.GetBytes("SentinelCore.Demon3.VisualEvidence.v1"));
        try
        {
            foreach (var attachment in report.Attachments)
            {
                if (!string.Equals(attachment.Type, "OWNER_VERIFICATION_IMAGE", StringComparison.Ordinal)
                    || !IsSafeToken(attachment.EvidenceRef)) continue;

                var referenceHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(attachment.EvidenceRef)));
                var expectedPath = Path.GetFullPath(Path.Combine(expectedDirectory, $"visual_{referenceHash}.jpg.dpapi"));
                string storedPath;
                try { storedPath = Path.GetFullPath(attachment.EncryptedPath); }
                catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { continue; }
                if (!pathComparer.Equals(expectedPath, storedPath)) continue;

                try
                {
                    var attributes = File.GetAttributes(expectedPath);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    var info = new FileInfo(expectedPath);
                    if (info.Length is <= 0 or > 10 * 1024 * 1024 + 64 * 1024) continue;
                    var protectedBytes = File.ReadAllBytes(expectedPath);
                    try
                    {
                        var clear = ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.CurrentUser);
                        var hash = Convert.ToHexString(SHA256.HashData(clear));
                        if (clear.Length is > 3 and <= 10 * 1024 * 1024
                            && clear[0] == 0xFF && clear[1] == 0xD8 && clear[2] == 0xFF
                            && hash.Equals(attachment.Sha256, StringComparison.OrdinalIgnoreCase))
                            return clear;
                        CryptographicOperations.ZeroMemory(clear);
                    }
                    finally { CryptographicOperations.ZeroMemory(protectedBytes); }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or ArgumentException)
                {
                    // A missing, tampered, or other-user DPAPI attachment is omitted from the PDF.
                }
            }
        }
        finally { CryptographicOperations.ZeroMemory(entropy); }
        return null;
    }

    public async Task<bool> AttachVisualEvidenceAsync(string correlationId, string evidenceRef, byte[] imageBytes,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("La protection des preuves utilise DPAPI Windows.");
        if (string.IsNullOrWhiteSpace(correlationId) || string.IsNullOrWhiteSpace(evidenceRef) || !IsSafeToken(evidenceRef)
            || imageBytes is not { Length: > 3 and <= 10 * 1024 * 1024 }
            || imageBytes[0] != 0xFF || imageBytes[1] != 0xD8 || imageBytes[2] != 0xFF) return false;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(DatabasePath)) return false;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var find = connection.CreateCommand();
            find.CommandText = "SELECT report_id, report_json FROM reports WHERE correlation_id=$case ORDER BY created_at_utc DESC LIMIT 1";
            find.Parameters.AddWithValue("$case", correlationId);
            await using var reader = await find.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return false;
            var reportId = reader.GetString(0);
            var json = reader.GetString(1);
            await reader.DisposeAsync().ConfigureAwait(false);
            var report = JsonSerializer.Deserialize<RiskReport>(json, JsonOptions);
            if (report is null) return false;

            var refHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(evidenceRef)));
            var encryptedPath = Path.Combine(_directory, $"visual_{refHash}.jpg.dpapi");
            var entropy = SHA256.HashData(Encoding.UTF8.GetBytes("SentinelCore.Demon3.VisualEvidence.v1"));
            var encrypted = ProtectedData.Protect(imageBytes, entropy, DataProtectionScope.CurrentUser);
            await File.WriteAllBytesAsync(encryptedPath, encrypted, cancellationToken).ConfigureAwait(false);
            var attachment = new ReportAttachment("OWNER_VERIFICATION_IMAGE", evidenceRef, encryptedPath,
                Convert.ToHexString(SHA256.HashData(imageBytes)));
            var attachments = (report.Attachments ?? []).Where(x => x.EvidenceRef != evidenceRef).Append(attachment).ToArray();
            var updated = report with { Attachments = attachments };
            var updatedJson = JsonSerializer.Serialize(updated, JsonOptions);
            await using var update = connection.CreateCommand();
            update.CommandText = "UPDATE reports SET report_json=$json WHERE report_id=$id";
            update.Parameters.AddWithValue("$json", updatedJson);
            update.Parameters.AddWithValue("$id", reportId);
            await update.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await RewriteReportFilesAsync(reportId, updatedJson, updated, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> UpdateLatestAiAdviceAsync(string correlationId, AdvisorOutcome advice, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(advice);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(DatabasePath)) return false;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var find = connection.CreateCommand();
            find.CommandText = "SELECT report_id, report_json FROM reports WHERE correlation_id=$case ORDER BY created_at_utc DESC LIMIT 1";
            find.Parameters.AddWithValue("$case", correlationId);
            await using var reader = await find.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return false;
            var reportId = reader.GetString(0);
            var json = reader.GetString(1);
            await reader.DisposeAsync().ConfigureAwait(false);
            var report = JsonSerializer.Deserialize<RiskReport>(json, JsonOptions);
            if (report is null) return false;
            var updated = report with { AiAdvice = advice };
            var updatedJson = JsonSerializer.Serialize(updated, JsonOptions);
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE reports SET report_json=$json WHERE report_id=$id";
            command.Parameters.AddWithValue("$json", updatedJson);
            command.Parameters.AddWithValue("$id", reportId);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await RewriteReportFilesAsync(reportId, updatedJson, updated, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally { _gate.Release(); }
    }

    public async Task<RiskReport?> UpdateLatestDecisionAsync(string correlationId, RiskDecision decision,
        IReadOnlyList<DecisionEvidence> signals, AdvisorOutcome advice, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(signals);
        ArgumentNullException.ThrowIfNull(advice);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(DatabasePath)) return null;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var find = connection.CreateCommand();
            find.CommandText = "SELECT report_id, report_json FROM reports WHERE correlation_id=$case ORDER BY created_at_utc DESC LIMIT 1";
            find.Parameters.AddWithValue("$case", correlationId);
            await using var reader = await find.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return null;
            var reportId = reader.GetString(0);
            var json = reader.GetString(1);
            await reader.DisposeAsync().ConfigureAwait(false);
            var current = JsonSerializer.Deserialize<RiskReport>(json, JsonOptions);
            if (current is null) return null;
            var patternKey = PatternKey(signals);
            var previous = await FindPreviousExcludingAsync(connection, decision.CorrelationId, patternKey, reportId, cancellationToken).ConfigureAwait(false);
            var updated = current with
            {
                Decision = decision,
                Signals = signals.ToArray(),
                AiAdvice = advice,
                Comparison = CompareWithPrevious(previous, decision)
            };
            var updatedJson = JsonSerializer.Serialize(updated, JsonOptions);
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE reports SET risk=$risk, decision=$decision, pattern_key=$pattern, report_json=$json WHERE report_id=$id";
            command.Parameters.AddWithValue("$risk", decision.Risk.ToString());
            command.Parameters.AddWithValue("$decision", decision.Decision.ToString());
            command.Parameters.AddWithValue("$pattern", patternKey);
            command.Parameters.AddWithValue("$json", updatedJson);
            command.Parameters.AddWithValue("$id", reportId);
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await RewriteReportFilesAsync(reportId, updatedJson, updated, cancellationToken).ConfigureAwait(false);
            return updated;
        }
        finally { _gate.Release(); }
    }

    public async Task<RiskReport?> ReadLatestForCorrelationAsync(string correlationId, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(DatabasePath)) return null;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT report_json FROM reports WHERE correlation_id=$case ORDER BY created_at_utc DESC LIMIT 1";
            command.Parameters.AddWithValue("$case", correlationId);
            var json = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
            return json is null ? null : JsonSerializer.Deserialize<RiskReport>(json, JsonOptions);
        }
        finally { _gate.Release(); }
    }

    public async Task<bool> UpdateActionResultAsync(Guid reportId, ActionExecutionResult result, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(DatabasePath)) return false;
            await using var connection = await OpenDatabaseAsync(cancellationToken).ConfigureAwait(false);
            await using var find = connection.CreateCommand();
            find.CommandText = "SELECT report_json FROM reports WHERE report_id=$id";
            find.Parameters.AddWithValue("$id", reportId.ToString("D"));
            await using var reader = await find.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)) return false;
            var json = reader.GetString(0);
            await reader.DisposeAsync().ConfigureAwait(false);
            var report = JsonSerializer.Deserialize<RiskReport>(json, JsonOptions);
            if (report is null) return false;
            var updated = report with { ActionResult = result, Decision = report.Decision with { SimulationOnly = result.SimulationOnly } };
            var updatedJson = JsonSerializer.Serialize(updated, JsonOptions);
            await using var command = connection.CreateCommand();
            command.CommandText = "UPDATE reports SET report_json=$json WHERE report_id=$id";
            command.Parameters.AddWithValue("$json", updatedJson);
            command.Parameters.AddWithValue("$id", reportId.ToString("D"));
            await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await RewriteReportFilesAsync(reportId.ToString("D"), updatedJson, updated, cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally { _gate.Release(); }
    }

    private async Task RewriteReportFilesAsync(string reportId, string reportJson, RiskReport report, CancellationToken token)
    {
        var suffix = Guid.Parse(reportId).ToString("N");
        var jsonFile = Directory.EnumerateFiles(_directory, $"*_{suffix}.json").FirstOrDefault();
        if (jsonFile is null) return;
        await File.WriteAllTextAsync(jsonFile, reportJson, new UTF8Encoding(false), token).ConfigureAwait(false);
        await File.WriteAllTextAsync(Path.ChangeExtension(jsonFile, ".txt"), ToFrenchText(report), new UTF8Encoding(false), token).ConfigureAwait(false);
    }

    private async Task<SqliteConnection> OpenDatabaseAsync(CancellationToken token)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = DatabasePath, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString());
        try
        {
            await connection.OpenAsync(token).ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE IF NOT EXISTS reports(report_id TEXT PRIMARY KEY, correlation_id TEXT NOT NULL, created_at_utc TEXT NOT NULL, risk TEXT NOT NULL, decision TEXT NOT NULL, report_json TEXT NOT NULL);";
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            await using var columns = connection.CreateCommand();
            columns.CommandText = "PRAGMA table_info(reports)";
            await using var reader = await columns.ExecuteReaderAsync(token).ConfigureAwait(false);
            var hasPatternKey = false;
            while (await reader.ReadAsync(token).ConfigureAwait(false))
                if (reader.GetString(1) == "pattern_key") hasPatternKey = true;
            await reader.DisposeAsync().ConfigureAwait(false);
            await using var migration = connection.CreateCommand();
            migration.CommandText = (hasPatternKey ? string.Empty : "ALTER TABLE reports ADD COLUMN pattern_key TEXT NOT NULL DEFAULT ''; ")
                + "CREATE INDEX IF NOT EXISTS ix_reports_correlation_time ON reports(correlation_id, created_at_utc DESC); CREATE INDEX IF NOT EXISTS ix_reports_pattern_time ON reports(pattern_key, created_at_utc DESC);";
            await migration.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static async Task<RiskReport?> FindPreviousAsync(SqliteConnection connection, string correlationId, string patternKey, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT report_json FROM reports WHERE correlation_id=$case OR pattern_key=$pattern ORDER BY CASE WHEN correlation_id=$case THEN 0 ELSE 1 END, created_at_utc DESC LIMIT 1";
        command.Parameters.AddWithValue("$case", correlationId);
        command.Parameters.AddWithValue("$pattern", patternKey);
        var result = await command.ExecuteScalarAsync(token).ConfigureAwait(false);
        return result is string json ? JsonSerializer.Deserialize<RiskReport>(json, JsonOptions) : null;
    }

    private static async Task<RiskReport?> FindPreviousExcludingAsync(SqliteConnection connection, string correlationId,
        string patternKey, string excludedReportId, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT report_json FROM reports WHERE report_id<>$exclude AND (correlation_id=$case OR pattern_key=$pattern) ORDER BY CASE WHEN correlation_id=$case THEN 0 ELSE 1 END, created_at_utc DESC LIMIT 1";
        command.Parameters.AddWithValue("$exclude", excludedReportId);
        command.Parameters.AddWithValue("$case", correlationId);
        command.Parameters.AddWithValue("$pattern", patternKey);
        var result = await command.ExecuteScalarAsync(token).ConfigureAwait(false);
        return result is string json ? JsonSerializer.Deserialize<RiskReport>(json, JsonOptions) : null;
    }

    private static DecisionComparison CompareWithPrevious(RiskReport? previous, RiskDecision decision)
    {
        if (previous is null)
            return new("FIRST", null, null, "Aucune décision précédente pour cette affaire ou un cas de même forme.");
        var basis = previous.Decision.CorrelationId == decision.CorrelationId ? "SAME_CASE" : "SIMILAR_SIGNAL_PATTERN";
        return previous.Decision.Risk == decision.Risk && previous.Decision.Decision == decision.Decision
            ? new("UNCHANGED", previous.Decision.Risk, previous.Decision.Decision,
                "La nouvelle décision correspond à la précédente.", basis)
            : new("CHANGED", previous.Decision.Risk, previous.Decision.Decision,
                $"La décision a changé de {previous.Decision.Risk}/{previous.Decision.Decision} vers {decision.Risk}/{decision.Decision}. Les règles ne sont pas modifiées automatiquement.", basis);
    }

    private static string PatternKey(IReadOnlyList<DecisionEvidence> signals)
    {
        var normalized = signals.Select(x => $"{x.SourceDaemon}|{x.MessageType}|{x.Severity}|{x.ReasonCode ?? ""}")
            .Order(StringComparer.Ordinal);
        var bytes = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", normalized)));
        return Convert.ToHexString(bytes);
    }

    private static bool IsSafeToken(string value) => value.Length <= 96
        && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':');

    private static string ToFrenchText(RiskReport report)
    {
        var b = new StringBuilder();
        b.AppendLine("RAPPORT DE RISQUE SENTINELCORE — DÉMON 3");
        b.AppendLine($"Date UTC : {report.CreatedAtUtc:O}");
        b.AppendLine($"Référence : {report.Decision.CorrelationId}");
        b.AppendLine($"Niveau : {report.Decision.Risk}");
        b.AppendLine($"Décision : {report.Decision.Decision}");
        b.AppendLine($"Mesure proposée : {report.Decision.ProposedAction}");
        b.AppendLine($"Mode simulation : {(report.Decision.SimulationOnly ? "oui" : "non")}");
        if (report.ActionResult is { } action)
            b.AppendLine($"Résultat de mesure : {action.ActionId} — {action.Status} — {action.Explanation}");
        b.AppendLine($"Validation humaine requise : {(report.Decision.RequiresHumanApproval ? "oui" : "non")}");
        b.AppendLine($"Explication : {report.Decision.Explanation}");
        b.AppendLine($"Motifs : {string.Join(", ", report.Decision.ReasonCodes)}");
        b.AppendLine($"Preuves : {string.Join(", ", report.Decision.EvidenceRefs)}");
        if (report.Attachments is { Count: > 0 })
        {
            b.AppendLine("Pièces jointes chiffrées :");
            foreach (var attachment in report.Attachments) b.AppendLine($"- {attachment.Type} — {attachment.EvidenceRef} — {attachment.EncryptedPath} — SHA-256 {attachment.Sha256}");
        }
        b.AppendLine($"Comparaison antérieure : {report.Comparison.Result} ({report.Comparison.Basis}) — {report.Comparison.Explanation}");
        if (report.AiAdvice is { } advice)
        {
            var duration = advice.DurationMilliseconds is { } elapsed ? $", durée {elapsed:F0} ms" : string.Empty;
            b.AppendLine($"Conseil IA local : {advice.Status} ({advice.Model}), code {advice.ErrorCode ?? "aucun"}{duration}");
            if (advice.Advice is { } suggestion)
            {
                b.AppendLine($"Évaluation IA retenue : {suggestion.RiskBand} (confiance {suggestion.Confidence:P0}); mesure suggérée {suggestion.SuggestedMeasure}");
                b.AppendLine($"Analyse : {suggestion.Assessment}");
                b.AppendLine($"Résumé : {suggestion.Summary}");
                b.AppendLine($"Justification : {suggestion.Rationale}");
                foreach (var fact in suggestion.KeyFindings.Take(8)) b.AppendLine($"Fait reformulé par l’IA (à rapprocher des signaux bruts ci-dessous) : {fact}");
                foreach (var explanation in suggestion.BenignExplanations.Take(8)) b.AppendLine($"Explication bénigne possible : {explanation}");
                foreach (var hypothesis in suggestion.ThreatHypotheses.Take(8)) b.AppendLine($"Hypothèse de menace : {hypothesis}");
                foreach (var uncertainty in suggestion.Uncertainties.Take(8)) b.AppendLine($"Incertitude : {uncertainty}");
                if (!string.IsNullOrWhiteSpace(suggestion.CapabilityGap))
                    b.AppendLine($"Capacité manquante : {suggestion.CapabilityGap}");
                if (!string.IsNullOrWhiteSpace(suggestion.PlaybookDraft))
                    b.AppendLine($"Brouillon de procédure (texte inerte, jamais exécuté) :\n{suggestion.PlaybookDraft}");
            }
        }
        b.AppendLine("Signaux :");
        foreach (var signal in report.Signals)
            b.AppendLine($"- {signal.SourceDaemon}/{signal.MessageType}, niveau {signal.Severity}, motif {signal.ReasonCode ?? "non précisé"}, preuves {string.Join(",", signal.EvidenceRefs)}");
        return b.ToString();
    }
}

using System.Text.Json;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon3.Core.Decision;

namespace SentinelCore.Demon3.Core.Replay;

public sealed record ScenarioReplayResult(string ScenarioId, string Category, string Title, string ExpectedLabel,
    RiskLevel ActualRisk, DecisionKind ActualDecision, bool AiConsultSuggested, bool MappingConsistent);

public sealed record FixtureReplayReport(DateTimeOffset StartedAtUtc, string FixturePath,
    int Total, int Consistent, int Inconsistent, IReadOnlyList<ScenarioReplayResult> Scenarios,
    string Interpretation);

/// <summary>
/// Replays already-produced D2 reports into the D3 policy. This checks protocol-to-policy mapping,
/// not D2 detection quality and not model accuracy; D2 owns the findings being replayed.
/// </summary>
public sealed class D2FixtureReplayService(RiskDecisionEngine? engine = null)
{
    private readonly RiskDecisionEngine _engine = engine ?? new RiskDecisionEngine();

    public async Task<FixtureReplayReport> ReplayAsync(string sqlitePath, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sqlitePath) || !File.Exists(sqlitePath))
            throw new FileNotFoundException("Base de scénarios D2 introuvable.", sqlitePath);
        var fullPath = Path.GetFullPath(sqlitePath);
        var connectionString = new SqliteConnectionStringBuilder { DataSource = fullPath, Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString();
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT s.scenario_id,s.category,s.title,s.label,r.report_type,r.severity,r.confidence,r.evidence_event_ids FROM scenarios s JOIN reports r ON r.scenario_id=s.scenario_id ORDER BY s.scenario_id";
        var results = new List<ScenarioReplayResult>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var id = reader.GetString(0);
            var category = reader.GetString(1);
            var title = reader.GetString(2);
            var label = reader.GetString(3).ToLowerInvariant();
            var reportType = reader.GetString(4).ToUpperInvariant();
            var severity = reportType == "NEEDS_CONTEXT" ? "UNKNOWN" : reader.GetString(5).ToUpperInvariant();
            double? confidence = reader.IsDBNull(6) ? null : reader.GetDouble(6);
            var refs = ParseEvidenceRefs(reader.IsDBNull(7) ? "[]" : reader.GetString(7));
            var now = DateTimeOffset.UtcNow;
            var signal = new DecisionEvidence("ThreatMonitor",
                reportType == "OBSERVATION" ? "THREAT_FINDING" : reportType == "NEEDS_CONTEXT" ? "TELEMETRY_GAP" : "THREAT_FINDING",
                severity, confidence, reportType == "NEEDS_CONTEXT" ? "D2_FIXTURE_NEEDS_CONTEXT" : "D2_FIXTURE_FINDING", refs, now);
            var decision = _engine.Evaluate(id, [signal]);
            var ai = decision.Risk is RiskLevel.UNKNOWN or RiskLevel.ELEVATED;
            var consistent = label switch
            {
                "benign" => decision.Risk is RiskLevel.LOW or RiskLevel.GUARDED,
                "suspicious" => decision.Risk is RiskLevel.HIGH or RiskLevel.CRITICAL,
                "uncertain" => ai && decision.Risk is RiskLevel.UNKNOWN or RiskLevel.ELEVATED,
                _ => false
            };
            results.Add(new(id, category, title, label, decision.Risk, decision.Decision, ai, consistent));
        }
        return new(DateTimeOffset.UtcNow, fullPath, results.Count, results.Count(x => x.MappingConsistent),
            results.Count(x => !x.MappingConsistent), results,
            "Ce résultat vérifie seulement que les constats D2 déjà présents dans la base mènent à la classe de décision attendue dans D3. Il ne mesure ni la capacité de D2 à détecter une menace, ni la qualité d’Ollama.");
    }

    private static IReadOnlyList<string> ParseEvidenceRefs(string value)
    {
        try
        {
            using var doc = JsonDocument.Parse(value);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return [];
            return doc.RootElement.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => x.GetString()!).Where(x => !string.IsNullOrWhiteSpace(x) && x.Length <= 96
                    && x.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or ':')).Take(64).ToArray();
        }
        catch (JsonException) { return []; }
    }
}

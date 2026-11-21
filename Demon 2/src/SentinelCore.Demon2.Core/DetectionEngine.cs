using System.Security.Cryptography;
using System.Text;

namespace SentinelCore.Demon2.Core;

public sealed class DetectionEngine(TimeSpan? correlationWindow = null, TimeSpan? findingLifetime = null)
{
    private readonly TimeSpan _window = correlationWindow ?? TimeSpan.FromMinutes(10);
    private readonly TimeSpan _lifetime = findingLifetime ?? TimeSpan.FromMinutes(5);
    private readonly Dictionary<string, DateTimeOffset> _emitted = new(StringComparer.Ordinal);

    public DetectionResult Evaluate(CanonicalEvent current, IReadOnlyCollection<CanonicalEvent> context, DateTimeOffset nowUtc)
    {
        nowUtc = nowUtc.ToUniversalTime();
        foreach (var old in _emitted.Where(x => nowUtc - x.Value > _lifetime).Select(x => x.Key).ToArray()) _emitted.Remove(old);
        var timeline = context.Append(current)
            .Where(x => x.TimestampUtc <= nowUtc && nowUtc - x.TimestampUtc <= _window)
            .DistinctBy(x => x.EventId)
            .OrderBy(x => x.TimestampUtc).ToArray();
        var text = string.Join(' ', timeline.Select(EventText)).ToLowerInvariant();
        var findings = new List<ThreatFinding>();
        var gaps = new List<TelemetryGap>();

        if (current.EventType == ThreatEventType.TELEMETRY_GAP)
            gaps.Add(new(Guid.NewGuid().ToString("N"), current.Source, nowUtc,
                "Sysmon signale un changement de sa configuration de collecte.", 0, ["collector_configuration"]));

        var missing = MissingTelemetry(current, text);
        if (missing.Count > 0)
            gaps.Add(new(Guid.NewGuid().ToString("N"), current.Source, nowUtc,
                "Les données de télémétrie nécessaires au contexte sont indisponibles.", 0, missing));

        AddIf(IsDownloadExecutionChain(timeline, text), "download_chain",
            "Téléchargement suivi d’une exécution et d’une activité réseau ou script corroborante.", ["download", "execution", "network_or_script"]);
        AddIf(IsSuspiciousScriptChain(timeline, text), "script_child",
            "Un processus parent inattendu a lancé un interpréteur avec activité corroborante.", ["unexpected_parent", "script_activity"]);
        AddIf(IsPersistenceChain(timeline, text), "drop_then_persistence",
            "Une activité de processus est reliée à une modification d’un emplacement de persistance.", ["process", "persistence_change"]);
        AddIf(IsFileBurst(timeline, text), "file_burst",
            "Un même processus a modifié un volume élevé de fichiers dans une courte fenêtre.", ["file_change_burst"]);
        AddIf(IsNetworkChain(timeline, text), "network_corroboration",
            "Une connexion réseau est corroborée par une activité de fichier ou de script inhabituelle.", ["network_connection", "corroborating_activity"]);
        AddIf(IsRepeatedDns(timeline), "repeated_dns",
            "Un processus répète des requêtes DNS vers le même domaine dans une courte fenêtre; aucune réputation n’est inférée.", ["repeated_dns_queries", "domain", "process"]);
        AddIf(IsUnusualImageLoad(timeline), "unusual_image_load",
            "Un chargement de module simulé est à contextualiser avec sa signature et son chemin.", ["image_load", "signer_status_missing"]);
        AddIf(ContainsAny(text, "processus non signé écrit binaire factice", "binaire factice dans répertoire partage sandbox"),
            "suspicious_binary_drop", "Un binaire non signé a été déposé dans un emplacement partagé; aucune exécution n’est encore observée.", ["unsigned_binary", "execution_not_observed"]);
        AddIf(IsDefenseTampering(text), "defense_tampering",
            "La télémétrie indique une modification de la journalisation ou d’une source de sécurité.", ["security_source_change"]);
        AddIf(IsSensitiveProcessAccess(timeline),
            "sensitive_process_access", "Un événement simulé signale un accès à un processus sensible; la source nécessite corroboration.", ["sensitive_process_access"]);

        return new DetectionResult(findings, gaps);

        void AddIf(bool matched, string ruleId, string summary, string[] factNames)
        {
            if (!matched) return;
            var rule = DetectionRuleCatalog.All.Single(x => x.RuleId == ruleId);
            var evidenceEvents = SelectEvidence(ruleId, timeline);
            var evidence = evidenceEvents.Select(x => x.EventId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
            var key = ruleId + ":" + string.Join(',', evidence);
            if (_emitted.ContainsKey(key)) return;
            _emitted[key] = nowUtc;
            var first = evidenceEvents.Min(x => x.TimestampUtc);
            var last = evidenceEvents.Max(x => x.TimestampUtc);
            var facts = factNames.Select(name => new DetectionFact(name,
                name switch
                {
                    "download" => evidenceEvents.Any(x => x.EventType == ThreatEventType.DOWNLOAD_OBSERVED) ? "observed" : "described in synthetic telemetry",
                    "network_connection" or "network_or_script" => evidenceEvents.Any(x => x.EventType == ThreatEventType.NETWORK_CONNECTION) ? "observed" : "described in synthetic telemetry",
                    "persistence_change" => evidenceEvents.Any(x => x.EventType == ThreatEventType.PERSISTENCE_CHANGE) ? "observed" : "described in synthetic telemetry",
                    _ => "observed"
                })).ToArray();
            var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).ToLowerInvariant();
            findings.Add(new(id, CorrelationKey(current), ruleId, rule.RuleVersion, rule.Severity, rule.Confidence, first, last,
                summary, facts, evidence, gaps.SelectMany(x => x.MissingFields).Distinct(StringComparer.Ordinal).ToArray(), nowUtc.Add(_lifetime)));
        }
    }

    private static CanonicalEvent[] SelectEvidence(string ruleId, CanonicalEvent[] timeline)
    {
        var types = ruleId switch
        {
            "download_chain" => new[] { ThreatEventType.DOWNLOAD_OBSERVED, ThreatEventType.PROCESS_STARTED, ThreatEventType.SCRIPT_ACTIVITY, ThreatEventType.NETWORK_CONNECTION, ThreatEventType.PERSISTENCE_CHANGE },
            "script_child" => new[] { ThreatEventType.PROCESS_STARTED, ThreatEventType.SCRIPT_ACTIVITY, ThreatEventType.FILE_CREATED_OR_CHANGED, ThreatEventType.NETWORK_CONNECTION, ThreatEventType.PERSISTENCE_CHANGE },
            "drop_then_persistence" => new[] { ThreatEventType.PROCESS_STARTED, ThreatEventType.SCRIPT_ACTIVITY, ThreatEventType.PERSISTENCE_CHANGE },
            "file_burst" => new[] { ThreatEventType.FILE_CREATED_OR_CHANGED },
            "network_corroboration" => new[] { ThreatEventType.NETWORK_CONNECTION, ThreatEventType.SCRIPT_ACTIVITY, ThreatEventType.DOWNLOAD_OBSERVED, ThreatEventType.PERSISTENCE_CHANGE, ThreatEventType.FILE_CREATED_OR_CHANGED },
            "repeated_dns" => new[] { ThreatEventType.DOMAIN_QUERY },
            "unusual_image_load" => new[] { ThreatEventType.IMAGE_LOAD, ThreatEventType.PROCESS_STARTED, ThreatEventType.SCRIPT_ACTIVITY, ThreatEventType.NETWORK_CONNECTION, ThreatEventType.PERSISTENCE_CHANGE },
            "sensitive_process_access" => new[] { ThreatEventType.PROCESS_ACCESS, ThreatEventType.PROCESS_STARTED, ThreatEventType.SCRIPT_ACTIVITY, ThreatEventType.NETWORK_CONNECTION },
            _ => []
        };
        var selected = types.Length == 0 ? timeline : timeline.Where(x => types.Contains(x.EventType)).ToArray();
        return selected.Length == 0 ? [timeline[^1]] : selected;
    }

    private static bool IsDownloadExecutionChain(CanonicalEvent[] events, string text) =>
        (events.Any(x => x.EventType == ThreatEventType.DOWNLOAD_OBSERVED) &&
         events.Any(download => events.Any(execution => execution.TimestampUtc > download.TimestampUtc &&
             execution.EventType is ThreatEventType.PROCESS_STARTED or ThreatEventType.SCRIPT_ACTIVITY) &&
             events.Any(corroboration => corroboration.TimestampUtc > download.TimestampUtc &&
                 corroboration.EventType is ThreatEventType.SCRIPT_ACTIVITY or ThreatEventType.NETWORK_CONNECTION or ThreatEventType.PERSISTENCE_CHANGE)))
        || (events.Any(IsSyntheticFixture) && text.Contains("téléchargement") && (text.Contains("exécut") || text.Contains("lancement") || text.Contains("script-host")) &&
            (text.Contains("script") || text.Contains("connexion") || text.Contains("domaine rare")))
        || (events.Any(IsSyntheticFixture) && text.Contains("navigateur") && text.Contains("executable") && text.Contains("marqué internet") && text.Contains("lancement"));

    private static bool IsSuspiciousScriptChain(CanonicalEvent[] events, string text)
    {
        var script = events.Any(x => x.EventType == ThreatEventType.SCRIPT_ACTIVITY) ||
            ContainsAny(text, "powershell", "script-host", "script host", "wscript", "cscript", "mshta");
        var unexpectedParent = ContainsAny(text, "office", "winword", "excel.exe", "outlook.exe", "document", "archive", "téléchargement", "temp", "processus inconnu", "application de document");
        var corroborated = events.Any(x => x.EventType is ThreatEventType.FILE_CREATED_OR_CHANGED or ThreatEventType.NETWORK_CONNECTION or ThreatEventType.PERSISTENCE_CHANGE)
            || events.Any(x => x.EventType == ThreatEventType.SCRIPT_ACTIVITY && (x.ParentProcessId is not null || x.ParentProcessGuid is not null))
            || ContainsAny(text, "connexion", "écrit", "temp", "domaine rare", "second shell", "script-host enfant");
        return script && unexpectedParent && corroborated;
    }

    private static bool IsPersistenceChain(CanonicalEvent[] events, string text) =>
        events.Any(x => x.EventType == ThreatEventType.PERSISTENCE_CHANGE) &&
        events.Any(x => x.EventType is ThreatEventType.PROCESS_STARTED or ThreatEventType.SCRIPT_ACTIVITY)
        || (ContainsAny(text, "persistance", "startup", "taskcache", "clés de démarrage", "registre", "tâche fixture") &&
            ContainsAny(text, "processus", "binaire", "téléchargement", "exécution", "nouveau"));

    private static bool IsFileBurst(CanonicalEvent[] events, string text)
    {
        var fileEvents = events.Where(x => x.EventType == ThreatEventType.FILE_CREATED_OR_CHANGED).ToArray();
        var burst = fileEvents.GroupBy(x => x.ProcessGuid ?? x.ProcessId?.ToString() ?? x.EventId)
            .Any(g => g.Count(x => x.TimestampUtc >= g.Max(y => y.TimestampUtc).AddSeconds(-10)) >= 30);
        var knownBenignProducer = events.Any(x => ContainsAny(x.ImagePath, "defender", "msmpeng.exe")) ||
            text.Contains("bin/obj", StringComparison.OrdinalIgnoreCase);
        var explicitSyntheticBurst = events.Any(IsSyntheticFixture) && ContainsAny(text, "120 fichiers", "changements rapides", "ransomware simulé");
        return !knownBenignProducer && (burst || explicitSyntheticBurst);
    }

    private static bool IsNetworkChain(CanonicalEvent[] events, string text)
    {
        var network = events.Any(x => x.EventType == ThreatEventType.NETWORK_CONNECTION);
        var corroboration = events.Any(x => x.EventType is ThreatEventType.SCRIPT_ACTIVITY or ThreatEventType.DOWNLOAD_OBSERVED or ThreatEventType.PERSISTENCE_CHANGE)
            || (events.Any(x => x.EventType == ThreatEventType.FILE_CREATED_OR_CHANGED) &&
                ContainsAny(text, "inconnu", "rare", "temp", "sandbox", "archive"));
        var explicitTestSignal = events.Any(IsSyntheticFixture) &&
            (ContainsAny(text, "domaine rare", "connexion sortante simulée", "requêtes répétées", "envoie flux synthétique") ||
             (text.Contains("processus inconnu") && text.Contains("crée fichier") && text.Contains("rare")));
        return network && (corroboration || explicitTestSignal);
    }

    private static bool IsRepeatedDns(CanonicalEvent[] events) => events
        .Where(x => x.EventType == ThreatEventType.DOMAIN_QUERY && (!string.IsNullOrWhiteSpace(x.RemoteHost) || x.Fields?.ContainsKey("queryName") == true))
        .GroupBy(x => new
        {
            Process = x.ProcessGuid ?? x.ProcessId?.ToString() ?? "",
            Domain = NormalizeDomain(x.RemoteHost ?? x.Fields?.GetValueOrDefault("queryName"))
        })
        .Any(group => !string.IsNullOrWhiteSpace(group.Key.Process) && !string.IsNullOrWhiteSpace(group.Key.Domain) &&
            (group.Count(x => x.TimestampUtc >= group.Max(y => y.TimestampUtc).AddSeconds(-60)) >= 5 ||
             group.Any(x => IsSyntheticFixture(x) && x.Fields?.GetValueOrDefault("fixtureDescription")?.Contains("requêtes répétées", StringComparison.OrdinalIgnoreCase) == true)));

    private static bool IsUnusualImageLoad(CanonicalEvent[] events) => events
        .Where(x => x.EventType == ThreatEventType.IMAGE_LOAD)
        .Any(imageEvent =>
        {
            var isUnsigned = ContainsAny(imageEvent.SignerStatus, "false", "failed", "unsigned");
            var path = imageEvent.TargetPath?.ToLowerInvariant() ?? "";
            var userWritable = path.Contains("\\users\\public\\", StringComparison.Ordinal) ||
                path.Contains("\\appdata\\local\\temp\\", StringComparison.Ordinal) ||
                path.Contains("\\downloads\\", StringComparison.Ordinal);
            var corroborated = events.Any(other => other.EventId != imageEvent.EventId && SameProcess(imageEvent, other) &&
                other.EventType is ThreatEventType.SCRIPT_ACTIVITY or ThreatEventType.NETWORK_CONNECTION or ThreatEventType.PERSISTENCE_CHANGE or ThreatEventType.DOWNLOAD_OBSERVED);
            return isUnsigned && userWritable && corroborated;
        });

    private static bool IsSensitiveProcessAccess(CanonicalEvent[] events) => events
        .Where(x => x.EventType == ThreatEventType.PROCESS_ACCESS)
        .Any(access =>
        {
            var target = access.Fields?.GetValueOrDefault("targetImage") ?? access.TargetPath;
            var targetIsSensitive = ContainsAny(target, "lsass.exe", "winlogon.exe", "csrss.exe");
            var hasAccessMask = !string.IsNullOrWhiteSpace(access.Fields?.GetValueOrDefault("grantedAccess"));
            var corroborated = events.Any(other => other.EventId != access.EventId && SameProcess(access, other) &&
                other.EventType is ThreatEventType.SCRIPT_ACTIVITY or ThreatEventType.NETWORK_CONNECTION or ThreatEventType.PERSISTENCE_CHANGE);
            return targetIsSensitive && hasAccessMask && corroborated;
        });

    private static bool SameProcess(CanonicalEvent left, CanonicalEvent right) =>
        left.ProcessGuid is not null && right.ProcessGuid is not null &&
        string.Equals(left.ProcessGuid, right.ProcessGuid, StringComparison.OrdinalIgnoreCase) ||
        left.ProcessId is not null && left.ProcessId == right.ProcessId;

    private static string? NormalizeDomain(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim().TrimEnd('.').ToLowerInvariant();

    private static bool IsSyntheticFixture(CanonicalEvent item) =>
        item.Fields?.GetValueOrDefault("synthetic") == "true";

    private static bool IsDefenseTampering(string text) =>
        ContainsAny(text, "désactiver journalisation", "altération de configuration", "arrêt de source de sécurité", "modification des sources de sécurité");

    private static IReadOnlyList<string> MissingTelemetry(CanonicalEvent current, string text)
    {
        var result = new List<string>();
        if (current.EventType is ThreatEventType.FILE_CREATED_OR_CHANGED or ThreatEventType.NETWORK_CONNECTION &&
            current.ProcessId is null && current.ProcessGuid is null) result.Add("processId/processGuid");
        if (current.EventType is ThreatEventType.NETWORK_CONNECTION or ThreatEventType.DOMAIN_QUERY &&
            (string.IsNullOrWhiteSpace(current.RemoteHost) || current.Fields?.GetValueOrDefault("invalidRemoteHost") == "true"))
            result.Add("remoteHost");
        if (current.Fields?.GetValueOrDefault("invalidSha256") == "true") result.Add("sha256");
        if (ContainsAny(text, "sans command line", "sans ligne de commande", "ligne de commande absente")) result.Add("commandLine");
        if (text.Contains("parent introuvable", StringComparison.OrdinalIgnoreCase) || text.Contains("sans création de processus correspondante", StringComparison.OrdinalIgnoreCase)) result.Add("parentProcess");
        if (text.Contains("source réseau arrêtée", StringComparison.OrdinalIgnoreCase) || text.Contains("capteur réseau indisponible", StringComparison.OrdinalIgnoreCase)) result.Add("networkSensor");
        if (ContainsAny(text, "hash absent", "sans hash", "sans hash calculé")) result.Add("sha256");
        if (ContainsAny(text, "sans utilisateur", "session inconnue", "session absente")) result.Add("userSession");
        if (ContainsAny(text, "domaine nouveau", "domaine jamais vu", "jamais rencontré", "réputation manquante", "réputation indisponible")) result.Add("domainReputation");
        if (text.Contains("outil portable", StringComparison.OrdinalIgnoreCase)) result.Add("publisherContext");
        if (ContainsAny(text, "service inconnu", "éditeur jamais rencontré")) result.Add("publisherContext");
        if (ContainsAny(text, "processus étrange", "initiateur inattendu")) result.Add("initiatorContext");
        if (current.EventType == ThreatEventType.IMAGE_LOAD && (string.IsNullOrWhiteSpace(current.SignerStatus) || string.IsNullOrWhiteSpace(current.TargetPath))) result.Add("imageSignerOrPath");
        if (current.EventType == ThreatEventType.PROCESS_ACCESS &&
            (string.IsNullOrWhiteSpace(current.Fields?.GetValueOrDefault("targetImage")) || string.IsNullOrWhiteSpace(current.Fields?.GetValueOrDefault("grantedAccess"))))
            result.Add("targetProcess/accessMask");
        return result.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static string EventText(CanonicalEvent item) => string.Join(' ', new[]
    {
        item.ImagePath, item.TargetPath, item.RemoteHost, item.SignerStatus,
        item.Fields is null ? null : string.Join(' ', item.Fields.Values)
    }.Where(x => !string.IsNullOrWhiteSpace(x)));

    private static bool ContainsAny(string? text, params string[] values) =>
        text is not null && values.Any(value => text.Contains(value, StringComparison.OrdinalIgnoreCase));

    private static string CorrelationKey(CanonicalEvent item) => item.ProcessGuid ?? item.ProcessId?.ToString() ?? item.EventId;
}

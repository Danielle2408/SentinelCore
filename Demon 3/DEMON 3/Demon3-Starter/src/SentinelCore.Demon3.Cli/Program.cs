using System.Diagnostics;
using System.Text.Json;
using System.Windows.Forms;
using SentinelCore.Demon3.Cli;
using SentinelCore.Demon3.Core.AI;
using SentinelCore.Demon3.Core.Actions;
using SentinelCore.Demon3.Core.Contracts;
using SentinelCore.Demon3.Core.Decision;
using SentinelCore.Demon3.Core.Notifications;
using SentinelCore.Demon3.Core.Reports;
using SentinelCore.Demon3.Core.Replay;
using SentinelCore.Demon3.Core.Runtime;
using SentinelCore.Demon3.Core.Transport;
using SentinelCore.Demon3.Core.Validation;

var now = DateTimeOffset.UtcNow;
if (args is ["--publish-d2-fixtures", var publisherPath])
{
    var publishResult = await new D2FixturePublisher().PublishAsync(publisherPath);
    Console.WriteLine($"Messages D2 simulés acceptés : {publishResult.Sent}; rejetés : {publishResult.Rejected}; canal : \\.\\pipe\\{publishResult.PipeName}");
    Console.WriteLine("Les scénarios sont fictifs et n’exécutent aucun programme suspect.");
    return;
}

if (args is ["--replay-d2", var fixturePath])
{
    var replay = await new D2FixtureReplayService().ReplayAsync(fixturePath);
    var reportsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon3", "reports");
    Directory.CreateDirectory(reportsPath);
    var replayFile = Path.Combine(reportsPath, $"rejeu_d2_{replay.StartedAtUtc:yyyyMMddTHHmmssfffZ}.json");
    await File.WriteAllTextAsync(replayFile, JsonSerializer.Serialize(replay, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }));
    foreach (var scenario in replay.Scenarios)
        Console.WriteLine($"{scenario.ScenarioId} | {scenario.ExpectedLabel,-10} → {scenario.ActualRisk,-9} | IA suggérée : {(scenario.AiConsultSuggested ? "oui" : "non"),-3} | {(scenario.MappingConsistent ? "concorde" : "À REVOIR")} | {scenario.Title}");
    Console.WriteLine($"Cohérence D2→D3 : {replay.Consistent}/{replay.Total} ({(replay.Total == 0 ? 0 : 100.0 * replay.Consistent / replay.Total):F1} %)");
    Console.WriteLine("Ce chiffre mesure uniquement l’accord de la règle de correspondance sur les constats existants, pas la précision de détection de D2 ni la qualité de l’IA.");
    Console.WriteLine("Résultat enregistré : " + replayFile);
    return;
}

if (args.Length >= 1 && args[0] == "--reports")
{
    var directory = DefaultReportsDirectory();
    if (args.Length == 3 && args[1] == "--directory") directory = Path.GetFullPath(args[2]);
    else if (args.Length != 1) { Console.Error.WriteLine("Usage : --reports [--directory <dossier>]"); return; }
    var store = new RiskReportStore(directory);
    var reports = await store.ReadRecentAsync(50);
    Console.WriteLine($"Rapports enregistrés : {reports.Count}");
    foreach (var report in reports)
        Console.WriteLine($"{report.CreatedAtUtc:O} | {report.Decision.CorrelationId} | {report.Decision.Risk} | {report.Decision.Decision} | comparaison {report.Comparison.Result} ({report.Comparison.Basis})");
    Console.WriteLine("Dossier : " + directory);
    return;
}

if (args.Length >= 1 && args[0] == "--serve")
{
    var actionMode = ActionCatalogMode.SimulationOnly;
    var reportsDirectory = DefaultReportsDirectory();
    var selectedModel = OllamaAdvisorOptions.Default.Model;
    var additionalD1PipeClientSids = new List<string>();
    var additionalD2PipeClientSids = new List<string>();
    for (var i = 1; i < args.Length; i++)
    {
        if (args[i] == "--enable-defender-scan") actionMode = ActionCatalogMode.DefenderQuickScanEnabled;
        else if (args[i] == "--reports-dir" && i + 1 < args.Length) reportsDirectory = Path.GetFullPath(args[++i]);
        else if (args[i] == "--model" && i + 1 < args.Length)
        {
            selectedModel = args[++i];
            if (string.IsNullOrWhiteSpace(selectedModel) || selectedModel.Length > 120
                || OllamaAdvisorOptions.IsCloudModelTag(selectedModel)
                || selectedModel.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not (':' or '_' or '-' or '.' or '/')))
            { Console.Error.WriteLine("Nom invalide ou modèle cloud interdit; D3 n’accepte que les modèles locaux."); return; }
        }
        else if (args[i] is "--allow-d1-client-sid" or "--allow-d2-client-sid" && i + 1 < args.Length)
        {
            var d1Role = args[i] == "--allow-d1-client-sid";
            var sid = args[++i];
            if (!sid.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                || sid.Length > 184 || sid.Any(c => !char.IsAsciiDigit(c) && c != '-') || sid.EndsWith('-'))
            { Console.Error.WriteLine("SID invalide. Exemple : S-1-5-80-123456789-123456789-123456789-123456789-123456789"); return; }
            (d1Role ? additionalD1PipeClientSids : additionalD2PipeClientSids).Add(sid);
        }
        else { Console.Error.WriteLine("Usage : --serve [--enable-defender-scan] [--reports-dir <dossier>] [--model <modèle-local>] [--allow-d1-client-sid <SID-D1>] [--allow-d2-client-sid <SID-D2>]"); return; }
    }
    using var stop = new CancellationTokenSource();
    Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; stop.Cancel(); };
    using var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    var advisor = new OllamaAmbiguousCaseAdvisor(http, OllamaAdvisorOptions.Default with { Model = selectedModel });
    var inboundJournal = new SqliteInboundMessageJournal(Path.Combine(reportsDirectory, "inbound-message-inbox.sqlite3"));
    await using var pipe = new NamedPipeInterDaemonServer(additionalD1ClientSids: additionalD1PipeClientSids,
        additionalD2ClientSids: additionalD2PipeClientSids, journal: inboundJournal);
    var reportStore = new RiskReportStore(reportsDirectory);
    var sessionActivityReports = new SessionActivityReportService(reportsDirectory);
    var host = new Demon3Host(pipe, new RiskDecisionEngine(), reportStore, advisor,
        new ActionCatalog(actionMode), sessionActivityReports: sessionActivityReports);
    using var telegramHttp = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
    var telegramAlerts = new TelegramReportNotifier(reportStore, new TelegramAlertSettingsStore(),
        new TelegramBotApiClient(telegramHttp), notice => Console.WriteLine($"{DateTimeOffset.UtcNow:O} | INFO | {notice}"));
    host.ReportCreated += report => Console.WriteLine($"{report.CreatedAtUtc:O} | {report.Decision.CorrelationId} | {report.Decision.Risk} | {report.Decision.Decision} | comparaison {report.Comparison.Result}");
    host.ReportCreated += report => { telegramAlerts.QueueIfImportant(report); };
    host.OperationalNotice += notice => Console.WriteLine($"{DateTimeOffset.UtcNow:O} | INFO | {notice}");
    Console.WriteLine("Les rapports seront enregistrés dans : " + reportsDirectory);
    Console.WriteLine("Les rapports d’activité de session (démarrage, instantanés périodiques et arrêt normal) utilisent le même dossier.");
    Console.WriteLine($"Modèle Ollama : {selectedModel}. Mesures : {(actionMode == ActionCatalogMode.SimulationOnly ? "simulation" : "analyse rapide Microsoft Defender autorisée")}; confinement toujours bloqué sans validation propriétaire. Tape STOP ou Ctrl+C pour arrêter.");
    // Start the IPC host before the asynchronous console reader. The latter can occupy the
    // initial worker scheduled for pipe startup on Windows, leaving a falsely-ready listener.
    var hostTask = host.RunAsync(stop.Token);
    var stopReader = ReadStopCommandAsync(stop);
    var telegramTask = telegramAlerts.RunAsync(stop.Token);
    WindowsShutdownMonitor? shutdownMonitor = null;
    try
    {
        shutdownMonitor = new WindowsShutdownMonitor(
            beforeShutdown: () =>
            {
                try
                {
                    sessionActivityReports.CreateSnapshotAsync("SHUTDOWN_REQUEST").WaitAsync(TimeSpan.FromSeconds(4)).GetAwaiter().GetResult();
                    Console.WriteLine($"{DateTimeOffset.UtcNow:O} | INFO | Instantané de pré-arrêt enregistré.");
                }
                catch (Exception exception) { Console.WriteLine($"{DateTimeOffset.UtcNow:O} | WARNING | Instantané de pré-arrêt indisponible : {exception.GetType().Name}."); }
            },
            onShutdown: () =>
            {
                stop.Cancel();
                try { hostTask.Wait(TimeSpan.FromSeconds(4)); }
                catch (AggregateException) { }
            });
    }
    catch (Exception exception)
    { Console.WriteLine($"{DateTimeOffset.UtcNow:O} | WARNING | Veille de fermeture Windows indisponible : {exception.GetType().Name}."); }
    try { await hostTask; }
    catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    finally
    {
        shutdownMonitor?.Dispose();
        stop.Cancel();
        try { await stopReader; }
        catch (OperationCanceledException) { }
        try { await telegramTask; }
        catch (OperationCanceledException) { }
    }
    return;
}

static string DefaultReportsDirectory()
    => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon3", "reports");

static async Task ReadStopCommandAsync(CancellationTokenSource stop)
{
    try
    {
        while (true)
        {
            var line = await Console.In.ReadLineAsync(stop.Token);
            if (line is null)
            {
                // The Center may close while the protection daemons are configured to keep
                // running. EOF detaches D3; explicit STOP or Windows SessionEnding stops it.
                await Task.Delay(Timeout.InfiniteTimeSpan, stop.Token);
                return;
            }
            if (string.Equals(line.Trim(), "STOP", StringComparison.OrdinalIgnoreCase))
            {
                stop.Cancel();
                return;
            }
        }
    }
    catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
}

if (args.Length is 1 or 2 && args[0] == "--ollama-advisory-demo")
{
    var model = args.Length == 2 ? args[1] : OllamaAdvisorOptions.Default.Model;
    if (string.IsNullOrWhiteSpace(model) || model.Length > 120
        || OllamaAdvisorOptions.IsCloudModelTag(model)
        || model.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not (':' or '_' or '-' or '.' or '/')))
    {
        Console.Error.WriteLine("Nom invalide ou modèle cloud interdit. Exemple de modèle local : gemma3:1b");
        return;
    }
    using var http = new HttpClient { Timeout = Timeout.InfiniteTimeSpan };
    var advisor = new OllamaAmbiguousCaseAdvisor(http, OllamaAdvisorOptions.Default with { Model = model });
    var syntheticCase = new AmbiguousSecurityCase(
        "D3-OLLAMA-DEMO-002",
        [
            new SecuritySignalSummary("ThreatMonitor", "THREAT_FINDING", "HIGH", 0.91,
                "Simulation: enchaînement script puis téléchargement; relation parent, signature et destination manquantes.", ["D2-EVIDENCE-001"],
                ["sequence=script->download", "missing=parentProcess,signerStatus,destinationReputation", "network=UNKNOWN"]),
            new SecuritySignalSummary("HumanBehaviorMonitor", "BEHAVIOR_DEVIATION", "LOW", 0.92,
                "Simulation: usage habituel d’un IDE à une heure fréquente; vérification visuelle absente.", ["D1-CONTEXT-001"],
                ["application=IDE.exe", "hourCommon=yes", "deviationPercent=18", "visualStatus=NOT_REQUESTED"])
        ],
        [ContextRequestKind.D1_SESSION_CONTEXT, ContextRequestKind.D2_THREAT_DETAILS, ContextRequestKind.D1_VISUAL_IDENTITY]);
    var elapsed = Stopwatch.StartNew();
    var outcome = await advisor.AnalyzeAsync(syntheticCase);
    elapsed.Stop();
    Console.WriteLine("Démon 3 — avis Ollama local (cas synthétique uniquement)");
    Console.WriteLine($"Statut : {outcome.Status} | Modèle : {outcome.Model} | Erreur : {outcome.ErrorCode ?? "aucune"}");
    Console.WriteLine($"Durée totale : {elapsed.Elapsed.TotalSeconds:F1} s");
    if (outcome.Advice is { } advice)
        Console.WriteLine(JsonSerializer.Serialize(advice, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            WriteIndented = true,
            Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false) }
        }));
    Console.WriteLine("Cas synthétique : l’IA formule le verdict et la mesure; D3 n’exécute ici aucune action système.");
    return;
}

var payload = JsonDocument.Parse("{\"mode\":\"simulation\",\"synthetic\":true}").RootElement.Clone();
var sample = new DaemonEnvelope
{
    MessageId = Guid.NewGuid(), CorrelationId = "D3-LOCAL-DEMO-001",
    TimestampUtc = now, SourceDaemon = DaemonNames.ThreatMonitor,
    Destination = DaemonNames.RiskResponseGuard, MessageType = "THREAT_FINDING",
    SchemaVersion = 1, ExpiresAtUtc = now.AddSeconds(30), Payload = payload
};
var bytes = JsonSerializer.SerializeToUtf8Bytes(sample).Length;
var result = new EnvelopeValidator().Validate(sample, bytes);
Console.WriteLine("SentinelCore Demon 3 — Phase 1 foundation");
Console.WriteLine($"Mode: SIMULATION ONLY | Validation: {(result.IsValid ? "ACCEPTED" : "REJECTED")}");
Console.WriteLine($"MessageId: {sample.MessageId}");
Console.WriteLine($"Wire size: {bytes} bytes / {EnvelopeValidator.MaxMessageBytes} bytes");
if (!result.IsValid) Console.WriteLine($"Reason: {result.Error}");

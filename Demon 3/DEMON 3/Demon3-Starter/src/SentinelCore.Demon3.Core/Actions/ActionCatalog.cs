using System.Collections.Concurrent;
using System.Diagnostics;
using SentinelCore.Demon3.Core.Decision;

namespace SentinelCore.Demon3.Core.Actions;

public enum ActionCatalogMode { SimulationOnly, DefenderQuickScanEnabled }
public enum ActionExecutionStatus { NOT_REQUIRED, SIMULATED, COMPLETED, FAILED, BLOCKED_POLICY, DUPLICATE }
public sealed record ActionExecutionResult(string ActionId, ActionExecutionStatus Status, string Explanation,
    DateTimeOffset StartedAtUtc, DateTimeOffset CompletedAtUtc, bool SimulationOnly);
public interface IDefenderQuickScanRunner
{
    Task<ActionExecutionResult> RunAsync(CancellationToken cancellationToken);
}

/// <summary>Closed list of SentinelCore responses. It never accepts a shell command or arbitrary path.</summary>
public sealed class ActionCatalog
{
    private readonly ConcurrentDictionary<string, Lazy<Task<ActionExecutionResult>>> _running = new(StringComparer.Ordinal);
    private readonly IDefenderQuickScanRunner _scanRunner;
    public ActionCatalogMode Mode { get; }
    public bool RequiresOwnerApprovalForEnabledActions => Mode == ActionCatalogMode.DefenderQuickScanEnabled;

    public ActionCatalog(ActionCatalogMode mode = ActionCatalogMode.SimulationOnly, IDefenderQuickScanRunner? scanRunner = null)
    {
        Mode = mode;
        _scanRunner = scanRunner ?? new DefenderQuickScanRunner();
    }

    public Task<ActionExecutionResult> ExecuteAsync(RiskDecision decision, IReadOnlyList<DecisionEvidence> signals,
        CancellationToken cancellationToken = default, bool forceSimulation = false, bool ownerApproved = false)
    {
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(signals);
        if (!Enum.IsDefined(decision.ProposedAction))
            return Task.FromResult(Result("UNKNOWN", ActionExecutionStatus.BLOCKED_POLICY, "Action inconnue rejetée.", true));
        if (decision.ProposedAction == ProposedAction.NONE)
            return Task.FromResult(Result("NONE", ActionExecutionStatus.NOT_REQUIRED, "Aucune mesure système nécessaire.", true));
        if (decision.ProposedAction == ProposedAction.ISOLATE_FILE_REVIEW)
            return Task.FromResult(Result(decision.ProposedAction.ToString(), ActionExecutionStatus.BLOCKED_POLICY,
                "Le confinement de fichier est une proposition de revue; aucun moteur de mise en quarantaine n’est installé.", true));
        if (decision.ProposedAction != ProposedAction.RUN_DEFENDER_SCAN || decision.Risk != RiskLevel.HIGH
            || !signals.Any(x => x.SourceDaemon == "ThreatMonitor" && x.MessageType == "THREAT_FINDING"))
            return Task.FromResult(Result(decision.ProposedAction.ToString(), ActionExecutionStatus.BLOCKED_POLICY,
                "La mesure ne correspond pas à une règle autorisée du catalogue.", true));

        if (forceSimulation || Mode == ActionCatalogMode.SimulationOnly)
            return Task.FromResult(Result("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.SIMULATED,
                "Simulation : une analyse rapide Microsoft Defender serait demandée.", true));
        if (decision.RequiresHumanApproval && !ownerApproved)
            return Task.FromResult(Result("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.BLOCKED_POLICY,
                "L’analyse rapide réelle attend l’authentification et l’accord explicite du propriétaire.", true));
        if (!OperatingSystem.IsWindows())
            return Task.FromResult(Result("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.FAILED, "Microsoft Defender est disponible uniquement sous Windows.", false));

        return _running.GetOrAdd(decision.CorrelationId,
            _ => new Lazy<Task<ActionExecutionResult>>(() => _scanRunner.RunAsync(cancellationToken), LazyThreadSafetyMode.ExecutionAndPublication)).Value;
    }

    private sealed class DefenderQuickScanRunner : IDefenderQuickScanRunner
    {
        public async Task<ActionExecutionResult> RunAsync(CancellationToken cancellationToken)
        {
            var started = DateTimeOffset.UtcNow;
            var executable = FindDefenderCommand();
            if (executable is null) return new("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.FAILED,
                "Microsoft Defender MpCmdRun.exe introuvable dans son dossier système.", started, DateTimeOffset.UtcNow, false);

            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = executable,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = Path.GetDirectoryName(executable)!
                }
            };
            process.StartInfo.ArgumentList.Add("-Scan");
            process.StartInfo.ArgumentList.Add("-ScanType");
            process.StartInfo.ArgumentList.Add("1");
            try
            {
                if (!process.Start()) return new("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.FAILED, "Le scan Defender n’a pas démarré.", started, DateTimeOffset.UtcNow, false);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeout.CancelAfter(TimeSpan.FromMinutes(15));
                try { await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false); }
                catch (OperationCanceledException)
                {
                    try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                    return new("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.FAILED, "Le scan Defender a été interrompu ou a dépassé 15 minutes.", started, DateTimeOffset.UtcNow, false);
                }
                return new("RUN_DEFENDER_QUICK_SCAN", process.ExitCode == 0 ? ActionExecutionStatus.COMPLETED : ActionExecutionStatus.FAILED,
                    process.ExitCode == 0 ? "L’analyse rapide Microsoft Defender s’est terminée." : $"Defender a terminé avec le code {process.ExitCode}.", started, DateTimeOffset.UtcNow, false);
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
            {
                return new("RUN_DEFENDER_QUICK_SCAN", ActionExecutionStatus.FAILED, "Impossible de lancer l’analyse Microsoft Defender.", started, DateTimeOffset.UtcNow, false);
            }
        }

        private static string? FindDefenderCommand()
        {
            var roots = new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) }
                .Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase);
            foreach (var root in roots)
            {
                var basePath = Path.Combine(root, "Windows Defender");
                var direct = Path.Combine(basePath, "MpCmdRun.exe");
                if (File.Exists(direct)) return direct;
                var platform = Path.Combine(basePath, "Platform");
                if (Directory.Exists(platform))
                {
                    var candidate = Directory.EnumerateFiles(platform, "MpCmdRun.exe", SearchOption.AllDirectories)
                        .OrderByDescending(File.GetLastWriteTimeUtc).FirstOrDefault();
                    if (candidate is not null) return candidate;
                }
            }
            return null;
        }
    }

    private static ActionExecutionResult Result(string id, ActionExecutionStatus status, string explanation, bool simulated)
        => new(id, status, explanation, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, simulated);
}

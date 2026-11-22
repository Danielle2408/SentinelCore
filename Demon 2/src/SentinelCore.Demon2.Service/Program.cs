using SentinelCore.Demon2.Core;
using System.Runtime.Versioning;

namespace SentinelCore.Demon2.Service;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private static async Task Main(string[] args)
    {
        var configuredDataDirectory = ParseDataDirectory(args);
        // The user-started test/control process must not require elevation. A real SCM service
        // keeps its shared database under ProgramData and receives a dedicated ACL at deployment.
        var dataRoot = configuredDataDirectory ?? (Environment.UserInteractive
            ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            : Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        var root = Path.Combine(dataRoot, "SentinelCore", "Demon2");
        Directory.CreateDirectory(root);
        var previousError = Console.Error;
        using var log = new ServiceErrorLogWriter(Path.Combine(root, "logs"), previousError);
        Console.SetError(log);
        try
        {
            var databasePath = Path.Combine(root, "events.sqlite");
            var retentionDays = int.TryParse(Environment.GetEnvironmentVariable("SENTINELCORE_D2_RETENTION_DAYS"), out var configuredDays) ? configuredDays : 7;
            if (retentionDays is < 1 or > 365) throw new InvalidOperationException("SENTINELCORE_D2_RETENTION_DAYS must be between 1 and 365.");
            await using var store = new SqliteEventStore(databasePath, TimeSpan.FromDays(retentionDays));
            await store.InitializeAsync();
            await using var bus = new NamedPipeInterDaemonBus();
            var sysmonBookmark = await store.LoadCursorAsync("Sysmon");
            var defenderBookmark = await store.LoadCursorAsync("WindowsDefender");
            var powerShellBookmark = await store.LoadCursorAsync("PowerShell");
            var source = new CombinedWindowsSecurityEventSource(
                new SysmonEventSource(sysmonBookmark),
                new WindowsDefenderEventSource(defenderBookmark),
                new PowerShellScriptBlockEventSource(powerShellBookmark));
            var pipeline = new ThreatMonitorPipeline(source, source, new WindowsSecurityEventNormalizer(), store,
                new DetectionEngine(), bus);
            try { WindowsServiceDispatcher.Run(pipeline.RunAsync); }
            finally { await source.DisposeAsync(); }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Threat Monitor startup or runtime failure: {ex}");
            throw;
        }
        finally { Console.SetError(previousError); }
    }

    private static string? ParseDataDirectory(string[] args)
    {
        if (args.Length == 0) return null;
        if (args.Length == 2 && args[0] == "--data-dir" && !string.IsNullOrWhiteSpace(args[1]))
            return Path.GetFullPath(args[1]);
        throw new ArgumentException("Usage : SentinelCore.Demon2.Service.exe [--data-dir <dossier>] pour isoler les données d’un test.");
    }
}

using SentinelCore.Demon2.Core;
using System.Runtime.Versioning;

namespace SentinelCore.Demon2.Service;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private static async Task Main()
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentinelCore", "Demon2");
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
            var bookmark = await store.LoadCursorAsync("Sysmon");
            var source = new SysmonEventSource(bookmark);
            var pipeline = new ThreatMonitorPipeline(source, source, new SysmonEventNormalizer(), store,
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
}

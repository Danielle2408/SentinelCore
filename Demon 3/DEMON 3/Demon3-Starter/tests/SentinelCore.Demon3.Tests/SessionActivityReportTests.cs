using SentinelCore.Demon3.Core.Reports;
using Xunit;

namespace SentinelCore.Demon3.Tests;

public sealed class SessionActivityReportTests
{
    [Fact]
    public async Task StartupAndManualSnapshotsIncludeActivityAndCoverageWithoutThreatsBeingRequired()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-SessionReport-" + Guid.NewGuid().ToString("N"));
        try
        {
            var service = new SessionActivityReportService(folder);
            var bootAt = DateTimeOffset.UtcNow.AddHours(-2);
            var startup = await service.BeginSessionAsync(bootAt);

            Assert.Equal("STARTUP", startup.Trigger);
            Assert.False(startup.IsFinal);
            Assert.Equal(bootAt.ToUniversalTime(), startup.ComputerBootAtUtc);
            Assert.Equal(0, startup.TotalActivityCount);
            Assert.Equal(0, startup.ThreatCount);
            Assert.True(File.Exists(startup.JsonPath));
            Assert.True(File.Exists(startup.TextPath));

            var now = DateTimeOffset.UtcNow;
            await service.RecordHeartbeatAsync("HumanBehaviorMonitor", now.AddSeconds(-4));
            await service.RecordHeartbeatAsync("ThreatMonitor", now.AddSeconds(-3));
            await service.RecordActivityAsync("HumanBehaviorMonitor", "USER_CONTEXT", "LOW", "KNOWN_APPLICATION", "case-1", now.AddSeconds(-2));
            await service.RecordActivityAsync("ThreatMonitor", "THREAT_FINDING", "HIGH", "SCRIPT_CHAIN", "case-1", now.AddSeconds(-1));
            await service.RecordActivityAsync("ThreatMonitor", "TELEMETRY_GAP", "UNKNOWN", "SOURCE_UNAVAILABLE", "case-2", now);
            await service.RecordDecisionAsync("HIGH", "RUN_BOUNDED_SCAN", "case-1", now);

            var snapshot = await service.CreateSnapshotAsync();
            Assert.Equal("MANUAL", snapshot.Trigger);
            Assert.Equal(startup.SessionId, snapshot.SessionId);
            Assert.Equal(4, snapshot.TotalActivityCount);
            Assert.Equal(1, snapshot.D1ActivityCount);
            Assert.Equal(2, snapshot.D2ActivityCount);
            Assert.Equal(1, snapshot.ThreatCount);
            Assert.Equal(1, snapshot.TelemetryGapCount);
            Assert.Equal(1, snapshot.DecisionCount);
            Assert.Equal(1, snapshot.D1HeartbeatCount);
            Assert.Equal(1, snapshot.D2HeartbeatCount);
            Assert.NotNull(snapshot.D1LastSeenAtUtc);
            Assert.NotNull(snapshot.D2LastSeenAtUtc);
            Assert.Equal(4, snapshot.RecentActivities.Count);
            Assert.Contains("1 menace(s)", snapshot.Summary);

            var recent = await service.ReadRecentAsync();
            Assert.Contains(recent, report => report.ReportId == startup.ReportId);
            Assert.Contains(recent, report => report.ReportId == snapshot.ReportId);
            Assert.Equal(snapshot.ReportId, (await service.ReadByIdAsync(snapshot.ReportId))?.ReportId);
            var jsonText = await File.ReadAllTextAsync(snapshot.JsonPath);
            Assert.Contains("USER_CONTEXT", jsonText);
            Assert.Contains("KNOWN_APPLICATION", jsonText);
            Assert.DoesNotContain("raw-keystroke", jsonText);
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public async Task FinalReportIsIdempotentAndSavedEvenWhenNoActivityWasObserved()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-SessionFinal-" + Guid.NewGuid().ToString("N"));
        try
        {
            var service = new SessionActivityReportService(folder);
            var startup = await service.BeginSessionAsync();
            var first = await service.FinalizeSessionAsync("SESSION_END");
            var repeated = await service.FinalizeSessionAsync("SESSION_END");

            Assert.Equal(startup.SessionId, first.SessionId);
            Assert.True(first.IsFinal);
            Assert.Equal("FINAL", first.SessionState);
            Assert.Equal(0, first.TotalActivityCount);
            Assert.Equal(first.ReportId, repeated.ReportId);
            Assert.True(File.Exists(first.JsonPath));
            Assert.True(File.Exists(first.TextPath));
            Assert.Equal(2, (await service.ReadRecentAsync()).Count);
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public async Task NewD3SessionClosesAnUnfinishedPreviousSessionAsInterrupted()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-SessionRecovery-" + Guid.NewGuid().ToString("N"));
        try
        {
            var service = new SessionActivityReportService(folder);
            var first = await service.BeginSessionAsync();
            await service.RecordActivityAsync("ThreatMonitor", "TELEMETRY_GAP", "UNKNOWN", "SOURCE_UNAVAILABLE", "case-1", DateTimeOffset.UtcNow);
            var second = await service.BeginSessionAsync();

            Assert.NotEqual(first.SessionId, second.SessionId);
            var reports = await service.ReadRecentAsync();
            var recovered = Assert.Single(reports, report => report.SessionId == first.SessionId && report.IsFinal);
            Assert.Equal("INTERRUPTED", recovered.SessionState);
            Assert.Equal("INTERRUPTED_AFTER_RESTART", recovered.Trigger);
            Assert.Equal(1, recovered.TelemetryGapCount);
            Assert.Equal("ACTIVE", second.SessionState);
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
    }
}

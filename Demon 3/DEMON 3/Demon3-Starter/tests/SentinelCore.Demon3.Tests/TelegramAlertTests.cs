using System.Net;
using System.Security.Cryptography;
using System.Text;
using SentinelCore.Demon3.Core.AI;
using SentinelCore.Demon3.Core.Actions;
using SentinelCore.Demon3.Core.Decision;
using SentinelCore.Demon3.Core.Notifications;
using SentinelCore.Demon3.Core.Reports;
using Xunit;

namespace SentinelCore.Demon3.Tests;

public sealed class TelegramAlertTests
{
    private const string Token = "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    private const string ChatId = "-1001234567890";

    [Fact]
    public void AlertSettingsAreValidatedAndProtectedAtRest()
    {
        Assert.True(TelegramAlertSettingsStore.IsValidBotToken(Token));
        Assert.True(TelegramAlertSettingsStore.IsValidChatId(ChatId));
        Assert.False(TelegramAlertSettingsStore.IsValidBotToken("token with spaces"));
        Assert.False(TelegramAlertSettingsStore.IsValidChatId("@bad id"));
        if (!OperatingSystem.IsWindows()) return;

        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-TelegramSettings-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(folder, "telegram.dpapi");
        try
        {
            var store = new TelegramAlertSettingsStore(path);
            var expected = new TelegramAlertSettings(true, ChatId, Token);
            Assert.True(store.Save(expected));
            var protectedFile = File.ReadAllBytes(path);
            Assert.DoesNotContain(Token, Encoding.UTF8.GetString(protectedFile));
            Assert.Equal(expected, store.Load());
            Assert.True(store.Delete());
            Assert.Null(store.Load());
        }
        finally { if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public void AuthenticationFailureGateNotifiesOnlyOnTheSecondFailure()
    {
        var gate = new AuthenticationFailureAlertGate(2);

        Assert.False(gate.RecordFailure());
        Assert.True(gate.RecordFailure());
        Assert.False(gate.RecordFailure());
        Assert.Throws<ArgumentOutOfRangeException>(() => new AuthenticationFailureAlertGate(0));
    }

    [Fact]
    public void AlertOutboxPersistsRetryAndSuppressesDuplicateCorrelation()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-TelegramOutbox-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var path = Path.Combine(folder, "outbox.json");
            var store = new TelegramAlertOutboxStore(path);
            var reportId = Guid.NewGuid();
            Assert.True(store.TryEnqueue(reportId, "telegram-outbox-case"));
            Assert.False(store.TryEnqueue(Guid.NewGuid(), "telegram-outbox-case"));
            var nextAttempt = DateTimeOffset.UtcNow.AddMinutes(1);
            Assert.True(store.ScheduleRetry(reportId, 2, nextAttempt));

            var restarted = new TelegramAlertOutboxStore(path);
            var restored = Assert.Single(restarted.ReadAll());
            Assert.Equal(reportId, restored.ReportId);
            Assert.Equal(2, restored.Attempts);
            Assert.Equal(nextAttempt, restored.NextAttemptAtUtc);
            Assert.True(restarted.MarkDelivered(reportId));
            Assert.True(Assert.Single(restarted.ReadAll()).Delivered);
            Assert.False(restarted.TryEnqueue(Guid.NewGuid(), "telegram-outbox-case"));
        }
        finally { Directory.Delete(folder, recursive: true); }
    }

    [Fact]
    public async Task BotApiUploadsPdfOverHttpsAndRejectsMalformedConfiguration()
    {
        Uri? observedUri = null;
        string? observedBody = null;
        var handler = new CallbackHandler(async (request, token) =>
        {
            observedUri = request.RequestUri;
            observedBody = await request.Content!.ReadAsStringAsync(token);
            return new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("""{"ok":true,"result":{}}""") };
        });
        using var http = new HttpClient(handler);
        var client = new TelegramBotApiClient(http);
        var settings = new TelegramAlertSettings(true, ChatId, Token);
        var result = await client.SendPdfAsync(settings, "Alerte SentinelCore", [0x25, 0x50, 0x44, 0x46], "rapport.pdf");

        Assert.True(result.Succeeded);
        Assert.NotNull(observedUri);
        Assert.Equal("https", observedUri.Scheme);
        Assert.Contains("sendDocument", observedUri.AbsolutePath, StringComparison.Ordinal);
        Assert.Contains("chat_id", observedBody, StringComparison.Ordinal);
        Assert.Contains("rapport.pdf", observedBody, StringComparison.Ordinal);

        var invalid = await client.SendMessageAsync(settings with { BotToken = "invalid" }, "test");
        Assert.Equal(TelegramDeliveryStatus.INVALID_CONFIGURATION, invalid.Status);
    }

    [Fact]
    public async Task NotifierSendsPdfOnceForHighRiskAndIgnoresLowRisk()
    {
        var folder = Path.Combine(Path.GetTempPath(), "SentinelCore-TelegramReport-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var reportStore = new RiskReportStore(folder);
            var decision = CreateDecision("telegram-high", RiskLevel.HIGH);
            var report = await reportStore.SaveAsync(decision, []);
            var settingsFile = Path.Combine(folder, "telegram.dpapi");
            var settingsStore = new TelegramAlertSettingsStore(settingsFile);
            if (!OperatingSystem.IsWindows()) return;
            Assert.True(settingsStore.Save(new TelegramAlertSettings(true, ChatId, Token)));

            var received = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
            var handler = new CallbackHandler(async (request, token) =>
            {
                var body = await request.Content!.ReadAsStringAsync(token);
                received.TrySetResult(body);
                return new HttpResponseMessage(HttpStatusCode.OK)
                { Content = new StringContent("""{"ok":true,"result":{}}""") };
            });
            using var http = new HttpClient(handler);
            var notices = new List<string>();
            var outbox = new TelegramAlertOutboxStore(Path.Combine(folder, "outbox.json"));
            var notifier = new TelegramReportNotifier(reportStore, settingsStore, new TelegramBotApiClient(http), notices.Add, outbox);
            Assert.False(notifier.QueueIfImportant(report with { Decision = CreateDecision("telegram-low", RiskLevel.LOW) }));
            Assert.True(notifier.QueueIfImportant(report));
            Assert.False(notifier.QueueIfImportant(report with { ReportId = Guid.NewGuid() }));

            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var worker = notifier.RunAsync(stop.Token);
            var body = await received.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Contains("SentinelCore-", body, StringComparison.Ordinal);
            Assert.Contains("application/pdf", body, StringComparison.Ordinal);
            Assert.Contains("alerte HIGH", string.Join(" ", notices), StringComparison.OrdinalIgnoreCase);
            Assert.True(Assert.Single(outbox.ReadAll()).Delivered);
            stop.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => worker);
        }
        finally { Directory.Delete(folder, recursive: true); }
    }

    [Theory]
    [InlineData(RiskLevel.HIGH, null, true)]
    [InlineData(RiskLevel.CRITICAL, null, true)]
    [InlineData(RiskLevel.ELEVATED, AdvisorStatus.Unavailable, true)]
    [InlineData(RiskLevel.ELEVATED, AdvisorStatus.Advised, false)]
    [InlineData(RiskLevel.LOW, AdvisorStatus.Unavailable, false)]
    public void AlertEligibilityOnlyIncludesHighRiskOrUnresolvedElevatedCases(RiskLevel risk, AdvisorStatus? status, bool expected)
    {
        var decision = CreateDecision("telegram-gate", risk);
        var advice = status is null ? null : AdvisorOutcome.Failure(status.Value, "gemma3:1b", "TEST");
        var report = new RiskReport(Guid.NewGuid(), DateTimeOffset.UtcNow, decision, [],
            new DecisionComparison("FIRST", null, null, "test"), advice);
        using var http = new HttpClient();
        var notifier = new TelegramReportNotifier(new RiskReportStore(Path.GetTempPath()),
            new TelegramAlertSettingsStore(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))),
            new TelegramBotApiClient(http), outbox: new TelegramAlertOutboxStore(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"))));
        Assert.Equal(expected, notifier.QueueIfImportant(report));
    }

    private static RiskDecision CreateDecision(string correlation, RiskLevel risk)
        => new(correlation, risk, DecisionKind.MONITOR, ProposedAction.NONE, "Résumé de test",
            [], [], false, true, DateTimeOffset.UtcNow);

    private sealed class CallbackHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> callback) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => callback(request, cancellationToken);
    }
}

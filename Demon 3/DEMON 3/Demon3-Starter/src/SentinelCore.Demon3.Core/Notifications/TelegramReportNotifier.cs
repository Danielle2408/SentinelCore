using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Threading.Channels;
using SentinelCore.Demon3.Core.AI;
using SentinelCore.Demon3.Core.Decision;
using SentinelCore.Demon3.Core.Reports;

namespace SentinelCore.Demon3.Core.Notifications;

/// <summary>Queues high-risk reports locally and retries Telegram delivery while D3 is running.</summary>
public sealed class TelegramReportNotifier(RiskReportStore reports, TelegramAlertSettingsStore settings,
    TelegramBotApiClient client, Action<string>? notice = null, TelegramAlertOutboxStore? outbox = null)
{
    private readonly Channel<RiskReport> _queue = Channel.CreateBounded<RiskReport>(new BoundedChannelOptions(64)
    {
        FullMode = BoundedChannelFullMode.Wait,
        SingleReader = true,
        SingleWriter = false
    });
    private readonly ConcurrentDictionary<string, DateTimeOffset> _queuedCases = new(StringComparer.Ordinal);
    private readonly TelegramAlertOutboxStore _outbox = outbox ?? new TelegramAlertOutboxStore();

    public bool QueueIfImportant(RiskReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        PruneOldCases();
        if (!IsImportant(report) || !_queuedCases.TryAdd(report.Decision.CorrelationId, DateTimeOffset.UtcNow)) return false;
        if (_queue.Writer.TryWrite(report)) return true;
        _queuedCases.TryRemove(report.Decision.CorrelationId, out _);
        notice?.Invoke("Telegram : file d’envoi pleine; le rapport reste enregistré localement.");
        return false;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        foreach (var entry in _outbox.ReadAll())
            _queuedCases.TryAdd(entry.CorrelationId, entry.QueuedAtUtc);

        Task<bool>? waitingForInput = null;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            while (_queue.Reader.TryRead(out var incoming))
            {
                var destination = settings.Load();
                if (destination is not { Enabled: true })
                {
                    _queuedCases.TryRemove(incoming.Decision.CorrelationId, out _);
                    continue;
                }
                if (!_outbox.TryEnqueue(incoming.ReportId, incoming.Decision.CorrelationId))
                    notice?.Invoke("Telegram : alerte déjà en attente/envoyée, ou file persistante pleine.");
            }

            var currentSettings = settings.Load();
            if (currentSettings is not { Enabled: true })
            {
                _outbox.RemovePending();
            }
            else
            {
                foreach (var pending in _outbox.ReadAll()
                    .Where(x => !x.Delivered && x.NextAttemptAtUtc <= DateTimeOffset.UtcNow))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await DeliverAsync(pending, currentSettings, cancellationToken).ConfigureAwait(false);
                }
            }

            var nextAttempt = _outbox.ReadAll().Where(x => !x.Delivered)
                .Select(x => (DateTimeOffset?)x.NextAttemptAtUtc).Min();
            waitingForInput ??= _queue.Reader.WaitToReadAsync(cancellationToken).AsTask();
            if (nextAttempt is null)
            {
                if (!await waitingForInput.ConfigureAwait(false)) return;
                waitingForInput = null;
                continue;
            }

            var delay = nextAttempt.Value - DateTimeOffset.UtcNow;
            if (delay <= TimeSpan.Zero) continue;
            var delayed = Task.Delay(delay, cancellationToken);
            var completed = await Task.WhenAny(waitingForInput, delayed).ConfigureAwait(false);
            if (completed == waitingForInput)
            {
                if (!await waitingForInput.ConfigureAwait(false)) return;
                waitingForInput = null;
            }
            else await delayed.ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
        }
    }

    private async Task DeliverAsync(TelegramAlertOutboxEntry pending, TelegramAlertSettings destination, CancellationToken token)
    {
        try
        {
            var report = await reports.ReadByIdAsync(pending.ReportId, token).ConfigureAwait(false);
            if (report is null)
            {
                _outbox.MarkDelivered(pending.ReportId);
                notice?.Invoke($"Telegram : rapport local introuvable ({pending.ReportId:N}); envoi abandonné.");
                return;
            }

            var caption = BuildCaption(report);
            var pdf = await reports.CreatePdfAsync(report.ReportId, token).ConfigureAwait(false);
            TelegramDeliveryResult result;
            if (pdf is { Length: > 0 and <= 10 * 1024 * 1024 })
            {
                try
                {
                    var fileName = $"SentinelCore-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{report.ReportId:N}.pdf";
                    result = await client.SendPdfAsync(destination, caption, pdf, fileName, token).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(pdf); }
            }
            else
            {
                result = await client.SendMessageAsync(destination, caption, token).ConfigureAwait(false);
            }

            if (result.Succeeded)
            {
                _outbox.MarkDelivered(pending.ReportId);
                notice?.Invoke($"Telegram : alerte {report.Decision.Risk} envoyée; rapport D3 {report.ReportId:N}.");
                return;
            }

            var attempts = pending.Attempts + 1;
            var backoffSeconds = Math.Min(300, 5 * Math.Pow(2, Math.Min(attempts - 1, 6)));
            _outbox.ScheduleRetry(pending.ReportId, attempts, DateTimeOffset.UtcNow.AddSeconds(backoffSeconds));
            notice?.Invoke($"Telegram : envoi non confirmé ({result.ReasonCode}); nouvelle tentative automatique dans {backoffSeconds:0} s. Rapport conservé localement.");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            var attempts = pending.Attempts + 1;
            var backoffSeconds = Math.Min(300, 5 * Math.Pow(2, Math.Min(attempts - 1, 6)));
            _outbox.ScheduleRetry(pending.ReportId, attempts, DateTimeOffset.UtcNow.AddSeconds(backoffSeconds));
            notice?.Invoke($"Telegram : échec temporaire; nouvelle tentative dans {backoffSeconds:0} s. Rapport conservé localement.");
        }
    }

    private static bool IsImportant(RiskReport report)
        => report.Decision.Risk is RiskLevel.HIGH or RiskLevel.CRITICAL
            || (int)report.Decision.Risk >= (int)RiskLevel.ELEVATED
                && (report.AiAdvice?.Status is AdvisorStatus.Unavailable or AdvisorStatus.InvalidResponse
                    || report.AiAdvice?.Advice?.RiskBand == AdviceRiskBand.UNCERTAIN);

    private static string BuildCaption(RiskReport report)
    {
        var ai = report.AiAdvice?.Advice?.Summary;
        var fallback = report.AiAdvice?.Status is AdvisorStatus.Unavailable or AdvisorStatus.InvalidResponse
            ? "Analyse Ollama indisponible ou non exploitable."
            : report.Decision.Explanation;
        var summary = string.IsNullOrWhiteSpace(ai) ? fallback : ai;
        summary = new string(summary.Where(c => !char.IsControl(c) || c is '\r' or '\n').ToArray());
        if (summary.Length > 500) summary = summary[..500] + "…";
        return $"SENTINELCORE — ALERTE {report.Decision.Risk}\n"
            + $"Décision : {report.Decision.Decision}\n"
            + $"Corrélation : {report.Decision.CorrelationId}\n"
            + summary;
    }

    private void PruneOldCases()
    {
        var cutoff = DateTimeOffset.UtcNow.AddDays(-7);
        foreach (var item in _queuedCases)
            if (item.Value < cutoff) _queuedCases.TryRemove(item.Key, out _);
    }
}

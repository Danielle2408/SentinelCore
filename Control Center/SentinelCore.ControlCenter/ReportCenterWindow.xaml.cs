using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using SentinelCore.Demon3.Core.Reports;

namespace SentinelCore.ControlCenter;

/// <summary>Local viewer for D3 security decisions and D1/D2 session activity snapshots.</summary>
public partial class ReportCenterWindow : Window
{
    private readonly SessionActivityReportService _sessionReports;
    private readonly RiskReportStore _riskReports;
    private readonly ObservableCollection<ReportRow> _rows = [];

    public ReportCenterWindow()
        : this(new SessionActivityReportService(), new RiskReportStore()) { }

    internal ReportCenterWindow(SessionActivityReportService sessionReports, RiskReportStore riskReports)
    {
        _sessionReports = sessionReports ?? throw new ArgumentNullException(nameof(sessionReports));
        _riskReports = riskReports ?? throw new ArgumentNullException(nameof(riskReports));
        InitializeComponent();
        ReportsGrid.ItemsSource = _rows;
        Loaded += async (_, _) => await RefreshReportsAsync();
    }

    private async void Generate_Click(object sender, RoutedEventArgs e)
    {
        SetBusy(true, "Création d’un instantané à partir des activités déjà reçues…");
        try
        {
            var result = await _sessionReports.CreateManualSnapshotAsync();
            var report = result.Report;
            await RefreshReportsAsync(report.ReportId);
            var journalNote = result.SessionInitializedForSnapshot
                ? " D3 n’avait pas ouvert le journal d’activité; le suivi repart maintenant. Les anciennes décisions D3 restent dans l’historique de sécurité séparé."
                : string.Empty;
            StatusText.Text = $"Instantané enregistré à {report.CapturedAtUtc.ToLocalTime():dd/MM/yyyy HH:mm:ss}. Il contient {report.TotalActivityCount} activité(s) observée(s).{journalNote}";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Création impossible ({ex.GetType().Name}). Vérifie que D3 a initialisé son espace local.";
        }
        finally { SetBusy(false); }
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshReportsAsync();

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void ReportsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ReportsGrid.SelectedItem is not ReportRow selected)
        {
            ShowEmptyPreview();
            return;
        }

        PreviewTitle.Text = selected.Title;
        PreviewMetadata.Text = selected.Metadata;
        PreviewSummary.Text = selected.Summary;
        ActivityItems.ItemsSource = selected.Activities;
        NoActivitiesText.Visibility = selected.Activities.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async Task RefreshReportsAsync(Guid? selectReportId = null)
    {
        var wasBusy = GenerateButton.IsEnabled;
        SetBusy(true, "Lecture des rapports locaux…");
        try
        {
            var sessionsTask = _sessionReports.ReadRecentAsync(100);
            var risksTask = _riskReports.ReadRecentAsync(100);
            await Task.WhenAll(sessionsTask, risksTask);

            _rows.Clear();
            foreach (var report in await sessionsTask)
                _rows.Add(ReportRow.FromSession(report));
            foreach (var report in await risksTask)
                _rows.Add(ReportRow.FromRisk(report));

            var ordered = _rows.OrderByDescending(row => row.CreatedAtUtc).ToArray();
            _rows.Clear();
            foreach (var row in ordered) _rows.Add(row);

            ReportCountText.Text = _rows.Count == 1 ? "1 rapport" : $"{_rows.Count} rapports";
            EmptyState.Visibility = _rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            if (selectReportId is { } reportId)
                ReportsGrid.SelectedItem = _rows.FirstOrDefault(row => row.ReportId == reportId);
            else if (ReportsGrid.SelectedItem is null && _rows.Count > 0)
                ReportsGrid.SelectedIndex = 0;

            if (ReportsGrid.SelectedItem is null) ShowEmptyPreview();
            StatusText.Text = _rows.Count == 0
                ? "Aucun rapport archivé. Tu peux créer un premier instantané, même sans menace détectée."
                : $"{_rows.Count} rapport(s) local(aux) chargé(s) · activité et décisions de sécurité.";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Lecture des rapports impossible ({ex.GetType().Name}).";
        }
        finally { SetBusy(!wasBusy, StatusText.Text); }
    }

    private void ShowEmptyPreview()
    {
        PreviewTitle.Text = "Sélectionne un rapport";
        PreviewMetadata.Text = string.Empty;
        PreviewSummary.Text = "Les détails du rapport sélectionné apparaîtront ici.";
        ActivityItems.ItemsSource = null;
        NoActivitiesText.Visibility = Visibility.Collapsed;
    }

    private void SetBusy(bool busy, string? status = null)
    {
        GenerateButton.IsEnabled = !busy;
        RefreshButton.IsEnabled = !busy;
        if (status is not null) StatusText.Text = status;
    }

    private sealed record ActivityRow(string Label, string Detail, string CountLabel);

    private sealed record ReportRow(Guid ReportId, DateTimeOffset CreatedAtUtc, string CreatedAtLocal,
        string ReportType, string TriggerLabel, string Title, string Metadata, string Summary,
        IReadOnlyList<ActivityRow> Activities)
    {
        public static ReportRow FromSession(SessionActivityReport report)
        {
            var created = report.CapturedAtUtc;
            var trigger = TriggerName(report.Trigger);
            var activities = new List<ActivityRow>
            {
                new("Démon 1 · comportement", "Activités et signaux de session reçus par D3.", $"{report.D1ActivityCount:N0}"),
                new("Démon 2 · surveillance technique", "Événements techniques observés et relayés.", $"{report.D2ActivityCount:N0}"),
                new("Présence de D1", LastSeen("D1", report.D1LastSeenAtUtc), $"{report.D1HeartbeatCount:N0} battement(s)"),
                new("Présence de D2", LastSeen("D2", report.D2LastSeenAtUtc), $"{report.D2HeartbeatCount:N0} battement(s)"),
                new("Décisions D3", "Décisions de risque enregistrées pendant cette session.", $"{report.DecisionCount:N0}"),
                new("Menaces signalées", "Constats D2 associés à cette session.", $"{report.ThreatCount:N0}"),
                new("Lacunes de télémétrie", "Sources ou données qui n’étaient pas disponibles.", $"{report.TelemetryGapCount:N0}")
            };
            activities.AddRange(report.RecentActivities
                .OrderByDescending(item => item.ObservedAtUtc)
                .Take(40)
                .Select(item => new ActivityRow(
                    $"{item.SourceDaemon} · {item.MessageType}",
                    string.Join(" · ", new[] { item.Severity, item.Summary }.Where(value => !string.IsNullOrWhiteSpace(value))),
                    item.ObservedAtUtc.ToLocalTime().ToString("HH:mm:ss"))));

            var end = report.SessionEndedAtUtc is { } ended
                ? $" · fin {ended.ToLocalTime():dd/MM/yyyy HH:mm:ss}"
                : " · session en cours";
            var metadata = $"Type : rapport d’activité · État : {report.SessionState} · Déclencheur : {trigger} · Démarrage PC estimé : {report.ComputerBootAtUtc.ToLocalTime():dd/MM/yyyy HH:mm:ss} · Début de session : {report.SessionStartedAtUtc.ToLocalTime():dd/MM/yyyy HH:mm:ss}{end} · Capture : {created.ToLocalTime():dd/MM/yyyy HH:mm:ss} · Session : {report.SessionId}";
            var title = report.IsFinal ? "Clôture de session" : report.Trigger == "MANUAL" ? "Instantané manuel" : $"État de session · {trigger}";
            var summary = $"{report.Summary}\n\nTotal : {report.TotalActivityCount:N0} activité(s) observée(s).";
            return new(report.ReportId, created, created.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"),
                "Activité", trigger, title, metadata, summary, activities);
        }

        public static ReportRow FromRisk(RiskReport report)
        {
            var created = report.CreatedAtUtc;
            var activities = report.Signals
                .OrderByDescending(signal => signal.ObservedAtUtc)
                .Take(40)
                .Select(signal => new ActivityRow(
                    $"{signal.SourceDaemon} · {signal.MessageType}",
                    string.Join(" · ", new[] { signal.Severity, signal.ContextSummary ?? signal.ReasonCode }
                        .Where(value => !string.IsNullOrWhiteSpace(value))),
                    signal.ObservedAtUtc.ToLocalTime().ToString("HH:mm:ss")))
                .ToArray();
            var metadata = $"Type : décision de sécurité · Niveau : {report.Decision.Risk} · Décision : {report.Decision.Decision} · Créé : {created.ToLocalTime():dd/MM/yyyy HH:mm:ss} · Corrélation : {report.Decision.CorrelationId}";
            return new(report.ReportId, created, created.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"),
                "Sécurité", "Signal D1/D2", $"Décision D3 · {report.Decision.Risk}", metadata,
                report.Decision.Explanation, activities);
        }

        private static string TriggerName(string trigger) => trigger switch
        {
            "STARTUP" or "SESSION_START" => "Démarrage PC/session",
            "SHUTDOWN" or "SESSION_END" => "Fin de session",
            "PERIODIC" => "Sauvegarde périodique",
            "MANUAL" => "Instantané à la demande",
            _ => trigger
        };

        private static string LastSeen(string daemon, DateTimeOffset? timestamp)
            => timestamp is { } seen
                ? $"Dernier signal {daemon} reçu à {seen.ToLocalTime():dd/MM HH:mm:ss}."
                : $"Aucun signal {daemon} reçu pendant cette session.";
    }
}

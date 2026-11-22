using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Microsoft.Data.Sqlite;
using SentinelCore.Demon2.Core;
using SentinelCore.Demon3.Core.Reports;

namespace SentinelCore.ControlCenter;

/// <summary>Local read-only timeline backed by Demon 2's event store and Demon 3's risk reports.</summary>
public partial class DaemonActivityPage : System.Windows.Controls.UserControl
{
    private static readonly TimeSpan EventLookback = TimeSpan.FromDays(7);
    private const int MaximumEvents = 250;
    private const int MaximumFindings = 250;
    private const int MaximumReports = 100;
    private static readonly JsonSerializerOptions D2JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };
    private static readonly JsonSerializerOptions D3JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly ObservableCollection<ActivityRow> _activityRows = [];
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(5) };
    private bool _isRefreshing;

    public DaemonActivityPage()
    {
        InitializeComponent();
        DataContext = this;
        SizeChanged += (_, _) => ApplyResponsiveLayout();
        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
        Loaded += Page_Loaded;
        Unloaded += Page_Unloaded;
    }

    private void ApplyResponsiveLayout()
    {
        if (ActualWidth <= 0) return;
        var compact = ActualWidth < 1100;
        ActivityRootGrid.Margin = compact ? new Thickness(12, 14, 12, 14) : new Thickness(30, 24, 30, 26);
        ActivityStatsGrid.Columns = ActualWidth < 720 ? 1 : compact ? 2 : 3;
        LastRefresh.Visibility = ActualWidth < 900 ? Visibility.Collapsed : Visibility.Visible;
        TransportStatus.TextWrapping = TextWrapping.Wrap;

        if (ActivityGrid.Columns.Count < 6) return;
        if (ActualWidth < 720)
        {
            ActivityGrid.Columns[0].Width = new DataGridLength(82);
            ActivityGrid.Columns[1].Width = new DataGridLength(50);
            ActivityGrid.Columns[2].Width = new DataGridLength(88);
            ActivityGrid.Columns[3].Width = new DataGridLength(62);
            ActivityGrid.Columns[4].Width = new DataGridLength(1, DataGridLengthUnitType.Star);
            ActivityGrid.Columns[5].Visibility = Visibility.Collapsed;
        }
        else if (ActualWidth < 1000)
        {
            ActivityGrid.Columns[0].Width = new DataGridLength(108);
            ActivityGrid.Columns[1].Width = new DataGridLength(62);
            ActivityGrid.Columns[2].Width = new DataGridLength(118);
            ActivityGrid.Columns[3].Width = new DataGridLength(76);
            ActivityGrid.Columns[4].Width = new DataGridLength(1, DataGridLengthUnitType.Star);
            ActivityGrid.Columns[5].Visibility = Visibility.Collapsed;
        }
        else
        {
            ActivityGrid.Columns[0].Width = new DataGridLength(145);
            ActivityGrid.Columns[1].Width = new DataGridLength(82);
            ActivityGrid.Columns[2].Width = new DataGridLength(190);
            ActivityGrid.Columns[3].Width = new DataGridLength(105);
            ActivityGrid.Columns[4].Width = new DataGridLength(1, DataGridLengthUnitType.Star);
            ActivityGrid.Columns[5].Width = new DataGridLength(210);
            ActivityGrid.Columns[5].Visibility = Visibility.Visible;
        }
    }

    public ObservableCollection<ActivityRow> ActivityRows => _activityRows;

    public void SetTransportStatus(bool? d1ToD3Acknowledged, bool? d2ToD3Acknowledged,
        bool? d3ListenerReady, DateTimeOffset? lastD2AcknowledgementUtc)
    {
        static string State(bool? value) => value switch
        {
            true => "confirmé",
            false => "en échec",
            null => "inconnu"
        };

        TransportStatus.Text = $"D3 listener : {State(d3ListenerReady)}  ·  D1 → D3 : {State(d1ToD3Acknowledged)}  ·  D2 → D3 : {State(d2ToD3Acknowledged)}"
            + (lastD2AcknowledgementUtc is { } acknowledged ? $"  ·  dernier ACK D2 : {acknowledged.ToLocalTime():HH:mm:ss}" : string.Empty);
        var confirmed = d3ListenerReady == true && d1ToD3Acknowledged == true && d2ToD3Acknowledged == true;
        TransportStatus.Foreground = (System.Windows.Media.Brush)FindResource(confirmed ? "AccentBrush" : "AmberBrush");
    }

    private async void Page_Loaded(object sender, RoutedEventArgs e)
    {
        _refreshTimer.Start();
        await RefreshAsync();
    }

    private void Page_Unloaded(object sender, RoutedEventArgs e) => _refreshTimer.Stop();

    private async void Refresh_Click(object sender, RoutedEventArgs e) => await RefreshAsync();

    public async Task RefreshAsync()
    {
        if (_isRefreshing) return;
        _isRefreshing = true;
        RefreshButton.IsEnabled = false;
        ActivityStatus.Text = "Lecture des historiques locaux…";

        try
        {
            var d2Task = LoadD2Async();
            var d3Task = LoadD3Async();
            await Task.WhenAll(d2Task, d3Task);
            var d2 = await d2Task;
            var d3 = await d3Task;

            D2EventCount.Text = d2.Events.Count.ToString("N0");
            D2FindingCount.Text = d2.Findings.Count.ToString("N0");
            D3ReportCount.Text = d3.Reports.Count.ToString("N0");
            D2EventStatus.Text = d2.Status;
            D2FindingStatus.Text = d2.Status;
            D3ReportStatus.Text = d3.Status;

            _activityRows.Clear();
            foreach (var row in d2.Events.Select(ToActivityRow)
                         .Concat(d2.Findings.Select(ToActivityRow))
                         .Concat(d3.Reports.Select(ToActivityRow))
                         .OrderByDescending(x => x.SortTimestampUtc)
                         .Take(MaximumEvents + MaximumFindings + MaximumReports))
                _activityRows.Add(row);

            EmptyState.Visibility = _activityRows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            LastRefresh.Text = $"Dernière lecture : {DateTimeOffset.Now:HH:mm:ss}";

            var errors = new[] { d2.Error, d3.Error }.Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
            ActivityStatus.Text = errors.Length == 0
                ? $"Lecture terminée · {_activityRows.Count:N0} activité(s) affichée(s)"
                : $"Lecture partielle · {string.Join(" · ", errors)}";
        }
        catch (Exception ex)
        {
            ActivityStatus.Text = $"Lecture impossible : {ShortError(ex)}";
        }
        finally
        {
            RefreshButton.IsEnabled = true;
            _isRefreshing = false;
        }
    }

    private static async Task<D2Snapshot> LoadD2Async()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelCore", "Demon2", "events.sqlite");
        if (!File.Exists(path)) return new([], [], "Base locale D2 absente", "events.sqlite absent");

        try
        {
            await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = path,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            }.ToString());
            await connection.OpenAsync();
            var since = DateTimeOffset.UtcNow.Subtract(EventLookback);
            var events = await ReadPayloadRowsAsync<CanonicalEvent>(connection,
                "SELECT payload_json FROM events WHERE timestamp_utc >= $since ORDER BY timestamp_utc DESC LIMIT $limit",
                D2JsonOptions, ("$since", since.ToUniversalTime().ToString("O")), ("$limit", MaximumEvents));
            var findings = await ReadPayloadRowsAsync<ThreatFinding>(connection,
                "SELECT payload_json FROM findings WHERE expires_utc > $now ORDER BY timestamp_utc DESC LIMIT $limit",
                D2JsonOptions, ("$now", DateTimeOffset.UtcNow.ToString("O")), ("$limit", MaximumFindings));
            return new(events, findings, $"Base lue · {events.Count:N0} événement(s), {findings.Count:N0} signalement(s)", null);
        }
        catch (Exception ex)
        {
            return new([], [], "Lecture D2 indisponible", ShortError(ex));
        }
    }

    private static async Task<D3Snapshot> LoadD3Async()
    {
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SentinelCore", "Demon3", "reports");
        var database = Path.Combine(directory, "decision-history.sqlite3");
        if (!File.Exists(database)) return new([], "Aucun historique D3 dans la base locale", null);

        try
        {
            await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = database,
                Mode = SqliteOpenMode.ReadOnly,
                Pooling = false
            }.ToString());
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT report_json FROM reports ORDER BY created_at_utc DESC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", MaximumReports);
            var reports = new List<RiskReport>();
            await using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                try
                {
                    if (JsonSerializer.Deserialize<RiskReport>(reader.GetString(0), D3JsonOptions) is { } report)
                        reports.Add(report);
                }
                catch (JsonException) { }
            }
            return new(reports, $"Base lue · {reports.Count:N0} rapport(s)", null);
        }
        catch (Exception ex)
        {
            return new([], "Lecture D3 indisponible", ShortError(ex));
        }
    }

    private static ActivityRow ToActivityRow(CanonicalEvent item)
    {
        var image = string.IsNullOrWhiteSpace(item.ImagePath) ? null : Path.GetFileName(item.ImagePath);
        var details = string.Join(" · ", new[]
        {
            image,
            item.TargetPath,
            item.RemoteHost is null ? null : item.RemotePort is null ? item.RemoteHost : $"{item.RemoteHost}:{item.RemotePort}",
            item.Source
        }.Where(x => !string.IsNullOrWhiteSpace(x)));
        return new(item.TimestampUtc, item.TimestampUtc.ToLocalTime().ToString("dd/MM HH:mm:ss"), "D2",
            item.EventType.ToString(), "ÉVÉNEMENT", details.Length == 0 ? item.EventId : details,
            item.Fields?.GetValueOrDefault("correlationId") ?? string.Empty);
    }

    private static ActivityRow ToActivityRow(ThreatFinding item)
        => new(item.LastSeenUtc, item.LastSeenUtc.ToLocalTime().ToString("dd/MM HH:mm:ss"), "D2",
            item.RuleId, item.Severity.ToString().ToUpperInvariant(), item.Summary, item.CorrelationId);

    private static ActivityRow ToActivityRow(RiskReport item)
        => new(item.CreatedAtUtc, item.CreatedAtUtc.ToLocalTime().ToString("dd/MM HH:mm:ss"), "D3",
            item.Decision.Decision.ToString(), item.Decision.Risk.ToString(), item.Decision.Explanation,
            item.Decision.CorrelationId);

    private static string ShortError(Exception exception)
    {
        var message = exception.Message.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return message.Length <= 140 ? message : message[..137] + "…";
    }

    private static async Task<List<T>> ReadPayloadRowsAsync<T>(SqliteConnection connection, string sql,
        JsonSerializerOptions options, params (string Name, object Value)[] parameters)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        var values = new List<T>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            try
            {
                if (JsonSerializer.Deserialize<T>(reader.GetString(0), options) is { } item)
                    values.Add(item);
            }
            catch (JsonException) { }
        }
        return values;
    }

    private sealed record D2Snapshot(IReadOnlyList<CanonicalEvent> Events, IReadOnlyList<ThreatFinding> Findings,
        string Status, string? Error);
    private sealed record D3Snapshot(IReadOnlyList<RiskReport> Reports, string Status, string? Error);

    public sealed record ActivityRow(DateTimeOffset SortTimestampUtc, string Time, string Daemon,
        string Kind, string Severity, string Summary, string CorrelationId);
}

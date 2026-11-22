using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Input;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using SentinelCore.Demon1.Learning.Controller;
using SentinelCore.Demon3.Core.AI;
using SentinelCore.Demon3.Core.Notifications;
using SentinelCore.Demon3.Core.Reports;
using Path = System.IO.Path;
using MessageBox = System.Windows.MessageBox;
using Brushes = System.Windows.Media.Brushes;
using Color = System.Windows.Media.Color;
using Cursors = System.Windows.Input.Cursors;
using Brush = System.Windows.Media.Brush;
using Application = System.Windows.Application;

namespace SentinelCore.ControlCenter;

public partial class MainWindow : Window
{
    private static readonly HttpClient LocalHttp = new() { Timeout = TimeSpan.FromSeconds(3) };
    private readonly ObservableCollection<string> _logs = [];
    private readonly Dictionary<string, Process> _processes = new(StringComparer.Ordinal);
    private readonly AuthStore _auth;
    private Demon1LearningControl? _d1Control;
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(2) };
    private string? _workspaceRoot;
    private string _selectedAiModel = OllamaAdvisorOptions.Default.Model;
    private string[] _availableAiModels = [];
    private DateTimeOffset? _ollamaInferenceVerifiedAtUtc;
    private bool _defenderQuickScanEnabled;
    private bool _isBusy;
    private bool _settingsLoaded;
    private bool _guardListenerReady;
    private bool _d2GuardAcknowledged;
    private DateTimeOffset? _lastD2GuardAcknowledgementUtc;
    private bool _autoStartAtLogon;
    private bool _keepDaemonsRunningOnClose;
    private readonly bool _startProtectionAfterAuth;
    private readonly TelegramAlertSettingsStore _telegramSettingsStore = new();

    public MainWindow(AuthStore auth, bool startProtectionAfterAuth = false)
    {
        _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        _startProtectionAfterAuth = startProtectionAfterAuth;
        InitializeComponent();
        FitInitialWindowToWorkArea();
        SizeChanged += (_, _) => ApplyResponsiveLayout();
        Loaded += (_, _) => ApplyResponsiveLayout();
        var settings = LoadSettings();
        _workspaceRoot = settings?.WorkspaceRoot;
        if (!string.IsNullOrWhiteSpace(settings?.AiModel) && IsValidModelName(settings.AiModel))
            _selectedAiModel = settings.AiModel;
        _defenderQuickScanEnabled = settings?.DefenderQuickScanEnabled == true;
        _autoStartAtLogon = settings?.AutoStartAtLogon == true;
        _keepDaemonsRunningOnClose = settings?.KeepDaemonsRunningOnClose == true;
        AiModelSelector.Text = _selectedAiModel;
        DefenderScanToggle.IsChecked = _defenderQuickScanEnabled;
        AutoStartToggle.IsChecked = _autoStartAtLogon;
        KeepRunningToggle.IsChecked = _keepDaemonsRunningOnClose;
        var telegramSettings = _telegramSettingsStore.Load();
        TelegramAlertsToggle.IsChecked = telegramSettings?.Enabled == true;
        TelegramChatIdBox.Text = telegramSettings?.ChatId ?? string.Empty;
        TelegramAlertStatus.Text = telegramSettings is null
            ? "Non configuré. Le Bot API exige un jeton de bot et un chat ID."
            : telegramSettings.Enabled ? "Configuration chiffrée enregistrée pour ce compte Windows."
            : "Configuration enregistrée, alertes désactivées.";
        ConfiguredModelText.Text = $"Modèle D3 : {_selectedAiModel}";
        _settingsLoaded = true;
        LogList.ItemsSource = _logs;
        _workspaceRoot ??= DiscoverWorkspaceRoot();
        UpdateWorkspaceLabel();
        _refreshTimer.Tick += async (_, _) => { RefreshProcessCards(); await RefreshOllamaAsync(); };
        _refreshTimer.Start();
        Loaded += async (_, _) =>
        {
            Log("Centre de contrôle initialisé après authentification propriétaire.");
            await RefreshReportsAsync();
            await RefreshOllamaAsync();
            if (_startProtectionAfterAuth)
            {
                Log("Session Windows : authentification réussie; démarrage automatique de D2 et D3 demandé.");
                await StartStackAsync();
            }
        };
        Closing += OnWindowClosing;
    }

    private void FitInitialWindowToWorkArea()
    {
        var workArea = SystemParameters.WorkArea;
        if (workArea.Width < 400 || workArea.Height < 300) return;

        MinWidth = Math.Min(840, Math.Max(300, workArea.Width - 24));
        MinHeight = Math.Min(600, Math.Max(240, workArea.Height - 24));
        Width = Math.Min(1500, Math.Max(MinWidth, workArea.Width * 0.94));
        Height = Math.Min(980, Math.Max(MinHeight, workArea.Height * 0.94));
        Left = workArea.Left + Math.Max(0, (workArea.Width - Width) / 2);
        Top = workArea.Top + Math.Max(0, (workArea.Height - Height) / 2);
    }

    private void ApplyResponsiveLayout()
    {
        if (!IsInitialized || ActualWidth <= 0 || ActualHeight <= 0) return;
        var width = ActualWidth;
        var compact = width < 1260;
        var contentWidth = Math.Max(0, width - (compact ? 72 : 248));
        var veryCompact = contentWidth < 680;
        var tiny = contentWidth < 500;

        ShellGrid.ColumnDefinitions[0].Width = new GridLength(compact ? 72 : 248);
        SidebarDockPanel.Margin = compact ? new Thickness(8, 16, 8, 12) : new Thickness(22, 24, 18, 18);
        SidebarBranding.Margin = compact ? new Thickness(0, 0, 0, 22) : new Thickness(0, 0, 0, 32);
        SidebarBranding.HorizontalAlignment = compact ? System.Windows.HorizontalAlignment.Center : System.Windows.HorizontalAlignment.Stretch;
        SidebarBrandIcon.Width = compact ? 40 : 42;
        SidebarBrandIcon.Height = compact ? 40 : 42;
        SidebarBrandIcon.Margin = compact ? new Thickness(0) : new Thickness(0, 0, 12, 0);
        SidebarBrandName.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        SidebarWorkspaceLabel.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        SidebarFooter.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        var navLabels = new[] { NavOverviewLabel, NavD1Label, NavActivitiesLabel, NavAiLabel, NavConfigurationLabel };
        foreach (var label in navLabels) label.Visibility = compact ? Visibility.Collapsed : Visibility.Visible;
        var navButtons = new[] { NavOverview, NavD1, NavActivities, NavAi, NavConfiguration };
        foreach (var button in navButtons)
        {
            button.HorizontalContentAlignment = compact ? System.Windows.HorizontalAlignment.Center : System.Windows.HorizontalAlignment.Stretch;
            button.Padding = compact ? new Thickness(4, 10, 4, 10) : new Thickness(12, 11, 12, 11);
        }
        var navIcons = new[] { NavOverviewIcon, NavD1Icon, NavActivitiesIcon, NavAiIcon, NavConfigurationIcon };
        foreach (var icon in navIcons) icon.Margin = compact ? new Thickness(0) : new Thickness(0, 0, 10, 0);
        HeaderGrid.Margin = compact ? new Thickness(14, 0, 14, 0) : new Thickness(30, 0, 30, 0);
        PageTitle.FontSize = compact ? 17 : 22;
        PageTitle.TextTrimming = TextTrimming.CharacterEllipsis;
        OverviewContent.Margin = compact ? new Thickness(14, 16, 14, 18) : new Thickness(30, 24, 30, 30);
        LogPanelGrid.Margin = compact ? new Thickness(12, 8, 12, 8) : new Thickness(30, 14, 30, 14);
        MainContentGrid.RowDefinitions[0].Height = new GridLength(veryCompact ? 58 : 76);
        MainContentGrid.RowDefinitions[2].Height = new GridLength(Math.Clamp(ActualHeight * 0.19, ActualHeight < 520 ? 76 : 96, 190));
        LogList.FontSize = ActualHeight < 760 ? 9 : 10;

        MetricsGrid.Columns = contentWidth < 620 ? 1 : contentWidth < 1220 ? 2 : 4;
        DaemonCardsGrid.Columns = contentWidth < 720 ? 1 : contentWidth < 1180 ? 2 : 3;
        ApplyResponsiveReportColumns(contentWidth);
        var stackReports = contentWidth < 1080;
        ReportsAiGrid.ColumnDefinitions[0].Width = new GridLength(1, GridUnitType.Star);
        ReportsAiGrid.ColumnDefinitions[1].Width = stackReports ? new GridLength(0) : new GridLength(0.9, GridUnitType.Star);
        Grid.SetRow(AiPanel, stackReports ? 1 : 0);
        Grid.SetColumn(AiPanel, stackReports ? 0 : 1);
        ReportsPanel.Margin = stackReports ? new Thickness(0, 0, 0, 12) : new Thickness(0, 0, 12, 0);
        OverallStatusPill.Visibility = veryCompact ? Visibility.Collapsed : Visibility.Visible;
        HeaderStartButton.Content = tiny ? "▶" : compact ? "Démarrer" : "Démarrer la protection";
        HeaderStopButton.Content = tiny ? "■" : "Arrêter";
        HeaderStartButton.Padding = compact ? new Thickness(10, 8, 10, 8) : new Thickness(18, 11, 18, 11);
        HeaderStopButton.Padding = compact ? new Thickness(10, 8, 10, 8) : new Thickness(18, 11, 18, 11);
        HeaderStartButton.Margin = tiny ? new Thickness(0, 0, 5, 0) : new Thickness(0, 0, 8, 0);
        AiModelSelector.Width = Math.Clamp(contentWidth * 0.2, 110, 180);
        D1PageHeader.Margin = compact ? new Thickness(14, 14, 14, 10) : new Thickness(30, 20, 30, 14);
        D1Host.Margin = compact ? new Thickness(12, 0, 12, 12) : new Thickness(30, 0, 30, 24);
    }

    private void ApplyResponsiveReportColumns(double contentWidth)
    {
        if (ReportsGrid.Columns.Count < 4) return;

        var (time, risk, decision) = contentWidth switch
        {
            < 450 => (72d, 54d, 86d),
            < 700 => (92d, 66d, 116d),
            < 1000 => (112d, 76d, 145d),
            _ => (135d, 100d, 185d)
        };

        ReportsGrid.Columns[0].Width = new DataGridLength(time);
        ReportsGrid.Columns[1].Width = new DataGridLength(risk);
        ReportsGrid.Columns[2].Width = new DataGridLength(decision);
        ReportsGrid.Columns[3].Width = new DataGridLength(1, DataGridLengthUnitType.Star);
    }

    private async void Build_Click(object sender, RoutedEventArgs e)
    {
        if (_isBusy) return;
        if (!EnsureWorkspace()) return;
        SetBusy(true);
        try
        {
            foreach (var solution in SolutionPaths())
            {
                Log($"Construction : {Path.GetFileName(solution)}");
                var code = await RunCommandAsync("dotnet", ["build", solution, "--configuration", "Release", "--nologo", "-m:1", "-p:NuGetAudit=false"], _workspaceRoot!);
                if (code != 0) { Log($"ÉCHEC : {Path.GetFileName(solution)} (code {code}). Consulte le journal."); return; }
            }
            Log("Construction terminée pour D1, D2, D3 et le Centre de contrôle.");
        }
        catch (Exception ex) { Log("Erreur de construction : " + ex.Message); }
        finally { SetBusy(false); }
    }

    private async void StartStack_Click(object sender, RoutedEventArgs e) => await StartStackAsync();

    private async Task StartStackAsync()
    {
        if (_isBusy || !EnsureWorkspace()) return;
        SetBusy(true);
        try
        {
            if (!AllBinariesExist())
            {
                Log("Certains modules ne sont pas encore construits; construction avant démarrage.");
                foreach (var solution in SolutionPaths())
                {
                    var code = await RunCommandAsync("dotnet", ["build", solution, "--configuration", "Release", "--nologo", "-m:1", "-p:NuGetAudit=false"], _workspaceRoot!);
                    if (code != 0) { Log($"Construction échouée : {Path.GetFileName(solution)} (code {code})."); return; }
                }
            }
            StartD3();
            await Task.Delay(1500);
            StartD2();
            await Task.Delay(700);
            EnsureD1Control();
            ShowPage("D1");
            Log("D1 est intégré au centre. Sa collecte reste arrêtée jusqu’à une authentification et une confirmation depuis l’écran D1.");
        }
        catch (Exception ex) { Log("Démarrage incomplet : " + ex.Message); }
        finally { SetBusy(false); RefreshProcessCards(); }
    }

    private async void StopStack_Click(object sender, RoutedEventArgs e) => await StopAllAsync(confirm: true);
    private void StartD1_Click(object sender, RoutedEventArgs e) => NavigateD1_Click(sender, e);
    private async void StopD1_Click(object sender, RoutedEventArgs e) => await StopD1Async();
    private void StartD2_Click(object sender, RoutedEventArgs e) { try { StartD2(); } catch (Exception ex) { Log("D2 : " + ex.Message); } }
    private void StartD3_Click(object sender, RoutedEventArgs e) { try { StartD3(); } catch (Exception ex) { Log("D3 : " + ex.Message); } }
    private async void StopD2_Click(object sender, RoutedEventArgs e) => await StopProcessAsync("D2");
    private async void StopD3_Click(object sender, RoutedEventArgs e) => await StopProcessAsync("D3");
    private async void RefreshReports_Click(object sender, RoutedEventArgs e) => await RefreshReportsAsync();
    private async void CheckOllama_Click(object sender, RoutedEventArgs e) => await RefreshOllamaAsync(logResult: true);

    private void NavigateOverview_Click(object sender, RoutedEventArgs e) => ShowPage("overview");
    private void NavigateActivities_Click(object sender, RoutedEventArgs e)
    {
        ShowPage("activities");
        _ = ActivityPage.RefreshAsync();
    }
    private void NavigateD1_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            EnsureD1Control();
            ShowPage("D1");
            RefreshProcessCards();
        }
        catch (Exception ex)
        {
            Log("D1 intégré indisponible : " + ex.Message);
            MessageBox.Show("Impossible d’ouvrir le module D1 intégré : " + ex.Message, Title,
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    private void NavigateAi_Click(object sender, RoutedEventArgs e)
    {
        ShowPage("overview");
        Dispatcher.BeginInvoke(() => AiPanel.BringIntoView(), DispatcherPriority.Loaded);
    }
    private void NavigateConfiguration_Click(object sender, RoutedEventArgs e)
    {
        ShowPage("overview");
        Dispatcher.BeginInvoke(() => ConfigurationPanel.BringIntoView(), DispatcherPriority.Loaded);
    }

    private void ShowPage(string page)
    {
        OverviewPage.Visibility = page == "overview" ? Visibility.Visible : Visibility.Collapsed;
        D1Page.Visibility = page == "D1" ? Visibility.Visible : Visibility.Collapsed;
        ActivityPage.Visibility = page == "activities" ? Visibility.Visible : Visibility.Collapsed;
        PageTitle.Text = page switch
        {
            "D1" => "Apprentissage & identité · Démon 1",
            "activities" => "Activités des démons 2 et 3",
            _ => "Vue d’ensemble"
        };
        NavOverview.Background = page == "overview" ? new SolidColorBrush(Color.FromRgb(25, 53, 67)) : Brushes.Transparent;
        NavD1.Background = page == "D1" ? new SolidColorBrush(Color.FromRgb(25, 53, 67)) : Brushes.Transparent;
        NavActivities.Background = page == "activities" ? new SolidColorBrush(Color.FromRgb(25, 53, 67)) : Brushes.Transparent;
        NavAi.Background = Brushes.Transparent;
        NavConfiguration.Background = Brushes.Transparent;
    }

    private void EnsureD1Control()
    {
        if (_d1Control is not null) return;
        if (!EnsureWorkspace()) throw new InvalidOperationException("Dossier du projet non configuré.");
        var executable = Path.Combine(AppContext.BaseDirectory, "SentinelCore.Demon1.Learning.Controller.exe");
        if (!File.Exists(executable)) executable = Path.Combine(_workspaceRoot!, "Demon 1", "Mode_Apprentissage", "src",
            "SentinelCore.Demon1.Learning.Controller", "bin", "Release", "net10.0-windows10.0.19041.0",
            "SentinelCore.Demon1.Learning.Controller.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("Construis le contrôleur D1 avant de l’intégrer au centre.", executable);
        var control = new Demon1LearningControl(_auth, executable);
        control.SetDialogOwner(new WindowHandleOwner(new System.Windows.Interop.WindowInteropHelper(this).Handle));
        _d1Control = control;
        D1Host.Child = control;
        Log("Interface D1 intégrée. Le collecteur n’est pas démarré automatiquement.");
    }

    private void StartD1BackgroundBroker()
    {
        var executable = ResolveD1ControllerExecutable();
        var result = Demon1BackgroundBrokerLauncher.Start(_auth, executable, _d1Control?.SelectedProfileId ?? "PROFIL_1");
        switch (result)
        {
            case BackgroundBrokerStartResult.Started:
                Log("Pont D1 d’arrière-plan lancé : demandes d’identité/contexte D3 disponibles après fermeture du Centre.");
                break;
            case BackgroundBrokerStartResult.AlreadyRunning:
                Log("Pont D1 d’arrière-plan déjà actif.");
                break;
            default:
                Log($"Pont D1 d’arrière-plan non lancé ({result}); les demandes D1 ne seront pas traitées après fermeture.");
                break;
        }
    }

    private string ResolveD1ControllerExecutable()
    {
        var executable = Path.Combine(AppContext.BaseDirectory, "SentinelCore.Demon1.Learning.Controller.exe");
        var workspaceRoot = _workspaceRoot ?? DiscoverWorkspaceRoot();
        if (!File.Exists(executable) && !string.IsNullOrWhiteSpace(workspaceRoot))
            executable = Path.Combine(workspaceRoot, "Demon 1", "Mode_Apprentissage", "src",
                "SentinelCore.Demon1.Learning.Controller", "bin", "Release", "net10.0-windows10.0.19041.0",
                "SentinelCore.Demon1.Learning.Controller.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("L’exécutable du contrôleur D1 est introuvable.", executable);
        return executable;
    }

    private sealed class WindowHandleOwner(IntPtr handle) : System.Windows.Forms.IWin32Window
    {
        public IntPtr Handle { get; } = handle;
    }

    private async void TestOllama_Click(object sender, RoutedEventArgs e)
    {
        var modelOptions = OllamaAdvisorOptions.Default with { Model = _selectedAiModel };
        TestOllamaButton.IsEnabled = false;
        AiSummary.Text = "Test en cours…";
        AiSummary.Foreground = (Brush)FindResource("AmberBrush");
        AiStatus.Text = $"Appel local à {modelOptions.Model}";
        var timer = Stopwatch.StartNew();
        try
        {
            var schema = new
            {
                type = "object",
                properties = new
                {
                    status = new { type = "string", @enum = new[] { "OK" } },
                    confidence = new { type = "number" }
                },
                required = new[] { "status", "confidence" },
                additionalProperties = false
            };
            var body = new
            {
                model = modelOptions.Model,
                messages = new[] { new { role = "user", content = "Retourne uniquement un objet JSON conforme au schéma : status vaut OK et confidence vaut 1." } },
                stream = false,
                format = schema,
                options = new { temperature = 0, num_ctx = modelOptions.ContextWindow, num_predict = 32, num_gpu = 0 },
                keep_alive = "30s"
            };
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(Math.Max(120, modelOptions.Timeout.TotalSeconds)) };
            using var content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var response = await client.PostAsync("http://127.0.0.1:11434/api/chat", content);
            response.EnsureSuccessStatusCode();
            using var reply = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            var text = reply.RootElement.GetProperty("message").GetProperty("content").GetString();
            using var structured = JsonDocument.Parse(text ?? "{}");
            var root = structured.RootElement;
            var valid = root.ValueKind == JsonValueKind.Object
                && root.TryGetProperty("status", out var status) && status.GetString() == "OK"
                && root.TryGetProperty("confidence", out var confidence) && confidence.TryGetDouble(out var score)
                && double.IsFinite(score) && score is >= 0 and <= 1;
            timer.Stop();
            if (!valid) throw new InvalidDataException("La réponse du modèle ne respecte pas le schéma de test.");
            _ollamaInferenceVerifiedAtUtc = DateTimeOffset.UtcNow;
            AiSummary.Text = "Inférence validée";
            AiSummary.Foreground = (Brush)FindResource("AccentBrush");
            AiStatus.Text = $"JSON structuré · {timer.Elapsed.TotalSeconds:F1} s";
            OllamaDetail.Text = $"{modelOptions.Model} a répondu sur l’API locale en {timer.Elapsed.TotalSeconds:F1} s avec un JSON valide au contexte de {modelOptions.ContextWindow:N0} jetons. Ce test vérifie le modèle et le format de sortie; il ne mesure pas encore une décision de sécurité complète.";
            Log($"Test Ollama réussi : {modelOptions.Model}, contexte {modelOptions.ContextWindow}, JSON valide, {timer.Elapsed.TotalSeconds:F1} s.");
        }
        catch (Exception ex)
        {
            timer.Stop();
            _ollamaInferenceVerifiedAtUtc = null;
            AiSummary.Text = "Inférence indisponible";
            AiSummary.Foreground = (Brush)FindResource("AmberBrush");
            AiStatus.Text = "Échec de la sonde locale";
            OllamaDetail.Text = "Ollama n’a pas fourni une réponse structurée valide. D3 doit rester en mode dégradé. Détail : " + ex.Message;
            Log("Test d’inférence Ollama échoué : " + ex.Message);
        }
        finally { TestOllamaButton.IsEnabled = true; }
    }

    private void StartD2()
    {
        if (!EnsureWorkspace()) return;
        var path = Path.Combine(_workspaceRoot!, "Demon 2", "src", "SentinelCore.Demon2.Service", "bin", "Release", "net10.0", "SentinelCore.Demon2.Service.exe");
        StartConsoleProcess("D2", path, []);
    }

    private void StartD3()
    {
        if (!EnsureWorkspace()) return;
        if (!IsValidModelName(_selectedAiModel)) throw new InvalidOperationException("Le nom du modèle Ollama est invalide.");
        var path = Path.Combine(_workspaceRoot!, "Demon 3", "DEMON 3", "Demon3-Starter", "src", "SentinelCore.Demon3.Cli", "bin", "Release", "net10.0", "SentinelCore.Demon3.Cli.exe");
        var args = new List<string> { "--serve", "--model", _selectedAiModel };
        if (_defenderQuickScanEnabled) args.Add("--enable-defender-scan");
        StartConsoleProcess("D3", path, args);
    }

    private void StartConsoleProcess(string key, string exe, IReadOnlyList<string> args)
    {
        if (_processes.TryGetValue(key, out var old) && !old.HasExited) { Log($"{key} est déjà actif."); return; }
        if (IsExternalProcessRunning(key)) { Log($"{key} est déjà actif hors du centre; aucun doublon n’a été lancé."); RefreshProcessCards(); return; }
        if (!File.Exists(exe)) throw new FileNotFoundException($"Exécutable introuvable : {exe}. Construis d’abord les modules.");
        var start = new ProcessStartInfo(exe)
        {
            WorkingDirectory = _workspaceRoot!, UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true
        };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        var process = new Process { StartInfo = start, EnableRaisingEvents = true };
        if (!process.Start()) throw new InvalidOperationException($"Windows n’a pas lancé {key}.");
        _processes[key] = process;
        process.OutputDataReceived += (_, data) => { if (data.Data is not null) ObserveDaemonOutput(key, data.Data, isError: false); };
        process.ErrorDataReceived += (_, data) => { if (data.Data is not null) ObserveDaemonOutput(key, data.Data, isError: true); };
        process.Exited += (_, _) => Dispatcher.Invoke(() => { Log($"{key} arrêté (code {SafeExitCode(process)})."); RefreshProcessCards(); });
        process.BeginOutputReadLine(); process.BeginErrorReadLine();
        Log($"{key} lancé : {Path.GetFileName(exe)} {string.Join(' ', args)}");
        RefreshProcessCards();
    }

    private async Task StopAllAsync(bool confirm)
    {
        if (confirm && _processes.Values.Any(p => IsRunning(p))
            && MessageBox.Show("Arrêter les processus SentinelCore lancés par ce centre ? D1 peut demander confirmation si une collecte est active.", "Arrêter SentinelCore", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        await StopD1Async();
        if (IsRunning("D1"))
        {
            Log("D2 et D3 restent actifs tant que l’interface D1 n’a pas confirmé sa fermeture.");
            RefreshProcessCards();
            return;
        }
        await StopProcessAsync("D2");
        await StopProcessAsync("D3");
        RefreshProcessCards();
    }

    private async Task StopD1Async()
    {
        if (Demon1BackgroundBrokerLauncher.IsRunning())
        {
            if (Demon1BackgroundBrokerLauncher.Stop(_auth))
            {
                var deadline = DateTimeOffset.UtcNow.AddSeconds(5);
                while (Demon1BackgroundBrokerLauncher.IsRunning() && DateTimeOffset.UtcNow < deadline)
                    await Task.Delay(100);
                Log(Demon1BackgroundBrokerLauncher.IsRunning()
                    ? "Arrêt du pont D1 demandé; son processus ne s’est pas confirmé arrêté dans les 5 secondes."
                    : "Pont D1 d’arrière-plan arrêté.");
            }
            else Log("Arrêt du pont D1 refusé : authentification propriétaire absente.");
        }
        if (_d1Control?.IsLearningActive == true)
        {
            _d1Control.StopLearningSafely();
            Log("Collecte D1 arrêtée depuis le centre; les périodes enregistrées sont conservées.");
            RefreshProcessCards();
            return;
        }
        if (!_processes.TryGetValue("D1", out var process) || !IsRunning(process))
        {
            Log(IsExternalProcessRunning("D1") ? "Une ancienne fenêtre autonome D1 est ouverte hors du centre; ferme cette fenêtre pour l’arrêter." : "La collecte D1 est déjà arrêtée.");
            return;
        }
        try
        {
            process.CloseMainWindow();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException) { Log("D1 n’a pas encore fermé sa fenêtre; traite son dialogue puis réessaie."); }
        }
        catch (Exception ex) { Log("Arrêt D1 : " + ex.Message); }
        RefreshProcessCards();
    }

    private async Task StopProcessAsync(string key)
    {
        if (!_processes.TryGetValue(key, out var process) || !IsRunning(process))
        {
            Log(IsExternalProcessRunning(key) ? $"{key} a été lancé hors du centre; arrête-le depuis son terminal." : $"{key} est déjà arrêté.");
            RefreshProcessCards();
            return;
        }
        try
        {
            if (process.StartInfo.RedirectStandardInput)
            {
                await process.StandardInput.WriteLineAsync("STOP");
                await process.StandardInput.FlushAsync();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                try { await process.WaitForExitAsync(timeout.Token); }
                catch (OperationCanceledException) { process.Kill(entireProcessTree: true); }
            }
            else process.Kill(entireProcessTree: true);
            Log($"Arrêt demandé pour {key}.");
        }
        catch (Exception ex) { Log($"Arrêt {key} : {ex.Message}"); }
        RefreshProcessCards();
    }

    private async Task RefreshOllamaAsync(bool logResult = false)
    {
        var configuredModel = _selectedAiModel;
        try
        {
            using var response = await LocalHttp.GetAsync("http://127.0.0.1:11434/api/tags");
            response.EnsureSuccessStatusCode();
            using var json = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            var modelRows = json.RootElement.GetProperty("models").EnumerateArray().ToArray();
            var names = modelRows
                .Where(x => x.TryGetProperty("size", out var size) && size.ValueKind == JsonValueKind.Number && size.GetInt64() > 0)
                .Select(x => x.TryGetProperty("name", out var name) ? name.GetString() : null)
                .Where(name => !OllamaAdvisorOptions.IsCloudModelTag(name))
                .Where(x => x is not null).Cast<string>().ToArray();
            UpdateAiModelChoices(names);
            var selected = names.FirstOrDefault(n => n.Equals(configuredModel, StringComparison.OrdinalIgnoreCase));
            ConfiguredModelText.Text = $"Modèle D3 : {configuredModel}";
            if (selected is not null)
            {
                if (_ollamaInferenceVerifiedAtUtc is { } verifiedAt)
                {
                    AiSummary.Text = "Modèle · testé"; AiSummary.Foreground = (Brush)FindResource("AccentBrush");
                    AiStatus.Text = $"Dernière réponse : {verifiedAt.ToLocalTime():HH:mm:ss}";
                    OllamaDetail.Text = $"Ollama répond sur 127.0.0.1:11434. {configuredModel} a fourni une réponse structurée valide à {verifiedAt.ToLocalTime():HH:mm:ss}.";
                    if (logResult) Log("Ollama répond; la dernière inférence locale a été validée.");
                }
                else
                {
                    AiSummary.Text = "Modèle · installé"; AiSummary.Foreground = (Brush)FindResource("AmberBrush");
                    AiStatus.Text = "Inférence à vérifier"; OllamaDetail.Text = $"Ollama répond sur 127.0.0.1:11434 et {selected} est installé. La présence du modèle ne confirme pas encore qu’il peut répondre sur cette machine.";
                    if (logResult) Log($"Ollama répond et {configuredModel} est installé; l’inférence reste à valider.");
                }
            }
            else
            {
                _ollamaInferenceVerifiedAtUtc = null;
                var localManifestRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ollama", "models", "manifests");
                var localWeightsExist = Directory.Exists(localManifestRoot)
                    && Directory.EnumerateFiles(localManifestRoot, "*", SearchOption.AllDirectories).Any();
                if (names.Length == 0 && localWeightsExist)
                {
                    AiSummary.Text = "Modèles non visibles"; AiSummary.Foreground = (Brush)FindResource("AmberBrush");
                    AiStatus.Text = "Ollama répond, stockage à vérifier";
                    OllamaDetail.Text = $"Des modèles existent dans %USERPROFILE%\\.ollama\\models, mais l’API ne les voit pas. Vérifie que le serveur Ollama utilise ce dossier. Les modèles cloud ne sont pas utilisables par SentinelCore.";
                    if (logResult) Log("Ollama répond mais ne voit pas les manifestes locaux du profil.");
                }
                else
                {
                    AiSummary.Text = "Modèle absent"; AiSummary.Foreground = (Brush)FindResource("AmberBrush");
                    AiStatus.Text = "Ollama actif, modèle local absent";
                    OllamaDetail.Text = "Modèles locaux visibles : " + (names.Length == 0 ? "aucun" : string.Join(", ", names));
                    if (logResult) Log($"Ollama actif, mais {configuredModel} est absent de la liste des modèles locaux.");
                }
            }
        }
        catch (Exception ex)
        {
            UpdateAiModelChoices([]);
            ConfiguredModelText.Text = $"Modèle D3 : {configuredModel}";
            AiSummary.Text = "Hors ligne"; AiSummary.Foreground = (Brush)FindResource("MutedBrush");
            AiStatus.Text = "Ollama non joignable en local"; OllamaDetail.Text = "L’API locale 127.0.0.1:11434 ne répond pas. D3 doit continuer selon son mode dégradé.";
            _ollamaInferenceVerifiedAtUtc = null;
            if (logResult) Log("Ollama local indisponible : " + ex.Message);
        }
    }

    private async Task RefreshReportsAsync()
    {
        try
        {
            var reports = await new RiskReportStore().ReadRecentAsync(50);
            ReportsGrid.ItemsSource = reports.Select(r => new ReportRow(
                r.CreatedAtUtc.ToLocalTime().ToString("dd/MM HH:mm:ss"), r.Decision.Risk.ToString(), r.Decision.Decision.ToString(),
                r.AiAdvice?.Advice?.Summary ?? r.Decision.Explanation)).ToArray();
            ReportCount.Text = reports.Count.ToString();
            LatestRisk.Text = reports.FirstOrDefault()?.Decision.Risk.ToString() ?? "—";
            ReportHint.Text = reports.Count == 0 ? "Aucun rapport enregistré pour le moment." : $"Affichage des {reports.Count} rapports les plus récents depuis le stockage local D3.";
            Log($"Rapports actualisés : {reports.Count}.");
        }
        catch (Exception ex) { ReportHint.Text = "Lecture indisponible : " + ex.Message; Log("Lecture des rapports : " + ex.Message); }
    }

    private void RefreshProcessCards()
    {
        var d1Collector = _d1Control?.IsLearningActive == true;
        var d1PipeReady = _d1Control?.IsConnectedToDemon3 == true;
        var d1 = d1PipeReady || d1Collector || IsExternalProcessRunning("D1");
        var d2 = IsObservedRunning("D2"); var d3 = IsObservedRunning("D3");
        SetCard(D1Status, D1Dot, d1PipeReady || d1Collector,
            d1PipeReady ? d1Collector ? "Connecté à D3 · collecte active" : "Connecté à D3 · collecte arrêtée"
            : d1Collector ? "Collecte active · canal D3 hors ligne" : IsExternalProcessRunning("D1") ? "Ancien contrôleur autonome détecté" : "Contrôleur intégré · D3 non connecté");
        SetCard(D2Status, D2Dot, d2 && _d2GuardAcknowledged,
            !d2 ? "Arrêté" : _d2GuardAcknowledged ? "Canal Guard acquitté" : IsRunning("D2") ? "Actif · transfert Guard en attente" : "Actif hors du centre · transport inconnu");
        SetCard(D3Status, D3Dot, d3 && _guardListenerReady,
            !d3 ? "Arrêté" : _guardListenerReady ? "Listener Guard prêt" : IsRunning("D3") ? "Processus actif · listener non confirmé" : "Actif hors du centre · listener inconnu");
        var active = (d1 ? 1 : 0) + (d2 ? 1 : 0) + (d3 ? 1 : 0);
        ActiveDaemonCount.Text = $"{active} / 3";
        var stackHealthy = d1PipeReady && d2 && d3 && _d2GuardAcknowledged && _guardListenerReady;
        OverallStatus.Text = stackHealthy ? "COMMUNICATION LOCALE CONFIRMÉE" : active == 0 ? "PRÊT À DÉMARRER" : "ÉTAT / TRANSPORT À VÉRIFIER";
        OverallStatus.Foreground = stackHealthy ? (Brush)FindResource("AccentBrush") : (Brush)FindResource("AmberBrush");
        OverallDot.Fill = OverallStatus.Foreground;
        D1StartButton.IsEnabled = true; D2StartButton.IsEnabled = !d2; D3StartButton.IsEnabled = !d3;
        ActivityPage.SetTransportStatus(d1PipeReady, d2 && _d2GuardAcknowledged, d3 && _guardListenerReady,
            _lastD2GuardAcknowledgementUtc);
    }

    private void ObserveDaemonOutput(string daemon, string line, bool isError)
    {
        if (daemon == "D3")
        {
            if (line.Contains("GUARD_PIPE_READY", StringComparison.Ordinal)) _guardListenerReady = true;
            if (line.Contains("GUARD_PIPE_FAILED", StringComparison.Ordinal)) _guardListenerReady = false;
        }
        else if (daemon == "D2")
        {
            if (line.Contains("GUARD_DELIVERY_OK", StringComparison.Ordinal))
            {
                _d2GuardAcknowledged = true;
                _lastD2GuardAcknowledgementUtc = DateTimeOffset.UtcNow;
            }
            if (line.Contains("GUARD_DELIVERY_FAILED", StringComparison.Ordinal)
                || line.Contains("Guard delivery failed", StringComparison.OrdinalIgnoreCase))
                _d2GuardAcknowledged = false;
        }
        Log($"{daemon}{(isError ? " !" : "  ")} {line}");
        Dispatcher.BeginInvoke(RefreshProcessCards);
    }

    private static void SetCard(TextBlock label, Ellipse dot, bool active, string text)
    {
        label.Text = text;
        var brush = (Brush)Application.Current.FindResource(active ? "AccentBrush" : "MutedBrush");
        label.Foreground = brush; dot.Fill = brush;
    }

    private bool IsRunning(string key) => _processes.TryGetValue(key, out var process) && IsRunning(process);
    private bool IsObservedRunning(string key) => IsRunning(key) || IsExternalProcessRunning(key);
    private bool IsExternalProcessRunning(string key)
    {
        var name = key switch
        {
            "D1" => "SentinelCore.Demon1.Learning.Controller",
            "D2" => "SentinelCore.Demon2.Service",
            "D3" => "SentinelCore.Demon3.Cli",
            _ => string.Empty
        };
        if (name.Length == 0) return false;
        var trackedId = _processes.TryGetValue(key, out var tracked) ? tracked.Id : -1;
        foreach (var candidate in Process.GetProcessesByName(name))
        {
            using (candidate)
                if (candidate.Id != trackedId && IsRunning(candidate)) return true;
        }
        return false;
    }
    private static bool IsRunning(Process process) { try { return !process.HasExited; } catch { return false; } }
    private static int SafeExitCode(Process process) { try { return process.ExitCode; } catch { return -1; } }

    private async Task<int> RunCommandAsync(string file, IReadOnlyList<string> args, string workingDirectory)
    {
        var start = new ProcessStartInfo(file) { WorkingDirectory = workingDirectory, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = new Process { StartInfo = start };
        process.OutputDataReceived += (_, data) => { if (data.Data is { Length: > 0 } line) Log(line); };
        process.ErrorDataReceived += (_, data) => { if (data.Data is { Length: > 0 } line) Log("! " + line); };
        if (!process.Start()) return -1;
        process.BeginOutputReadLine(); process.BeginErrorReadLine();
        await process.WaitForExitAsync();
        return process.ExitCode;
    }

    private IEnumerable<string> SolutionPaths()
    {
        yield return Path.Combine(_workspaceRoot!, "Demon 1", "SentinelCore.Demon1.slnx");
        yield return Path.Combine(_workspaceRoot!, "Demon 2", "SentinelCore.Demon2.slnx");
        yield return Path.Combine(_workspaceRoot!, "Demon 3", "DEMON 3", "Demon3-Starter", "SentinelCore.Demon3.slnx");
        yield return Path.Combine(_workspaceRoot!, "Control Center", "SentinelCore.ControlCenter.slnx");
    }

    private bool AllBinariesExist()
    {
        if (!EnsureWorkspace()) return false;
        return File.Exists(Path.Combine(_workspaceRoot!, "Demon 1", "Mode_Apprentissage", "src", "SentinelCore.Demon1.Learning.Controller", "bin", "Release", "net10.0-windows10.0.19041.0", "SentinelCore.Demon1.Learning.Controller.exe"))
            && File.Exists(Path.Combine(_workspaceRoot!, "Demon 2", "src", "SentinelCore.Demon2.Service", "bin", "Release", "net10.0", "SentinelCore.Demon2.Service.exe"))
            && File.Exists(Path.Combine(_workspaceRoot!, "Demon 3", "DEMON 3", "Demon3-Starter", "src", "SentinelCore.Demon3.Cli", "bin", "Release", "net10.0", "SentinelCore.Demon3.Cli.exe"));
    }

    private void ChooseWorkspace_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Sélectionner le dossier SentinelCore", Multiselect = false };
        if (dialog.ShowDialog(this) != true) return;
        var candidate = dialog.FolderName;
        if (!IsWorkspaceRoot(candidate)) { MessageBox.Show("Ce dossier ne contient pas les solutions D1, D2 et D3.", Title, MessageBoxButton.OK, MessageBoxImage.Warning); return; }
        _workspaceRoot = candidate; SaveSettings(); UpdateWorkspaceLabel(); Log("Workspace configuré : " + candidate);
    }

    private bool EnsureWorkspace()
    {
        if (_workspaceRoot is not null && IsWorkspaceRoot(_workspaceRoot)) return true;
        MessageBox.Show("Sélectionne le dossier racine SentinelCore dans Configuration.", Title, MessageBoxButton.OK, MessageBoxImage.Warning);
        return false;
    }

    private void UpdateWorkspaceLabel() => WorkspacePath.Text = _workspaceRoot ?? "Dossier du projet introuvable — sélectionne-le ci-dessous.";
    private void SetBusy(bool value) { _isBusy = value; Cursor = value ? Cursors.Wait : Cursors.Arrow; }

    private void Log(string message)
    {
        Dispatcher.Invoke(() =>
        {
            _logs.Add($"{DateTime.Now:HH:mm:ss}  {message}");
            while (_logs.Count > 250) _logs.RemoveAt(0);
            LogCount.Text = $"  •  {_logs.Count} événements";
            if (LogList.Items.Count > 0) LogList.ScrollIntoView(LogList.Items[^1]);
        });
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e) => _logs.Clear();

    private void OnWindowClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (_keepDaemonsRunningOnClose)
        {
            try { StartD1BackgroundBroker(); }
            catch (Exception ex) { Log("Le pont D1 d’arrière-plan n’a pas démarré : " + ex.Message); }
            Log("Fermeture du Centre : les démons restent actifs; D1 reprend son lien D1↔D3 dans son processus d’arrière-plan.");
            _refreshTimer.Stop();
            return;
        }
        if (_d1Control is not null && !_d1Control.ConfirmHostClosing())
        {
            e.Cancel = true;
            return;
        }
        if (_processes.Values.Any(IsRunning))
        {
            var choice = MessageBox.Show("Des composants sont encore actifs. Arrêter ceux lancés par ce centre avant de quitter ?", Title, MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (choice == MessageBoxResult.Cancel) { e.Cancel = true; return; }
            if (choice == MessageBoxResult.Yes) { e.Cancel = true; _ = StopAllThenCloseAsync(); return; }
        }
        _refreshTimer.Stop();
    }

    private async Task StopAllThenCloseAsync()
    {
        Closing -= OnWindowClosing;
        await StopAllAsync(confirm: false);
        if (_processes.Values.Any(IsRunning))
        {
            Closing += OnWindowClosing;
            Log("Le centre reste ouvert : au moins un démon n’a pas pu être arrêté proprement.");
            return;
        }
        _refreshTimer.Stop();
        Close();
    }

    private static string? DiscoverWorkspaceRoot()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Environment.CurrentDirectory })
            for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
                if (IsWorkspaceRoot(directory.FullName)) return directory.FullName;
        return null;
    }

    private static bool IsWorkspaceRoot(string path)
        => File.Exists(Path.Combine(path, "Demon 1", "SentinelCore.Demon1.slnx"))
            && File.Exists(Path.Combine(path, "Demon 2", "SentinelCore.Demon2.slnx"))
            && File.Exists(Path.Combine(path, "Demon 3", "DEMON 3", "Demon3-Starter", "SentinelCore.Demon3.slnx"));

    private static string ConfigPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "ControlCenter", "settings.json");
    private ControlSettings? LoadSettings()
    {
        try { return JsonSerializer.Deserialize<ControlSettings>(File.ReadAllText(ConfigPath)); }
        catch { return null; }
    }
    private void SaveSettings()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
        File.WriteAllText(ConfigPath, JsonSerializer.Serialize(new ControlSettings(_workspaceRoot, _selectedAiModel, _defenderQuickScanEnabled, _autoStartAtLogon, _keepDaemonsRunningOnClose), new JsonSerializerOptions { WriteIndented = true }));
    }

    private void DefenderScanToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        var enabled = DefenderScanToggle.IsChecked == true;
        if (_defenderQuickScanEnabled == enabled) return;
        _defenderQuickScanEnabled = enabled;
        SaveSettings();
        Log(enabled
            ? "Analyse rapide Defender activée pour le prochain démarrage de D3. Chaque exécution demandera la validation par mot de passe maître."
            : "Analyse rapide Defender désactivée pour le prochain démarrage de D3.");
    }

    private void SaveTelegram_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var settings = ReadTelegramSettings();
            if (!_telegramSettingsStore.Save(settings))
            {
                SetTelegramStatus("Chat ID ou jeton invalide. Vérifie le format des deux valeurs.", success: false);
                return;
            }
            TelegramBotTokenBox.Clear();
            SetTelegramStatus(settings.Enabled
                ? "Alertes activées. D3 les utilisera dès la prochaine alerte admissible."
                : "Configuration enregistrée; les alertes sont désactivées.", success: true);
            Log(settings.Enabled ? "Canal d’alertes Telegram enregistré et protégé localement." : "Alertes Telegram désactivées.");
        }
        catch (Exception ex)
        {
            SetTelegramStatus("Impossible d’enregistrer la configuration Telegram : " + ex.Message, success: false);
            Log("Enregistrement Telegram impossible : " + ex.GetType().Name);
        }
    }

    private async void TestTelegram_Click(object sender, RoutedEventArgs e)
    {
        TelegramDeliveryResult result;
        try
        {
            var settings = ReadTelegramSettings();
            if (!TelegramAlertSettingsStore.IsValidBotToken(settings.BotToken)
                || !TelegramAlertSettingsStore.IsValidChatId(settings.ChatId))
            {
                SetTelegramStatus("Saisis un jeton BotFather et un chat ID valides avant le test.", success: false);
                return;
            }
            if (!_telegramSettingsStore.Save(settings))
            {
                SetTelegramStatus("La configuration Telegram n’a pas pu être protégée.", success: false);
                return;
            }
            TelegramBotTokenBox.Clear();
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
            result = await new TelegramBotApiClient(client).SendTestMessageAsync(settings);
        }
        catch (Exception ex)
        {
            SetTelegramStatus("Test Telegram impossible : " + ex.GetType().Name, success: false);
            Log("Test Telegram impossible : " + ex.GetType().Name);
            return;
        }

        SetTelegramStatus(result.Succeeded
            ? "Message de test envoyé au chat configuré."
            : "Échec du test : " + result.ReasonCode + ". Vérifie le bot, le chat ID et la connexion.", result.Succeeded);
        Log(result.Succeeded ? "Test du canal Telegram réussi." : "Test du canal Telegram échoué : " + result.ReasonCode);
    }

    private void ForgetTelegram_Click(object sender, RoutedEventArgs e)
    {
        if (!_telegramSettingsStore.Delete())
        {
            SetTelegramStatus("Impossible d’effacer le fichier protégé Telegram.", success: false);
            return;
        }
        TelegramAlertsToggle.IsChecked = false;
        TelegramChatIdBox.Clear();
        TelegramBotTokenBox.Clear();
        SetTelegramStatus("Configuration Telegram effacée.", success: true);
        Log("Configuration Telegram effacée.");
    }

    private TelegramAlertSettings ReadTelegramSettings()
    {
        var previous = _telegramSettingsStore.Load();
        var token = string.IsNullOrWhiteSpace(TelegramBotTokenBox.Password)
            ? previous?.BotToken ?? string.Empty
            : TelegramBotTokenBox.Password.Trim();
        return new TelegramAlertSettings(TelegramAlertsToggle.IsChecked == true,
            TelegramChatIdBox.Text.Trim(), token);
    }

    private void SetTelegramStatus(string message, bool success)
    {
        TelegramAlertStatus.Text = message;
        TelegramAlertStatus.Foreground = (Brush)FindResource(success ? "AccentBrush" : "AmberBrush");
    }

    private void AutoStartToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        var enabled = AutoStartToggle.IsChecked == true;
        if (_autoStartAtLogon == enabled) return;
        try
        {
            SetRunAtLogon(enabled);
            _autoStartAtLogon = enabled;
            SaveSettings();
            Log(enabled
                ? "Démarrage à l’ouverture de session activé. Après authentification, D2 et D3 démarreront; D1 demandera toujours son autorisation."
                : "Démarrage à l’ouverture de session désactivé.");
        }
        catch (Exception ex)
        {
            AutoStartToggle.IsChecked = _autoStartAtLogon;
            Log("Impossible de modifier le démarrage de session : " + ex.Message);
            MessageBox.Show("Impossible de configurer le démarrage automatique : " + ex.Message, Title,
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static void SetRunAtLogon(bool enabled)
    {
        const string runKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string valueName = "SentinelCoreControlCenter";
        using var runKey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(runKeyPath, writable: true)
            ?? throw new InvalidOperationException("La clé de démarrage utilisateur Windows est indisponible.");
        if (!enabled)
        {
            runKey.DeleteValue(valueName, throwOnMissingValue: false);
            return;
        }

        var executable = Path.Combine(AppContext.BaseDirectory, "SentinelCore.ControlCenter.exe");
        if (!File.Exists(executable))
            throw new FileNotFoundException("Le Centre doit être publié avant d’activer son démarrage automatique.", executable);
        runKey.SetValue(valueName, $"\"{executable}\" --start-protection-after-auth", Microsoft.Win32.RegistryValueKind.String);
    }

    private void KeepRunningToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (!_settingsLoaded) return;
        var enabled = KeepRunningToggle.IsChecked == true;
        if (_keepDaemonsRunningOnClose == enabled) return;
        _keepDaemonsRunningOnClose = enabled;
        SaveSettings();
        Log(enabled
            ? "Maintien en arrière-plan activé : fermer le Centre laissera les processus démarrés tourner. Le canal D1↔D3 du Centre se déconnectera."
            : "Maintien en arrière-plan désactivé : la fermeture demandera si les processus doivent être arrêtés.");
    }

    private void AiModel_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_settingsLoaded || AiModelSelector.SelectedItem is not string model) return;
        SetSelectedAiModel(model);
    }

    private void AiModel_LostKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
        => SetSelectedAiModel(AiModelSelector.Text);

    private void SetSelectedAiModel(string? model)
    {
        var candidate = model?.Trim();
        if (candidate is null || !IsValidModelName(candidate))
        {
            AiModelSelector.Text = _selectedAiModel;
            Log("Nom de modèle ignoré : seuls les identifiants de modèles Ollama locaux sont acceptés.");
            return;
        }
        if (_selectedAiModel.Equals(candidate, StringComparison.Ordinal)) return;
        _selectedAiModel = candidate;
        ConfiguredModelText.Text = $"Modèle D3 : {_selectedAiModel}";
        _ollamaInferenceVerifiedAtUtc = null;
        SaveSettings();
        Log($"Modèle local configuré : {_selectedAiModel}. Le changement s’appliquera au prochain démarrage de D3.");
        _ = RefreshOllamaAsync();
    }

    private void UpdateAiModelChoices(IEnumerable<string> names)
    {
        var next = names.Where(IsValidModelName).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase).ToArray();
        if (_availableAiModels.SequenceEqual(next, StringComparer.OrdinalIgnoreCase)) return;
        _availableAiModels = next;
        AiModelSelector.Items.Clear();
        foreach (var name in next) AiModelSelector.Items.Add(name);
        AiModelSelector.Text = _selectedAiModel;
    }

    private static bool IsValidModelName(string? model)
        => !string.IsNullOrWhiteSpace(model) && model.Length <= 120
            && !OllamaAdvisorOptions.IsCloudModelTag(model)
            && model.All(c => char.IsAsciiLetterOrDigit(c) && c <= 127 || c is ':' or '_' or '-' or '.' or '/');

    private sealed record ControlSettings(string? WorkspaceRoot, string? AiModel, bool DefenderQuickScanEnabled = false, bool AutoStartAtLogon = false, bool KeepDaemonsRunningOnClose = false);
    private sealed record ReportRow(string Time, string Risk, string Decision, string Summary);
}

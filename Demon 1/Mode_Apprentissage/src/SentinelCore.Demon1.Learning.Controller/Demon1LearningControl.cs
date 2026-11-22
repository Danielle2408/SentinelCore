using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using SentinelCore.Demon1.Learning;
using SentinelCore.Demon1.Validation;
using SentinelCore.Demon1.VisualVerification;

namespace SentinelCore.Demon1.Learning.Controller;

/// <summary>
/// Reusable D1 operator surface. It can be hosted by the standalone WinForms shell or by
/// a WPF WindowsFormsHost. Loading this control never starts collection; that still requires
/// the separate owner authentication and explicit confirmation buttons below.
/// </summary>
public sealed class Demon1LearningControl : UserControl
{
    private const int WmWtsSessionChange = 0x02B1;
    private const uint NotifyForThisSession = 0;
    private readonly AuthStore _auth;
    private readonly string _sid = WindowsIdentity.GetCurrent().User!.Value;
    private readonly string _dataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon1Learning");
    private readonly string _workerExecutablePath;
    private LearningSettings _settings;
    private readonly Label _state = new() { AutoSize = true, Font = new Font("Segoe UI", 12, FontStyle.Bold) };
    private readonly Label _progress = new() { AutoSize = true };
    private readonly Label _measures = new() { AutoSize = true, MaximumSize = new Size(720, 0) };
    private readonly Label _context = new() { AutoSize = true, MaximumSize = new Size(720, 0) };
    private readonly TextBox _log = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Vertical, Dock = DockStyle.Fill };
    private readonly ComboBox _profileSelector = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 150, Height = 36, Margin = new Padding(4) };
    private readonly System.Windows.Forms.Timer _refresh = new() { Interval = 1000 };
    private readonly System.Windows.Forms.Timer _telemetry = new() { Interval = 1000 };
    private readonly System.Windows.Forms.Timer _pipeReconnect = new() { Interval = 5000 };
    private readonly string _sessionId = Process.GetCurrentProcess().SessionId.ToString();
    private InterDaemonPipeClient? _pipeClient;
    private VisualVerificationService? _visualVerifier;
    private DateTimeOffset _lastPublishedContextAt;
    private DateTimeOffset _lastEvaluatedBehaviorAt;
    private DateTimeOffset _nextTelemetryRetryUtc;
    private bool _publishingTelemetry;
    private bool _connectionFailureLogged;
    private bool _pipeConnecting;
    private bool _sessionLockStateKnown;
    private bool _sessionLocked;
    private bool _sessionNotificationsRegistered;
    private IntPtr _registeredSessionHandle;
    private bool _firstVisibleInitializationCompleted;
    private IWin32Window? _dialogOwner;
    private readonly object _visualServiceGate = new();
    private Process? _worker;

    /// <param name="auth">The already authenticated D1 credential store.</param>
    /// <param name="workerExecutablePath">Absolute path to the D1 controller executable that handles --worker.</param>
    public Demon1LearningControl(AuthStore auth, string workerExecutablePath)
    {
        _auth = auth ?? throw new ArgumentNullException(nameof(auth));
        if (string.IsNullOrWhiteSpace(workerExecutablePath)) throw new ArgumentException("Le chemin de l’exécutable D1 est obligatoire.", nameof(workerExecutablePath));
        _workerExecutablePath = Path.GetFullPath(workerExecutablePath);
        _settings = LearningSettings.Load(_dataRoot);
        Text = "SentinelCore — contrôle du mode apprentissage (Démon 1)";
        // Keep the embedded control below the minimum widths commonly required by compact laptop screens.
        MinimumSize = new Size(360, 280);
        Dock = DockStyle.Fill;
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), ColumnCount = 1, RowCount = 5 };
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize)); root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        root.Controls.Add(new Label { Text = "Apprentissage comportemental et contextuel — Démon 1", AutoSize = false, Height = 48, Dock = DockStyle.Fill, Font = new Font("Segoe UI", 16, FontStyle.Bold), AutoEllipsis = true }, 0, 0);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, WrapContents = true, Padding = new Padding(0, 12, 0, 12) };
        buttons.Controls.Add(new Label { Text = "Profil :", AutoSize = true, Padding = new Padding(4, 12, 0, 0) });
        buttons.Controls.Add(_profileSelector);
        RefreshProfiles();
        buttons.Controls.Add(Button("Démarrer avec le mot de passe maître", StartWithPassword, 270));
        buttons.Controls.Add(Button("Arrêter", StopLearning, 100));
        buttons.Controls.Add(Button("Voir la base", ShowDatabase, 120));
        buttons.Controls.Add(Button("Voir habitudes", ShowApplicationHabits, 130));
        buttons.Controls.Add(Button("Enrôler le visage", EnrollFaceAsync, 155));
        buttons.Controls.Add(Button("Tester demande D3 + caméra", SimulateVisualAlertAsync, 220));
        buttons.Controls.Add(Button("Rapports visuels", ShowVisualReports, 145));
        buttons.Controls.Add(Button("Paramètres", ShowSettings, 120));
        buttons.Controls.Add(Button("Changer le mot de passe", ChangePassword, 180));
        root.Controls.Add(buttons, 0, 1);
        var statePanel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
        statePanel.Controls.Add(_state); statePanel.Controls.Add(_progress); statePanel.Controls.Add(_measures); statePanel.Controls.Add(_context);
        root.Controls.Add(statePanel, 0, 2);
        root.Controls.Add(_log, 0, 3);
        root.Controls.Add(new Label { Text = "Aucune collecte ne commence à l’ouverture. Une authentification et une confirmation sont nécessaires à chaque démarrage.", AutoSize = true, ForeColor = Color.DimGray, Padding = new Padding(0, 10, 0, 0) }, 0, 4);
        Controls.Add(root);
        _refresh.Tick += (_, _) => RefreshStatus();
        _telemetry.Tick += async (_, _) =>
        {
            if (!_publishingTelemetry)
            {
                _publishingTelemetry = true;
                try { await PublishLatestContextAsync(); }
                finally { _publishingTelemetry = false; }
            }
        };
        _telemetry.Start();
        _pipeReconnect.Tick += async (_, _) => await ConnectToDemon3Async();
        VisibleChanged += async (_, _) =>
        {
            if (Visible)
            {
                _refresh.Start();
                RefreshStatus();
                if (_firstVisibleInitializationCompleted) return;
                _firstVisibleInitializationCompleted = true;
                _sessionLocked = false; // A visible D1 surface confirms the current desktop is unlocked.
                _sessionLockStateKnown = _sessionNotificationsRegistered;
                if (!_sessionLockStateKnown) Append("État verrouillé/inactif indisponible; D1 transmettra UNKNOWN pour la session.");
            }
            else
            {
                // The hidden page remains connected to D3 and keeps collecting telemetry if its
                // separately authorized worker is active; only the visible status refresh pauses.
                _refresh.Stop();
            }
            if (!Visible || !_firstVisibleInitializationCompleted) return;
            await ConnectToDemon3Async();
        };
        Append("Base locale : " + Path.Combine(_dataRoot, "learning.db"));
        Append("Les mesures sont agrégées; aucun texte tapé n’est enregistré.");
        try
        {
            using var repository = new SqliteLearningProfileRepository(Path.Combine(_dataRoot, "learning.db"), _settings.ContextRetentionDays);
            repository.PruneExpiredHistory(_sid);
        }
        catch (Exception ex) { Append("Purge de l’historique différée : " + ex.Message); }
    }

    protected override void OnSizeChanged(EventArgs e)
    {
        base.OnSizeChanged(e);
        var textWidth = Math.Max(180, ClientSize.Width - 40);
        _state.MaximumSize = new Size(textWidth, 0);
        _progress.MaximumSize = new Size(textWidth, 0);
        _measures.MaximumSize = new Size(textWidth, 0);
        _context.MaximumSize = new Size(textWidth, 0);
    }

    protected override void WndProc(ref Message message)
    {
        if (message.Msg == WmWtsSessionChange
            && WindowsInteractiveSessionContext.TryClassifyLockEvent(message.WParam.ToInt32(), out var locked))
        {
            _sessionLocked = locked;
            _sessionLockStateKnown = true;
        }
        base.WndProc(ref message);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        _registeredSessionHandle = Handle;
        _sessionNotificationsRegistered = WTSRegisterSessionNotification(_registeredSessionHandle, NotifyForThisSession);
        _sessionLockStateKnown = false;
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        if (_sessionNotificationsRegistered && _registeredSessionHandle != IntPtr.Zero)
            WTSUnRegisterSessionNotification(_registeredSessionHandle);
        _sessionNotificationsRegistered = false;
        _registeredSessionHandle = IntPtr.Zero;
        base.OnHandleDestroyed(e);
    }

    /// <summary>
    /// Allows a WPF host to supply its top-level window as the owner for D1 modal dialogs.
    /// Leave null in the standalone WinForms shell; the nearest Form will then be used.
    /// </summary>
    public void SetDialogOwner(IWin32Window? owner) => _dialogOwner = owner;

    /// <summary>Reports whether the separately authorized learning worker is still running.</summary>
    public bool IsLearningActive => IsRunning();

    /// <summary>Reports whether D1 currently has a live, handshaken local channel to D3.</summary>
    public bool IsConnectedToDemon3 => _pipeClient?.IsConnectedToServer == true;
    public string SelectedProfileId => _profileSelector.SelectedItem?.ToString() ?? "PROFIL_1";

    /// <summary>
    /// Must be called by a host before disposing the control during application shutdown.
    /// A Yes answer stops the worker; No leaves the explicitly started worker running in background.
    /// </summary>
    public bool ConfirmHostClosing()
    {
        if (_worker is not { HasExited: false }) return true;
        var choice = MessageBox.Show(DialogOwnerWindow,
            "La collecte est active. Oui : l’arrêter avant de fermer. Non : la laisser continuer en arrière-plan. Annuler : revenir à l’application.",
            Text, MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning);
        if (choice == DialogResult.Cancel) return false;
        if (choice == DialogResult.Yes) StopLearning();
        return true;
    }

    /// <summary>Stops the currently running learning worker without closing the hosted surface.</summary>
    public void StopLearningSafely() => StopLearning();

    private IWin32Window DialogOwnerWindow => _dialogOwner ?? (IWin32Window?)FindForm() ?? this;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _pipeReconnect.Stop();
            _refresh.Stop();
            _telemetry.Stop();
            _pipeReconnect.Dispose();
            _refresh.Dispose();
            _telemetry.Dispose();
            if (_sessionNotificationsRegistered && _registeredSessionHandle != IntPtr.Zero)
                WTSUnRegisterSessionNotification(_registeredSessionHandle);
            _sessionNotificationsRegistered = false;
            _registeredSessionHandle = IntPtr.Zero;
            if (_pipeClient is not null) _ = _pipeClient.DisposeAsync();
            _pipeClient = null;
            _visualVerifier?.Dispose();
            _visualVerifier = null;
            _worker?.Dispose();
            _worker = null;
        }
        base.Dispose(disposing);
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSRegisterSessionNotification(IntPtr windowHandle, uint flags);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSUnRegisterSessionNotification(IntPtr windowHandle);

    private static Button Button(string text, Action action, int width)
    {
        var button = new Button { Text = text, Width = width, Height = 42, Margin = new Padding(4) };
        button.Click += (_, _) => action(); return button;
    }

    private void StartWithPassword()
    {
        if (IsRunning()) { Append("L’apprentissage est déjà actif."); return; }
        using var dialog = new MasterPasswordDialog(isSetup: false);
        if (dialog.ShowDialog(DialogOwnerWindow) != DialogResult.OK || dialog.Password is null) return;
        bool valid;
        try { valid = _auth.VerifyPassword(dialog.Password); }
        catch (Exception ex) { MessageBox.Show(DialogOwnerWindow, "Configuration du mot de passe illisible : " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
        if (!valid) { Append("Mot de passe maître incorrect; aucun démarrage."); MessageBox.Show(DialogOwnerWindow, "Mot de passe incorrect. Aucune collecte n’a démarré.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
        ConfirmAndStart("Mot de passe maître");
    }

    private void ConfirmAndStart(string method)
    {
        if (MessageBox.Show(DialogOwnerWindow, $"Identité confirmée par {method}. Démarrer maintenant l’apprentissage du clavier et de la souris ?", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
        StartWorker();
    }

    private void StartWorker()
    {
        try
        {
            Directory.CreateDirectory(_dataRoot);
            var stopPath = Path.Combine(_dataRoot, "stop.signal"); if (File.Exists(stopPath)) File.Delete(stopPath);
            var ticketPath = Path.Combine(_dataRoot, "auth-ticket-" + Guid.NewGuid().ToString("N") + ".bin");
            var proof = OneTimeAuthorizationTicket.Create(ticketPath, _sid);
            if (!File.Exists(_workerExecutablePath)) throw new FileNotFoundException("L’exécutable contrôleur D1 configuré pour lancer le collecteur est introuvable.", _workerExecutablePath);
            var worker = new Process { StartInfo = new ProcessStartInfo(_workerExecutablePath) { UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden } };
            var profileId = _profileSelector.SelectedItem?.ToString() ?? "PROFIL_1";
            var context = $"{profileId}|LOCAL|DEFAULT_KB|DEFAULT_MOUSE";
            foreach (var argument in new[] { "--worker", "collect", "--db", Path.Combine(_dataRoot, "learning.db"), "--sid", _sid, "--context", context, "--status", Path.Combine(_dataRoot, "status.json"), "--stop", stopPath, "--auth-ticket", ticketPath, "--auth-proof", proof, "--window-seconds", _settings.WindowSeconds.ToString(), "--idle-seconds", _settings.IdleStopSeconds.ToString(), "--context-retention-days", _settings.ContextRetentionDays.ToString(), "--ignore-pid", Environment.ProcessId.ToString() }) worker.StartInfo.ArgumentList.Add(argument);
            if (!worker.Start()) throw new InvalidOperationException("Le collecteur n’a pas démarré.");
            _worker = worker;
            Append($"Collecte démarrée pour {profileId} après authentification et confirmation explicite. Les fenêtres clavier/souris de ce profil sont séparées des autres.");
            RefreshStatus();
        }
        catch (Exception ex) { Append("Échec du démarrage : " + ex.Message); MessageBox.Show(DialogOwnerWindow, ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void StopLearning()
    {
        if (!IsRunning()) { Append("Aucune collecte active."); return; }
        try
        {
            File.WriteAllText(Path.Combine(_dataRoot, "stop.signal"), "stop");
            if (!_worker!.WaitForExit(5000)) { _worker.Kill(entireProcessTree: true); _worker.WaitForExit(3000); }
            Append("Collecte arrêtée; les périodes enregistrées restent dans la base."); RefreshStatus();
        }
        catch (Exception ex) { Append("Erreur à l’arrêt : " + ex.Message); }
    }

    private bool IsRunning() => _worker is { HasExited: false };

    private void RefreshStatus()
    {
        var active = IsRunning(); _state.Text = active ? "ÉTAT : APPRENTISSAGE ACTIF" : "ÉTAT : ARRÊTÉ"; _state.ForeColor = active ? Color.DarkGreen : Color.DimGray;
        var path = Path.Combine(_dataRoot, "status.json"); if (!File.Exists(path)) return;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path)); var json = doc.RootElement;
            _progress.Text = $"Profil : {LearningLabels.State(Value(json, "State"))} | périodes acceptées : {Value(json, "AcceptedWindows")} | jours : {Value(json, "DistinctDays")} | calibration : {Value(json, "CalibrationProgressPercent")}%";
            _measures.Text = "Mesures de la dernière période : " + (json.TryGetProperty("latestMeasures", out var measures) ? string.Join(" · ", measures.EnumerateObject().Select(x => $"{LearningLabels.Feature(x.Name)} : {x.Value}")) : "en attente");
            if (json.TryGetProperty("latestContext", out var context) && context.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                var app = context.TryGetProperty("ApplicationName", out var appName) ? appName.GetString() : "—";
                var seconds = context.TryGetProperty("ForegroundSeconds", out var duration) ? duration.GetInt32() : 0;
                var hour = context.TryGetProperty("LocalHour", out var localHour) ? localHour.GetInt32() : 0;
                var cpu = context.TryGetProperty("ForegroundCpuPercent", out var cpuValue) && cpuValue.ValueKind == System.Text.Json.JsonValueKind.Number ? $"{cpuValue.GetDouble():0.0}%" : "indisponible";
                var memory = context.TryGetProperty("ForegroundMemoryMiB", out var memoryValue) && memoryValue.ValueKind == System.Text.Json.JsonValueKind.Number ? $"{memoryValue.GetDouble():0} Mio" : "indisponible";
                _context.Text = $"Contexte appris : {app}, ~{seconds}s au premier plan vers {hour}h; CPU du programme {cpu}; mémoire {memory}. Nom de fenêtre et contenu non collectés.";
            }
            var note = Value(json, "note"); if (!string.IsNullOrWhiteSpace(note)) _measures.Text += "\nNote : " + note;
        }
        catch (IOException) { }
        catch (System.Text.Json.JsonException) { }
    }

    private static string Value(System.Text.Json.JsonElement json, string name) => json.TryGetProperty(name, out var value) ? value.ToString() : "—";

    private void ShowDatabase()
    {
        try
        {
            using var repository = new SqliteLearningProfileRepository(Path.Combine(_dataRoot, "learning.db"), _settings.ContextRetentionDays);
            var entries = repository.ReadRecent(_sid, 200).Select(x => new
            {
                Date = x.ObservedAtUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"),
                Contexte = LearningLabels.Context(x.ContextKey), Résultat = LearningLabels.Disposition(x.Disposition),
                Profil = LearningLabels.State(x.State), PériodesAcceptées = x.AcceptedWindows,
                Qualité = Math.Round(x.Quality, 2), Mesures = string.Join("; ", x.Features.Select(f => $"{LearningLabels.Feature(f.Key)} : {Math.Round(f.Value, 3)}")), Motif = x.Reason
            }).ToArray();
            var form = new Form { Text = "Base d’apprentissage — dernières périodes", StartPosition = FormStartPosition.CenterParent, Size = new Size(1000, 600), MinimumSize = new Size(800, 400) };
            var grid = new DataGridView { Dock = DockStyle.Fill, ReadOnly = true, AutoGenerateColumns = true, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells, DataSource = entries };
            grid.DataBindingComplete += (_, _) =>
            {
                if (grid.Columns["Date"] is { } dateColumn) dateColumn.HeaderText = "Date et heure";
                if (grid.Columns["Contexte"] is { } contextColumn) contextColumn.HeaderText = "Contexte clavier/souris";
                if (grid.Columns["PériodesAcceptées"] is { } acceptedColumn) acceptedColumn.HeaderText = "Périodes acceptées";
            };
            form.Controls.Add(grid); form.ShowDialog(DialogOwnerWindow);
        }
        catch (Exception ex) { MessageBox.Show(DialogOwnerWindow, "Impossible de lire la base : " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void ShowApplicationHabits()
    {
        try
        {
            var profileId = _profileSelector.SelectedItem?.ToString() ?? "PROFIL_1";
            using var repository = new SqliteLearningProfileRepository(Path.Combine(_dataRoot, "learning.db"), _settings.ContextRetentionDays);
            var samples = repository.ReadRecentContextActivity(_sid, profileId, 20000);
            var habits = ContextActivityAnalysis.BuildApplicationHabits(samples).Select(x => new
            {
                Application = x.ApplicationName,
                Périodes = x.PeriodCount,
                TempsObservéMinutes = Math.Round(x.ForegroundMinutes, 1),
                HeuresHabituelles = string.Join(", ", x.TypicalLocalHours.Select(h => $"{h}h")),
                CPUmédianPourcent = x.MedianCpuPercent is null ? "—" : Math.Round(x.MedianCpuPercent.Value, 1).ToString(),
                MémoireMédianeMio = x.MedianMemoryMiB is null ? "—" : Math.Round(x.MedianMemoryMiB.Value, 1).ToString()
            }).ToArray();
            var form = new Form { Text = $"Habitudes d’applications — {profileId}", StartPosition = FormStartPosition.CenterParent, Size = new Size(900, 500), MinimumSize = new Size(700, 350) };
            var grid = new DataGridView { Dock = DockStyle.Fill, ReadOnly = true, AutoGenerateColumns = true, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells, DataSource = habits };
            form.Controls.Add(grid);
            form.ShowDialog(DialogOwnerWindow);
        }
        catch (Exception ex) { MessageBox.Show(DialogOwnerWindow, "Impossible de lire les habitudes : " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void ChangePassword()
    {
        using var oldPassword = new MasterPasswordDialog(isSetup: false) { Text = "Vérifier le mot de passe actuel" };
        if (oldPassword.ShowDialog(DialogOwnerWindow) != DialogResult.OK || oldPassword.Password is null || !_auth.VerifyPassword(oldPassword.Password)) { Append("Changement de mot de passe annulé ou vérification incorrecte."); return; }
        using var newPassword = new MasterPasswordDialog(isSetup: true) { Text = "Définir le nouveau mot de passe maître" };
        if (newPassword.ShowDialog(DialogOwnerWindow) == DialogResult.OK && newPassword.Password is not null) { _auth.SetPassword(newPassword.Password); Append("Mot de passe maître modifié."); }
    }

    private void ShowSettings()
    {
        using var dialog = new LearningSettingsDialog(_settings);
        if (dialog.ShowDialog(DialogOwnerWindow) != DialogResult.OK) return;
        _settings = dialog.Value; _settings.Save(_dataRoot);
        _visualVerifier?.Dispose(); _visualVerifier = null;
        RefreshProfiles();
        Append($"Paramètres enregistrés : période {_settings.WindowSeconds}s, arrêt après {_settings.IdleStopSeconds}s d’inactivité, {_settings.ProfileCount} profil(s).");
    }

    private bool ConfirmMasterPassword()
    {
        using var dialog = new MasterPasswordDialog(isSetup: false) { Text = "Authentifier la configuration visuelle" };
        if (dialog.ShowDialog(DialogOwnerWindow) != DialogResult.OK || dialog.Password is null || !_auth.VerifyPassword(dialog.Password))
        {
            Append("Configuration visuelle non authentifiée.");
            return false;
        }
        return true;
    }

    private VisualVerificationService CreateVisualVerifier(bool forceEnabled = false)
    {
        if (!forceEnabled)
        {
            lock (_visualServiceGate)
            {
                if (_visualVerifier is not null) return _visualVerifier;
                _visualVerifier = new VisualVerificationService(BuildVisualOptions(_settings.VisualVerificationEnabled));
                return _visualVerifier;
            }
        }
        return new VisualVerificationService(BuildVisualOptions(enabled: true));
    }

    private VisualVerificationOptions BuildVisualOptions(bool enabled)
    {
        var models = Path.Combine(_dataRoot, "models");
        return new VisualVerificationOptions(
            Path.Combine(models, "face_detection_yunet_2023mar.onnx"),
            Path.Combine(models, "face_recognition_sface_2021dec.onnx"),
            Path.Combine(models, "MiniFASNetV2.onnx"),
            Path.Combine(_dataRoot, "visual"),
            CameraIndex: _settings.VisualCameraIndex,
            CaptureSeconds: 5,
            MaximumWaitSeconds: 60,
            Enabled: enabled,
            AlternativeLivenessModelPath: Path.Combine(models, "Facenox-MiniFASNetV2-SE.onnx"));
    }

    private async void EnrollFaceAsync()
    {
        if (!ConfirmMasterPassword()) return;
        var profileId = _profileSelector.SelectedItem?.ToString() ?? "PROFIL_1";
        if (MessageBox.Show(DialogOwnerWindow, $"Filmer environ 5 secondes pour enregistrer le profil {profileId} ? Place le visage face à la caméra, dans une pièce éclairée.", Text,
                MessageBoxButtons.YesNo, MessageBoxIcon.Information) != DialogResult.Yes) return;
        try
        {
            var verifier = CreateVisualVerifier();
            var result = await verifier.EnrollProfileAsync(profileId);
            VisualCheckReportStore.AppendEnrollment(_dataRoot, profileId, result.Success, result.ReasonCode, verifier.LastCaptureDiagnostics);
            if (result.Success)
            {
                _settings = _settings with { VisualVerificationEnabled = true };
                _settings.Save(_dataRoot);
                verifier.Dispose(); _visualVerifier = null;
            }
            Append($"Enrôlement visuel {profileId} : {(result.Success ? "réussi" : "non effectué")} ({result.ReasonCode}).");
            MessageBox.Show(DialogOwnerWindow, result.Success ? $"Le profil visuel {profileId} est enregistré localement et chiffré." : $"L’enregistrement n’a pas été validé : {result.ReasonCode}", Text,
                MessageBoxButtons.OK, result.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }
        catch (Exception ex) { Append("Moteur visuel indisponible : " + ex.Message); MessageBox.Show(DialogOwnerWindow, "Vérifie les modèles dans le dossier indiqué par Mode_Validation/Modeles/README.md.\n\n" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private async void SimulateVisualAlertAsync()
    {
        VisualVerificationService? verifier = null;
        try
        {
            verifier = CreateVisualVerifier(forceEnabled: true);
            var correlationId = Guid.NewGuid().ToString("D");
            var now = DateTimeOffset.UtcNow;
            var request = new VisualIdentityRequest(correlationId, "SUSPICION", now, now.AddSeconds(60), true);
            var handler = new Demon1VisualRequestHandler(verifier, () => true);
            var response = await handler.HandleAsync(request);
            VisualCheckReportStore.Append(_dataRoot, "SIMULATION_D3_CAMERA_REELLE", response, verifier.LastCaptureDiagnostics);
            Append($"Simulation D3 réelle : {response.Status}/{response.Liveness}, profil={response.ProfileId ?? "aucun"}, qualité={response.FaceQuality:0.00}, images={response.ValidFrames}, preuve={response.EvidenceRef ?? "aucune"}, motif={response.ReasonCode}.");
            MessageBox.Show(DialogOwnerWindow, $"D3 a demandé une vérification; D1 a réellement capturé la caméra et exécuté le moteur facial.\n\nRésultat : {response.Status}\nPrésence : {response.Liveness}\nProfil : {response.ProfileId ?? "aucun"}\nQualité : {response.FaceQuality:0.00}\nImages valides : {response.ValidFrames}\nMotif : {response.ReasonCode}", Text, MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex) { Append("Test caméra/D3 impossible : " + ex.Message); MessageBox.Show(DialogOwnerWindow, "Vérifie les modèles et la caméra.\n\n" + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally { verifier?.Dispose(); }
    }

    private void ShowVisualReports()
    {
        using var reports = new VisualReportsDialog(_dataRoot);
        reports.ShowDialog(DialogOwnerWindow);
    }

    private async Task ConnectToDemon3Async()
    {
        if (_pipeClient is not null || _pipeConnecting || IsDisposed) return;
        _pipeConnecting = true;
        var client = new InterDaemonPipeClient();
        client.MessageReceived += (_, message) => _ = HandleDemon3MessageAsync(client, message);
        client.ConnectionFailed += (_, error) =>
        {
            if (ReferenceEquals(_pipeClient, client)) _pipeClient = null;
            _ = client.DisposeAsync();
            if (!IsDisposed && IsHandleCreated)
            {
                try { BeginInvoke(new Action(() => _pipeReconnect.Start())); }
                catch (InvalidOperationException) { }
            }
            if (!_connectionFailureLogged)
            {
                _connectionFailureLogged = true;
                AppendFromAnyThread("Connexion au démon 3 interrompue : " + error.Message);
            }
        };
        try
        {
            var welcome = await client.ConnectAndHandshakeAsync();
            _pipeClient = client;
            _connectionFailureLogged = false;
            _pipeReconnect.Stop();
            var session = welcome.TryGetProperty("sessionId", out var sessionId) ? sessionId.ToString() : "session inconnue";
            AppendFromAnyThread($"D1 connecté au démon 3 par le canal local sécurisé ({session}).");
        }
        catch (Exception ex)
        {
            await client.DisposeAsync();
            if (!_connectionFailureLogged)
            {
                _connectionFailureLogged = true;
                AppendFromAnyThread("Démon 3 non disponible; D1 continue localement et réessaiera : " + ex.Message);
            }
            _pipeReconnect.Start();
        }
        finally { _pipeConnecting = false; }
    }

    private async Task PublishLatestContextAsync()
    {
        var client = _pipeClient;
        if (client is null || !IsRunning() || DateTimeOffset.UtcNow < _nextTelemetryRetryUtc) return;
        var statusPath = Path.Combine(_dataRoot, "status.json");
        try
        {
            using var json = JsonDocument.Parse(await File.ReadAllBytesAsync(statusPath));
            if (!json.RootElement.TryGetProperty("latestContext", out var current) || current.ValueKind != JsonValueKind.Object) return;
            if (!current.TryGetProperty("ObservedAtUtc", out var atValue) || !DateTimeOffset.TryParse(atValue.GetString(), out var observedAt)
                || observedAt > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - observedAt > TimeSpan.FromMinutes(5)) return;
            var profileId = current.TryGetProperty("ProfileId", out var profileValue) ? profileValue.GetString() : null;
            if (string.IsNullOrWhiteSpace(profileId)) return;
            if (observedAt > _lastPublishedContextAt)
            {
        using var repository = new SqliteLearningProfileRepository(Path.Combine(_dataRoot, "learning.db"), _settings.ContextRetentionDays);
                var observations = repository.ReadRecentContextActivity(_sid, profileId, 20000);
                var payload = BehaviorProfileValidator.ToUserContextPayload(observations, _sessionId);
                if (payload is null) return;
                await client.SendAsync("USER_CONTEXT", Guid.NewGuid().ToString("D"), payload,
                    DateTimeOffset.UtcNow.AddSeconds(30));
                _lastPublishedContextAt = observedAt;
            }

            if (json.RootElement.TryGetProperty("behaviorAssessment", out var assessmentJson)
                && assessmentJson.ValueKind == JsonValueKind.Object
                && assessmentJson.TryGetProperty("ObservedAtUtc", out var behaviorAtValue)
                && DateTimeOffset.TryParse(behaviorAtValue.GetString(), out var behaviorAt)
                && behaviorAt > _lastEvaluatedBehaviorAt)
            {
                if (json.RootElement.TryGetProperty("behaviorDeviationPayload", out var deviation)
                    && deviation.ValueKind == JsonValueKind.Object
                    && deviation.TryGetProperty("expiresAtUtc", out var expiryValue)
                    && DateTimeOffset.TryParse(expiryValue.GetString(), out var expiresAt)
                    && expiresAt > DateTimeOffset.UtcNow)
                {
                    await client.SendAsync("BEHAVIOR_DEVIATION", Guid.NewGuid().ToString("D"), deviation,
                        expiresAt);
                    AppendFromAnyThread("D1 a transmis à D3 une divergence calculée avant la mise à jour du profil, avec le contexte appris.");
                }
                _lastEvaluatedBehaviorAt = behaviorAt;
            }
        }
        catch (JsonException) { /* The collector writes status.json in place; a partial read is transient. */ }
        catch (Exception ex) when (ex is IOException or InvalidDataException or TimeoutException or InvalidOperationException)
        {
            _nextTelemetryRetryUtc = DateTimeOffset.UtcNow.AddSeconds(5);
            AppendFromAnyThread("Publication du contexte D1 non effectuée : " + ex.Message);
        }
    }

    private async Task HandleDemon3MessageAsync(InterDaemonPipeClient client, InterDaemonEnvelope message)
    {
        try
        {
            if (message.MessageType == "VISUAL_IDENTITY_REQUEST")
            {
                var request = message.Payload.Deserialize<VisualIdentityRequest>()
                    ?? throw new InvalidDataException("Demande visuelle vide.");
                if (!StringComparer.Ordinal.Equals(request.CorrelationId, message.CorrelationId)
                    || request.DeadlineUtc > message.ExpiresAtUtc)
                    throw new InvalidDataException("La demande visuelle ne respecte pas sa corrélation ou son expiration.");
                var verifier = await Task.Run(() => CreateVisualVerifier()).ConfigureAwait(false);
                var handler = new Demon1VisualRequestHandler(verifier, () => _settings.VisualVerificationEnabled);
                var response = await handler.HandleAsync(request);
                VisualCheckReportStore.Append(_dataRoot, "REQUETE_D3", response, verifier.LastCaptureDiagnostics);
                await client.SendAsync("VISUAL_IDENTITY_RESPONSE", message.CorrelationId, response, DateTimeOffset.UtcNow.AddSeconds(30));
                AppendFromAnyThread($"Réponse D1 à la demande visuelle {message.CorrelationId} : {response.Status}/{response.Liveness} ({response.ReasonCode}).");
            }
            else if (message.MessageType == "VISUAL_EVIDENCE_READ_REQUEST")
            {
                var request = message.Payload.Deserialize<VisualEvidenceReadRequest>()
                    ?? throw new InvalidDataException("Demande de preuve visuelle vide.");
                var reader = new VisualEvidenceReader(Path.Combine(_dataRoot, "visual"));
                var chunk = reader.ReadChunk(request)
                    ?? new VisualEvidenceChunk(request.EvidenceRef, Math.Max(0, request.Offset), 0, string.Empty, true);
                await client.SendAsync("VISUAL_EVIDENCE_CHUNK", message.CorrelationId, chunk, DateTimeOffset.UtcNow.AddSeconds(30));
            }
            else if (message.MessageType == "CONTEXT_REQUEST")
            {
                var profileId = message.Payload.TryGetProperty("profileId", out var value) ? value.GetString() : _profileSelector.SelectedItem?.ToString();
                UserContextPayload? context = null;
                if (!string.IsNullOrWhiteSpace(profileId))
                {
                    using var repository = new SqliteLearningProfileRepository(Path.Combine(_dataRoot, "learning.db"), _settings.ContextRetentionDays);
                    context = BehaviorProfileValidator.ToUserContextPayload(repository.ReadRecentContextActivity(_sid, profileId, 20000), _sessionId);
                }
                var sessionContext = WindowsInteractiveSessionContext.Capture(_sessionLockStateKnown, _sessionLocked);
                var observedAt = DateTimeOffset.UtcNow;
                var response = new
                {
                    status = "AVAILABLE",
                    applicationStatus = context is null ? "NOT_AVAILABLE" : "AVAILABLE",
                    reasonCode = context is null ? "NO_RECENT_CONTEXT" : null,
                    observedAtUtc = observedAt,
                    sessionId = context?.SessionId ?? _sessionId,
                    applicationContext = context?.ApplicationContext,
                    expiresAtUtc = observedAt.AddSeconds(30),
                    sessionContext = new
                    {
                        sessionState = sessionContext.SessionState,
                        localOrRemote = sessionContext.LocalOrRemote,
                        recentAuthBand = sessionContext.RecentAuthBand
                    },
                    sessionContextObservedAtUtc = sessionContext.ObservedAtUtc
                };
                await client.SendAsync("CONTEXT_RESPONSE", message.CorrelationId, response, DateTimeOffset.UtcNow.AddSeconds(30));
            }
            else if (message.MessageType == "MASTER_AUTH_REQUIRED")
            {
                var challengeId = message.Payload.TryGetProperty("challengeId", out var challenge) && challenge.ValueKind == JsonValueKind.String
                    ? challenge.GetString() : null;
                var actionId = message.Payload.TryGetProperty("actionId", out var action) && action.ValueKind == JsonValueKind.String
                    ? action.GetString() : null;
                var deadline = message.Payload.TryGetProperty("deadlineUtc", out var deadlineValue)
                    && deadlineValue.ValueKind == JsonValueKind.String && deadlineValue.TryGetDateTimeOffset(out var parsedDeadline)
                    ? parsedDeadline : DateTimeOffset.MinValue;
                var approved = false;
                DateTimeOffset? verifiedAt = null;
                if (challengeId is { Length: > 0 and <= 96 } && actionId == "RUN_DEFENDER_SCAN" && deadline > DateTimeOffset.UtcNow)
                {
                    approved = await PromptOwnerApprovalAsync(actionId).ConfigureAwait(false);
                    if (approved) verifiedAt = DateTimeOffset.UtcNow;
                }
                await client.SendAsync("MASTER_AUTH_RESULT", message.CorrelationId, new
                {
                    challengeId = challengeId ?? "invalid-challenge",
                    actionId = actionId ?? "UNKNOWN",
                    approved,
                    verifiedAtUtc = verifiedAt,
                    reasonCode = approved ? "OWNER_MASTER_PASSWORD_CONFIRMED" : "OWNER_DENIED_OR_AUTHENTICATION_FAILED"
                }, DateTimeOffset.UtcNow.AddSeconds(15)).ConfigureAwait(false);
                AppendFromAnyThread(approved
                    ? $"Accord du propriétaire transmis à D3 pour {actionId}."
                    : $"Accord refusé, annulé ou expiré pour {actionId ?? "la mesure demandée"}. Aucune mesure n’a été autorisée.");
            }
        }
        catch (Exception ex)
        {
            AppendFromAnyThread($"Échec de traitement du message D3 {message.MessageType} : {ex.Message}");
            if (message.MessageType == "VISUAL_IDENTITY_REQUEST")
            {
                var failed = new VisualIdentityResponse(message.CorrelationId, "INDETERMINATE", null, "INDETERMINATE", null, 0, 0, null, DateTimeOffset.UtcNow, "D1_VISUAL_HANDLER_ERROR");
                try { await client.SendAsync("VISUAL_IDENTITY_RESPONSE", message.CorrelationId, failed, DateTimeOffset.UtcNow.AddSeconds(30)); }
                catch { /* D3 will mark the correlation timed out and continue processing D2. */ }
            }
        }
    }

    private Task<bool> PromptOwnerApprovalAsync(string actionId)
    {
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        void ShowPrompt()
        {
            if (IsDisposed || Disposing) { completion.TrySetResult(false); return; }
            using var dialog = new MasterPasswordDialog(isSetup: false, purpose: actionId)
            { Text = "Autorisation d’une mesure — SentinelCore" };
            if (dialog.ShowDialog(DialogOwnerWindow) != DialogResult.OK || dialog.Password is null)
            { completion.TrySetResult(false); return; }
            try
            {
                var valid = _auth.VerifyPassword(dialog.Password);
                if (!valid) MessageBox.Show(DialogOwnerWindow, "Mot de passe incorrect. La mesure reste bloquée.", Text,
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                completion.TrySetResult(valid);
            }
            catch (Exception ex)
            {
                Append("Vérification du mot de passe pour l’autorisation impossible : " + ex.Message);
                completion.TrySetResult(false);
            }
        }

        if (InvokeRequired)
        {
            try { BeginInvoke(new Action(ShowPrompt)); }
            catch (InvalidOperationException) { completion.TrySetResult(false); }
        }
        else ShowPrompt();
        return completion.Task;
    }

    private void AppendFromAnyThread(string message)
    {
        if (IsDisposed || Disposing) return;
        if (InvokeRequired)
        {
            try { BeginInvoke(new Action(() => Append(message))); }
            catch (InvalidOperationException) { }
        }
        else Append(message);
    }

    private void RefreshProfiles()
    {
        var previous = _profileSelector.SelectedItem?.ToString();
        _profileSelector.Items.Clear();
        for (var i = 1; i <= _settings.ProfileCount; i++) _profileSelector.Items.Add($"PROFIL_{i}");
        var index = previous is null ? 0 : _profileSelector.Items.IndexOf(previous);
        _profileSelector.SelectedIndex = index >= 0 ? index : 0;
    }

    private void Append(string message) => _log.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
}

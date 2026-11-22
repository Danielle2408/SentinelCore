using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using SentinelCore.Demon1.Learning;
using SentinelCore.Demon1.Validation;
using SentinelCore.Demon1.VisualVerification;

namespace SentinelCore.Demon1.Learning.Controller;

public enum BackgroundBrokerStartResult
{
    Started,
    AlreadyRunning,
    RefusedUnauthenticated,
    ExecutableNotFound,
    InvalidProfile,
    StartFailed
}

/// <summary>
/// Starts or stops the D1 pipe/request broker as a separate hidden process. Start requires the
/// AuthStore instance that completed owner authentication in the current application process.
/// </summary>
public static class Demon1BackgroundBrokerLauncher
{
    private static readonly string DataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon1Learning");

    public static bool IsRunning()
    {
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid)) return false;
        try
        {
            using var existing = Mutex.OpenExisting(MutexName(sid));
            return true;
        }
        catch (WaitHandleCannotBeOpenedException) { return false; }
        catch (UnauthorizedAccessException) { return true; }
    }

    public static BackgroundBrokerStartResult Start(AuthStore auth, string executablePath, string profileId)
    {
        ArgumentNullException.ThrowIfNull(auth);
        if (!auth.IsAuthenticatedInThisProcess) return BackgroundBrokerStartResult.RefusedUnauthenticated;
        if (string.IsNullOrWhiteSpace(executablePath) || !File.Exists(executablePath)) return BackgroundBrokerStartResult.ExecutableNotFound;
        if (!IsConfiguredProfile(profileId, LearningSettings.Load(DataRoot).ProfileCount)) return BackgroundBrokerStartResult.InvalidProfile;

        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid)) return BackgroundBrokerStartResult.StartFailed;
        var mutexName = MutexName(sid);
        try
        {
            using var existing = Mutex.OpenExisting(mutexName);
            return BackgroundBrokerStartResult.AlreadyRunning;
        }
        catch (WaitHandleCannotBeOpenedException) { }
        catch (UnauthorizedAccessException) { return BackgroundBrokerStartResult.AlreadyRunning; }

        Directory.CreateDirectory(DataRoot);
        var ticketPath = Path.Combine(DataRoot, "broker-ticket-" + Guid.NewGuid().ToString("N") + ".bin");
        string? proof = null;
        try
        {
            proof = OneTimeAuthorizationTicket.CreateBackgroundBroker(ticketPath, sid);
            var startInfo = new ProcessStartInfo(Path.GetFullPath(executablePath))
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(executablePath)) ?? AppContext.BaseDirectory
            };
            foreach (var argument in new[] { "--broker", "--auth-ticket", ticketPath, "--auth-proof", proof, "--profile", profileId })
                startInfo.ArgumentList.Add(argument);
            using var process = Process.Start(startInfo);
            return process is { HasExited: false } ? BackgroundBrokerStartResult.Started : BackgroundBrokerStartResult.StartFailed;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return BackgroundBrokerStartResult.StartFailed;
        }
        finally
        {
            proof = null;
            // A successful child atomically claims and removes the ticket. On launch failure,
            // remove it here so no unused authorization remains on disk.
            try { if (File.Exists(ticketPath)) File.Delete(ticketPath); } catch (IOException) { }
        }
    }

    /// <summary>Requests a graceful stop. It does not stop or restart keyboard/mouse collection.</summary>
    public static bool Stop(AuthStore auth)
    {
        ArgumentNullException.ThrowIfNull(auth);
        if (!auth.IsAuthenticatedInThisProcess) return false;
        var sid = WindowsIdentity.GetCurrent().User?.Value;
        if (string.IsNullOrWhiteSpace(sid)) return false;
        try
        {
            using var signal = EventWaitHandle.OpenExisting(StopEventName(sid));
            signal.Set();
            return true;
        }
        catch (WaitHandleCannotBeOpenedException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    internal static string MutexName(string sid) => "Local\\SentinelCore.D1Broker." + SidKey(sid);
    internal static string StopEventName(string sid) => "Local\\SentinelCore.D1BrokerStop." + SidKey(sid);
    private static string SidKey(string sid) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sid)))[..24];

    private static bool IsConfiguredProfile(string? profileId, int profileCount)
        => profileId is { Length: 8 or 9 }
            && profileId.StartsWith("PROFIL_", StringComparison.Ordinal)
            && int.TryParse(profileId.AsSpan(7), out var number)
            && number >= 1 && number <= profileCount;
}

internal static class Demon1BackgroundBrokerRuntime
{
    private static readonly string DataRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon1Learning");

    public static int Run(string[] args)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Le broker D1 nécessite Windows.");
            var options = Parse(args);
            var sid = WindowsIdentity.GetCurrent().User?.Value
                ?? throw new InvalidOperationException("Le compte Windows du broker est introuvable.");
            var ticketPath = Path.GetFullPath(Need(options, "auth-ticket"));
            var expectedDirectory = Path.GetFullPath(DataRoot) + Path.DirectorySeparatorChar;
            if (!ticketPath.StartsWith(expectedDirectory, StringComparison.OrdinalIgnoreCase)
                || !Path.GetFileName(ticketPath).StartsWith("broker-ticket-", StringComparison.OrdinalIgnoreCase)
                || !ticketPath.EndsWith(".bin", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Ticket de lancement du broker hors du dossier autorisé.");
            if (!Demon1BackgroundBrokerLauncherStartAllowed(Need(options, "auth-proof"), sid, ticketPath))
                throw new UnauthorizedAccessException("Ticket du broker absent, expiré, déjà utilisé ou invalide.");

            var settings = LearningSettings.Load(DataRoot);
            var profile = Need(options, "profile");
            if (!IsConfiguredProfile(profile, settings.ProfileCount)) throw new UnauthorizedAccessException("Profil de broker non configuré.");

            using var singleton = new Mutex(initiallyOwned: true, Demon1BackgroundBrokerLauncher.MutexName(sid), out var createdNew);
            if (!createdNew) return 0;

            ApplicationConfiguration.Initialize();
            using var shell = new BackgroundBrokerMessageWindow();
            var broker = new Demon1BackgroundBrokerHost(sid, profile, DataRoot, shell);
            shell.Shown += async (_, _) =>
            {
                shell.Hide();
                try { await broker.RunAsync(); }
                catch (Exception ex) { Debug.WriteLine("SentinelCore D1 broker stopped: " + ex.Message); }
                finally { broker.Dispose(); shell.Close(); }
            };
            Application.Run(shell);
            singleton.ReleaseMutex();
            return 0;
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception or CryptographicException)
        {
            Debug.WriteLine("SentinelCore D1 broker refused: " + ex.Message);
            return 2;
        }
    }

    private static bool Demon1BackgroundBrokerLauncherStartAllowed(string proof, string sid, string ticketPath)
        => OneTimeAuthorizationTicket.ConsumeBackgroundBroker(ticketPath, proof, sid);

    private static Dictionary<string, string> Parse(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] is not ("--auth-ticket" or "--auth-proof" or "--profile") || i + 1 >= args.Length)
                throw new ArgumentException("Arguments broker manquants ou inconnus.");
            if (!result.TryAdd(args[i][2..], args[++i])) throw new ArgumentException("Argument broker dupliqué.");
        }
        return result;
    }

    private static string Need(Dictionary<string, string> options, string key)
        => options.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value : throw new ArgumentException("Argument broker manquant : " + key);

    private static bool IsConfiguredProfile(string? profileId, int profileCount)
        => profileId is { Length: 8 or 9 }
            && profileId.StartsWith("PROFIL_", StringComparison.Ordinal)
            && int.TryParse(profileId.AsSpan(7), out var number)
            && number >= 1 && number <= profileCount;
}

internal sealed class BackgroundBrokerMessageWindow : Form
{
    private const int WmWtsSessionChange = 0x02B1;
    private const uint NotifyForThisSession = 0;
    private bool _registered;
    public bool LockStateKnown { get; private set; }
    public bool IsLocked { get; private set; }

    public BackgroundBrokerMessageWindow()
    {
        ShowInTaskbar = false;
        ShowIcon = false;
        FormBorderStyle = FormBorderStyle.FixedToolWindow;
        WindowState = FormWindowState.Minimized;
        Opacity = 0;
        Text = "SentinelCore background broker";
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        _registered = WTSRegisterSessionNotification(Handle, NotifyForThisSession);
    }

    protected override void WndProc(ref Message message)
    {
        if (message.Msg == WmWtsSessionChange
            && WindowsInteractiveSessionContext.TryClassifyLockEvent(message.WParam.ToInt32(), out var locked))
        {
            IsLocked = locked;
            LockStateKnown = true;
        }
        base.WndProc(ref message);
    }

    protected override void OnHandleDestroyed(EventArgs e)
    {
        if (_registered) WTSUnRegisterSessionNotification(Handle);
        _registered = false;
        base.OnHandleDestroyed(e);
    }

    [System.Runtime.InteropServices.DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSRegisterSessionNotification(IntPtr windowHandle, uint flags);
    [System.Runtime.InteropServices.DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSUnRegisterSessionNotification(IntPtr windowHandle);
}

internal sealed class Demon1BackgroundBrokerHost : IDisposable
{
    private static readonly TimeSpan TelemetryInterval = TimeSpan.FromSeconds(2);
    private readonly string _sid;
    private readonly string _launchProfile;
    private readonly string _dataRoot;
    private readonly BackgroundBrokerMessageWindow _shell;
    private readonly SynchronizationContext _uiContext;
    private readonly AuthStore _auth = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly VisualEvidenceReader _evidenceReader;
    private InterDaemonPipeClient? _client;
    private bool _connectionFailed;
    private DateTimeOffset _lastContextPublished;
    private DateTimeOffset _lastBehaviorPublished;
    private bool _disposed;

    public Demon1BackgroundBrokerHost(string sid, string launchProfile, string dataRoot, BackgroundBrokerMessageWindow shell)
    {
        _sid = sid;
        _launchProfile = launchProfile;
        _dataRoot = dataRoot;
        _shell = shell;
        _uiContext = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _evidenceReader = new VisualEvidenceReader(Path.Combine(dataRoot, "visual"));
    }

    public async Task RunAsync()
    {
        using var stopSignal = new EventWaitHandle(false, EventResetMode.AutoReset,
            Demon1BackgroundBrokerLauncher.StopEventName(_sid));
        var stopRequested = Task.Run(() => stopSignal.WaitOne());
        using var stopRegistration = _shutdown.Token.Register(() => { });
        while (!_shutdown.IsCancellationRequested && !stopRequested.IsCompleted)
        {
            if (_client is null || _connectionFailed || !_client.IsConnectedToServer)
            {
                await DisconnectAsync().ConfigureAwait(true);
                await TryConnectAsync().ConfigureAwait(true);
                if (_client is null)
                {
                    await WaitOrStopAsync(stopRequested, TimeSpan.FromSeconds(5)).ConfigureAwait(true);
                    continue;
                }
            }

            if (DateTimeOffset.UtcNow - _lastContextPublished >= TelemetryInterval)
                await PublishLatestContextAsync(_client).ConfigureAwait(true);
            await WaitOrStopAsync(stopRequested, TimeSpan.FromSeconds(1)).ConfigureAwait(true);
        }
        _shutdown.Cancel();
        await DisconnectAsync().ConfigureAwait(true);
    }

    private async Task TryConnectAsync()
    {
        var client = new InterDaemonPipeClient();
        client.ConnectionFailed += (_, _) => _connectionFailed = true;
        client.MessageReceived += (_, message) => _ = HandleMessageSafelyAsync(client, message);
        try
        {
            await client.ConnectAndHandshakeAsync(_shutdown.Token).ConfigureAwait(true);
            _client = client;
            _connectionFailed = false;
        }
        catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException or InvalidOperationException)
        {
            await client.DisposeAsync().ConfigureAwait(true);
        }
    }

    private async Task DisconnectAsync()
    {
        var client = _client;
        _client = null;
        _connectionFailed = false;
        if (client is not null) await client.DisposeAsync().ConfigureAwait(true);
    }

    private async Task HandleMessageSafelyAsync(InterDaemonPipeClient client, InterDaemonEnvelope message)
    {
        try
        {
            var processor = new Demon1BackgroundRequestProcessor(
                (type, correlation, payload, expires) => client.SendAsync(type, correlation, payload, expires, _shutdown.Token),
                CreateContextResponse,
                VerifyVisualAsync,
                request => _evidenceReader.ReadChunk(request),
                RequestOwnerApprovalAsync);
            await processor.HandleAsync(message, _shutdown.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or TimeoutException or OperationCanceledException)
        {
            Debug.WriteLine($"D1 broker request failed ({message.MessageType}): {ex.Message}");
        }
    }

    private object CreateContextResponse(string? requestedProfileId)
    {
        var settings = LearningSettings.Load(_dataRoot);
        var profileId = IsConfiguredProfile(requestedProfileId, settings.ProfileCount)
            ? requestedProfileId! : _launchProfile;
        UserContextPayload? context = null;
        if (IsConfiguredProfile(profileId, settings.ProfileCount))
        {
            try
            {
                using var repository = new SqliteLearningProfileRepository(Path.Combine(_dataRoot, "learning.db"), settings.ContextRetentionDays);
                var observations = repository.ReadRecentContextActivity(_sid, profileId, 20000);
                context = BehaviorProfileValidator.ToUserContextPayload(observations, Process.GetCurrentProcess().SessionId.ToString());
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
            {
                Debug.WriteLine("D1 broker context unavailable: " + ex.Message);
            }
        }
        var session = WindowsInteractiveSessionContext.Capture(_shell.LockStateKnown, _shell.IsLocked);
        var observedAt = DateTimeOffset.UtcNow;
        return new
        {
            status = "AVAILABLE",
            applicationStatus = context is null ? "NOT_AVAILABLE" : "AVAILABLE",
            reasonCode = context is null ? "NO_RECENT_CONTEXT" : null,
            observedAtUtc = observedAt,
            sessionId = context?.SessionId ?? Process.GetCurrentProcess().SessionId.ToString(),
            applicationContext = context?.ApplicationContext,
            expiresAtUtc = observedAt.AddSeconds(30),
            sessionContext = new { sessionState = session.SessionState, localOrRemote = session.LocalOrRemote, recentAuthBand = session.RecentAuthBand },
            sessionContextObservedAtUtc = session.ObservedAtUtc
        };
    }

    private async Task<VisualIdentityResponse> VerifyVisualAsync(VisualIdentityRequest request, CancellationToken cancellationToken)
    {
        var settings = LearningSettings.Load(_dataRoot);
        if (!settings.VisualVerificationEnabled)
            return Inconclusive(request.CorrelationId, "VISUAL_VERIFICATION_DISABLED");

        var verifier = await Task.Run(() => new VisualVerificationService(BuildVisualOptions(settings)), cancellationToken).ConfigureAwait(false);
        using (verifier)
        {
            var configured = verifier.HasEnrolledProfiles;
            var handler = new Demon1VisualRequestHandler(verifier, () => settings.VisualVerificationEnabled && configured, _evidenceReader);
            var response = await handler.HandleAsync(request, cancellationToken).ConfigureAwait(false);
            VisualCheckReportStore.Append(_dataRoot, "REQUETE_D3_BROKER", response, verifier.LastCaptureDiagnostics);
            return response;
        }
    }

    private VisualVerificationOptions BuildVisualOptions(LearningSettings settings)
    {
        var models = Path.Combine(_dataRoot, "models");
        return new VisualVerificationOptions(
            Path.Combine(models, "face_detection_yunet_2023mar.onnx"),
            Path.Combine(models, "face_recognition_sface_2021dec.onnx"),
            Path.Combine(models, "MiniFASNetV2.onnx"),
            Path.Combine(_dataRoot, "visual"),
            CameraIndex: settings.VisualCameraIndex,
            CaptureSeconds: 5,
            MaximumWaitSeconds: 60,
            Enabled: settings.VisualVerificationEnabled,
            AlternativeLivenessModelPath: Path.Combine(models, "Facenox-MiniFASNetV2-SE.onnx"));
    }

    private Task<bool> RequestOwnerApprovalAsync(string challengeId, string actionId, DateTimeOffset deadline, CancellationToken cancellationToken)
    {
        if (deadline <= DateTimeOffset.UtcNow) return Task.FromResult(false);
        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Form? dialog = null;
        System.Threading.Timer? timeout = null;
        CancellationTokenRegistration registration = default;
        _uiContext.Post(_ =>
        {
            if (_shutdown.IsCancellationRequested || deadline <= DateTimeOffset.UtcNow)
            {
                completion.TrySetResult(false);
                return;
            }
            using var prompt = new MasterPasswordDialog(isSetup: false, purpose: actionId)
            { Text = "Autorisation du propriétaire — SentinelCore" };
            dialog = prompt;
            var remaining = deadline - DateTimeOffset.UtcNow;
            timeout = new System.Threading.Timer(_ =>
            {
                try { _uiContext.Post(__ => { if (prompt.Visible) prompt.Close(); }, null); }
                catch (System.ComponentModel.InvalidAsynchronousStateException) { }
            }, null, remaining, Timeout.InfiniteTimeSpan);
            registration = cancellationToken.Register(() =>
            {
                try { _uiContext.Post(__ => { if (prompt.Visible) prompt.Close(); }, null); }
                catch (System.ComponentModel.InvalidAsynchronousStateException) { }
            });
            try
            {
                var accepted = prompt.ShowDialog() == DialogResult.OK && prompt.Password is not null
                    && !cancellationToken.IsCancellationRequested && DateTimeOffset.UtcNow < deadline
                    && _auth.VerifyPassword(prompt.Password);
                completion.TrySetResult(accepted);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or System.ComponentModel.Win32Exception)
            {
                Debug.WriteLine("D1 owner authentication refused: " + ex.Message);
                completion.TrySetResult(false);
            }
            finally
            {
                timeout?.Dispose();
                registration.Dispose();
                dialog = null;
            }
        }, null);
        return completion.Task;
    }

    private async Task PublishLatestContextAsync(InterDaemonPipeClient client)
    {
        var statusPath = Path.Combine(_dataRoot, "status.json");
        try
        {
            using var json = JsonDocument.Parse(await File.ReadAllBytesAsync(statusPath, _shutdown.Token).ConfigureAwait(true));
            var root = json.RootElement;
            if (!root.TryGetProperty("active", out var active) || active.ValueKind != JsonValueKind.True
                || !root.TryGetProperty("latestContext", out var current) || current.ValueKind != JsonValueKind.Object
                || !current.TryGetProperty("ObservedAtUtc", out var atValue) || !DateTimeOffset.TryParse(atValue.GetString(), out var observedAt)
                || observedAt > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - observedAt > TimeSpan.FromMinutes(5)) return;
            if (observedAt > _lastContextPublished)
            {
                var profileId = current.TryGetProperty("ProfileId", out var profileValue) ? profileValue.GetString() : null;
                if (!IsConfiguredProfile(profileId, LearningSettings.Load(_dataRoot).ProfileCount)) return;
                using var repository = new SqliteLearningProfileRepository(Path.Combine(_dataRoot, "learning.db"), LearningSettings.Load(_dataRoot).ContextRetentionDays);
                var payload = BehaviorProfileValidator.ToUserContextPayload(
                    repository.ReadRecentContextActivity(_sid, profileId!, 20000), Process.GetCurrentProcess().SessionId.ToString());
                if (payload is not null)
                {
                    await client.SendAsync("USER_CONTEXT", Guid.NewGuid().ToString("D"), payload, DateTimeOffset.UtcNow.AddSeconds(30), _shutdown.Token).ConfigureAwait(true);
                    _lastContextPublished = observedAt;
                }
            }

            if (root.TryGetProperty("behaviorAssessment", out var assessment)
                && assessment.ValueKind == JsonValueKind.Object
                && assessment.TryGetProperty("ObservedAtUtc", out var behaviorAtValue)
                && DateTimeOffset.TryParse(behaviorAtValue.GetString(), out var behaviorAt)
                && behaviorAt > _lastBehaviorPublished
                && root.TryGetProperty("behaviorDeviationPayload", out var deviation)
                && deviation.ValueKind == JsonValueKind.Object
                && deviation.TryGetProperty("expiresAtUtc", out var expiryValue)
                && DateTimeOffset.TryParse(expiryValue.GetString(), out var expiresAt)
                && expiresAt > DateTimeOffset.UtcNow)
            {
                await client.SendAsync("BEHAVIOR_DEVIATION", Guid.NewGuid().ToString("D"), deviation, expiresAt, _shutdown.Token).ConfigureAwait(true);
                _lastBehaviorPublished = behaviorAt;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or InvalidDataException or TimeoutException or InvalidOperationException or OperationCanceledException)
        {
            Debug.WriteLine("D1 broker telemetry deferred: " + ex.Message);
        }
    }

    private async Task WaitOrStopAsync(Task stopRequested, TimeSpan delay)
    {
        await Task.WhenAny(Task.Delay(delay, _shutdown.Token), stopRequested).ConfigureAwait(true);
        if (stopRequested.IsCompleted) _shutdown.Cancel();
    }

    private static VisualIdentityResponse Inconclusive(string correlationId, string reason)
        => new(correlationId, "INDETERMINATE", null, "INDETERMINATE", null, 0, 0, null, DateTimeOffset.UtcNow, reason);

    private static bool IsConfiguredProfile(string? profileId, int profileCount)
        => profileId is { Length: 8 or 9 }
            && profileId.StartsWith("PROFIL_", StringComparison.Ordinal)
            && int.TryParse(profileId.AsSpan(7), out var number)
            && number >= 1 && number <= profileCount;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _shutdown.Cancel();
        _shutdown.Dispose();
    }
}

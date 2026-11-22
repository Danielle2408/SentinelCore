using SentinelCore.Demon1.VisualVerification;

namespace SentinelCore.Demon1.Learning.Controller;

internal sealed class StartupAuthDialog : Form
{
    private readonly AuthStore _auth;
    private readonly string _dataRoot;
    private readonly LearningSettings _settings;
    private readonly Action? _onFailedAttempt;
    private readonly Button _face = new() { Text = "Reconnaissance faciale locale", Width = 390, Height = 46 };
    private readonly Button _password = new() { Text = "Mot de passe maître", Width = 390, Height = 46 };
    private readonly Label _status = new() { AutoSize = true, MaximumSize = new Size(400, 0) };

    public StartupAuthDialog(AuthStore auth, string dataRoot, LearningSettings settings, Action? onFailedAttempt = null)
    {
        _auth = auth; _dataRoot = dataRoot; _settings = settings; _onFailedAttempt = onFailedAttempt;
        Text = "Authentification — SentinelCore"; StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false;
        AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
        _face.Enabled = settings.VisualVerificationEnabled;
        _face.Click += async (_, _) => await VerifyFaceAsync();
        _password.Click += (_, _) => VerifyPassword();
        _status.Text = settings.VisualVerificationEnabled
            ? "Choisis une méthode pour ouvrir SentinelCore. La vérification faciale capture quelques secondes de vidéo et traite les images localement."
            : "La reconnaissance faciale n’est pas encore configurée. Ouvre avec le mot de passe maître, puis enrôle le visage dans l’application.";
        var panel = new TableLayoutPanel { AutoSize = true, Padding = new Padding(20), ColumnCount = 1, RowCount = 4 };
        panel.Controls.Add(new Label { Text = "Comment veux-tu ouvrir l’application ?", AutoSize = true, Font = new Font("Segoe UI", 11, FontStyle.Bold) });
        panel.Controls.Add(_face); panel.Controls.Add(_password); panel.Controls.Add(_status);
        Controls.Add(panel);
    }

    private async Task VerifyFaceAsync()
    {
        _face.Enabled = _password.Enabled = false;
        VisualVerificationService? verifier = null;
        try
        {
            verifier = CreateVerifier();
            if (!verifier.HasEnrolledProfiles)
            {
                _status.Text = "Aucun visage n’est enrôlé. Ouvre avec le mot de passe maître et configure le profil.";
                ReportFailedAttempt();
                return;
            }
            _status.Text = "Vérification en cours : regarde la caméra. Le contrôle peut prendre jusqu’à 60 secondes.";
            var correlationId = Guid.NewGuid().ToString("D");
            var result = await verifier.VerifyAlertAsync(correlationId);
            VisualCheckReportStore.Append(_dataRoot, "STARTUP_FACE_AUTH", result, verifier.LastCaptureDiagnostics);
            if (result.Match == VisualMatch.MATCH && result.Liveness == LivenessResult.LIVE && result.ProfileId is not null)
            {
                _auth.MarkOwnerAuthenticated();
                DialogResult = DialogResult.OK; Close(); return;
            }
            _status.Text = $"Visage non validé : {result.ReasonCode}. Tu peux réessayer ou utiliser le mot de passe maître.";
            ReportFailedAttempt();
        }
        catch (Exception ex) { _status.Text = "Vérification faciale impossible : " + ex.Message + " Tu peux utiliser le mot de passe maître."; ReportFailedAttempt(); }
        finally { verifier?.Dispose(); if (!IsDisposed) _face.Enabled = _password.Enabled = true; }
    }

    private VisualVerificationService CreateVerifier()
    {
        var modelRoot = Path.Combine(_dataRoot, "models");
        return new VisualVerificationService(new VisualVerificationOptions(
            Path.Combine(modelRoot, "face_detection_yunet_2023mar.onnx"),
            Path.Combine(modelRoot, "face_recognition_sface_2021dec.onnx"),
            Path.Combine(modelRoot, "MiniFASNetV2.onnx"),
            Path.Combine(_dataRoot, "visual"),
            CameraIndex: _settings.VisualCameraIndex,
            CaptureSeconds: 5,
            MaximumWaitSeconds: 60,
            Enabled: _settings.VisualVerificationEnabled,
            AlternativeLivenessModelPath: Path.Combine(modelRoot, "Facenox-MiniFASNetV2-SE.onnx")));
    }

    private void VerifyPassword()
    {
        using var dialog = new MasterPasswordDialog(isSetup: false) { Text = "Mot de passe maître — ouvrir SentinelCore" };
        if (dialog.ShowDialog(this) != DialogResult.OK || dialog.Password is null) return;
        try
        {
            if (!_auth.VerifyPassword(dialog.Password)) { ReportFailedAttempt(); MessageBox.Show("Mot de passe incorrect.", Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }
            DialogResult = DialogResult.OK; Close();
        }
        catch (Exception ex) { ReportFailedAttempt(); MessageBox.Show("Impossible de vérifier le mot de passe : " + ex.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Error); }
    }

    private void ReportFailedAttempt()
    {
        try { _onFailedAttempt?.Invoke(); }
        catch { /* Notification failure must never alter the authentication result. */ }
    }
}

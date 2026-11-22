namespace SentinelCore.Demon1.Learning.Controller;

internal sealed class LearningSettingsDialog : Form
{
    private readonly NumericUpDown _window = new() { Minimum = 10, Maximum = 60, Increment = 5, Width = 110 };
    private readonly NumericUpDown _idle = new() { Minimum = 30, Maximum = 900, Increment = 30, Width = 110 };
    private readonly NumericUpDown _profiles = new() { Minimum = 1, Maximum = 8, Increment = 1, Width = 110 };
    private readonly NumericUpDown _camera = new() { Minimum = 0, Maximum = 8, Increment = 1, Width = 110 };
    private readonly NumericUpDown _retention = new() { Minimum = 1, Maximum = 90, Increment = 1, Width = 110 };
    private readonly CheckBox _visualEnabled = new() { Text = "Autoriser le contrôle visuel demandé par le démon 3", AutoSize = true };
    public LearningSettings Value => new((int)_window.Value, (int)_idle.Value, (int)_profiles.Value,
        _visualEnabled.Checked, (int)_camera.Value, (int)_retention.Value);

    public LearningSettingsDialog(LearningSettings settings)
    {
        Text = "Paramètres du mode apprentissage"; StartPosition = FormStartPosition.CenterParent; FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false; MinimizeBox = false; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
        _window.Value = settings.WindowSeconds; _idle.Value = settings.IdleStopSeconds; _profiles.Value = settings.ProfileCount;
        _camera.Value = settings.VisualCameraIndex; _visualEnabled.Checked = settings.VisualVerificationEnabled;
        _retention.Value = settings.ContextRetentionDays;
        var panel = new TableLayoutPanel { Padding = new Padding(18), AutoSize = true, ColumnCount = 2 };
        panel.Controls.Add(new Label { Text = "Durée d’une période de mesure (secondes) :", AutoSize = true, Anchor = AnchorStyles.Left }); panel.Controls.Add(_window);
        panel.Controls.Add(new Label { Text = "Arrêt après inactivité (secondes) :", AutoSize = true, Anchor = AnchorStyles.Left }); panel.Controls.Add(_idle);
        panel.Controls.Add(new Label { Text = "Nombre de profils d’apprentissage sur ce PC :", AutoSize = true, Anchor = AnchorStyles.Left }); panel.Controls.Add(_profiles);
        panel.Controls.Add(new Label { Text = "Les profils sont séparés pour l’apprentissage. Sélectionne le bon profil avant de démarrer une collecte.", AutoSize = true, MaximumSize = new Size(420, 0) }); panel.SetColumnSpan(panel.GetControlFromPosition(0, 3)!, 2);
        panel.Controls.Add(new Label { Text = "Le texte saisi n’est pas enregistré. Les mesures agrégées du clavier sont conservées au plus 24 h; le profil chiffré garde uniquement ses résumés d’apprentissage.", AutoSize = true, MaximumSize = new Size(420, 0) }); panel.SetColumnSpan(panel.GetControlFromPosition(0, 4)!, 2);
        panel.Controls.Add(new Label { Text = "Conserver l’historique des applications et ressources (jours) :", AutoSize = true, Anchor = AnchorStyles.Left }); panel.Controls.Add(_retention);
        panel.Controls.Add(new Label { Text = "Index de la caméra :", AutoSize = true, Anchor = AnchorStyles.Left }); panel.Controls.Add(_camera);
        panel.Controls.Add(_visualEnabled); panel.SetColumnSpan(_visualEnabled, 2);
        panel.Controls.Add(new Label { Text = "Après activation et enrôlement, le contrôle démarre sur demande D3, sans confirmation répétée.", AutoSize = true, MaximumSize = new Size(420, 0) }); panel.SetColumnSpan(panel.GetControlFromPosition(0, 8)!, 2);
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
        var save = new Button { Text = "Enregistrer", DialogResult = DialogResult.OK, AutoSize = true }; var cancel = new Button { Text = "Annuler", DialogResult = DialogResult.Cancel, AutoSize = true };
        buttons.Controls.Add(save); buttons.Controls.Add(cancel); panel.Controls.Add(buttons); panel.SetColumnSpan(buttons, 2);
        Controls.Add(panel); AcceptButton = save; CancelButton = cancel;
    }
}

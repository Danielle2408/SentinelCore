namespace SentinelCore.Demon1.Learning.Controller;

internal sealed class MasterPasswordDialog : Form
{
    private readonly TextBox _password = new() { UseSystemPasswordChar = true, Width = 300 };
    private readonly TextBox _confirm = new() { UseSystemPasswordChar = true, Width = 300 };
    private readonly Label _message = new() { AutoSize = true, MaximumSize = new Size(400, 0) };
    public string? Password => _password.Text;

    public MasterPasswordDialog(bool isSetup, string? purpose = null)
    {
        Text = isSetup ? "Première configuration — SentinelCore" : "Mot de passe maître — SentinelCore";
        FormBorderStyle = FormBorderStyle.FixedDialog; StartPosition = FormStartPosition.CenterScreen; MaximizeBox = false; MinimizeBox = false;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(16), AutoSize = true, ColumnCount = 1 };
        var prompt = isSetup ? "Crée le mot de passe maître requis pour démarrer l’apprentissage."
            : string.IsNullOrWhiteSpace(purpose) ? "Entre le mot de passe maître pour confirmer ton identité."
            : $"Entre le mot de passe maître pour autoriser la mesure de sécurité : {purpose}.";
        layout.Controls.Add(new Label { Text = prompt, AutoSize = true, MaximumSize = new Size(400, 0) });
        layout.Controls.Add(new Label { Text = "Mot de passe (12 caractères minimum) :", AutoSize = true }); layout.Controls.Add(_password);
        if (isSetup) { layout.Controls.Add(new Label { Text = "Confirme le mot de passe :", AutoSize = true }); layout.Controls.Add(_confirm); }
        layout.Controls.Add(_message);
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
        var ok = new Button { Text = isSetup ? "Enregistrer" : "Vérifier", DialogResult = DialogResult.None, AutoSize = true };
        var cancel = new Button { Text = "Annuler", DialogResult = DialogResult.Cancel, AutoSize = true };
        buttons.Controls.Add(ok); buttons.Controls.Add(cancel); layout.Controls.Add(buttons); Controls.Add(layout);
        AcceptButton = ok; CancelButton = cancel; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink;
        ok.Click += (_, _) =>
        {
            if (_password.Text.Length < 12) { _message.Text = "Choisis au moins 12 caractères."; return; }
            if (isSetup && !StringComparer.Ordinal.Equals(_password.Text, _confirm.Text)) { _message.Text = "Les deux mots de passe sont différents."; return; }
            DialogResult = DialogResult.OK; Close();
        };
    }
}

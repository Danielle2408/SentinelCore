namespace SentinelCore.Demon1.Learning.Controller;

/// <summary>Standalone WinForms shell for the reusable D1 learning surface.</summary>
internal sealed class MainForm : Form
{
    private readonly Demon1LearningControl _learning;

    public MainForm(AuthStore auth, string workerExecutablePath)
    {
        Text = "SentinelCore — contrôle du mode apprentissage (Démon 1)";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(820, 620);
        Size = new Size(930, 700);
        _learning = new Demon1LearningControl(auth, workerExecutablePath) { Dock = DockStyle.Fill };
        Controls.Add(_learning);
        FormClosing += (_, e) =>
        {
            if (!_learning.ConfirmHostClosing()) e.Cancel = true;
        };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _learning.Dispose();
        base.Dispose(disposing);
    }
}

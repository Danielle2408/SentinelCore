using SentinelCore.Demon1.VisualVerification;

namespace SentinelCore.Demon1.Learning.Controller;

internal sealed class VisualReportsDialog : Form
{
    public VisualReportsDialog(string dataRoot)
    {
        Text = "Rapports de vérification visuelle — Démon 1"; StartPosition = FormStartPosition.CenterParent;
        Size = new Size(1280, 700); MinimumSize = new Size(950, 480);
        var rows = VisualCheckReportStore.ReadRecent(dataRoot).Select(x => new
        {
            Date = x.ObservedAtUtc.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"),
            Source = x.Source, Résultat = x.Status, Présence = x.Liveness, Profil = x.ProfileId ?? "—",
            Similarité = x.Similarity?.ToString("0.000") ?? "—", Qualité = x.FaceQuality.ToString("0.00"),
            Images = x.ValidFrames, Motif = x.ReasonCode, Diagnostic = x.DiagnosticSummary ?? "—",
            Preuve = string.IsNullOrWhiteSpace(x.EvidenceRef) ? "Aucune image" : "Afficher l’image",
            RéférencePreuve = x.EvidenceRef, Corrélation = x.CorrelationId
        }).ToArray();
        var grid = new DataGridView { Dock = DockStyle.Fill, ReadOnly = true, AutoGenerateColumns = true,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells, AllowUserToAddRows = false, DataSource = rows };
        if (grid.Columns["RéférencePreuve"] is { } evidenceColumn) evidenceColumn.Visible = false;
        var preview = new PictureBox { Dock = DockStyle.Fill, SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.FromArgb(28, 30, 34) };
        var previewLabel = new Label { Dock = DockStyle.Top, Height = 34, Text = "Image associée au rapport", TextAlign = ContentAlignment.MiddleLeft };
        var previewPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8) };
        previewPanel.Controls.Add(preview);
        previewPanel.Controls.Add(previewLabel);
        var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, SplitterDistance = 875, FixedPanel = FixedPanel.Panel2 };
        split.Panel1.Controls.Add(grid);
        split.Panel2.Controls.Add(previewPanel);
        Controls.Add(split);

        var evidenceReader = new VisualEvidenceReader(Path.Combine(dataRoot, "visual"));
        grid.SelectionChanged += (_, _) =>
        {
            preview.Image?.Dispose();
            preview.Image = null;
            var reference = grid.CurrentRow?.Cells["RéférencePreuve"].Value as string;
            if (string.IsNullOrWhiteSpace(reference))
            {
                previewLabel.Text = "Aucune image n’est associée à ce rapport";
                return;
            }

            try
            {
                var bytes = evidenceReader.ReadEvidence(reference);
                if (bytes is null) { previewLabel.Text = "Image absente ou illisible"; return; }
                using var stream = new MemoryStream(bytes);
                using var decoded = Image.FromStream(stream);
                preview.Image = new Bitmap(decoded);
                previewLabel.Text = "Image locale déchiffrée pour l’affichage";
            }
            catch (Exception ex) when (ex is IOException or ArgumentException or System.ComponentModel.Win32Exception or System.Runtime.InteropServices.ExternalException)
            {
                previewLabel.Text = "Impossible d’afficher l’image : " + ex.Message;
            }
        };
        Disposed += (_, _) => preview.Image?.Dispose();
    }
}

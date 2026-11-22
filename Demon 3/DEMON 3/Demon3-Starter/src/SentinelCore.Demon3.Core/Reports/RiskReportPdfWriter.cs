using System.Globalization;
using System.Text;
using SentinelCore.Demon3.Core.Decision;

namespace SentinelCore.Demon3.Core.Reports;

/// <summary>
/// Creates a small self-contained PDF without introducing another runtime dependency.
/// The only image format accepted is a bounded JPEG supplied by the report store.
/// </summary>
internal static class RiskReportPdfWriter
{
    private const int MaximumLines = 10_000;
    private const int LinesPerPage = 48;
    private const int MaximumTextLength = 2_000;

    public static byte[] Create(RiskReport report, byte[]? visualEvidence)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (visualEvidence is { Length: > 10 * 1024 * 1024 }) visualEvidence = null;
        var image = visualEvidence is { Length: > 3 } ? JpegInfo.TryRead(visualEvidence) : null;
        var lines = BuildLines(report, image is not null);
        if (lines.Count > MaximumLines) lines = lines.Take(MaximumLines).Append("Contenu tronqué : limite du rapport atteinte.").ToList();
        var textPages = lines.Chunk(LinesPerPage).Select(chunk => BuildTextPage(chunk)).ToList();
        if (textPages.Count == 0) textPages.Add(BuildTextPage(["Rapport vide."]));
        var pages = textPages.Select(x => new PdfPage(x, null)).ToList();
        if (image is not null) pages.Add(new PdfPage(BuildImagePage(), image));
        return WritePdf(pages);
    }

    private static List<string> BuildLines(RiskReport report, bool hasImage)
    {
        var lines = new List<string>
        {
            "SENTINELCORE - RAPPORT DE RISQUE",
            $"Date UTC : {report.CreatedAtUtc:O}",
            $"Reference : {report.Decision.CorrelationId}",
            $"Niveau de risque : {report.Decision.Risk}",
            $"Decision : {report.Decision.Decision}",
            $"Mesure proposee : {report.Decision.ProposedAction}",
            $"Mode simulation : {(report.Decision.SimulationOnly ? "oui" : "non")}",
            $"Approbation du proprietaire requise : {(report.Decision.RequiresHumanApproval ? "oui" : "non")}",
            "",
            "EXPLICATION",
            Limit(report.Decision.Explanation),
            "",
            "MOTIFS",
            Limit(string.Join(", ", report.Decision.ReasonCodes)),
            "",
            "REFERENCES DE PREUVE",
            Limit(string.Join(", ", report.Decision.EvidenceRefs)),
            "",
            $"Photo de verification : {(hasImage ? "incluse sur la derniere page" : "aucune copie decryptable incluse")}",
            $"Comparaison anterieure : {report.Comparison.Result} ({report.Comparison.Basis})",
            Limit(report.Comparison.Explanation)
        };

        if (report.ActionResult is { } action)
        {
            lines.Add(""); lines.Add("RESULTAT DE LA MESURE");
            lines.Add($"{action.ActionId} - {action.Status} - simulation : {(action.SimulationOnly ? "oui" : "non")}");
            lines.Add(Limit(action.Explanation));
        }

        if (report.AiAdvice is { } advice)
        {
            lines.Add(""); lines.Add("CONSEIL IA LOCALE");
            lines.Add($"Statut : {advice.Status}; modele : {Limit(advice.Model, 120)}; code : {Limit(advice.ErrorCode ?? "aucun", 120)}");
            if (advice.DurationMilliseconds is { } duration && double.IsFinite(duration))
                lines.Add($"Duree : {duration.ToString("F0", CultureInfo.InvariantCulture)} ms");
            if (advice.Advice is { } suggestion)
            {
                lines.Add($"Evaluation : {suggestion.RiskBand}; confiance : {suggestion.Confidence:P0}; mesure : {suggestion.SuggestedMeasure}");
                lines.Add("Analyse : " + Limit(suggestion.Assessment));
                lines.Add("Resume : " + Limit(suggestion.Summary));
                lines.Add("Justification : " + Limit(suggestion.Rationale));
                AddList(lines, "Constats IA", suggestion.KeyFindings);
                AddList(lines, "Explications benignes possibles", suggestion.BenignExplanations);
                AddList(lines, "Hypotheses de menace", suggestion.ThreatHypotheses);
                AddList(lines, "Incertitudes", suggestion.Uncertainties);
                if (!string.IsNullOrWhiteSpace(suggestion.CapabilityGap))
                    lines.Add("Capacite manquante : " + Limit(suggestion.CapabilityGap));
                if (!string.IsNullOrWhiteSpace(suggestion.PlaybookDraft))
                    lines.Add("Un brouillon de procedure inerte est conserve dans le rapport JSON et n'est pas reproduit dans ce PDF.");
            }
        }

        lines.Add(""); lines.Add("SIGNAUX REÇUS");
        foreach (var signal in report.Signals.Take(100))
            lines.Add(Limit($"{signal.SourceDaemon}/{signal.MessageType} - niveau {signal.Severity} - motif {signal.ReasonCode ?? "non precise"} - preuves {string.Join(",", signal.EvidenceRefs.Take(16))}"));
        return lines.SelectMany(WrapLine).Take(MaximumLines + 1).ToList();
    }

    private static void AddList(List<string> lines, string title, IReadOnlyList<string> items)
    {
        if (items.Count == 0) return;
        lines.Add(title + " :");
        foreach (var item in items.Take(8)) lines.Add("- " + Limit(item));
    }

    private static string Limit(string? value, int maximum = MaximumTextLength)
    {
        if (string.IsNullOrWhiteSpace(value)) return "non precise";
        var normalized = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return normalized.Length <= maximum ? normalized : normalized[..maximum] + "...";
    }

    private static IEnumerable<string> WrapLine(string line)
    {
        const int max = 102;
        var text = Limit(line);
        while (text.Length > max)
        {
            var cut = text.LastIndexOf(' ', max, max);
            if (cut <= 0) cut = max;
            yield return text[..cut];
            text = text[cut..].TrimStart();
        }
        yield return text;
    }

    private static byte[] BuildTextPage(IReadOnlyList<string> lines)
    {
        var builder = new StringBuilder("BT\n/F1 10 Tf\n14 TL\n54 738 Td\n");
        foreach (var line in lines)
        {
            builder.Append('(').Append(EscapePdfText(line)).Append(") Tj\nT*\n");
        }
        builder.Append("ET\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static byte[] BuildImagePage()
    {
        const string content = "BT\n/F1 10 Tf\n54 750 Td\n(Preuve visuelle associee a la verification d'identite) Tj\nET\nq\n460 0 0 345 67 350 cm\n/Im0 Do\nQ\n";
        return Encoding.ASCII.GetBytes(content);
    }

    private static string EscapePdfText(string value)
    {
        var normalized = value.Normalize(NormalizationForm.FormD);
        var result = new StringBuilder(Math.Min(normalized.Length, 512));
        foreach (var c in normalized)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.NonSpacingMark) continue;
            var safe = c is >= ' ' and <= '~' ? c : '?';
            if (safe is '\\' or '(' or ')') result.Append('\\');
            if (safe is >= ' ' and <= '~') result.Append(safe);
            if (result.Length >= 480) break;
        }
        return result.ToString();
    }

    private static byte[] WritePdf(IReadOnlyList<PdfPage> pages)
    {
        var objects = new List<byte[]?> { null };
        int AddObject(byte[] data) { objects.Add(data); return objects.Count - 1; }
        var catalogId = AddObject([]);
        var pagesId = AddObject([]);
        var fontId = AddObject(Ascii("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"));
        var imageId = pages.Select(x => x.Image).FirstOrDefault(x => x is not null) is { } visual
            ? AddObject(CreateImageObject(visual)) : 0;

        var pageIds = new List<int>();
        foreach (var page in pages)
        {
            var pageId = AddObject([]);
            var contentId = AddObject(CreateStreamObject(page.Content));
            var resources = imageId == 0
                ? $"/Font << /F1 {fontId} 0 R >>"
                : $"/Font << /F1 {fontId} 0 R >> /XObject << /Im0 {imageId} 0 R >>";
            objects[pageId] = Ascii($"<< /Type /Page /Parent {pagesId} 0 R /MediaBox [0 0 612 792] /Resources << {resources} >> /Contents {contentId} 0 R >>");
            pageIds.Add(pageId);
        }

        objects[pagesId] = Ascii($"<< /Type /Pages /Kids [{string.Join(' ', pageIds.Select(id => $"{id} 0 R"))}] /Count {pageIds.Count} >>");
        objects[catalogId] = Ascii($"<< /Type /Catalog /Pages {pagesId} 0 R >>");

        using var output = new MemoryStream();
        WriteAscii(output, "%PDF-1.4\n% SentinelCore report\n");
        var offsets = new long[objects.Count];
        for (var id = 1; id < objects.Count; id++)
        {
            offsets[id] = output.Position;
            WriteAscii(output, $"{id} 0 obj\n");
            output.Write(objects[id] ?? throw new InvalidOperationException("PDF object was not initialized."));
            WriteAscii(output, "\nendobj\n");
        }

        var xrefOffset = output.Position;
        WriteAscii(output, $"xref\n0 {objects.Count}\n0000000000 65535 f \n");
        for (var id = 1; id < offsets.Length; id++)
            WriteAscii(output, offsets[id].ToString("D10", CultureInfo.InvariantCulture) + " 00000 n \n");
        WriteAscii(output, $"trailer\n<< /Size {objects.Count} /Root {catalogId} 0 R >>\nstartxref\n{xrefOffset.ToString(CultureInfo.InvariantCulture)}\n%%EOF\n");
        return output.ToArray();
    }

    private static byte[] CreateImageObject(JpegInfo image)
    {
        var header = Ascii($"<< /Type /XObject /Subtype /Image /Width {image.Width} /Height {image.Height} /ColorSpace {(image.Components == 1 ? "/DeviceGray" : "/DeviceRGB")} /BitsPerComponent 8 /Filter /DCTDecode /Length {image.Bytes.Length} >>\nstream\n");
        var footer = Ascii("\nendstream");
        var result = new byte[header.Length + image.Bytes.Length + footer.Length];
        Buffer.BlockCopy(header, 0, result, 0, header.Length);
        Buffer.BlockCopy(image.Bytes, 0, result, header.Length, image.Bytes.Length);
        Buffer.BlockCopy(footer, 0, result, header.Length + image.Bytes.Length, footer.Length);
        return result;
    }

    private static byte[] CreateStreamObject(byte[] stream)
    {
        var header = Ascii($"<< /Length {stream.Length} >>\nstream\n");
        var footer = Ascii("\nendstream");
        var result = new byte[header.Length + stream.Length + footer.Length];
        Buffer.BlockCopy(header, 0, result, 0, header.Length);
        Buffer.BlockCopy(stream, 0, result, header.Length, stream.Length);
        Buffer.BlockCopy(footer, 0, result, header.Length + stream.Length, footer.Length);
        return result;
    }

    private static byte[] Ascii(string value) => Encoding.ASCII.GetBytes(value);
    private static void WriteAscii(Stream output, string value) => output.Write(Ascii(value));

    private sealed record PdfPage(byte[] Content, JpegInfo? Image);

    private sealed record JpegInfo(byte[] Bytes, int Width, int Height, int Components)
    {
        private static readonly HashSet<byte> StartOfFrameMarkers = [
            0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF];

        public static JpegInfo? TryRead(byte[] bytes)
        {
            if (bytes.Length is < 8 or > 10 * 1024 * 1024 || bytes[0] != 0xFF || bytes[1] != 0xD8) return null;
            var offset = 2;
            while (offset + 3 < bytes.Length)
            {
                if (bytes[offset++] != 0xFF) continue;
                while (offset < bytes.Length && bytes[offset] == 0xFF) offset++;
                if (offset >= bytes.Length) return null;
                var marker = bytes[offset++];
                if (marker is 0xD8 or 0xD9 or 0x01 or >= 0xD0 and <= 0xD7) continue;
                if (offset + 1 >= bytes.Length) return null;
                var segmentLength = (bytes[offset] << 8) | bytes[offset + 1];
                if (segmentLength < 2 || offset + segmentLength > bytes.Length) return null;
                if (StartOfFrameMarkers.Contains(marker))
                {
                    if (segmentLength < 8) return null;
                    var height = (bytes[offset + 3] << 8) | bytes[offset + 4];
                    var width = (bytes[offset + 5] << 8) | bytes[offset + 6];
                    var components = bytes[offset + 7];
                    return width > 0 && height > 0 && components is 1 or 3 ? new(bytes, width, height, components) : null;
                }
                offset += segmentLength;
            }
            return null;
        }
    }
}

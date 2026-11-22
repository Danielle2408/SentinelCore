using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SentinelCore.Demon2.Core;

/// <summary>
/// Converts PowerShell 4104 records into category-only events. Script bodies and paths are inspected
/// in memory and are deliberately never copied into the canonical event or SentinelCore database.
/// </summary>
public sealed class PowerShellScriptBlockEventNormalizer : IEventNormalizer<SysmonRecord>
{
    public const int MaxEventXmlCharacters = 1_048_576;
    public const int MaxBookmarkCharacters = 65_536;

    public bool TryNormalize(SysmonRecord record, out CanonicalEvent? result, out string? rejectionReason)
    {
        result = null;
        rejectionReason = null;
        try
        {
            if (record.SourceName != "PowerShell") return Reject("Record is not from PowerShell Operational.", out rejectionReason);
            if (string.IsNullOrWhiteSpace(record.Xml) || record.Xml.Length > MaxEventXmlCharacters)
                return Reject("PowerShell event XML is empty or exceeds the ingestion limit.", out rejectionReason);
            if (record.BookmarkXml?.Length > MaxBookmarkCharacters)
                return Reject("PowerShell bookmark exceeds the ingestion limit.", out rejectionReason);

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxEventXmlCharacters,
                MaxCharactersFromEntities = 0
            };
            using var reader = XmlReader.Create(new StringReader(record.Xml), settings);
            var document = XDocument.Load(reader, LoadOptions.None);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var system = document.Root?.Element(ns + "System");
            if (!int.TryParse((string?)system?.Element(ns + "EventID"), NumberStyles.None, CultureInfo.InvariantCulture, out var eventId)
                || eventId != 4104
                || !long.TryParse((string?)system?.Element(ns + "EventRecordID"), NumberStyles.None, CultureInfo.InvariantCulture, out var recordId)
                || recordId < 0
                || !DateTimeOffset.TryParse((string?)system?.Element(ns + "TimeCreated")?.Attribute("SystemTime"),
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var timestamp))
                return Reject("PowerShell event is missing an allowed ID, record number or UTC timestamp.", out rejectionReason);

            var execution = system.Element(ns + "Execution");
            int? processId = ParseProcessId((string?)execution?.Attribute("ProcessID"));
            if ((string?)execution?.Attribute("ProcessID") is { Length: > 0 } processIdText && processId is null)
                return Reject("PowerShell process identifier is invalid.", out rejectionReason);

            var data = document.Descendants(ns + "Data")
                .Where(x => x.Attribute("Name") is not null)
                .GroupBy(x => (string)x.Attribute("Name")!, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(x => x.Key, x => x.Last().Value, StringComparer.OrdinalIgnoreCase);
            if (!data.TryGetValue("ScriptBlockText", out var scriptText) || scriptText.Length > 1_000_000)
                return Reject("PowerShell event does not contain a bounded script-block fragment.", out rejectionReason);

            var indicators = ClassifyIndicators(scriptText);
            var fields = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["providerEventId"] = "4104",
                ["scriptLength"] = scriptText.Length.ToString(CultureInfo.InvariantCulture),
                ["scriptIndicators"] = indicators.Count == 0 ? "none" : string.Join(',', indicators),
                ["scriptTextStored"] = "false"
            };
            AddBoundedInteger(data, "MessageNumber", "fragmentNumber", fields);
            AddBoundedInteger(data, "MessageTotal", "fragmentTotal", fields);

            var stable = Encoding.UTF8.GetBytes($"PowerShell|{recordId.ToString(CultureInfo.InvariantCulture)}");
            result = new CanonicalEvent(Convert.ToHexString(SHA256.HashData(stable)).ToLowerInvariant(),
                timestamp.ToUniversalTime(), "PowerShell", recordId.ToString(CultureInfo.InvariantCulture),
                Environment.MachineName, ThreatEventType.SCRIPT_ACTIVITY, ProcessId: processId,
                Fields: fields, SchemaVersion: 1, SourceCursor: record.BookmarkXml);
            return true;
        }
        catch (Exception ex) when (ex is XmlException or FormatException or ArgumentException or InvalidOperationException)
        {
            return Reject($"Invalid PowerShell event XML ({ex.GetType().Name}).", out rejectionReason);
        }
    }

    private static int? ParseProcessId(string? value)
    {
        if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var processId) && processId >= 0)
            return processId;
        if (value?.StartsWith("0x", StringComparison.OrdinalIgnoreCase) == true
            && int.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out processId) && processId >= 0)
            return processId;
        return null;
    }

    private static void AddBoundedInteger(IReadOnlyDictionary<string, string> source, string inputName,
        string outputName, IDictionary<string, string> fields)
    {
        if (source.TryGetValue(inputName, out var value)
            && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed)
            && parsed is >= 1 and <= 10_000)
            fields[outputName] = parsed.ToString(CultureInfo.InvariantCulture);
    }

    private static IReadOnlyList<string> ClassifyIndicators(string script)
    {
        var remoteDownload = ContainsAny(script, "Invoke-WebRequest", "Invoke-RestMethod", "DownloadString(",
            "DownloadFile(", "Start-BitsTransfer", "Net.WebClient");
        var dynamicExecution = ContainsAny(script, "Invoke-Expression", "iex ", "iex(",
            "[ScriptBlock]::Create", "ScriptBlock]::Create");
        var encodedContent = ContainsAny(script, "-EncodedCommand", "-EncodedCommand ", "FromBase64String(");
        var defenderChange = ContainsAny(script, "DisableRealtimeMonitoring", "Add-MpPreference",
            "Set-MpPreference", "Stop-Service WinDefend", "Set-Service WinDefend");
        var credentialTooling = ContainsAny(script, "sekurlsa", "Invoke-Mimikatz", "MiniDumpWriteDump",
            "comsvcs.dll", "procdump.exe -ma");

        var result = new List<string>(4);
        if (remoteDownload && dynamicExecution) result.Add("REMOTE_CONTENT_EXECUTION");
        if (encodedContent && dynamicExecution) result.Add("OBFUSCATED_DYNAMIC_EXECUTION");
        if (defenderChange) result.Add("DEFENDER_CONFIGURATION_CHANGE");
        if (credentialTooling) result.Add("CREDENTIAL_DUMP_TOOLING");
        return result;
    }

    private static bool ContainsAny(string text, params string[] values)
        => values.Any(value => text.Contains(value, StringComparison.OrdinalIgnoreCase));

    private static bool Reject(string message, out string? rejectionReason)
    {
        rejectionReason = message;
        return false;
    }
}

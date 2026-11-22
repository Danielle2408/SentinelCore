using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace SentinelCore.Demon2.Core;

/// <summary>Routes allowlisted Windows security providers to their dedicated, privacy-minimized parsers.</summary>
public sealed class WindowsSecurityEventNormalizer : IEventNormalizer<SysmonRecord>
{
    private readonly SysmonEventNormalizer _sysmon = new();
    private readonly DefenderOperationalEventNormalizer _defender = new();
    private readonly PowerShellScriptBlockEventNormalizer _powerShell = new();

    public bool TryNormalize(SysmonRecord input, out CanonicalEvent? result, out string? rejectionReason)
        => input.SourceName switch
        {
            "Sysmon" => _sysmon.TryNormalize(input, out result, out rejectionReason),
            "WindowsDefender" => _defender.TryNormalize(input, out result, out rejectionReason),
            "PowerShell" => _powerShell.TryNormalize(input, out result, out rejectionReason),
            _ => Reject("Unknown Windows telemetry source.", out result, out rejectionReason)
        };

    private static bool Reject(string message, out CanonicalEvent? result, out string? reason)
    {
        result = null;
        reason = message;
        return false;
    }
}

/// <summary>
/// Reads only high-signal Defender Operational events. It intentionally stores neither detection paths,
/// threat names, user names nor raw XML in the canonical event.
/// </summary>
public sealed class DefenderOperationalEventNormalizer : IEventNormalizer<SysmonRecord>
{
    public const int MaxEventXmlCharacters = 1_048_576;
    public const int MaxBookmarkCharacters = 65_536;

    public bool TryNormalize(SysmonRecord record, out CanonicalEvent? result, out string? rejectionReason)
    {
        result = null;
        rejectionReason = null;
        try
        {
            if (record.SourceName != "WindowsDefender") return Reject("Record is not from Windows Defender.", out rejectionReason);
            if (string.IsNullOrWhiteSpace(record.Xml) || record.Xml.Length > MaxEventXmlCharacters)
                return Reject("Defender event XML is empty or exceeds the ingestion limit.", out rejectionReason);
            if (record.BookmarkXml?.Length > MaxBookmarkCharacters)
                return Reject("Defender bookmark exceeds the ingestion limit.", out rejectionReason);

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
                || !long.TryParse((string?)system?.Element(ns + "EventRecordID"), NumberStyles.None, CultureInfo.InvariantCulture, out var recordId)
                || recordId < 0
                || !DateTimeOffset.TryParse((string?)system?.Element(ns + "TimeCreated")?.Attribute("SystemTime"),
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var timestamp))
                return Reject("Defender event is missing a valid ID, record number or UTC timestamp.", out rejectionReason);

            var eventType = eventId switch
            {
                1116 => ThreatEventType.DEFENDER_MALWARE_DETECTED,
                1117 => ThreatEventType.DEFENDER_ACTION_TAKEN,
                5001 or 5010 => ThreatEventType.DEFENDER_PROTECTION_DISABLED,
                _ => (ThreatEventType?)null
            };
            if (eventType is null) return Reject($"Defender event ID {eventId} is outside the allowlist.", out rejectionReason);

            var data = document.Descendants(ns + "Data")
                .Where(x => x.Attribute("Name") is not null)
                .GroupBy(x => NormalizeName((string)x.Attribute("Name")!), StringComparer.Ordinal)
                .ToDictionary(x => x.Key, x => x.Last().Value.Trim(), StringComparer.Ordinal);

            var fields = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["providerEventId"] = eventId.ToString(CultureInfo.InvariantCulture),
                ["eventCategory"] = eventType.Value switch
                {
                    ThreatEventType.DEFENDER_MALWARE_DETECTED => "malware_detection",
                    ThreatEventType.DEFENDER_ACTION_TAKEN => "defender_action",
                    _ => "protection_disabled"
                }
            };
            if (eventId == 1116)
                fields["defenderSeverity"] = NormalizeSeverity(First(data, "severityname", "threatseverity", "severity"));
            if (eventId is 5001 or 5010)
                fields["protectionFeature"] = eventId == 5001 ? "real_time_protection" : "antispyware_scanning";

            var stable = Encoding.UTF8.GetBytes($"WindowsDefender|{recordId.ToString(CultureInfo.InvariantCulture)}");
            result = new CanonicalEvent(Convert.ToHexString(SHA256.HashData(stable)).ToLowerInvariant(),
                timestamp.ToUniversalTime(), "WindowsDefender", recordId.ToString(CultureInfo.InvariantCulture),
                Environment.MachineName, eventType.Value, Fields: fields, SchemaVersion: 1, SourceCursor: record.BookmarkXml);
            return true;
        }
        catch (Exception ex) when (ex is XmlException or FormatException or ArgumentException or InvalidOperationException)
        {
            return Reject($"Invalid Defender event XML ({ex.GetType().Name}).", out rejectionReason);
        }
    }

    private static string NormalizeName(string value)
        => new(value.Where(char.IsAsciiLetterOrDigit).Select(char.ToLowerInvariant).ToArray());

    private static string? First(IReadOnlyDictionary<string, string> values, params string[] keys)
        => keys.Select(key => values.GetValueOrDefault(key)).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    private static string NormalizeSeverity(string? value)
    {
        if (value?.Contains("severe", StringComparison.OrdinalIgnoreCase) == true) return "critical";
        if (value?.Contains("high", StringComparison.OrdinalIgnoreCase) == true) return "high";
        if (value?.Contains("low", StringComparison.OrdinalIgnoreCase) == true) return "low";
        if (value?.Contains("moderate", StringComparison.OrdinalIgnoreCase) == true
            || value?.Contains("medium", StringComparison.OrdinalIgnoreCase) == true) return "medium";
        return "unknown";
    }

    private static bool Reject(string message, out string? rejectionReason)
    {
        rejectionReason = message;
        return false;
    }
}

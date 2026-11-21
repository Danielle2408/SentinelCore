using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.Xml;

namespace SentinelCore.Demon2.Core;

public sealed class SysmonEventNormalizer : IEventNormalizer<SysmonRecord>
{
    public const int MaxSysmonXmlCharacters = 1_048_576;
    public const int MaxBookmarkCharacters = 65_536;
    private const int MaxWindowsPathCharacters = 32_767;
    private static readonly HashSet<string> Interpreters = new(StringComparer.OrdinalIgnoreCase)
    { "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "rundll32.exe" };

    public bool TryNormalize(SysmonRecord record, out CanonicalEvent? result, out string? rejectionReason)
    {
        result = null;
        rejectionReason = null;
        try
        {
            if (string.IsNullOrWhiteSpace(record.Xml))
            {
                rejectionReason = "Sysmon XML is empty.";
                return false;
            }
            if (record.Xml.Length > MaxSysmonXmlCharacters)
            {
                rejectionReason = $"Sysmon XML exceeds the {MaxSysmonXmlCharacters}-character ingestion limit.";
                return false;
            }
            if (record.BookmarkXml?.Length > MaxBookmarkCharacters)
            {
                rejectionReason = "Sysmon bookmark exceeds the ingestion limit.";
                return false;
            }

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxSysmonXmlCharacters,
                MaxCharactersFromEntities = 0
            };
            using var xmlReader = XmlReader.Create(new StringReader(record.Xml), settings);
            var document = XDocument.Load(xmlReader, LoadOptions.None);
            var ns = (XNamespace)"http://schemas.microsoft.com/win/2004/08/events/event";
            var system = document.Root?.Element(ns + "System");
            var eventIdText = (string?)system?.Element(ns + "EventID");
            var recordId = (string?)system?.Element(ns + "EventRecordID");
            var timeText = (string?)system?.Element(ns + "TimeCreated")?.Attribute("SystemTime");
            if (!int.TryParse(eventIdText, NumberStyles.None, CultureInfo.InvariantCulture, out var eventId) || eventId <= 0 ||
                !long.TryParse(recordId, NumberStyles.None, CultureInfo.InvariantCulture, out var numericRecordId) || numericRecordId < 0 ||
                !DateTimeOffset.TryParse(timeText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var timestamp))
            {
                rejectionReason = "Invalid or missing Sysmon event ID, record ID, or timestamp.";
                return false;
            }

            var data = document.Descendants(ns + "Data")
                .Where(x => x.Attribute("Name") is not null)
                .GroupBy(x => (string)x.Attribute("Name")!, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.Last().Value, StringComparer.OrdinalIgnoreCase);

            string? Get(string name) => data.GetValueOrDefault(name);
            int? Int(string? value)
            {
                if (int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)) return parsed;
                if (value?.StartsWith("0x", StringComparison.OrdinalIgnoreCase) == true && int.TryParse(value[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed)) return parsed;
                return null;
            }
            bool ValidOptionalProcessId(string field)
            {
                var value = Get(field);
                return string.IsNullOrEmpty(value) || Int(value) is >= 0;
            }
            if (!ValidOptionalProcessId("ProcessId") || !ValidOptionalProcessId("ParentProcessId") ||
                !ValidOptionalProcessId("SourceProcessId") || !ValidOptionalProcessId("TargetProcessId"))
            {
                rejectionReason = "Sysmon process identifiers must be non-negative integers.";
                return false;
            }
            var destinationPortText = Get("DestinationPort");
            var destinationPort = Int(destinationPortText);
            if (destinationPortText is not null && destinationPort is not (>= 1 and <= 65_535))
            {
                rejectionReason = "Sysmon destination port is outside the valid TCP/UDP port range.";
                return false;
            }

            var imagePath = Get("Image") ?? (eventId == 10 ? Get("SourceImage") : null);
            var targetPath = eventId == 7 ? Get("ImageLoaded") : Get("TargetFilename");
            if (targetPath?.Length > MaxWindowsPathCharacters || imagePath?.Length > MaxWindowsPathCharacters)
            {
                rejectionReason = "Sysmon process image or file path exceeds the Windows path limit.";
                return false;
            }

            ThreatEventType? type = eventId switch
            {
                1 => IsInterpreter(Get("Image")) ? ThreatEventType.SCRIPT_ACTIVITY : ThreatEventType.PROCESS_STARTED,
                2 or 11 or 23 or 26 => ThreatEventType.FILE_CREATED_OR_CHANGED,
                3 => ThreatEventType.NETWORK_CONNECTION,
                22 => ThreatEventType.DOMAIN_QUERY,
                7 => ThreatEventType.IMAGE_LOAD,
                10 => ThreatEventType.PROCESS_ACCESS,
                12 or 13 or 14 when IsPersistenceTarget(Get("TargetObject")) => ThreatEventType.PERSISTENCE_CHANGE,
                15 when IsZoneIdentifier(Get("TargetFilename")) => ThreatEventType.DOWNLOAD_OBSERVED,
                4 when string.Equals(Get("State"), "Stopped", StringComparison.OrdinalIgnoreCase) => ThreatEventType.TELEMETRY_GAP,
                16 => ThreatEventType.TELEMETRY_GAP,
                _ => null
            };
            if (type is null)
            {
                rejectionReason = $"Sysmon event ID {eventId} is outside the MVP event map.";
                return false;
            }

            var path = targetPath;
            if (type == ThreatEventType.DOWNLOAD_OBSERVED && path is not null)
                path = path[..path.IndexOf(":Zone.Identifier", StringComparison.OrdinalIgnoreCase)];

            var fields = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["providerEventId"] = eventId.ToString(CultureInfo.InvariantCulture)
            };
            AddIfPresent(fields, "parentImage", Get("ParentImage"));
            AddIfPresent(fields, "targetImage", Get("TargetImage"));
            AddIfPresent(fields, "targetProcessId", Get("TargetProcessId"));
            AddIfPresent(fields, "targetProcessGuid", Get("TargetProcessGuid"));
            AddIfPresent(fields, "grantedAccess", Get("GrantedAccess"));
            AddIfPresent(fields, "imageLoaded", Get("ImageLoaded"));
            AddIfPresent(fields, "signatureStatus", Get("Signed"));
            AddIfPresent(fields, "queryName", Get("QueryName"));
            AddIfPresent(fields, "queryStatus", Get("QueryStatus"));
            AddIfPresent(fields, "fixtureDescription", Get("FixtureDescription"));
            AddIfPresent(fields, "synthetic", Get("FixtureSynthetic"));
            AddIfPresent(fields, "targetObject", Get("TargetObject"));

            var remoteHostCandidates = new[] { Get("DestinationHostname"), Get("DestinationIp"), Get("QueryName") }
                .Where(x => !string.IsNullOrWhiteSpace(x)).ToArray();
            var remoteHost = remoteHostCandidates.Select(NormalizeRemoteHost).FirstOrDefault(x => x is not null);
            if (remoteHostCandidates.Length > 0 && remoteHost is null) fields["invalidRemoteHost"] = "true";

            var hashCandidate = Get("Hashes")?.Split(',', StringSplitOptions.TrimEntries)
                .FirstOrDefault(x => x.StartsWith("SHA256=", StringComparison.OrdinalIgnoreCase))?[7..];
            var hash = IsSha256(hashCandidate) ? hashCandidate : null;
            if (!string.IsNullOrWhiteSpace(hashCandidate) && hash is null) fields["invalidSha256"] = "true";
            var stable = Encoding.UTF8.GetBytes($"Sysmon|{numericRecordId.ToString(CultureInfo.InvariantCulture)}");
            result = new CanonicalEvent(
                Convert.ToHexString(SHA256.HashData(stable)).ToLowerInvariant(), timestamp.ToUniversalTime(), "Sysmon",
                recordId, Environment.MachineName, type.Value,
                Int(Get("ProcessId") ?? (eventId == 10 ? Get("SourceProcessId") : null)),
                Get("ProcessGuid") ?? (eventId == 10 ? Get("SourceProcessGuid") : null),
                Int(Get("ParentProcessId")), Get("ParentProcessGuid"),
                imagePath, Get("Signed"), hash,
                path ?? (eventId == 7 ? Get("ImageLoaded") : eventId == 10 ? Get("TargetImage") : null),
                remoteHost, destinationPort,
                null, null, fields, 1, record.BookmarkXml);
            return true;
        }
        catch (Exception ex) when (ex is System.Xml.XmlException or FormatException or ArgumentException)
        {
            rejectionReason = $"Invalid Sysmon XML ({ex.GetType().Name}).";
            return false;
        }
    }

    private static bool IsInterpreter(string? image) => image is not null && Interpreters.Contains(Path.GetFileName(image));
    private static bool IsSha256(string? value) => value is { Length: 64 } && value.All(Uri.IsHexDigit);
    private static string? NormalizeRemoteHost(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253 || value.Any(char.IsControl) || value.Any(char.IsWhiteSpace)) return null;
        var host = value.Trim().Trim('[', ']').TrimEnd('.');
        return IPAddress.TryParse(host, out _) || Uri.CheckHostName(host) == UriHostNameType.Dns ? value.Trim() : null;
    }
    private static bool IsZoneIdentifier(string? target) => target?.Contains(":Zone.Identifier", StringComparison.OrdinalIgnoreCase) == true;
    private static bool IsPersistenceTarget(string? target) => target is not null &&
        (target.Contains(@"\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN", StringComparison.OrdinalIgnoreCase)
         || target.Contains(@"\SYSTEM\CURRENTCONTROLSET\SERVICES\", StringComparison.OrdinalIgnoreCase)
         || target.Contains(@"\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\SCHEDULE\TASKCACHE\", StringComparison.OrdinalIgnoreCase));
    private static void AddIfPresent(IDictionary<string, string> fields, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) fields[name] = value;
    }
}

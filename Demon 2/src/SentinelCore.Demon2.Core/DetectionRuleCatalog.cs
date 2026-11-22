namespace SentinelCore.Demon2.Core;

public sealed record DetectionRuleDefinition(
    string RuleId,
    int RuleVersion,
    string Description,
    IReadOnlyList<string> Conditions,
    IReadOnlyList<string> Evidence,
    double Confidence,
    ThreatSeverity Severity);

public static class DetectionRuleCatalog
{
    public static IReadOnlyList<DetectionRuleDefinition> All { get; } =
    [
        Rule("download_chain", "Downloaded executable is followed by execution and corroborating network or script activity.",
            ["download observed", "later process or script execution observed", "subsequent network, script, or persistence corroboration within the correlation window"],
            ["download event", "process/script event", "network or persistence event"], .88, ThreatSeverity.high),
        Rule("script_child", "An unexpected document or archive parent launches an interpreter with corroborating activity.",
            ["script activity", "unexpected parent context", "parent/child or corroborating file, network, or persistence evidence"],
            ["parent process", "interpreter process", "corroborating event"], .82, ThreatSeverity.high),
        Rule("drop_then_persistence", "Process activity is linked to a change in an observed persistence location.",
            ["process or script event", "observed persistence change", "events linked in the time window"],
            ["process/script event", "persistence event"], .90, ThreatSeverity.high),
        Rule("file_burst", "A single process rapidly changes many files outside known benign producer contexts.",
            ["at least 30 file events by one process in 10 seconds, or explicit synthetic sandbox burst evidence", "not a known Defender or build output producer"],
            ["file change events", "process identity", "time window"], .94, ThreatSeverity.high),
        Rule("network_corroboration", "A network event is corroborated by suspicious script, download, persistence, or file activity.",
            ["network connection observed", "at least one corroborating behavior in the time window"],
            ["network event", "corroborating event"], .68, ThreatSeverity.high),
        Rule("repeated_dns", "One process repeatedly queries the same domain in a short interval; no reputation is inferred.",
            ["at least five DNS query events in 60 seconds for production telemetry, or an explicit synthetic repeated-query summary", "same process identity", "same normalized domain"],
            ["DNS query events", "process identity", "normalized domain", "time window"], .75, ThreatSeverity.high),
        Rule("unusual_image_load", "An unsigned image from a user-writable location is loaded by a process with corroborating suspicious activity.",
            ["Sysmon ImageLoad event", "unsigned signer status", "user-writable image path", "same process has corroborating script, network, persistence, or download evidence"],
            ["image-load event", "signer status", "image path", "corroborating process event"], .75, ThreatSeverity.high),
        Rule("suspicious_binary_drop", "Synthetic fixture describes an unsigned binary dropped in a shared sandbox location.",
            ["explicit unsigned-binary fixture signal", "execution is not observed"], ["file drop source event"], .58, ThreatSeverity.high),
        Rule("defense_tampering", "Telemetry describes a change to security logging or a security source.",
            ["explicit security-source change signal"], ["configuration/source-change event"], .96, ThreatSeverity.high),
        Rule("defender_malware_detection", "Microsoft Defender logged a malware or potentially unwanted software detection.",
            ["Defender Operational event 1116", "severity category is available or explicitly unknown"],
            ["Defender detection event", "severity category"], .99, ThreatSeverity.high),
        Rule("defender_protection_disabled", "Microsoft Defender logged that a protection capability was disabled.",
            ["Defender Operational event 5001 or 5010", "protection feature category is known"],
            ["Defender protection state event", "protection feature category"], .96, ThreatSeverity.high),
        Rule("powershell_script_indicators", "PowerShell Script Block Logging recorded a block containing a high-signal combination of risky behavior indicators; this does not prove execution or success.",
            ["PowerShell Operational event 4104", "remote content plus dynamic execution, encoded content plus dynamic execution, a Defender configuration change, or credential-dump tooling indicator"],
            ["PowerShell script-block event", "fixed behavior indicator categories", "execution not established by this event"], .76, ThreatSeverity.medium),
        Rule("sensitive_process_access", "Process access to a sensitive Windows process is corroborated by additional behavior from the same source process.",
            ["Sysmon ProcessAccess event", "sensitive target image", "access mask available", "same source process has corroborating activity"],
            ["source process", "target image", "access mask", "corroborating process event"], .82, ThreatSeverity.high)
    ];

    private static DetectionRuleDefinition Rule(string id, string description, string[] conditions, string[] evidence,
        double confidence, ThreatSeverity severity) => new(id, 1, description, conditions, evidence, confidence, severity);
}

# SentinelCore Demon 2 Threat Monitor

This directory contains the Demon 2 implementation. It observes Windows telemetry, normalizes events, correlates process activity, stores evidence locally, applies deterministic rules, and publishes findings to Demon 3. It does not execute response actions, profile users, collect keystrokes, access a camera, disable Microsoft Defender, or invoke a shell.

## Architecture

- `SentinelCore.Demon2.Service` hosts the Windows service and reads the Sysmon Operational event log through `EventLogWatcher`.
- `SentinelCore.Demon2.Core` contains typed canonical events, Sysmon normalization, bounded temporal correlation, deterministic rules, telemetry health, SQLite persistence, a durable bounded outbox, and the inter-daemon envelope contract.
- `SentinelCore.Demon2.Tests` is the repository's executable check harness, following the existing Demon 1 test convention. It replays the unchanged synthetic SQLite reference database.

The collector resumes from a persisted Event Log bookmark. It writes normalized records to SQLite before advancing that cursor. Duplicate source records are ignored while still advancing a previously committed cursor. A malformed observed record is rejected with a deterministic, idempotent `TELEMETRY_GAP`; its cursor is committed so a poison record cannot block later telemetry. Collector overflow is reported separately as a dropped-event count. The watcher reports unavailable while it is disconnected and degraded while active with an error or recorded loss; it retries the source and reports healthy again when fresh telemetry resumes. No events are synthesized to fill a gap. The local event retention defaults to seven days and can be changed with `SENTINELCORE_D2_RETENTION_DAYS` (1–365). The service database is stored under `%ProgramData%\SentinelCore\Demon2`.

The Core project targets `net10.0` and uses `Microsoft.Data.Sqlite` 11.0.0. The resolved native dependency is SQLite 3.53.4 through `SQLitePCLRaw.bundle_e_sqlite3` 3.0.5. The test harness checks the loaded `sqlite_version()` at runtime.

## MVP telemetry source

Sysmon is the single primary source, read from `Microsoft-Windows-Sysmon/Operational`. The implementation maps process start, interpreter activity, selected file events, Zone.Identifier download observations, network/DNS activity, persistence registry changes, and Sysmon configuration changes. Only selected event IDs are normalized; unsupported provider events are rejected with a diagnostic. The service does not install or reconfigure Sysmon. Microsoft Defender remains active.

The guide does not specify a domain reputation provider. `DOMAIN_REPUTATION` exists in the canonical event model so a declared provider can be added later, but no reputation is inferred from a domain name. Sysmon configuration may also omit event IDs required for downloads, DNS, network, or registry monitoring; this implementation reports source failures and queue losses, but it cannot prove that every event class is enabled in the local Sysmon policy.

## Inter-daemon communication

Production publishing is a local client connection to `\\.\pipe\SentinelCore.Guard`. D2 sends the v1 envelope, performs HELLO/WELCOME, waits for ACK, retries at most three times, and never sends an `ACTION_REQUEST`. The pipe server and its ACLs belong to Demon 3 and are not present in this repository, so a full production handshake was not exercised here. JSONL is available for repeatable tests through the same envelope interface.

Findings and gaps use event IDs as evidence references; source paths, user names, command lines, and raw event XML are not copied into published payloads. The outbox is capped at 4,096 pending messages, reserves capacity for findings/gaps ahead of heartbeats, and records failed or expired deliveries. If it fills, the service logs that the message was not queued; the finding itself remains in the local event store.

## Reference data

`tests/Fixtures/Demon2_Training.sqlite` is a byte-for-byte copy of the supplied `Demon2_Training.sqlite` archive entry (SHA-256 `59B5698B0D16CB06E0DBDBBD92B5158801847B22362F653A9409660F1E39717C`). Tests open it read-only. Its split contains 40 development cases and 10 validation cases; the complete set contains 15 benign, 20 suspicious, and 15 uncertain cases.

Reference inconsistencies are preserved and reported rather than rewritten:

1. `interop_messages` labels all 50 scenarios as `THREAT_FINDING`, although `reports` divides them into 20 `THREAT_FINDING`, 15 `OBSERVATION`, and 15 `NEEDS_CONTEXT` records. These wire rows cannot all be treated as expected production output; the replay compares report semantics and evidence instead.
2. `D2-010` is **not** a reference conflict: the human simulation says to filter benign editor noise, and SQLite expects `OBSERVATION` without a finding. The earlier replay harness incorrectly claimed that this case requested a finding; that stale clarification has been removed.
3. Severity conflicts exist in `D2-019` and `D2-035` (human simulation says critical; SQLite expects high), `D2-027` (human simulation says medium; SQLite expects high), and `D2-032` (human simulation says critical; SQLite expects high). The rule catalog is not changed to guess which severity was intended.
4. Expected suspicious findings lack required structured evidence in `D2-027` (the only row is generic, not an ImageLoad with signer/path and corroboration), `D2-028` (no target image, access mask, or corroboration), `D2-031` (no network/exfiltration event although the narrative makes that a condition for the finding), and `D2-032` (the narrative mentions an outbound flow but the sole row is generic file/system activity). `D2-044` likewise has no parent event or process identity to test late correlation.
5. The outcome type needs clarification for `D2-039`, `D2-040`, `D2-042`, `D2-043`, and `D2-050`: SQLite expects `NEEDS_CONTEXT`, while the narrative emphasizes no confirmed threat or observation, but the fixture does not consistently supply a concrete missing-context field. Specifically, D2-040's event is 12:01 UTC rather than a modeled night-time update; D2-042 has no Defender source or historical detection timestamp; D2-043 has one SQLite row (the harness duplicates that row in memory to test idempotence); and D2-050 lacks `Zone.Identifier` evidence and a follow-up window duration.

These cases need reference-owner decisions or additional synthetic event fields before they can serve as strict pass/fail security validation. No supplied reference row is changed to obtain a pass.

The fixtures are synthetic narratives and small event summaries. They are useful for deterministic replay and regression checks, not for measuring detection rates on real Windows telemetry.

Latest replay results: 50 scenarios executed, 38 passed, 0 unexplained failures, and 12 require clarification. The clarification cases are D2-019, D2-027, D2-028, D2-031, D2-032, D2-035, D2-039, D2-040, D2-042, D2-043, D2-044, and D2-050. Event coverage is 10/11 (`DOMAIN_REPUTATION` is not supplied by the selected telemetry); fixture rule coverage is 8/10 (`sensitive_process_access` and `unusual_image_load` lack sufficient evidence in the scenarios), while direct positive/negative tests cover both rules. These results report reference ambiguities and missing telemetry without changing the supplied database. The replay harness emits UTF-8 and classifies French fixture descriptions after Unicode diacritic normalization; fixture interpretation therefore does not rely on byte-mangled accent spellings. The fixture database was opened read-only and left unchanged.

## Build and checks

```powershell
dotnet build 'Demon 2\tests\SentinelCore.Demon2.Tests\SentinelCore.Demon2.Tests.csproj'
dotnet run --project 'Demon 2\tests\SentinelCore.Demon2.Tests\SentinelCore.Demon2.Tests.csproj'
```

The executable checks cover event normalization, the v1 envelope and JSONL, SQLite idempotence/cursors/retention/outbox and runtime version, the persistent Named Pipe session, all 50 fixture replays, benign/suspicious/ambiguous outcomes, duplicate findings, event and finding expiry, out-of-order parent correlation, source unavailable/recovery health, malformed-event rejection and continuation, deterministic duplicate gap handling, and separation of malformed input from source outage. The latest resilience run added an integration check in which valid, duplicate, distinct, malformed, recovered-valid, and source-outage records pass through one pipeline; all three distinct valid events remained stored and the two gap types remained separately traceable.

## Windows operation

`SentinelCore.Demon2.Service.Program.Main` is the entry point. The existing `WindowsServiceDispatcher` connects the process to the Windows Service Control Manager as `SentinelCoreDemon2`. When started from an interactive console rather than SCM, it runs the same worker in the foreground and handles Ctrl+C as a clean stop. The dispatcher is the service wrapper; the repository does not include an installer or register the service automatically.

To run in the foreground for diagnosis, build the solution and run:

```powershell
dotnet run --project 'Demon 2\src\SentinelCore.Demon2.Service\SentinelCore.Demon2.Service.csproj'
```

Stop the foreground process with Ctrl+C. For a Windows service deployment, publish the service, register it once from an elevated PowerShell session, then use SCM to start and stop it. Registration changes Windows service configuration and is intentionally not part of daemon startup:

```powershell
dotnet publish 'Demon 2\src\SentinelCore.Demon2.Service\SentinelCore.Demon2.Service.csproj' -c Release -o 'C:\SentinelCore\Demon2'
$serviceExe = 'C:\SentinelCore\Demon2\SentinelCore.Demon2.Service.exe'
$dataRoot = Join-Path $env:ProgramData 'SentinelCore\Demon2'
New-Item -ItemType Directory -Force -Path $dataRoot | Out-Null
New-Service -Name 'SentinelCoreDemon2' -DisplayName 'SentinelCore Demon 2 Threat Monitor' -BinaryPathName "`"$serviceExe`"" -StartupType Manual
# Configure the dedicated non-admin identity in Services.msc > Log On before starting.
# Then grant it Modify on $dataRoot, and read access to the Sysmon channel if its ACL requires it.
Start-Service -Name 'SentinelCoreDemon2'
Get-Service -Name 'SentinelCoreDemon2'
Stop-Service -Name 'SentinelCoreDemon2'
Get-Service -Name 'SentinelCoreDemon2'
```

Successful `Get-Service` status is `Running`. The service handles SCM Stop and Shutdown by cancelling collection and the pipeline, disposing the Event Log watcher, waiting for its worker loops, then closing SQLite and Named Pipe resources. The foreground path treats Ctrl+C cancellation as a normal exit. The persisted Sysmon bookmark advances only after an event is saved (or a malformed event is recorded as a gap); an event interrupted before that point can be replayed after restart. Windows Event Log history may be overwritten while D2 is stopped; there is no claim that overwritten events can be recovered.

### Least privilege and storage access

The service does not require an administrator token by design. Its runtime identity needs read access to `Microsoft-Windows-Sysmon/Operational`, `Modify` access only to `%ProgramData%\SentinelCore\Demon2` (SQLite database, WAL/SHM sidecars, cursors, and logs), and the Windows right to log on as a service. The channel's effective ACL must be checked on the target machine; this repository cannot grant or verify it. Service registration and any channel ACL change are deployment operations that require an authorized administrator. Run the foreground test under the intended service identity to confirm channel access before deployment. After creating the service, configure its dedicated non-administrator identity in the Services console and set a restrictive ACL on the data directory before starting it. Do not grant local administrator membership to make event collection work.

Sysmon events are parsed with DTDs prohibited and a 1 Mi-character XML cap; bookmarks are capped at 65,536 characters. Process IDs and ports are range-checked, domains/IP strings are validated, and malformed optional host/hash values remain explicitly unavailable. Windows paths are retained as opaque evidence (maximum 32,767 characters); no telemetry value is passed to a process, shell, or command API. Command lines and user SIDs are not copied into canonical events. Raw XML is not persisted. Local normalized records can include machine name, image/path, process identifiers, and selected provider fields; findings publish event references and summarized facts rather than raw paths or event content.

SQLite commands use parameters. The store enables WAL, foreign keys, and `secure_delete`; event age retention defaults to seven days. There is no hard database-size quota, so a high event rate or long retention can still exhaust disk space. A write failure propagates to the service worker and is surfaced as a critical runtime failure rather than being treated as successful collection; log persistence may also fail if its directory is inaccessible. The directory ACL in the deployment example limits access, but ACLs and actual channel readability must be verified on the target Windows host.

Error logs use UTC timestamps, redact common secret-like key/value fields, truncate long lines, and stop writing once a daily file reaches 10 MiB; persistent file output resumes on the next UTC day. Daily files are not automatically deleted, so the operator must apply an approved retention policy and monitor total disk use. The daemon performs no active domain lookups, reputation queries, scans, or network blocking; `DOMAIN_REPUTATION` is not emitted without an actual provider.

The service database and bookmarks are under `%ProgramData%\SentinelCore\Demon2\events.sqlite`. Error and diagnostic output is written to daily UTF-8 files under `%ProgramData%\SentinelCore\Demon2\logs\threat-monitor-YYYYMMDD.log` (capped at 10 MiB per day) and also forwarded to interactive stderr. The current log level is fixed to diagnostic/error messages; there is no log-level environment switch. Check health in the Guard heartbeat: `status`, `queueDepth`, `droppedCount`, and `outboxDepth` are reported there. `TELEMETRY_GAP` messages distinguish an unavailable source, malformed record, and counted queue loss. The process does not expose a local HTTP health endpoint.

## Explicit configuration

| Setting | Current behavior |
| --- | --- |
| Runtime and target | C# / .NET; projects target `net10.0`. This host has SDKs 10.0.404 and 11.0.100 and runtime 10.0.15; with no `global.json`, the CLI currently selects SDK 11.0.100. |
| Telemetry source | Sysmon Event Log channel `Microsoft-Windows-Sysmon/Operational`; event driven, with a 2-second retry after watcher failure. |
| Storage | Fixed database path above; retention defaults to 7 days. `SENTINELCORE_D2_RETENTION_DAYS` accepts 1–365. |
| Observation mode | Always observation-only; no response actions, persistence edits, process suspension, shell execution, or active network contact. Microsoft Defender is not changed. |
| Internal intervals | Health sampling 5 seconds, heartbeat 10 seconds, outbox retry poll 250 ms, retention cleanup 1 hour; collector queue capacity 2,048 records. |
| Correlation | 10-minute temporal window and up to 4,096 candidate events per correlation query. |
| Rules | Deterministic, versioned catalog in `DetectionRuleCatalog`; no runtime rule-edit configuration. |
| Dependencies | NuGet `PackageReference` with `project.assets.json` restore; Service directly references `System.Diagnostics.EventLog` 8.0.1. SQLite resolves to `Microsoft.Data.Sqlite` 11.0.0 and native SQLite 3.53.4. |

Fixture/replay mode is the test executable, not a service switch. Run the second command in **Build and checks** to replay the read-only 50-scenario reference database. The test harness uses temporary SQLite files for lifecycle and load cases and removes those temporary test files after the checks.

## Reproducible performance sample

The executable check `Sustained-load performance measurement` sends 256 synthetic Sysmon Event ID 11 records with distinct event IDs, paths, and process IDs through normalization, SQLite storage, correlation, and rule evaluation, followed by one malformed XML record. It measures wall-clock duration, process CPU time, managed heap delta, process working-set delta, total managed allocations, valid events, rejections, source queue depth/capacity, source-reported drops, findings, event throughput, and separately timed correlation and detection for the final event. The last two values are a single-event stage sample, not percentiles. This is an in-process replay on the current Windows host, not a production Sysmon throughput benchmark.

Most recent Release sample: 256 processed, 1 rejected, 0 source-reported drops, 0 findings; 1.08 seconds elapsed, 4.21 ms average pipeline time per valid record, 237.52 events/s, 57.99% of one logical CPU equivalent, +3.00 MB managed heap, +6.61 MB working set, and 121.62 MB managed allocations. The sampled source queue depth was 0; final-event correlation took 3.33 ms and detection took 30.10 microseconds. These values vary with host load, SDK/runtime, and storage performance; they are a repeatable baseline, not a service capacity guarantee.

## Test environment limits

The executable harness covers unit-style checks for normalization, rules, correlation, expiry, and health, plus SQLite-backed pipeline integration, fixture replay, restart/idempotence, cancellation during normalization, invalid-input continuation, and sustained replay. The persistent Named Pipe test uses an actual local Windows named pipe and a test peer in the same process. The tests do not install or start the Windows service, read the machine's Sysmon channel, or induce a real Event Log outage; those checks require a separately provisioned Windows test machine with Sysmon and SCM access. No such live system change was performed for this validation.

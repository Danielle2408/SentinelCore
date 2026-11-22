# SentinelCore Demon 2 Threat Monitor

This directory contains the Demon 2 implementation. It observes Windows telemetry, normalizes events, correlates process activity, stores evidence locally, applies deterministic rules, and publishes findings to Demon 3. It does not execute response actions, profile users, collect keystrokes, access a camera, disable Microsoft Defender, or invoke a shell.

## Architecture

- `SentinelCore.Demon2.Service` hosts the Windows service and observes Sysmon, selected Microsoft Defender Operational events, and PowerShell Script Block Logging through `EventLogWatcher`.
- `SentinelCore.Demon2.Core` contains typed canonical events, provider-specific Windows event normalization, bounded temporal correlation, deterministic rules, telemetry health, SQLite persistence, a durable bounded outbox, and the inter-daemon envelope contract.
- `SentinelCore.Demon2.Tests` is the repository's executable check harness, following the existing Demon 1 test convention. It replays the 50-case synthetic SQLite reference database with strict report and wire-message expectations.

The collector resumes from a persisted Event Log bookmark. It writes normalized records to SQLite before advancing that cursor. Duplicate source records are ignored while still advancing a previously committed cursor. A malformed observed record is rejected with a deterministic, idempotent `TELEMETRY_GAP`; its cursor is committed so a poison record cannot block later telemetry. Collector overflow is reported separately as a dropped-event count. The watcher reports unavailable while it is disconnected and degraded while active with an error or recorded loss; it retries the source and reports healthy again when fresh telemetry resumes. No events are synthesized to fill a gap. The local event retention defaults to seven days and can be changed with `SENTINELCORE_D2_RETENTION_DAYS` (1–365). The service database is stored under `%ProgramData%\SentinelCore\Demon2`.

The Core project targets `net10.0` and uses `Microsoft.Data.Sqlite` 11.0.0. The resolved native dependency is SQLite 3.53.4 through `SQLitePCLRaw.bundle_e_sqlite3` 3.0.5. The test harness checks the loaded `sqlite_version()` at runtime.

## MVP telemetry source

Sysmon remains the detailed behavior source, read from `Microsoft-Windows-Sysmon/Operational`. The implementation maps process start, interpreter activity, selected file events, Zone.Identifier download observations, network/DNS activity, persistence registry changes, and Sysmon configuration changes. It also listens to the filtered `Microsoft-Windows-Windows Defender/Operational` events 1116 (detection), 1117 (action taken), 5001 (real-time protection disabled), and 5010 (antispyware scanning disabled). PowerShell Script Block Logging event 4104 is observed from `Microsoft-Windows-PowerShell/Operational`; fixed combinations such as remote download plus dynamic execution, encoded content plus dynamic execution, Defender configuration changes, or credential-dump tooling create a medium-severity review finding. Event 4104 alone does not prove the script ran successfully. The first start of each source subscribes to new events only; subsequent starts resume from that source's independent persisted bookmark. Unsupported event IDs are excluded by the event-log query rather than being treated as malformed telemetry.

Defender detections, protection-state changes, and PowerShell script indicators provide useful findings even if Sysmon is absent. They do not replace Sysmon's process, download, persistence, DNS, or network chains: the combined health remains degraded while any configured source is unavailable. The service never installs or reconfigures Sysmon, PowerShell logging, or Microsoft Defender. A Defender 1116 event is reduced to its severity category; PowerShell 4104 text is inspected in memory and reduced to fixed category names. Raw threat names, script text, paths, user names, and provider XML are not placed in canonical records or inter-daemon messages. Windows itself may retain raw PowerShell script text in its native event log while Script Block Logging is enabled; SentinelCore neither clears nor changes that OS log.

Microsoft documents event 4104 as PowerShell Script Block Logging. The policy logs PowerShell script input to the Operational channel; handle that native event log according to the device owner's retention and access policy. [PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.3), [Windows PowerShell policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowspowershell).

The guide does not specify a domain reputation provider. `DOMAIN_REPUTATION` exists in the canonical event model so a declared provider can be added later, but no reputation is inferred from a domain name. Sysmon configuration may also omit event IDs required for downloads, DNS, network, or registry monitoring; this implementation reports source failures and queue losses, but it cannot prove that every event class is enabled in the local Sysmon policy.

## Inter-daemon communication

Production communication is a local client connection to `\\.\pipe\SentinelCore.Guard`. D2 sends the v1 envelope, performs HELLO/WELCOME, waits for ACK, retries delivery at most three times, and never sends an `ACTION_REQUEST`. The persistent pipe is duplex: it accepts D3 `CONTEXT_REQUEST` messages into a bounded 32-item queue, acknowledges receipt promptly, and lets a separate pipeline worker answer on the same correlation ID. A full queue is rejected with `REQUEST_QUEUE_FULL` so the pipe reader cannot deadlock behind a busy analysis loop.

The D2 threat-context response is limited to the requested allowlisted fields: a fixed catalog summary, catalog rule ID/version/severity/confidence plus categorical facts, stored evidence IDs and event types, and known missing-telemetry categories. The responder correlates by `correlationId`, resolves references against stored evidence, and excludes raw Sysmon fields, paths, commands, usernames, and XML. Separately, a finding with missing telemetry triggers one `SESSION_CONTEXT_REQUEST` per correlation ID, with a 15-second deadline. D2 accepts only `SESSION_CONTEXT_RESPONSE` containing `AVAILABLE`/`NOT_AVAILABLE` and the three exact categories (`sessionState`, `localOrRemote`, `recentAuthBand`); it stores that category-only response linked to the triggering finding. This never changes the finding or its severity. Request deduplication and the attached categories are retained with the local event-store retention period. The D3 pipe server is outside this project. The production D2 and D3 processes now have a repeatable local handshake/ACK check at `scripts/Verify-InterDaemonTransport.ps1`; service-account ACL deployment remains unverified. JSONL is available for repeatable message tests through the same envelope interface.

For an isolated local IPC check, D2 accepts an optional `--data-dir <directory>` argument. Without it, the interactive process keeps using `%LOCALAPPDATA%` and the Windows service keeps using `%ProgramData%`. `scripts/Verify-InterDaemonTransport.ps1 -ProbePowerShellCapture` additionally launches one harmless Windows PowerShell command so the test can prove event 4104 reaches D2 and only category data is persisted. That probe creates a benign record in Windows' native PowerShell Operational log; use the switch only when that test record is acceptable on the machine.

Findings and gaps use event IDs as evidence references; source paths, user names, command lines, and raw event XML are not copied into published payloads. The outbox is capped at 4,096 pending messages, reserves capacity for findings/gaps ahead of heartbeats, and records failed or expired deliveries. If it fills, the service logs that the message was not queued; the finding itself remains in the local event store.

## Reference data

`tests/Fixtures/Demon2_Training.sqlite` is a byte-for-byte copy of the supplied `Demon2_Training.sqlite` archive entry (SHA-256 `3B9A59C61B8815D11C161D04B0C448E88525453AB13758C074A02935A900AB23`). Tests open it read-only. Its split contains 40 development cases and 10 validation cases; the complete set contains 15 benign, 20 suspicious, and 15 uncertain cases.

Reference inconsistencies are preserved and reported rather than rewritten:

1. `interop_messages` labels all 50 scenarios as `THREAT_FINDING`, although `reports` divides them into 20 `THREAT_FINDING`, 15 `OBSERVATION`, and 15 `NEEDS_CONTEXT` records. The implementation uses report and evidence semantics, not the wire-table message type, as scenario expectations.
2. D2-010 is labeled benign and SQLite expects `OBSERVATION` without a finding, while the human simulation text asks for a high finding.
3. The expected-finding table assigns `high` to all 20 suspicious cases, while the human simulation text asks for a critical finding in D2-019 and D2-035. That severity mismatch is left unresolved pending clarification.
4. Several suspicious fixtures do not provide the evidence needed to confirm their structured finding expectation: D2-027 lacks image signer/context or corroboration; D2-028 lacks target-process and access-mask details; D2-031 and D2-032 lack the required distinct network event. Other expected outcomes conflict with their narrative or available source data, as recorded in the replay report. These cases need clarification before they can be used as strict pass/fail security validation.

The fixtures are synthetic narratives and small event summaries. They are useful for deterministic replay and regression checks, not for measuring detection rates on real Windows telemetry.

Latest replay results: 50 scenarios executed, 37 passed, 0 unexplained failures, and 13 require clarification. The clarification cases are D2-010, D2-019, D2-027, D2-028, D2-031, D2-032, D2-035, D2-039, D2-040, D2-042, D2-043, D2-044, and D2-050. The fixture report covers 10/14 event types; the missing types are `DOMAIN_REPUTATION`, `DEFENDER_MALWARE_DETECTED`, `DEFENDER_ACTION_TAKEN`, and `DEFENDER_PROTECTION_DISABLED`. Its rule replay activates 8/12 rules; the three Defender events and the `sensitive_process_access`/`unusual_image_load` rules have direct unit-style tests but no positive fixture scenario. These results report reference ambiguities and missing telemetry without changing the supplied database. The replay harness emits UTF-8 and classifies French fixture descriptions after Unicode diacritic normalization; fixture interpretation therefore does not rely on byte-mangled accent spellings. The fixture database was opened read-only and left unchanged.

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

Successful `Get-Service` status is `Running`. The service handles SCM Stop and Shutdown by cancelling collection and the pipeline, disposing the Event Log watcher, waiting for its worker loops, then closing SQLite and Named Pipe resources. In foreground mode, Ctrl+C or an exact `STOP` line on stdin cancels the same worker; the SCM path never reads stdin. The persisted Sysmon bookmark advances only after an event is saved (or a malformed event is recorded as a gap); an event interrupted before that point can be replayed after restart. Windows Event Log history may be overwritten while D2 is stopped; there is no claim that overwritten events can be recovered.

### Least privilege and storage access

The service does not require an administrator token by design. Its runtime identity needs read access to `Microsoft-Windows-Sysmon/Operational`, `Modify` access only to `%ProgramData%\SentinelCore\Demon2` (SQLite database, WAL/SHM sidecars, cursors, and logs), and the Windows right to log on as a service. The channel's effective ACL must be checked on the target machine; this repository cannot grant or verify it. Service registration and any channel ACL change are deployment operations that require an authorized administrator. Run the foreground test under the intended service identity to confirm channel access before deployment. After creating the service, configure its dedicated non-administrator identity in the Services console and set a restrictive ACL on the data directory before starting it. Do not grant local administrator membership to make event collection work.

Sysmon events are parsed with DTDs prohibited and a 1 Mi-character XML cap; bookmarks are capped at 65,536 characters. Process IDs and ports are range-checked, domains/IP strings are validated, and malformed optional host/hash values remain explicitly unavailable. Windows paths are retained as opaque evidence (maximum 32,767 characters); no telemetry value is passed to a process, shell, or command API. Command lines and user SIDs are not copied into canonical events. Raw XML is not persisted. Local normalized records can include machine name, image/path, process identifiers, and selected provider fields; findings publish event references and summarized facts rather than raw paths or event content.

SQLite commands use parameters. The store enables WAL, foreign keys, and `secure_delete`; event age retention defaults to seven days. There is no hard database-size quota, so a high event rate or long retention can still exhaust disk space. A write failure propagates to the service worker and is surfaced as a critical runtime failure rather than being treated as successful collection; log persistence may also fail if its directory is inaccessible. The directory ACL in the deployment example limits access, but ACLs and actual channel readability must be verified on the target Windows host.

Error logs use UTC timestamps, redact common secret-like key/value fields, truncate long lines, and stop writing once a daily file reaches 10 MiB; persistent file output resumes on the next UTC day. Daily files are not automatically deleted, so the operator must apply an approved retention policy and monitor total disk use. The daemon performs no active domain lookups, reputation queries, scans, or network blocking; `DOMAIN_REPUTATION` is not emitted without an actual provider.

When launched interactively by the Control Center, the database, bookmarks, and logs are under `%LocalAppData%\SentinelCore\Demon2`; this lets a standard user run the test/control copy without changing system ACLs. When started by the Service Control Manager, shared data is under `%ProgramData%\SentinelCore\Demon2\events.sqlite` and logs remain under its `logs` folder. The installed service identity must have its own restrictive Modify ACL on that directory. Error and diagnostic output is written to daily UTF-8 files (capped at 10 MiB per day) and also forwarded to interactive stderr. The current log level is fixed to diagnostic/error messages; there is no log-level environment switch. Check health in the Guard heartbeat: `status`, `queueDepth`, `droppedCount`, and `outboxDepth` are reported there. `TELEMETRY_GAP` messages distinguish an unavailable source, malformed record, and counted queue loss. The process does not expose a local HTTP health endpoint.

## Explicit configuration

| Setting | Current behavior |
| --- | --- |
| Runtime and target | C# / .NET; projects target `net10.0`. This host has SDKs 10.0.404 and 11.0.100 and runtime 10.0.15; with no `global.json`, the CLI currently selects SDK 11.0.100. |
| Telemetry sources | Sysmon Operational, selected Windows Defender Operational events, and PowerShell 4104; event driven with a 2-second retry after watcher failure. Each source has a separate persisted bookmark. |
| Storage | Fixed database path above; retention defaults to 7 days. `SENTINELCORE_D2_RETENTION_DAYS` accepts 1–365. |
| Observation mode | Always observation-only; no response actions, persistence edits, process suspension, shell execution, or active network contact. Microsoft Defender is not changed. |
| Internal intervals | Health sampling 5 seconds, heartbeat 10 seconds, outbox retry poll 250 ms, session-context deadline 15 seconds, retention cleanup 1 hour; collector queue capacity 2,048 records. |
| Correlation | 10-minute temporal window and up to 4,096 candidate events per correlation query. |
| Rules | Deterministic, versioned catalog in `DetectionRuleCatalog`; no runtime rule-edit configuration. |
| Dependencies | NuGet `PackageReference` with `project.assets.json` restore; Service directly references `System.Diagnostics.EventLog` 8.0.1. SQLite resolves to `Microsoft.Data.Sqlite` 11.0.0 and native SQLite 3.53.4. |

Fixture/replay mode is the test executable, not a service switch. Run the second command in **Build and checks** to replay the read-only 50-scenario reference database. The test harness uses temporary SQLite files for lifecycle and load cases and removes those temporary test files after the checks.

## Reproducible performance sample

The executable check `Sustained-load performance measurement` sends 256 synthetic Sysmon Event ID 11 records with distinct event IDs, paths, and process IDs through normalization, SQLite storage, correlation, and rule evaluation, followed by one malformed XML record. It measures wall-clock duration, process CPU time, managed heap delta, process working-set delta, total managed allocations, valid events, rejections, source queue depth/capacity, source-reported drops, findings, event throughput, and separately timed correlation and detection for the final event. The last two values are a single-event stage sample, not percentiles. This is an in-process replay on the current Windows host, not a production Sysmon throughput benchmark.

Latest local Release sample from 22 November 2026: 256 processed, 1 rejected, 0 source-reported drops, 0 findings; 547 ms elapsed, 2.14 ms average pipeline time per valid record, 468.27 events/s, 97.18% of one logical CPU equivalent, +3.84 MB managed heap, +6.06 MB working set, and +122.43 MB managed allocations. The sampled source queue depth was 0; final-event correlation took 2.44 ms and detection took 18.60 microseconds. These values vary with host load, SDK/runtime, and storage performance; they are a repeatable baseline, not a service capacity guarantee.

## Test environment limits

The executable harness covers unit-style checks for normalization, rules, correlation, expiry, and health, plus SQLite-backed pipeline integration, fixture replay, restart/idempotence, cancellation during normalization, invalid-input continuation, and sustained replay. The persistent Named Pipe test uses an actual local Windows named pipe and a test peer in the same process. It exercises HELLO/WELCOME, outgoing heartbeat and session-request ACKs, the one-per-correlation ambiguity trigger, rejection of an invalid identity category, the valid category-only session response and finding attachment, the separate inbound D3 threat-detail request, its minimized same-correlation response, privacy-marker exclusion, and the response ACK. The tests do not install or start the Windows service, read the machine's Sysmon channel, or induce a real Event Log outage; those checks require a separately provisioned Windows test machine with Sysmon and SCM access. No such live system change was performed for this validation.

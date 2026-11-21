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

Two reference inconsistencies are preserved and reported rather than rewritten:

1. `interop_messages` labels all 50 scenarios as `THREAT_FINDING`, although `reports` divides them into 20 `THREAT_FINDING`, 15 `OBSERVATION`, and 15 `NEEDS_CONTEXT` records. The implementation uses report and evidence semantics, not the wire-table message type, as scenario expectations.
2. The expected-finding table marks all 20 suspicious scenarios high. Several fixtures do not provide the evidence needed to confirm that expectation: D2-027 lacks image signer/context or corroboration; D2-028 lacks target-process and access-mask details; D2-031 and D2-032 lack the required distinct network event. Other expected outcomes conflict with their narrative or available source data, as recorded in the replay report. These cases need clarification before they can be used as strict pass/fail security validation.

The fixtures are synthetic narratives and small event summaries. They are useful for deterministic replay and regression checks, not for measuring detection rates on real Windows telemetry.

Latest replay results: 50 scenarios executed, 40 passed, 0 unexplained failures, and 10 require clarification. The clarification cases are D2-027, D2-028, D2-031, D2-032, D2-039, D2-040, D2-042, D2-043, D2-044, and D2-050. Event coverage is 10/11 (`DOMAIN_REPUTATION` is not supplied by the selected telemetry); rule coverage is 8/10 (`sensitive_process_access` and `unusual_image_load` did not fire). These results report reference ambiguities and missing telemetry without changing the supplied database. The replay harness emits UTF-8 and classifies French fixture descriptions after Unicode diacritic normalization; fixture interpretation therefore does not rely on byte-mangled accent spellings. The fixture database was opened read-only and left unchanged.

## Build and checks

```powershell
dotnet build 'Demon 2\tests\SentinelCore.Demon2.Tests\SentinelCore.Demon2.Tests.csproj'
dotnet run --project 'Demon 2\tests\SentinelCore.Demon2.Tests\SentinelCore.Demon2.Tests.csproj'
```

The executable checks cover event normalization, the v1 envelope and JSONL, SQLite idempotence/cursors/retention/outbox and runtime version, the persistent Named Pipe session, all 50 fixture replays, benign/suspicious/ambiguous outcomes, duplicate findings, event and finding expiry, out-of-order parent correlation, source unavailable/recovery health, malformed-event rejection and continuation, deterministic duplicate gap handling, and separation of malformed input from source outage. The latest resilience run added an integration check in which valid, duplicate, distinct, malformed, recovered-valid, and source-outage records pass through one pipeline; all three distinct valid events remained stored and the two gap types remained separately traceable.

# SentinelCore — Demon 3 (Risk and Response Guard)

Phase 1 foundation for Windows + VS Code. Target framework: .NET 10 LTS.

## Safety boundary
- Risk assessment and report generation run locally. Measures run in simulation by default.
- An explicit `--enable-defender-scan` option enables only a fixed Microsoft Defender quick scan for a high-risk D2 finding, after a fresh master-password approval from D1. The program starts the installed Defender executable with fixed arguments, never a shell command from a report or model.
- Critical file containment remains blocked because no quarantine engine exists. No file isolation or process termination is implemented.
- A local Windows Named Pipe host handles D1/D2 envelopes. Access is limited to the current Windows user plus optional, explicitly named service-account SIDs; no broad `Everyone` grant is used.
- `JsonlInterDaemonBus` is a test transport, not a security boundary.
- `ACTION_REQUEST` is rejected on inter-daemon transport; measures go only through an internal typed catalog and policy gate.

## Prerequisites
- Windows 10/11
- .NET 10 SDK
- Visual Studio Code
- C# Dev Kit extension (recommended)

.NET 10 was selected as the supported LTS baseline. Install the current .NET 10 SDK from https://dotnet.microsoft.com/download/dotnet/10.0.

## Open and run
1. Extract the ZIP.
2. Open the `Demon3-Starter` folder in VS Code.
3. Open Terminal > New Terminal.
4. Run:

```powershell
dotnet --version
dotnet restore .\SentinelCore.Demon3.slnx
dotnet build .\SentinelCore.Demon3.slnx
dotnet test .\SentinelCore.Demon3.slnx
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj
```

Expected CLI output includes `Validation: ACCEPTED` and `Mode: SIMULATION ONLY`.

## Structure
- `src/SentinelCore.Demon3.Core/Contracts`: V1 message envelope and constants.
- `src/SentinelCore.Demon3.Core/Validation`: fail-closed envelope validation.
- `src/SentinelCore.Demon3.Core/Transport`: transport abstraction, JSONL test transport and local Windows Named Pipe host (`SentinelCore.Guard`).
- `src/SentinelCore.Demon3.Core/Decision`: deterministic fusion and risk decision policy.
- `src/SentinelCore.Demon3.Core/Reports`: SQLite history, structured reports and French text copies.
- `src/SentinelCore.Demon3.Core/Runtime`: continuous receive/correlate/report loop, bounded AI context rounds and typed action execution.
- `src/SentinelCore.Demon3.Core/AI`: local primary analysis with Gemma 3 1B by default; see its README for measured latency, limitations and model selection.
- `src/SentinelCore.Demon3.Cli`: local validation demo.
- `tests`: validator tests.
- `data/fixtures`: original SQLite training database and 50-case scenario file, copied unchanged.

## Optional local AI advisory simulation
Install/start Ollama and use `gemma3:1b` locally. If it is missing on another computer, pull it with `ollama pull gemma3:1b`. Then run:

```powershell
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --ollama-advisory-demo
```

This sends only synthetic, minimized signals to Ollama on loopback. The model returns a structured risk conclusion, rationale, context requests and a typed action proposal; D3 checks authorization and executes only catalogued actions. The demo executes no system action and prints the response time. You can append a local model tag such as `gemma2:2b` to compare models. If Ollama is offline, D3 uses its bounded fallback. The fixture database contains evaluation/replay examples, not model-training data. Details and measured limits: [`AI/README.md`](src/SentinelCore.Demon3.Core/AI/README.md).

## Important fixture observations
The SQLite `inputs.payload_json` fixtures use a reduced legacy-shaped envelope: `timestampUtc` is absent and `messageId` values are scenario IDs rather than UUIDs. The `interop_messages` table also contains `destination=InternalActionDispatcher` and `messageType=CONTEXT_RESPONSE`, which does not match the inter-daemon destination enum in the technical addendum. Keep originals unchanged; implement an explicit fixture adapter/migration mapping in the replay layer.

The pipe host accepts D1/D2 `HELLO`, validates direction and expiry, journals accepted messages in a local SQLite inbox, then acknowledges them and exposes accepted envelopes to the host. Pending messages are replayed after a D3 restart; duplicate message IDs are acknowledged without reprocessing. The inbox retains at most 4,096 pending messages and rejects additional messages with `D3_INBOX_FULL` until D3 drains the queue. Processed IDs are retained for 30 days to suppress retries. D1 and D2 use different handshake/ack formats, so D3 mirrors each client’s existing contract. D3 can send typed requests to D1 and D2; D2's duplex pipe returns filtered threat details for the same correlation. By default only the D3 owner account is allowed for both development daemons. A separately configured identity can be added to one role only: use `--allow-d2-client-sid` for a D2 service identity and `--allow-d1-client-sid` for a D1 process identity. D3 checks the connecting Windows SID during `HELLO` as well as applying the restrictive pipe ACL. A D2 service identity therefore cannot present itself as D1 to fabricate an owner approval. For example, after registering D2 with the virtual account `NT SERVICE\SentinelCoreDemon2`, resolve its SID in PowerShell and start D3 with it:

```powershell
$d2Sid = ([System.Security.Principal.NTAccount]::new('NT SERVICE\SentinelCoreDemon2')).Translate([System.Security.Principal.SecurityIdentifier]).Value
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --serve --allow-d2-client-sid $d2Sid
```

The service must actually run under the identity whose SID is granted. The D3 SID setting does not install or reconfigure D2. Durable message deduplication and signed-binary verification remain future hardening. The continuous loop is launched with `--serve` below.

An opt-in live integration test connects the production D1 and D2 named-pipe clients to D3 and sends the resulting case through the locally installed Ollama model. Test responders return protocol-only data; they do not open the camera or execute operating-system measures. To run it on a machine with Ollama and `gemma3:1b` already available:

```powershell
$env:SENTINELCORE_LIVE_OLLAMA_TEST = '1'
dotnet test .\tests\SentinelCore.Demon3.Tests\SentinelCore.Demon3.Tests.csproj -c Release --filter 'FullyQualifiedName~LiveOllamaReceivesRealD1D2PipeContextAndWritesAuditedReport'
Remove-Item Env:SENTINELCORE_LIVE_OLLAMA_TEST
```

This verifies the IPC and report path against an actual local inference response; it does not measure model accuracy on a representative security dataset.

## Run Demon 3
Start D3 before D1 and D2. For a menu-driven launch, run `.\Lancer-Demon3.ps1`; select simulation, reports or the Ollama demo. The Defender option enables only the bounded scan path and still requires a fresh D1 master-password approval.

To start directly in simulation:

```powershell
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --serve
```

If D2 runs under a distinct service identity, add `--allow-d2-client-sid $d2Sid` as described in the pipe configuration above.

To explicitly enable the bounded Defender quick scan:

```powershell
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --serve --enable-defender-scan
```

D3 accepts D1/D2 messages, groups messages sharing the same `correlationId`, applies its policy and saves each decision. For real high/critical D2 findings it requests D2 rule details and fresh D1 session context plus visual identity; synthetic fixtures never activate sensors. A fresh D1 `MATCH` with `LIVE` and adequate quality reduces the deterministic risk by one level, including CRITICAL to HIGH. It is recorded as an independent reason; D2's original alert and evidence remain in the report. D3 requests the matching JPEG from D1 and stores an encrypted report copy protected for the current Windows account. Ambiguous cases receive bounded Ollama analysis, at most three turns as new context arrives. A valid model verdict is stored as the case assessment; D3 still restricts measures to its fixed catalog, requires a D2 finding and fresh D1 master-password approval for a real Defender scan, and blocks critical containment. Model text cannot become an executable command.

Reports are kept under `%LOCALAPPDATA%\SentinelCore\Demon3\reports` in SQLite, JSON and readable French text. View a short history with:

```powershell
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --reports
```

## Alertes Telegram facultatives
Dans Configuration du Centre, saisis le jeton BotFather et le chat ID, puis active les alertes. Le jeton est protégé par DPAPI pour le compte Windows courant; il n’est pas transmis en argument de processus ni écrit dans le journal. Le bouton de test envoie un message réel au chat configuré. D3 envoie un PDF pour un risque HIGH/CRITICAL ou une situation ELEVATED non résolue par Ollama. Après deux échecs de connexion dans le même dialogue d’authentification du Centre, un avertissement texte est envoyé. Aucun message n’est envoyé si les alertes sont désactivées.

Les PDF peuvent contenir la photo de vérification d’identité si elle est jointe au rapport. Ils sont transmis au service Telegram et au chat choisis; le document exporté n’est pas chiffré par SentinelCore. Les rapports restent enregistrés localement. Si l’envoi échoue, une file locale conserve seulement les identifiants des rapports et retente l’envoi pendant sept jours tant que D3 tourne; le délai augmente jusqu’à cinq minutes. Désactiver les alertes efface les envois en attente. [Référence officielle du Bot API Telegram](https://core.telegram.org/bots/api).

Le Bot API ne crée pas automatiquement une discussion « Sentinel alerte ». Crée la discussion dans Telegram, ajoute le bot, envoie `/start`, puis saisis son chat ID dans le Centre. Les identifiants d’application MTProto (API ID/API hash) ne remplacent pas un jeton Bot API.

## Rejouer les scénarios D2
To check only the mapping from existing D2 reports to the D3 decision categories:

```powershell
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --replay-d2 "..\..\..\Demon 2\Demon2_Training.sqlite"
```

This writes a JSON result in the D3 reports folder. Its percentage measures mapping agreement only; it does not measure D2 detection quality or Ollama accuracy.

To exercise the same local pipe framing used by the D3 host, start D3 with `--serve` in one PowerShell window, then publish synthetic D2 findings from another:

```powershell
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --publish-d2-fixtures "..\..\..\Demon 2\Demon2_Training.sqlite"
```

This fixture client sends a fresh `HELLO`, `HEARTBEAT`, then 50 synthetic findings with acknowledgements. It does not run suspicious programs. Messages marked synthetic cannot activate D1's camera or a real Windows action, even if the Defender option is enabled. Review the resulting reports with `--reports`.

Each report compares the new decision with the most recent decision for the same case, or for a case with the same signal pattern. It records changes for review; it does not silently retrain or change policy. D1 session context travels directly between D3 and D1. D2 threat-detail requests return matching finding summaries, rule details, evidence kinds and telemetry gaps. D2 session-context requests are relayed through D3 to D1 and returned as only the allowed session categories.

## Known limits
The D2 source is checked into the sibling `Demon 2` folder from GitHub branch `Demon-2`. D3 tests reference the actual D2 core and named-pipe publisher/bus, and integration tests verify handshake, finding/context exchange, D3 reports, and durable inbox replay across a D3 restart. This does not start the Windows service or test its Sysmon collection on this machine. D2 context responses contain minimized matching threat details. Production service-account isolation still needs deployment-specific configuration and verification.

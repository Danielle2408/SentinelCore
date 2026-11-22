param(
    [ValidateRange(5, 120)]
    [int]$TimeoutSeconds = 45,
    [switch]$EnableDefenderScanMode,
    [switch]$ProbePowerShellCapture,
    [string]$D2ExecutablePath,
    [string]$D3ExecutablePath
)

$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$d2Project = Join-Path $workspaceRoot 'Demon 2\src\SentinelCore.Demon2.Service\SentinelCore.Demon2.Service.csproj'
$d3Project = Join-Path $workspaceRoot 'Demon 3\DEMON 3\Demon3-Starter\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj'
$d2Exe = if ([string]::IsNullOrWhiteSpace($D2ExecutablePath)) {
    Join-Path $workspaceRoot 'Demon 2\src\SentinelCore.Demon2.Service\bin\Release\net10.0\SentinelCore.Demon2.Service.exe'
} else { [System.IO.Path]::GetFullPath($D2ExecutablePath) }
$d3Exe = if ([string]::IsNullOrWhiteSpace($D3ExecutablePath)) {
    Join-Path $workspaceRoot 'Demon 3\DEMON 3\Demon3-Starter\src\SentinelCore.Demon3.Cli\bin\Release\net10.0\SentinelCore.Demon3.Cli.exe'
} else { [System.IO.Path]::GetFullPath($D3ExecutablePath) }
$testRoot = Join-Path $env:TEMP ('SentinelCore-InterDaemon-Test-' + [guid]::NewGuid().ToString('N'))
$dataDirectory = Join-Path $testRoot 'D2-data'
$reportsDirectory = Join-Path $testRoot 'D3-reports'
$processes = [System.Collections.Generic.List[System.Diagnostics.Process]]::new()
$states = [System.Collections.Generic.List[object]]::new()
$capturedLines = [System.Collections.Generic.List[string]]::new()
$script:listenerReadySeen = $false
$script:d2AcknowledgedSeen = $false
$script:defenderScanModeSeen = $false
$script:powerShellCaptureSeen = $false
$script:powerShellCaptureSkipped = $false

function Build-ReleaseProject([string]$projectPath) {
    & dotnet build $projectPath --configuration Release --no-restore --nologo -m:1 -p:NuGetAudit=false
    if ($LASTEXITCODE -ne 0) { throw "Échec de compilation : $projectPath" }
}

function Start-LoggedProcess([string]$name, [string]$exePath, [string[]]$arguments) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $exePath
    $startInfo.WorkingDirectory = $workspaceRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $arguments) { [void]$startInfo.ArgumentList.Add($argument) }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "Windows n'a pas lancé $name." }
    $processes.Add($process)
    $states.Add([pscustomobject]@{
        Name = $name
        Process = $process
        StdTask = $process.StandardOutput.ReadLineAsync()
        ErrTask = $process.StandardError.ReadLineAsync()
    })
}

function Receive-AvailableLines {
    foreach ($state in $states) {
        foreach ($streamName in @('Std', 'Err')) {
            $taskProperty = "${streamName}Task"
            $task = $state.$taskProperty
            if ($null -eq $task -or -not $task.IsCompleted) { continue }
            $line = $task.Result
            if ($null -ne $line) {
                $capturedLines.Add("$($state.Name) | $line")
                if ($state.Name -eq 'D3' -and $line -match 'GUARD_PIPE_READY') { $script:listenerReadySeen = $true }
                if ($state.Name -eq 'D3' -and $line -match 'analyse rapide Microsoft Defender autorisée') { $script:defenderScanModeSeen = $true }
                if ($state.Name -eq 'D2' -and $line -match 'GUARD_DELIVERY_OK') { $script:d2AcknowledgedSeen = $true }
                if ($state.Name -eq 'D2' -and $streamName -eq 'Err' -and $line -match 'GUARD_DELIVERY_FAILED') {
                    throw "D2 signale un échec de livraison : $line"
                }
            }
            $nextTask = $null
            if (-not $state.Process.HasExited) {
                if ($streamName -eq 'Std') { $nextTask = $state.Process.StandardOutput.ReadLineAsync() }
                else { $nextTask = $state.Process.StandardError.ReadLineAsync() }
            }
            $state.$taskProperty = $nextTask
        }
    }
}

function Stop-StartedProcesses {
    foreach ($process in $processes) {
        if ($process.HasExited) { continue }
        try { $process.StandardInput.WriteLine('STOP'); $process.StandardInput.Flush() } catch { }
    }
    foreach ($process in $processes) {
        if ($process.HasExited) { continue }
        if (-not $process.WaitForExit(10000)) {
            $process.Kill($true)
            [void]$process.WaitForExit(5000)
        }
    }
    Receive-AvailableLines
}

function Read-PowerShellCaptureStatus([string]$databasePath, [string]$sourceEventId, [string]$marker) {
    $pythonCode = @'
import json, sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
marker = sys.argv[3]
rows = connection.execute("SELECT payload_json FROM events WHERE source='PowerShell' AND source_event_id=?", (sys.argv[2],)).fetchall()
raw_marker = any(marker in row[0] for row in rows)
classified = False
indicator_values = set()
stored_values = set()
for row in rows:
    payload = json.loads(row[0])
    fields = payload.get('fields') or payload.get('Fields') or {}
    indicators = fields.get('scriptIndicators', fields.get('ScriptIndicators'))
    text_stored = fields.get('scriptTextStored', fields.get('ScriptTextStored'))
    indicator_values.add(indicators if indicators in ('none', 'REMOTE_CONTENT_EXECUTION', 'OBFUSCATED_DYNAMIC_EXECUTION', 'DEFENDER_CONFIGURATION_CHANGE', 'CREDENTIAL_DUMP_TOOLING') else 'OTHER_OR_MISSING')
    stored_values.add(str(text_stored) if text_stored in ('false', False) else 'OTHER_OR_MISSING')
    if indicators == 'none' and text_stored == 'false':
        classified = True
        break
print(f"{len(rows)}|{int(raw_marker)}|{int(classified)}|{','.join(sorted(indicator_values))}|{','.join(sorted(stored_values))}")
'@
    $output = & python -c $pythonCode $databasePath $sourceEventId $marker
    if ($LASTEXITCODE -ne 0) { throw 'Python ne peut pas lire la base SQLite isolée pour vérifier le probe.' }
    $parts = ([string]$output).Trim() -split '\|'
    if ($parts.Length -ne 5) { throw 'Résultat inattendu en lisant la base SQLite de vérification.' }
    return [pscustomobject]@{ Count = [int]$parts[0]; RawMarkerStored = [int]$parts[1] -eq 1; CategoryOnly = [int]$parts[2] -eq 1; Indicators = $parts[3]; Stored = $parts[4] }
}

function Send-BenignPowerShellProbe([string]$marker, [string]$probeScriptPath) {
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path -LiteralPath $exe)) { throw 'Windows PowerShell 5.1 introuvable pour le probe 4104.' }
    $padding = 'A' * 4096
    $quote = [char]39
    $probeScriptBody = @(
        ('$sentinelProbePadding = ' + $quote + $padding + $quote)
        ('$sentinelProbeScript = ' + $quote + 'Write-Output ' + $quote + $quote + $marker + $quote + $quote + $quote)
        '[scriptblock]::Create($sentinelProbeScript).Invoke() | Out-Null'
    )
    Set-Content -LiteralPath $probeScriptPath -Value $probeScriptBody -Encoding UTF8
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $exe
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $probeScriptPath)) {
        [void]$info.ArgumentList.Add($argument)
    }
    $probe = [System.Diagnostics.Process]::new()
    $probe.StartInfo = $info
    try {
        if (-not $probe.Start()) { throw 'Echec du lancement du probe Windows PowerShell inoffensif.' }
        if (-not $probe.WaitForExit(15000)) { $probe.Kill($true); throw 'Le probe PowerShell a dépassé 15 secondes.' }
        if ($probe.ExitCode -ne 0) { throw ('Le probe PowerShell a échoué avec le code ' + $probe.ExitCode + '.') }
    }
    finally { $probe.Dispose() }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        $events = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddMinutes(-2)} -MaxEvents 1000 -ErrorAction SilentlyContinue)
        foreach ($event in $events) {
            try {
                if ($event.Message.Contains($marker, [StringComparison]::Ordinal)) {
                    return [string]$event.RecordId
                }
            }
            catch { }
        }
        Start-Sleep -Milliseconds 250
    }
    return $null
}

try {
    if (-not (Test-Path -LiteralPath $d2Project) -or -not (Test-Path -LiteralPath $d3Project)) {
        throw 'Exécute ce script depuis le dossier scripts du workspace SentinelCore.'
    }
    if (-not (Test-Path -LiteralPath $d2Exe) -or -not (Test-Path -LiteralPath $d3Exe)) {
        throw 'Les exécutables D2 et D3 à vérifier doivent exister.'
    }
    Build-ReleaseProject $d3Project
    Build-ReleaseProject $d2Project
    New-Item -ItemType Directory -Path $testRoot | Out-Null

    $d3Arguments = @('--serve', '--reports-dir', $reportsDirectory)
    if ($EnableDefenderScanMode) { $d3Arguments += '--enable-defender-scan' }
    Start-LoggedProcess 'D3' $d3Exe $d3Arguments
    $d3 = $states | Where-Object Name -eq 'D3' | Select-Object -First 1
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        Receive-AvailableLines
        if ($listenerReadySeen -and (-not $EnableDefenderScanMode -or $defenderScanModeSeen)) { break }
        if ($d3.Process.HasExited) { throw "D3 s'est arrêté avec le code $($d3.Process.ExitCode)." }
        Start-Sleep -Milliseconds 100
    }
    if (-not $listenerReadySeen) { throw "D3 n'a pas confirmé son listener avant le délai." }
    if ($EnableDefenderScanMode -and -not $defenderScanModeSeen) { throw "D3 n'a pas confirmé le mode d'analyse rapide Defender avant le délai." }

    $probe = [System.IO.Pipes.NamedPipeClientStream]::new('.', 'SentinelCore.Guard', [System.IO.Pipes.PipeDirection]::InOut)
    try { $probe.Connect(3000) }
    finally { $probe.Dispose() }

    Start-LoggedProcess 'D2' $d2Exe @('--data-dir', $dataDirectory)
    $d2 = $states | Where-Object Name -eq 'D2' | Select-Object -First 1
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        Receive-AvailableLines
        if ($d2AcknowledgedSeen) { break }
        if ($d2.Process.HasExited) { throw "D2 s'est arrêté avec le code $($d2.Process.ExitCode)." }
        Start-Sleep -Milliseconds 100
    }
    if (-not $d2AcknowledgedSeen) {
        throw "D2 n'a pas reçu d'accusé D3 en $TimeoutSeconds secondes."
    }

    if ($ProbePowerShellCapture) {
        $databasePath = Join-Path $dataDirectory 'SentinelCore\Demon2\events.sqlite'
        $probeMarker = 'SentinelCoreBenignTelemetryProbe-' + [guid]::NewGuid().ToString('N')
        $probeScriptPath = Join-Path $testRoot 'benign-powershell-probe.ps1'
        $probeRecordId = Send-BenignPowerShellProbe $probeMarker $probeScriptPath
        if ($null -eq $probeRecordId) {
            $script:powerShellCaptureSkipped = $true
            Write-Warning "Windows n’a pas publié de nouvel événement 4104 pour ce probe; l’ingestion réelle PowerShell est donc non vérifiée sur ce poste."
        } else {
            $captureDeadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
            while ([DateTimeOffset]::UtcNow -lt $captureDeadline) {
                $capture = Read-PowerShellCaptureStatus $databasePath $probeRecordId $probeMarker
                if ($capture.Count -gt 0) {
                    if ($capture.RawMarkerStored) { throw 'Le texte brut du probe a été retrouvé dans la base D2; la minimisation ne fonctionne pas.' }
                    if (-not $capture.CategoryOnly) { throw ("PowerShell data minimization mismatch: count={0}, indicators={1}, scriptTextStored={2}" -f $capture.Count, $capture.Indicators, $capture.Stored) }
                    $script:powerShellCaptureSeen = $true
                    break
                }
                Receive-AvailableLines
                Start-Sleep -Milliseconds 250
            }
            if (-not $powerShellCaptureSeen) { throw 'D2 ne persiste pas le nouvel evenement PowerShell 4104 normalise sous 20 secondes.' }
        }
    }

    if ($EnableDefenderScanMode) {
        $message = 'RÉSULTAT : D3 confirme le mode Defender (aucun scan déclenché), son listener accepte un client local, et D2 a transmis un message acquitté par D3.'
    } else {
        $message = 'RÉSULTAT : D3 a créé son listener et accepté un client local; D2 a ensuite envoyé un message reçu et acquitté par D3.'
    }
    if ($ProbePowerShellCapture -and $powerShellCaptureSeen) { $message += ' D2 a aussi ingéré un événement PowerShell réel sans en conserver le texte.' }
if ($ProbePowerShellCapture -and $powerShellCaptureSkipped) { $message += ' Le test réel 4104 a été ignoré faute de nouvel événement natif émis; seule la normalisation unitaire est vérifiée.' }
    Write-Host $message
    Write-Host "Les journaux et bases de cet essai sont isoles dans un dossier temporaire et seront supprimes apres l'arret."
}
finally {
    Stop-StartedProcesses
    foreach ($process in $processes) { $process.Dispose() }
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedTempRoot = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd([char]'\')
        $resolvedTestRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $testRoot).ProviderPath)
        $testRootInfo = Get-Item -LiteralPath $resolvedTestRoot
        $resolvedTestParent = [System.IO.Path]::GetDirectoryName($resolvedTestRoot).TrimEnd([char]'\')
        if ($resolvedTestParent -ne $resolvedTempRoot -or ($testRootInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refus de supprimer un dossier temporaire inattendu : $resolvedTestRoot"
        }
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }
}

$verificationFailed = -not $listenerReadySeen -or -not $d2AcknowledgedSeen -or ($EnableDefenderScanMode -and -not $defenderScanModeSeen) -or ($ProbePowerShellCapture -and -not $powerShellCaptureSeen -and -not $powerShellCaptureSkipped)
if ($verificationFailed) {
    throw "Le test interprocessus n'a pas confirmé les deux étapes attendues."
}
Write-Host 'Messages de preuve :'
$capturedLines | Where-Object { $_ -match 'GUARD_PIPE_READY|GUARD_DELIVERY_OK|GUARD_DELIVERY_FAILED|analyse rapide Microsoft Defender autorisée' } | ForEach-Object { Write-Host $_ }

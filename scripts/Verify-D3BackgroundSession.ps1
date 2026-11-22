[CmdletBinding()]
param(
    [ValidateRange(5, 60)]
    [int]$TimeoutSeconds = 20
)

$ErrorActionPreference = 'Stop'
$workspaceRoot = Split-Path -Parent $PSScriptRoot
$project = Join-Path $workspaceRoot 'Demon 3\DEMON 3\Demon3-Starter\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj'
$executable = Join-Path $workspaceRoot 'Demon 3\DEMON 3\Demon3-Starter\src\SentinelCore.Demon3.Cli\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.Demon3.Cli.exe'
$testRoot = Join-Path $env:TEMP ('SentinelCore-D3-Background-Test-' + [guid]::NewGuid().ToString('N'))
$reportsDirectory = Join-Path $testRoot 'reports'
$handleFile = Join-Path $testRoot 'shutdown-handle.txt'
$pipeName = 'SentinelCore.Guard.BackgroundTest.' + [guid]::NewGuid().ToString('N')
$process = $null

try {
    & dotnet build $project --configuration Release --nologo -m:1 -p:NuGetAudit=false
    if ($LASTEXITCODE -ne 0) { throw 'La compilation de D3 a échoué.' }
    New-Item -ItemType Directory -Force -Path $reportsDirectory | Out-Null

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $executable
    $startInfo.WorkingDirectory = $workspaceRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.Environment['SENTINELCORE_TEST_GUARD_PIPE_NAME'] = $pipeName
    $startInfo.Environment['SENTINELCORE_TEST_SHUTDOWN_HANDLE_PATH'] = $handleFile
    foreach ($argument in @('--serve', '--model', 'gemma3:1b', '--reports-dir', $reportsDirectory)) {
        [void]$startInfo.ArgumentList.Add($argument)
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) { throw "Windows n'a pas lancé D3." }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $process.StandardInput.Close()

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    $startupReports = @()
    do {
        $process.Refresh()
        if ($process.HasExited) {
            [void]$stdoutTask.Wait(1000)
            [void]$stderrTask.Wait(1000)
            throw "D3 s'est arrêté après la fermeture de l'entrée du Centre. Sortie : $($stdoutTask.Result) $($stderrTask.Result)"
        }
        $startupReports = @(Get-ChildItem -LiteralPath $reportsDirectory -Filter 'session_*.json' -File -ErrorAction SilentlyContinue)
        if ($startupReports.Count -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    if ($startupReports.Count -eq 0) { throw "Aucun rapport de démarrage n'a été créé avant expiration du délai." }
    $process.Refresh()
    if ($process.HasExited) { throw "D3 n'est pas resté actif après la fermeture de l'entrée du Centre." }

    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class SentinelCoreShutdownProbe {
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int maxCount);
    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr hWnd, uint message, IntPtr wParam, IntPtr lParam);
}
'@
    $windowTitle = "SentinelCoreShutdownMonitor:$($process.Id)"
    $window = [IntPtr]::Zero
    do {
        if (Test-Path -LiteralPath $handleFile) {
            $handleValue = [Convert]::ToInt64((Get-Content -LiteralPath $handleFile -Raw).Trim(), 16)
            $window = [IntPtr]::new($handleValue)
        }
        if ($window -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ($window -eq [IntPtr]::Zero) { throw "La fenêtre interne de notification Windows n'a pas été trouvée." }
    $titleBuffer = [System.Text.StringBuilder]::new(256)
    [void][SentinelCoreShutdownProbe]::GetWindowText($window, $titleBuffer, $titleBuffer.Capacity)
    if ($titleBuffer.ToString() -ne $windowTitle) { throw 'Le handle ne correspond pas à la fenêtre de D3 isolé.' }
    if ([SentinelCoreShutdownProbe]::IsWindowVisible($window)) { throw "La fenêtre interne de notification n'est pas masquée." }

    $queryResult = [SentinelCoreShutdownProbe]::SendMessage($window, 0x0011, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($queryResult -eq [IntPtr]::Zero) { throw "D3 n'a pas accepté la notification de pré-arrêt." }
    [void][SentinelCoreShutdownProbe]::SendMessage($window, 0x0016, [IntPtr]::new(1), [IntPtr]::Zero)
    if (-not $process.WaitForExit(8000)) { throw "D3 n'a pas terminé l'écriture après la notification de fin de session." }

    $finalReportFound = $false
    foreach ($file in (Get-ChildItem -LiteralPath $reportsDirectory -Filter 'session_*.json' -File)) {
        try {
            $report = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            if ($report.trigger -eq 'SESSION_END' -and $report.isFinal -eq $true) { $finalReportFound = $true; break }
        } catch { }
    }
    if (-not $finalReportFound) { throw "Le rapport final SESSION_END n'a pas été trouvé après la notification Windows." }
    Write-Host 'PASS D3 reste actif après la fermeture du canal stdin du Centre.'
    Write-Host 'PASS D3 enregistre un rapport de démarrage avant de poursuivre en arrière-plan.'
    Write-Host 'PASS une notification Windows simulée déclenche le rapport final sans arrêter le PC.'
}
finally {
    if ($null -ne $process) {
        try {
            if (-not $process.HasExited) { $process.Kill($true); [void]$process.WaitForExit(5000) }
        } catch { }
        $process.Dispose()
    }
    $fullTestRoot = [System.IO.Path]::GetFullPath($testRoot)
    $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($fullTestRoot.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $fullTestRoot)) {
        $item = Get-Item -LiteralPath $fullTestRoot -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            Remove-Item -LiteralPath $fullTestRoot -Recurse -Force
        }
    }
}

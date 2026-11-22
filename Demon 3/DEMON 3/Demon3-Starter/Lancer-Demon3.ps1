Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$project = Join-Path $PSScriptRoot 'src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj'
if (-not (Test-Path -LiteralPath $project)) {
    throw "Projet Demon 3 introuvable : $project"
}

Write-Host 'SentinelCore — lancement du démon 3'
Write-Host '1. Démarrer en simulation (choix recommandé)'
Write-Host '2. Démarrer avec analyse Defender activable après approbation D1'
Write-Host '3. Consulter les rapports'
Write-Host '4. Tester Ollama avec des signaux fictifs'
$choice = Read-Host 'Choix'

Push-Location $PSScriptRoot
try {
    $arguments = @('run', '--project', $project, '--')
    if ($choice -eq '1') { $arguments += '--serve' }
    elseif ($choice -eq '2') {
        Write-Host 'Le scan réel exige un finding D2 élevé et une approbation fraîche par mot de passe maître dans D1.'
        $arguments += @('--serve', '--enable-defender-scan')
    }
    elseif ($choice -eq '3') { $arguments += '--reports' }
    elseif ($choice -eq '4') {
        $model = Read-Host 'Modèle Ollama (laisser vide pour gemma3:1b)'
        if ([string]::IsNullOrWhiteSpace($model)) { $model = 'gemma3:1b' }
        $arguments += @('--ollama-advisory-demo', $model.Trim())
    }
    else { Write-Host 'Choix invalide; aucune action lancée.'; return }

    if ($choice -in @('1', '2')) {
        $d2Sid = Read-Host 'SID du compte de service D2 si différent du compte courant (laisser vide sinon)'
        if (-not [string]::IsNullOrWhiteSpace($d2Sid)) {
            $arguments += @('--allow-d2-client-sid', $d2Sid.Trim())
        }
    }

    & dotnet @arguments
    $resultCode = $LASTEXITCODE
}
finally {
    Pop-Location
}
exit $resultCode

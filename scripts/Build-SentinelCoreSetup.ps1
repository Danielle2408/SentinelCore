[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$workspaceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$separator = [System.IO.Path]::DirectorySeparatorChar
$packageRoot = Join-Path $env:TEMP ('SentinelCoreSetup-' + [guid]::NewGuid().ToString('N'))
$payloadRoot = Join-Path $packageRoot 'payload'
$modelsRoot = Join-Path $packageRoot 'models'
$outputRoot = Join-Path $workspaceRoot 'dist'
$innoCompiler = Join-Path $env:LOCALAPPDATA 'SentinelCore\BuildTools\InnoSetup-6.7.4\ISCC.exe'
$setupDefinition = Join-Path $PSScriptRoot 'SentinelCoreSetup.iss'

function Reset-SafeDirectory([string]$path) {
    $fullPath = [System.IO.Path]::GetFullPath($path)
    $prefix = [System.IO.Path]::GetFullPath($packageRoot).TrimEnd($separator) + $separator
    if (-not $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Suppression refusée hors du workspace : $fullPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
        $item = Get-Item -LiteralPath $fullPath -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Suppression refusée sur un lien symbolique : $fullPath"
        }
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $fullPath | Out-Null
}

if (-not (Test-Path -LiteralPath $setupDefinition)) { throw "Définition Inno Setup absente : $setupDefinition" }
if (-not (Test-Path -LiteralPath $innoCompiler)) { throw "ISCC.exe absent : installe Inno Setup 6.7.4 depuis https://jrsoftware.org/inno-setup/downloads" }
if (-not (Test-Path -LiteralPath (Join-Path $workspaceRoot 'Control Center\Assets\SentinelCore.ico'))) { throw 'Icône SentinelCore.ico absente.' }

Reset-SafeDirectory $payloadRoot
Reset-SafeDirectory $modelsRoot
New-Item -ItemType Directory -Force -Path $outputRoot | Out-Null

foreach ($name in @('Control Center', 'Demon 1', 'Demon 2', 'Demon 3')) {
    $source = Join-Path $workspaceRoot $name
    $destination = Join-Path $payloadRoot $name
    $excludedDirectories = @(Get-ChildItem -LiteralPath $source -Directory -Recurse -Force |
        Where-Object { $_.Name -in @('bin', 'obj', 'artifacts', '.git', '.vs', 'node_modules') } |
        ForEach-Object { $_.FullName })
    $copyArguments = @('/E')
    if ($excludedDirectories.Count -gt 0) { $copyArguments += @('/XD') + $excludedDirectories }
    $copyArguments += @('/XF', '*.zip', '*.pdf', '*.docx', '/NFL', '/NDL', '/NJH', '/NJS', '/NP')
    & robocopy $source $destination @copyArguments | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Échec de copie des sources $name (robocopy $LASTEXITCODE)." }
}

$sourceModels = Join-Path $env:LOCALAPPDATA 'SentinelCore\Demon1Learning\models'
$modelHashes = @{
    'face_detection_yunet_2023mar.onnx' = '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4'
    'face_recognition_sface_2021dec.onnx' = '0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79'
    'MiniFASNetV2.onnx' = 'b32929adc2d9c34b9486f8c4c7bc97c1b69bc0ea9befefc380e4faae4e463907'
    'Facenox-MiniFASNetV2-SE.onnx' = 'af2381b88f38769222ed93379e12444e2a50814575de1c46170de570c55a42b6'
}

# Hashes are repeated from Mode_Validation/Modeles/Download-Models.ps1 so a changed or untrusted model is never packed silently.
foreach ($entry in $modelHashes.GetEnumerator()) {
    $source = Join-Path $sourceModels $entry.Key
    if (-not (Test-Path -LiteralPath $source)) { throw "Modèle requis absent : $source" }
    $actualHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $entry.Value) { throw "Empreinte du modèle non conforme : $($entry.Key)" }
    Copy-Item -LiteralPath $source -Destination (Join-Path $modelsRoot $entry.Key)
}

$publishTargets = @(
    @(
        (Join-Path $workspaceRoot 'Demon 1\Mode_Apprentissage\src\SentinelCore.Demon1.Learning.Controller\SentinelCore.Demon1.Learning.Controller.csproj'),
        (Join-Path $payloadRoot 'Demon 1\Mode_Apprentissage\src\SentinelCore.Demon1.Learning.Controller\bin\Release\net10.0-windows10.0.19041.0')
    ),
    @(
        (Join-Path $workspaceRoot 'Demon 2\src\SentinelCore.Demon2.Service\SentinelCore.Demon2.Service.csproj'),
        (Join-Path $payloadRoot 'Demon 2\src\SentinelCore.Demon2.Service\bin\Release\net10.0')
    ),
    @(
        (Join-Path $workspaceRoot 'Demon 3\DEMON 3\Demon3-Starter\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj'),
        (Join-Path $payloadRoot 'Demon 3\DEMON 3\Demon3-Starter\src\SentinelCore.Demon3.Cli\bin\Release\net10.0-windows10.0.19041.0')
    ),
    @(
        (Join-Path $workspaceRoot 'Control Center\SentinelCore.ControlCenter\SentinelCore.ControlCenter.csproj'),
        (Join-Path $payloadRoot 'Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0')
    )
)

foreach ($target in $publishTargets) {
    $project = $target[0]
    $destination = $target[1]
    $isolatedBuildOutput = Join-Path $packageRoot (Join-Path 'build-bin' ([System.IO.Path]::GetFileNameWithoutExtension($project)))
    New-Item -ItemType Directory -Force -Path $isolatedBuildOutput | Out-Null
    Write-Host "Publication autonome : $([System.IO.Path]::GetFileNameWithoutExtension($project))"
    & dotnet publish $project --configuration Release --runtime win-x64 --self-contained true --output $destination `
        "-p:BaseOutputPath=$isolatedBuildOutput$separator" -p:NuGetAudit=false -p:PublishReadyToRun=false --nologo
    if ($LASTEXITCODE -ne 0) { throw "Publication échouée : $project" }
}

$expectedExecutables = @(
    (Join-Path $payloadRoot 'Control Center\SentinelCore.ControlCenter\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.ControlCenter.exe'),
    (Join-Path $payloadRoot 'Demon 1\Mode_Apprentissage\src\SentinelCore.Demon1.Learning.Controller\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.Demon1.Learning.Controller.exe'),
    (Join-Path $payloadRoot 'Demon 2\src\SentinelCore.Demon2.Service\bin\Release\net10.0\SentinelCore.Demon2.Service.exe'),
    (Join-Path $payloadRoot 'Demon 3\DEMON 3\Demon3-Starter\src\SentinelCore.Demon3.Cli\bin\Release\net10.0-windows10.0.19041.0\SentinelCore.Demon3.Cli.exe')
)
foreach ($path in $expectedExecutables) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Exécutable requis absent du paquet : $path" }
}

$compilerInfo = [System.Diagnostics.ProcessStartInfo]::new()
$compilerInfo.FileName = $innoCompiler
$compilerInfo.UseShellExecute = $false
$compilerInfo.WorkingDirectory = $workspaceRoot
foreach ($argument in @(
    '/Q',
    "/DSourceRoot=$workspaceRoot",
    "/DPayloadDir=$payloadRoot",
    "/DModelsDir=$modelsRoot",
    "/DOutputDir=$outputRoot",
    $setupDefinition
)) { [void]$compilerInfo.ArgumentList.Add($argument) }

$compiler = [System.Diagnostics.Process]::new()
$compiler.StartInfo = $compilerInfo
if (-not $compiler.Start()) { throw "Inno Setup Compiler n'a pas démarré." }
$compiler.WaitForExit()
if ($compiler.ExitCode -ne 0) { throw "Compilation de l’installateur échouée (code $($compiler.ExitCode))." }

$setupPath = Join-Path $outputRoot 'SentinelCore-Setup-1.0.0.exe'
if (-not (Test-Path -LiteralPath $setupPath)) { throw "ISCC n'a pas produit l'installateur attendu." }
Write-Host "Installateur créé : $setupPath"
Write-Host 'Paquet x64 autonome; installation par utilisateur; authentification conservée; modèles faciaux copiés après vérification SHA-256.'

$resolvedBuildRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $packageRoot).ProviderPath)
$resolvedTempRoot = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd($separator)
if ([System.IO.Path]::GetDirectoryName($resolvedBuildRoot).TrimEnd($separator) -ne $resolvedTempRoot) {
    throw "Nettoyage refusé sur le dossier temporaire inattendu : $resolvedBuildRoot"
}
$buildRootInfo = Get-Item -LiteralPath $resolvedBuildRoot -Force
if (($buildRootInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Nettoyage refusé sur un lien symbolique : $resolvedBuildRoot"
}
Remove-Item -LiteralPath $resolvedBuildRoot -Recurse -Force

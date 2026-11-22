[CmdletBinding()]
param([string]$Destination = (Join-Path $env:LOCALAPPDATA 'SentinelCore\Demon1Learning\models'))

$ErrorActionPreference = 'Stop'
$models = @(
    @{ Name = 'face_detection_yunet_2023mar.onnx'; Url = 'https://huggingface.co/opencv/face_detection_yunet/resolve/main/face_detection_yunet_2023mar.onnx'; Sha256 = '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4' },
    @{ Name = 'face_recognition_sface_2021dec.onnx'; Url = 'https://huggingface.co/opencv/opencv_zoo/resolve/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx'; Sha256 = '0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79' },
    @{ Name = 'MiniFASNetV2.onnx'; Url = 'https://github.com/yakhyo/face-anti-spoofing/releases/download/weights/MiniFASNetV2.onnx'; Sha256 = 'b32929adc2d9c34b9486f8c4c7bc97c1b69bc0ea9befefc380e4faae4e463907' },
    @{ Name = 'Facenox-MiniFASNetV2-SE.onnx'; Url = 'https://github.com/facenox/face-antispoof-onnx/releases/download/v1.0.0/best_model.onnx'; Sha256 = 'af2381b88f38769222ed93379e12444e2a50814575de1c46170de570c55a42b6' }
)

New-Item -ItemType Directory -Force -Path $Destination | Out-Null
foreach ($model in $models) {
    $target = Join-Path $Destination $model.Name
    $temporary = "$target.download"
    if (Test-Path -LiteralPath $target) {
        $existingHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($existingHash -eq $model.Sha256) { Write-Host "Déjà vérifié : $($model.Name)"; continue }
    }
    Write-Host "Téléchargement de $($model.Name)..."
    try {
        Invoke-WebRequest -Uri $model.Url -OutFile $temporary
        $actualHash = (Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $model.Sha256) { throw "SHA-256 incorrect pour $($model.Name) : $actualHash" }
        Move-Item -LiteralPath $temporary -Destination $target -Force
        Write-Host "Vérifié : $($model.Name)"
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
Write-Host "Modèles prêts dans $Destination"

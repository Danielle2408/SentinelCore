using System.Text.Json;
using SentinelCore.Demon1.VisualVerification;

if (args.Length == 0 || args[0] is not ("--camera-d3" or "--camera-request" or "--camera-failure" or "--camera-deadline"))
{
    Console.WriteLine("Usage: SentinelCore.Demon1.VisualSimulation.exe --camera-d3 | --camera-request | --camera-failure | --camera-deadline");
    return 2;
}

var appData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon1Learning");
var models = Path.Combine(appData, "models");
var testData = Path.Combine(Path.GetTempPath(), "SentinelCore-D1-VisualSimulation", Guid.NewGuid().ToString("N"));
var reportPath = Path.Combine(Environment.CurrentDirectory, "Demon 1", "Mode_Validation", "simulation", "historique_essais_camera.jsonl");
Directory.CreateDirectory(Path.GetDirectoryName(reportPath)!);
var correlationId = Guid.NewGuid().ToString("D");
var started = DateTimeOffset.UtcNow;
var mode = args[0];
string source = mode switch
{
    "--camera-failure" => "caméra invalide (index 8)",
    "--camera-deadline" => "webcam réelle avec échéance D3 de 350 ms",
    _ => "Integrated Camera (5 secondes)"
};
VisualIdentityResponse? response = null;
string? enrollmentStatus = null;
string? enrollmentReason = null;
string? enrollmentDiagnostics = null;
string? verificationDiagnostics = null;
string? error = null;
var temporaryDataDeleted = true;

try
{
    var options = new VisualVerificationOptions(
        Path.Combine(models, "face_detection_yunet_2023mar.onnx"),
        Path.Combine(models, "face_recognition_sface_2021dec.onnx"),
        Path.Combine(models, "MiniFASNetV2.onnx"),
        testData,
        CameraIndex: mode == "--camera-failure" ? 8 : 0,
        CaptureSeconds: 5,
        MaximumWaitSeconds: 60,
        Enabled: true,
        AlternativeLivenessModelPath: Path.Combine(models, "Facenox-MiniFASNetV2-SE.onnx"));
    using var verifier = new VisualVerificationService(options);
    if (mode == "--camera-d3")
    {
        var enrolled = await verifier.EnrollProfileAsync("PROPRIETAIRE_TEST");
        enrollmentDiagnostics = verifier.LastCaptureDiagnostics;
        enrollmentStatus = enrolled.Success ? "ENROLLED" : "FAILED";
        enrollmentReason = enrolled.ReasonCode;
        if (!enrolled.Success) throw new InvalidOperationException("L’enrôlement réel a échoué : " + enrolled.ReasonCode);
        var now = DateTimeOffset.UtcNow;
        var request = new VisualIdentityRequest(correlationId, "SUSPICION", now, now.AddSeconds(60), true);
        response = await new Demon1VisualRequestHandler(verifier, () => true).HandleAsync(request);
        verificationDiagnostics = verifier.LastCaptureDiagnostics;
    }
    else
    {
        var now = DateTimeOffset.UtcNow;
        var request = new VisualIdentityRequest(correlationId, "SUSPICION", now,
            now.AddMilliseconds(mode == "--camera-deadline" ? 350 : 60_000), true);
        response = await new Demon1VisualRequestHandler(verifier, () => true).HandleAsync(request);
        verificationDiagnostics = verifier.LastCaptureDiagnostics;
    }
}
catch (Exception ex) { error = ex.GetType().Name + ": " + ex.Message; }
finally
{
    try { if (Directory.Exists(testData)) Directory.Delete(testData, recursive: true); }
    catch (Exception ex)
    {
        temporaryDataDeleted = false;
        error ??= "Nettoyage du profil de test impossible : " + ex.Message;
    }
}

var record = new
{
    atUtc = DateTimeOffset.UtcNow,
    mode,
    source,
    correlationId,
    durationSeconds = (DateTimeOffset.UtcNow - started).TotalSeconds,
    enrollment = enrollmentStatus is null ? null : new { status = enrollmentStatus, reasonCode = enrollmentReason },
    enrollmentDiagnostics,
    d3Response = response,
    verificationDiagnostics,
    error,
    temporaryTemplateAndEvidenceDeleted = temporaryDataDeleted
};
var json = JsonSerializer.Serialize(record, new JsonSerializerOptions { WriteIndented = true });
File.AppendAllText(reportPath, json + Environment.NewLine);
Console.WriteLine(json);
Console.WriteLine("Rapport : " + reportPath);
return error is null && (mode != "--camera-d3" || response?.Status == "MATCH") ? 0 : 1;

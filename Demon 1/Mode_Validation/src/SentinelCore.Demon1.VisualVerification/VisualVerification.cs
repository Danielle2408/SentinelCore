using OpenCvSharp;
using OpenCvSharp.Dnn;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace SentinelCore.Demon1.VisualVerification;

public enum VisualMatch { MATCH, NO_MATCH, INDETERMINATE }
public enum LivenessResult { LIVE, SPOOF_SUSPECTED, INDETERMINATE }

public sealed record VisualCheckResult(
    string CorrelationId,
    DateTimeOffset CapturedAtUtc,
    VisualMatch Match,
    LivenessResult Liveness,
    string? ProfileId,
    double? Similarity,
    double FaceQuality,
    int ValidFrames,
    string? EvidenceRef,
    string ReasonCode);

public sealed record VisualVerificationOptions(
    string YuNetModelPath,
    string SFaceModelPath,
    string MiniFasNetModelPath,
    string DataDirectory,
    int CameraIndex = 0,
    int CaptureSeconds = 5,
    int MaximumWaitSeconds = 60,
    double SimilarityThreshold = 0.363,
    double MinimumLivenessProbability = 0.60,
    double MinimumFacePixels = 100,
    float MinimumFaceConfidence = 0.60f,
    int LiveClassIndex = 1,
    bool Enabled = true,
    string? AlternativeLivenessModelPath = null);

/// <summary>
/// Local-only visual enrollment and alert-time verification. It never sends frames or face
/// templates over the inter-daemon pipe; only the result and an opaque evidence reference go to D3.
/// </summary>
public sealed class VisualVerificationService : IDisposable
{
    private const int SampleIntervalMs = 350;
    private static readonly SemaphoreSlim CameraCaptureGate = new(1, 1);
    private readonly VisualVerificationOptions _options;
    private readonly FaceDetectorYN _detector;
    private readonly FaceRecognizerSF _recognizer;
    private readonly Net _liveness;
    private readonly Net? _alternativeLiveness;
    private readonly ProtectedVisualStore _store;
    private bool _disposed;
    public bool HasEnrolledProfiles => _store.LoadTemplates().Count > 0;
    public string LastCaptureDiagnostics { get; private set; } = "capture_non_exécutée";

    public VisualVerificationService(VisualVerificationOptions options)
    {
        _options = options;
        foreach (var path in new[] { options.YuNetModelPath, options.SFaceModelPath, options.MiniFasNetModelPath })
            if (!File.Exists(path)) throw new FileNotFoundException("Modèle visuel manquant. Consultez Mode_Validation/Modeles/README.md.", path);
        if (options.CaptureSeconds is < 2 or > 10) throw new ArgumentOutOfRangeException(nameof(options.CaptureSeconds));
        if (options.MaximumWaitSeconds is < 5 or > 60) throw new ArgumentOutOfRangeException(nameof(options.MaximumWaitSeconds));
        Directory.CreateDirectory(options.DataDirectory);
        _store = new ProtectedVisualStore(options.DataDirectory);
        _detector = FaceDetectorYN.Create(options.YuNetModelPath, string.Empty, new Size(640, 480), options.MinimumFaceConfidence, 0.3f, 5000);
        _recognizer = FaceRecognizerSF.Create(options.SFaceModelPath, string.Empty);
        _liveness = Cv2.Dnn.ReadNetFromONNX(options.MiniFasNetModelPath)
            ?? throw new InvalidDataException("OpenCV n’a pas pu charger le modèle anti-usurpation.");
        _liveness.SetPreferableBackend(Backend.OPENCV);
        if (!string.IsNullOrWhiteSpace(options.AlternativeLivenessModelPath) && File.Exists(options.AlternativeLivenessModelPath))
        {
            _alternativeLiveness = Cv2.Dnn.ReadNetFromONNX(options.AlternativeLivenessModelPath)
                ?? throw new InvalidDataException("OpenCV n’a pas pu charger le modèle anti-usurpation alternatif.");
            _alternativeLiveness.SetPreferableBackend(Backend.OPENCV);
        }
    }

    /// <summary>Enroll one configured profile from a live 5-second camera sequence.</summary>
    public async Task<(bool Success, string ReasonCode)> EnrollProfileAsync(string profileId, CancellationToken cancellationToken = default)
    {
        ValidateProfileId(profileId);
        var sequence = await CaptureSequenceAsync(cancellationToken).ConfigureAwait(false);
        LastCaptureDiagnostics = sequence.Diagnostics;
        if (sequence.FramesMultipleFaces > 0) return (false, "ENROLLMENT_MULTIPLE_FACES");
        if (sequence.Embeddings.Count < 4) return (false, EnrollmentFailureReason(sequence));
        if (sequence.LiveScores.Count < 4 || sequence.LiveScores.Average() < _options.MinimumLivenessProbability)
            return (false, "ENROLLMENT_LIVENESS_NOT_CONFIRMED");
        var template = AverageAndNormalize(sequence.Embeddings);
        _store.SaveTemplate(profileId, template);
        return (true, "PROFILE_ENROLLED_LOCAL_DPAPI");
    }

    /// <summary>
    /// Called by D1's D3-request handler after a suspicion/alert. It captures for at most the
    /// configured window, then returns an explicit tri-state result; timeout/failure is inconclusive.
    /// </summary>
    public async Task<VisualCheckResult> VerifyAlertAsync(string correlationId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(correlationId)) throw new ArgumentException("Une correlationId est obligatoire.", nameof(correlationId));
        var started = DateTimeOffset.UtcNow;
        if (!_options.Enabled) return Inconclusive(correlationId, started, "VISUAL_VERIFICATION_DISABLED");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(_options.MaximumWaitSeconds));
        CaptureSequence sequence;
        try { sequence = await CaptureSequenceAsync(deadline.Token).ConfigureAwait(false); }
        catch (OperationCanceledException)
        {
            return Inconclusive(correlationId, started, "VISUAL_CHECK_TIMEOUT");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
        {
            return Inconclusive(correlationId, started, "VISUAL_ENGINE_ERROR_" + ex.GetType().Name.ToUpperInvariant());
        }
        LastCaptureDiagnostics = sequence.Diagnostics;

        if (sequence.FramesMultipleFaces > 0)
            return Inconclusive(correlationId, started, "MULTIPLE_FACES_IN_FRAME", sequence, SaveEvidence(sequence.BestFrame, correlationId));
        if (sequence.Embeddings.Count < 3)
            return Inconclusive(correlationId, started, VerificationFailureReason(sequence), sequence, SaveEvidence(sequence.BestFrame, correlationId));
        if (sequence.LiveScores.Count < 3) return Inconclusive(correlationId, started, "LIVENESS_MODEL_NO_RESULT", sequence, SaveEvidence(sequence.BestFrame, correlationId));
        var liveness = sequence.LiveScores.Average() >= _options.MinimumLivenessProbability
            ? LivenessResult.LIVE : LivenessResult.SPOOF_SUSPECTED;
        if (liveness != LivenessResult.LIVE)
            return new(correlationId, DateTimeOffset.UtcNow, VisualMatch.INDETERMINATE, liveness, null, null,
                sequence.Quality, sequence.Embeddings.Count, SaveEvidence(sequence.BestFrame, correlationId), "LIVENESS_NOT_CONFIRMED");
        if (sequence.Quality < 0.55)
            return new(correlationId, DateTimeOffset.UtcNow, VisualMatch.INDETERMINATE, liveness, null, null,
                sequence.Quality, sequence.Embeddings.Count, SaveEvidence(sequence.BestFrame, correlationId), "FACE_QUALITY_TOO_LOW");

        var query = AverageAndNormalize(sequence.Embeddings);
        var ranked = _store.LoadTemplates().Select(x => (x.Key, Score: Cosine(query, x.Value)))
            .OrderByDescending(x => x.Score).ToArray();
        if (ranked.Length == 0)
            return new(correlationId, DateTimeOffset.UtcNow, VisualMatch.INDETERMINATE, liveness, null, null,
                sequence.Quality, sequence.Embeddings.Count, SaveEvidence(sequence.BestFrame, correlationId), "NO_ENROLLED_VISUAL_PROFILE");
        var best = ranked[0];
        var margin = ranked.Length == 1 ? 1 : best.Score - ranked[1].Score;
        if (margin < 0.04)
            return new(correlationId, DateTimeOffset.UtcNow, VisualMatch.INDETERMINATE, liveness, null, best.Score,
                sequence.Quality, sequence.Embeddings.Count, SaveEvidence(sequence.BestFrame, correlationId), "AMBIGUOUS_PROFILE_MARGIN");
        if (best.Score < _options.SimilarityThreshold)
            return new(correlationId, DateTimeOffset.UtcNow, VisualMatch.NO_MATCH, liveness, null, best.Score,
                sequence.Quality, sequence.Embeddings.Count, SaveEvidence(sequence.BestFrame, correlationId), "NO_PROFILE_OVER_CALIBRATED_THRESHOLD");
        return new(correlationId, DateTimeOffset.UtcNow, VisualMatch.MATCH, liveness, best.Key, best.Score,
            sequence.Quality, sequence.Embeddings.Count, SaveEvidence(sequence.BestFrame, correlationId), "PROFILE_MATCH_AND_LIVENESS_CONFIRMED");
    }

    private async Task<CaptureSequence> CaptureSequenceAsync(CancellationToken token)
    {
        await CameraCaptureGate.WaitAsync(token).ConfigureAwait(false);
        try
        {
            return await Task.Run(() =>
            {
                using var camera = new VideoCapture(_options.CameraIndex, VideoCaptureAPIs.DSHOW);
                if (!camera.IsOpened()) throw new IOException("La caméra configurée ne peut pas être ouverte.");
                camera.Set(VideoCaptureProperties.FrameWidth, 640);
                camera.Set(VideoCaptureProperties.FrameHeight, 480);
                var embeddings = new List<float[]>();
                var liveScores = new List<double>();
                var alternativeLiveScores = new List<double>();
                var faceBrightness = new List<double>();
                byte[]? bestFrame = null;
                var bestFrameQuality = -1.0;
                var qualitySum = 0.0;
                var framesRead = 0; var framesNoFace = 0; var framesMultipleFaces = 0; var framesTooSmall = 0; var framesLowConfidence = 0;
                var maxFaceSize = 0.0;
                var deadline = DateTimeOffset.UtcNow.AddSeconds(_options.CaptureSeconds);
                using var frame = new Mat();
                using var grayFrame = new Mat();
                using var detections = new Mat();
                using var aligned = new Mat();
                using var features = new Mat();
                while (DateTimeOffset.UtcNow < deadline)
                {
                    token.ThrowIfCancellationRequested();
                    if (!camera.Read(frame) || frame.Empty()) { Thread.Sleep(50); continue; }
                    framesRead++;
                    var frameQuality = 0.0;
                    _detector.SetInputSize(new Size(frame.Width, frame.Height));
                    _detector.Detect(frame, detections);
                    var detectionRows = detections.Rows;
                    if (detectionRows != 1)
                    {
                        if (detectionRows == 0) framesNoFace++;
                        else
                        {
                            framesMultipleFaces++;
                            for (var faceIndex = 0; faceIndex < detectionRows; faceIndex++)
                                maxFaceSize = Math.Max(maxFaceSize, Math.Min(detections.At<float>(faceIndex, 2), detections.At<float>(faceIndex, 3)));
                        }
                        if (bestFrame is null) { Cv2.ImEncode(".jpg", frame, out bestFrame); bestFrameQuality = 0; }
                        Thread.Sleep(SampleIntervalMs); continue;
                    }
                    var faceWidth = detections.At<float>(0, 2);
                    var faceHeight = detections.At<float>(0, 3);
                    maxFaceSize = Math.Max(maxFaceSize, Math.Min(faceWidth, faceHeight));
                    if (faceWidth > 0 && faceHeight > 0)
                    {
                        var faceLeft = Math.Clamp((int)Math.Floor(detections.At<float>(0, 0)), 0, frame.Width - 1);
                        var faceTop = Math.Clamp((int)Math.Floor(detections.At<float>(0, 1)), 0, frame.Height - 1);
                        var faceRight = Math.Clamp((int)Math.Ceiling(detections.At<float>(0, 0) + faceWidth), faceLeft + 1, frame.Width);
                        var faceBottom = Math.Clamp((int)Math.Ceiling(detections.At<float>(0, 1) + faceHeight), faceTop + 1, frame.Height);
                        Cv2.CvtColor(frame, grayFrame, ColorConversionCodes.BGR2GRAY);
                        using var faceGrayCrop = new Mat(grayFrame, new Rect(faceLeft, faceTop, faceRight - faceLeft, faceBottom - faceTop));
                        faceBrightness.Add(Cv2.Mean(faceGrayCrop).Val0);
                    }
                    var detectorScore = detections.At<float>(0, 14);
                    if (Math.Min(faceWidth, faceHeight) < _options.MinimumFacePixels || detectorScore < _options.MinimumFaceConfidence)
                    {
                        if (Math.Min(faceWidth, faceHeight) < _options.MinimumFacePixels) framesTooSmall++; else framesLowConfidence++;
                        if (bestFrame is null) { Cv2.ImEncode(".jpg", frame, out bestFrame); bestFrameQuality = 0; }
                        Thread.Sleep(SampleIntervalMs); continue;
                    }
                    _recognizer.AlignCrop(frame, detections, aligned);
                    _recognizer.Feature(aligned, features);
                    embeddings.Add(ReadFeature(features));
                    frameQuality = Math.Clamp(detectorScore * Math.Min(1.0, Math.Min(faceWidth, faceHeight) / 180.0), 0, 1);
                    qualitySum += frameQuality;
                    liveScores.Add(GetLivenessProbability(frame, detections));
                    if (_alternativeLiveness is not null)
                        alternativeLiveScores.Add(GetAlternativeLivenessProbability(frame, detections));
                    if (frameQuality > bestFrameQuality)
                    { Cv2.ImEncode(".jpg", frame, out bestFrame); bestFrameQuality = frameQuality; }
                    Thread.Sleep(SampleIntervalMs);
                }
                return new CaptureSequence(embeddings, liveScores, embeddings.Count == 0 ? 0 : qualitySum / embeddings.Count, bestFrame,
                    framesRead, framesNoFace, framesMultipleFaces, framesTooSmall, framesLowConfidence, maxFaceSize,
                    $"read={framesRead};face={embeddings.Count};none={framesNoFace};multiple={framesMultipleFaces};small={framesTooSmall};lowConfidence={framesLowConfidence};maxFacePx={maxFaceSize:0};faceLumaCount={faceBrightness.Count};faceLumaAvg={(faceBrightness.Count == 0 ? 0 : faceBrightness.Average()):0.0};faceLumaMin={(faceBrightness.Count == 0 ? 0 : faceBrightness.Min()):0.0};faceLumaMax={(faceBrightness.Count == 0 ? 0 : faceBrightness.Max()):0.0};liveCount={liveScores.Count};liveAvg={(liveScores.Count == 0 ? 0 : liveScores.Average()):0.000};liveMin={(liveScores.Count == 0 ? 0 : liveScores.Min()):0.000};liveMax={(liveScores.Count == 0 ? 0 : liveScores.Max()):0.000};facenoxCount={alternativeLiveScores.Count};facenoxAvg={(alternativeLiveScores.Count == 0 ? 0 : alternativeLiveScores.Average()):0.000};facenoxMin={(alternativeLiveScores.Count == 0 ? 0 : alternativeLiveScores.Min()):0.000};facenoxMax={(alternativeLiveScores.Count == 0 ? 0 : alternativeLiveScores.Max()):0.000}");
            }, token).ConfigureAwait(false);
        }
        finally { CameraCaptureGate.Release(); }
    }

    private double GetLivenessProbability(Mat frame, Mat face)
    {
        // MiniFASNetV2 expects a face crop enlarged 2.7x and resized to 80x80, BGR/NCHW, 0..255.
        var x = (int)face.At<float>(0, 0); var y = (int)face.At<float>(0, 1);
        var width = (int)face.At<float>(0, 2); var height = (int)face.At<float>(0, 3);
        // Match the upstream MiniFASNetV2 crop: keep the face-box aspect ratio and
        // expand no more than 2.7x or the available frame boundary permits.
        var scale = Math.Min(2.7, Math.Min((frame.Height - 1.0) / Math.Max(1, height),
            (frame.Width - 1.0) / Math.Max(1, width)));
        var cropWidth = Math.Max(1, (int)Math.Ceiling(width * scale));
        var cropHeight = Math.Max(1, (int)Math.Ceiling(height * scale));
        var centerX = x + width / 2.0; var centerY = y + height / 2.0;
        var left = Math.Clamp((int)(centerX - cropWidth / 2.0), 0, frame.Width - 1);
        var top = Math.Clamp((int)(centerY - cropHeight / 2.0), 0, frame.Height - 1);
        var right = Math.Clamp((int)(centerX + cropWidth / 2.0), left, frame.Width - 1);
        var bottom = Math.Clamp((int)(centerY + cropHeight / 2.0), top, frame.Height - 1);
        using var crop = new Mat(frame, new Rect(left, top, right - left + 1, bottom - top + 1));
        using var resized = new Mat();
        Cv2.Resize(crop, resized, new Size(80, 80));
        using var input = Cv2.Dnn.BlobFromImage(resized, 1.0, new Size(80, 80), new Scalar(), false, false);
        _liveness.SetInput(input);
        using var output = _liveness.Forward();
        var scores = new float[output.Total()];
        for (var i = 0; i < scores.Length; i++) scores[i] = output.At<float>(i);
        if (_options.LiveClassIndex < 0 || _options.LiveClassIndex >= scores.Length) return 0;
        // Handle logits and already normalized probabilities.
        var probability = scores.All(x => x is >= 0 and <= 1) && Math.Abs(scores.Sum() - 1) < 0.02
            ? scores[_options.LiveClassIndex]
            : Math.Exp(scores[_options.LiveClassIndex] - scores.Max()) / scores.Sum(x => Math.Exp(x - scores.Max()));
        return Math.Clamp(probability, 0, 1);
    }

    /// <summary>
    /// Experimental Facenox MiniFASNetV2-SE score for A/B diagnostics only. Its result never
    /// participates in MATCH/NO_MATCH until it has been calibrated against this camera and
    /// presentation attacks. Preprocessing follows the upstream implementation: RGB, square
    /// 1.5x face crop with reflected borders, 128x128 and float pixels scaled to [0,1].
    /// </summary>
    private double GetAlternativeLivenessProbability(Mat frame, Mat face)
    {
        if (_alternativeLiveness is null) return 0;

        using var rgb = new Mat();
        Cv2.CvtColor(frame, rgb, ColorConversionCodes.BGR2RGB);
        var x = (int)face.At<float>(0, 0);
        var y = (int)face.At<float>(0, 1);
        var width = (int)face.At<float>(0, 2);
        var height = (int)face.At<float>(0, 3);
        var cropSize = Math.Max(1, (int)(Math.Max(width, height) * 1.5));
        var centerX = x + width / 2.0;
        var centerY = y + height / 2.0;
        var left = (int)(centerX - cropSize / 2.0);
        var top = (int)(centerY - cropSize / 2.0);
        var right = left + cropSize;
        var bottom = top + cropSize;
        var sourceLeft = Math.Clamp(left, 0, rgb.Width);
        var sourceTop = Math.Clamp(top, 0, rgb.Height);
        var sourceRight = Math.Clamp(right, 0, rgb.Width);
        var sourceBottom = Math.Clamp(bottom, 0, rgb.Height);
        if (sourceRight <= sourceLeft || sourceBottom <= sourceTop) return 0;

        using var sourceCrop = new Mat(rgb, new Rect(sourceLeft, sourceTop, sourceRight - sourceLeft, sourceBottom - sourceTop));
        using var square = new Mat();
        Cv2.CopyMakeBorder(sourceCrop, square,
            Math.Max(0, -top), Math.Max(0, bottom - rgb.Height),
            Math.Max(0, -left), Math.Max(0, right - rgb.Width),
            BorderTypes.Reflect101);
        if (square.Width != cropSize || square.Height != cropSize)
            throw new InvalidDataException("La coupe de visage expérimentale n’a pas les dimensions attendues.");

        using var resized = new Mat();
        Cv2.Resize(square, resized, new Size(128, 128), 0, 0, InterpolationFlags.Area);
        using var input = Cv2.Dnn.BlobFromImage(resized, 1.0 / 255.0, new Size(128, 128), new Scalar(), false, false);
        _alternativeLiveness.SetInput(input);
        using var output = _alternativeLiveness.Forward();
        if (output.Total() != 2) throw new InvalidDataException("Le modèle Facenox doit produire exactement deux scores.");

        // Upstream labels logits[0] as Real and logits[1] as Spoof.
        var real = output.At<float>(0);
        var spoof = output.At<float>(1);
        var max = Math.Max(real, spoof);
        var realExp = Math.Exp(real - max);
        var spoofExp = Math.Exp(spoof - max);
        return Math.Clamp(realExp / (realExp + spoofExp), 0, 1);
    }

    private string SaveEvidence(byte[]? jpeg, string correlationId)
    {
        if (jpeg is null) return string.Empty;
        var evidenceRef = Guid.NewGuid().ToString("N");
        _store.SaveEvidence(evidenceRef, jpeg);
        return evidenceRef;
    }

    private static float[] ReadFeature(Mat feature)
    {
        var values = new float[feature.Cols * feature.Rows];
        for (var i = 0; i < values.Length; i++) values[i] = feature.At<float>(i / feature.Cols, i % feature.Cols);
        return values;
    }

    private static float[] AverageAndNormalize(IReadOnlyList<float[]> vectors)
    {
        var result = new float[vectors[0].Length];
        foreach (var vector in vectors) for (var i = 0; i < result.Length; i++) result[i] += vector[i] / vectors.Count;
        var norm = Math.Sqrt(result.Sum(x => x * x));
        if (norm <= 1e-12) throw new InvalidDataException("Le modèle a produit un gabarit vide.");
        for (var i = 0; i < result.Length; i++) result[i] = (float)(result[i] / norm);
        return result;
    }

    private static double Cosine(float[] left, float[] right)
    {
        if (left.Length != right.Length) return -1;
        return Math.Clamp(left.Zip(right).Sum(x => x.First * x.Second), -1, 1);
    }

    private static VisualCheckResult Inconclusive(string id, DateTimeOffset start, string reason, CaptureSequence? seq = null, string? evidenceRef = null)
        => new(id, DateTimeOffset.UtcNow, VisualMatch.INDETERMINATE, LivenessResult.INDETERMINATE, null, null,
            seq?.Quality ?? 0, seq?.Embeddings.Count ?? 0, evidenceRef, reason);

    private static string EnrollmentFailureReason(CaptureSequence sequence)
    {
        if (sequence.FramesRead == 0) return "ENROLLMENT_CAMERA_NO_FRAMES";
        if (sequence.FramesMultipleFaces > 0) return "ENROLLMENT_MULTIPLE_FACES";
        if (sequence.FramesTooSmall > 0 && sequence.FramesTooSmall >= sequence.FramesLowConfidence) return "ENROLLMENT_FACE_TOO_SMALL";
        if (sequence.FramesLowConfidence > 0) return "ENROLLMENT_FACE_CONFIDENCE_LOW";
        if (sequence.FramesNoFace == sequence.FramesRead) return "ENROLLMENT_FACE_NOT_DETECTED";
        return "ENROLLMENT_TOO_FEW_VALID_FACE_FRAMES";
    }

    private static string VerificationFailureReason(CaptureSequence sequence)
    {
        if (sequence.FramesRead == 0) return "CAMERA_NO_FRAMES";
        if (sequence.FramesMultipleFaces > 0) return "MULTIPLE_FACES_IN_FRAME";
        if (sequence.FramesTooSmall > 0 && sequence.FramesTooSmall >= sequence.FramesLowConfidence) return "FACE_TOO_SMALL";
        if (sequence.FramesLowConfidence > 0) return "FACE_CONFIDENCE_LOW";
        if (sequence.FramesNoFace == sequence.FramesRead) return "FACE_NOT_DETECTED";
        return "FACE_QUALITY_OR_FRAME_COUNT_LOW";
    }

    private static void ValidateProfileId(string id)
    {
        if (string.IsNullOrWhiteSpace(id) || id.Length > 64 || id.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '_' and not '-'))
            throw new ArgumentException("Identifiant de profil invalide.", nameof(id));
    }

    public byte[]? ReadEvidence(string evidenceRef) => _store.ReadEvidence(evidenceRef);
    public void DeleteProfile(string profileId) => _store.DeleteTemplate(profileId);
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _detector.Dispose(); _recognizer.Dispose(); _liveness.Dispose(); _alternativeLiveness?.Dispose();
    }

    private sealed record CaptureSequence(List<float[]> Embeddings, List<double> LiveScores, double Quality, byte[]? BestFrame,
        int FramesRead, int FramesNoFace, int FramesMultipleFaces, int FramesTooSmall, int FramesLowConfidence, double MaxFaceSizePixels, string Diagnostics);
}

/// <summary>Per-user DPAPI storage: templates and retained report evidence are encrypted at rest.</summary>
internal sealed class ProtectedVisualStore
{
    private static readonly byte[] Entropy = "SentinelCore.D1.Visual.v1"u8.ToArray();
    private readonly string _directory;
    private readonly string _templatesPath;
    public ProtectedVisualStore(string directory)
    {
        _directory = Path.GetFullPath(directory);
        _templatesPath = Path.Combine(_directory, "profils-visuels.dpapi");
    }

    public void SaveTemplate(string profileId, float[] vector)
    {
        var rows = LoadTemplates(); rows[profileId] = vector;
        var bytes = ProtectedDataBlob.Protect(JsonSerializer.SerializeToUtf8Bytes(rows), Entropy);
        var temp = _templatesPath + ".tmp";
        File.WriteAllBytes(temp, bytes); File.Move(temp, _templatesPath, true);
    }

    public Dictionary<string, float[]> LoadTemplates()
    {
        if (!File.Exists(_templatesPath)) return new(StringComparer.Ordinal);
        var json = ProtectedDataBlob.Unprotect(File.ReadAllBytes(_templatesPath), Entropy);
        return JsonSerializer.Deserialize<Dictionary<string, float[]>>(json) ?? new(StringComparer.Ordinal);
    }

    public void DeleteTemplate(string profileId)
    {
        var rows = LoadTemplates(); if (!rows.Remove(profileId)) return;
        if (rows.Count == 0) { File.Delete(_templatesPath); return; }
        File.WriteAllBytes(_templatesPath, ProtectedDataBlob.Protect(JsonSerializer.SerializeToUtf8Bytes(rows), Entropy));
    }

    public void SaveEvidence(string id, byte[] jpeg)
    {
        if (id.Length != 32 || id.Any(c => !Uri.IsHexDigit(c))) throw new ArgumentException("Référence de preuve invalide.", nameof(id));
        var path = Path.Combine(_directory, "evidence-" + id + ".dpapi");
        File.WriteAllBytes(path, ProtectedDataBlob.Protect(jpeg, Entropy));
    }

    public byte[]? ReadEvidence(string id)
    {
        if (id.Length != 32 || id.Any(c => !Uri.IsHexDigit(c))) return null;
        var path = Path.Combine(_directory, "evidence-" + id + ".dpapi");
        return File.Exists(path) ? ProtectedDataBlob.Unprotect(File.ReadAllBytes(path), Entropy) : null;
    }
}

/// <summary>Reads report evidence without loading face-recognition models or opening the camera.</summary>
public sealed class VisualEvidenceReader(string directory)
{
    private readonly ProtectedVisualStore _store = new(directory);
    public byte[]? ReadEvidence(string evidenceRef) => _store.ReadEvidence(evidenceRef);

    public VisualEvidenceChunk? ReadChunk(VisualEvidenceReadRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Offset < 0 || request.MaxBytes is < 1 or > 24 * 1024) return null;
        var image = _store.ReadEvidence(request.EvidenceRef);
        if (image is null || request.Offset > image.Length) return null;
        var length = Math.Min(request.MaxBytes, image.Length - request.Offset);
        return new(request.EvidenceRef, request.Offset, image.Length,
            Convert.ToBase64String(image.AsSpan(request.Offset, length)), request.Offset + length >= image.Length);
    }
}

internal static class ProtectedDataBlob
{
    private const int CryptProtectUiForbidden = 0x1;
    [StructLayout(LayoutKind.Sequential)] private struct DataBlob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref DataBlob input, string? description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob entropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr LocalFree(IntPtr memory);

    public static byte[] Protect(byte[] plain, byte[] entropy) => Transform(plain, entropy, true);
    public static byte[] Unprotect(byte[] cipher, byte[] entropy) => Transform(cipher, entropy, false);
    private static byte[] Transform(byte[] source, byte[] entropyBytes, bool protect)
    {
        var input = MakeBlob(source); var entropy = MakeBlob(entropyBytes);
        try
        {
            var ok = protect
                ? CryptProtectData(ref input, "SentinelCore D1 visuel", ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out var output)
                : CryptUnprotectData(ref input, IntPtr.Zero, ref entropy, IntPtr.Zero, IntPtr.Zero, CryptProtectUiForbidden, out output);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            try { var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, result.Length); return result; }
            finally { if (output.Data != IntPtr.Zero) LocalFree(output.Data); }
        }
        finally { FreeBlob(ref input); FreeBlob(ref entropy); }
    }
    private static DataBlob MakeBlob(byte[] bytes)
    {
        var ptr = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return new DataBlob { Size = bytes.Length, Data = ptr };
    }
    private static void FreeBlob(ref DataBlob blob)
    {
        if (blob.Data != IntPtr.Zero) { Marshal.FreeHGlobal(blob.Data); blob.Data = IntPtr.Zero; blob.Size = 0; }
    }
}

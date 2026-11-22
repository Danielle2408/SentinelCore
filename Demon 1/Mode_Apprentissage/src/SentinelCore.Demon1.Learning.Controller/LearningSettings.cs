using System.Text.Json;

namespace SentinelCore.Demon1.Learning.Controller;

internal sealed record LearningSettings(int WindowSeconds = 15, int IdleStopSeconds = 90, int ProfileCount = 1,
    bool VisualVerificationEnabled = false, int VisualCameraIndex = 0, int ContextRetentionDays = 30)
{
    public static LearningSettings Load(string root)
    {
        var path = Path.Combine(root, "settings.json");
        try
        {
            if (File.Exists(path))
            {
                var value = JsonSerializer.Deserialize<LearningSettings>(File.ReadAllBytes(path));
                if (value is not null) return new(Math.Clamp(value.WindowSeconds, 10, 60), Math.Clamp(value.IdleStopSeconds, 30, 900),
                    Math.Clamp(value.ProfileCount, 1, 8), value.VisualVerificationEnabled,
                    Math.Clamp(value.VisualCameraIndex, 0, 8), Math.Clamp(value.ContextRetentionDays, 1, 90));
            }
        }
        catch (IOException) { }
        catch (JsonException) { }
        return new();
    }

    public void Save(string root)
    {
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "settings.json"), JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}

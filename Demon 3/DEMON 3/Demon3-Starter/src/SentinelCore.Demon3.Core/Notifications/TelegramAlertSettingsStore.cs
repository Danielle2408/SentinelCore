using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SentinelCore.Demon3.Core.Notifications;

public sealed record TelegramAlertSettings(bool Enabled, string ChatId, string BotToken);

/// <summary>Stores the Bot API token and destination under current-user Windows DPAPI.</summary>
public sealed class TelegramAlertSettingsStore(string? filePath = null)
{
    private static readonly byte[] Entropy = SHA256.HashData(Encoding.UTF8.GetBytes("SentinelCore.TelegramAlertSettings.v1"));
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _filePath = filePath ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon3", "telegram-alerts.dpapi");

    public bool Save(TelegramAlertSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.Enabled && (!IsValidBotToken(settings.BotToken) || !IsValidChatId(settings.ChatId))) return false;
        if (!settings.Enabled && settings.BotToken.Length > 256) return false;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Les paramètres Telegram sont protégés par DPAPI Windows.");

        var clear = JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions);
        var protectedBytes = ProtectedData.Protect(clear, Entropy, DataProtectionScope.CurrentUser);
        try
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(_filePath))
                ?? throw new InvalidOperationException("Dossier de configuration Telegram invalide.");
            Directory.CreateDirectory(directory);
            var temporaryPath = _filePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                File.WriteAllBytes(temporaryPath, protectedBytes);
                File.Move(temporaryPath, _filePath, overwrite: true);
            }
            finally
            {
                if (File.Exists(temporaryPath)) File.Delete(temporaryPath);
            }
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public TelegramAlertSettings? Load()
    {
        if (!OperatingSystem.IsWindows() || !File.Exists(_filePath)) return null;
        byte[]? protectedBytes = null;
        byte[]? clear = null;
        try
        {
            var info = new FileInfo(_filePath);
            if (info.Length is <= 0 or > 16 * 1024) return null;
            protectedBytes = File.ReadAllBytes(_filePath);
            clear = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.CurrentUser);
            var settings = JsonSerializer.Deserialize<TelegramAlertSettings>(clear, JsonOptions);
            if (settings is null || (settings.Enabled && (!IsValidBotToken(settings.BotToken) || !IsValidChatId(settings.ChatId)))) return null;
            return settings;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or JsonException or ArgumentException)
        {
            return null;
        }
        finally
        {
            if (protectedBytes is not null) CryptographicOperations.ZeroMemory(protectedBytes);
            if (clear is not null) CryptographicOperations.ZeroMemory(clear);
        }
    }

    public bool Delete()
    {
        if (!File.Exists(_filePath)) return true;
        try { File.Delete(_filePath); return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    public static bool IsValidBotToken(string? token)
        => token is { Length: >= 25 and <= 256 }
            && token.All(c => char.IsAsciiLetterOrDigit(c) || c is ':' or '_' or '-');

    public static bool IsValidChatId(string? chatId)
    {
        if (string.IsNullOrWhiteSpace(chatId) || chatId.Length > 128) return false;
        if (chatId[0] == '@') return chatId.Length is >= 6 and <= 33
                && chatId.AsSpan(1).ToArray().All(c => char.IsAsciiLetterOrDigit(c) || c == '_');
        var digits = chatId[0] == '-' ? chatId.AsSpan(1) : chatId.AsSpan();
        return digits.Length is > 0 and <= 32 && digits.ToArray().All(char.IsAsciiDigit);
    }
}

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace SentinelCore.Demon3.Core.Notifications;

public enum TelegramDeliveryStatus { SENT, INVALID_CONFIGURATION, REJECTED, UNAVAILABLE }
public sealed record TelegramDeliveryResult(TelegramDeliveryStatus Status, string ReasonCode)
{
    public bool Succeeded => Status == TelegramDeliveryStatus.SENT;
}

/// <summary>Minimal HTTPS-only Telegram Bot API sender. It never logs the token or response body.</summary>
public sealed class TelegramBotApiClient(HttpClient httpClient)
{
    private const int MaximumPdfBytes = 10 * 1024 * 1024;
    private readonly HttpClient _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public Task<TelegramDeliveryResult> SendTestMessageAsync(TelegramAlertSettings settings,
        CancellationToken cancellationToken = default)
        => SendMessageAsync(settings, "Test SentinelCore : le canal d’alerte Telegram est opérationnel.", cancellationToken);

    public async Task<TelegramDeliveryResult> SendMessageAsync(TelegramAlertSettings settings, string text,
        CancellationToken cancellationToken = default)
    {
        if (!IsValid(settings) || string.IsNullOrWhiteSpace(text) || text.Length > 4096)
            return new(TelegramDeliveryStatus.INVALID_CONFIGURATION, "INVALID_CONFIGURATION");

        var uri = Endpoint(settings.BotToken, "sendMessage");
        using var request = new HttpRequestMessage(HttpMethod.Post, uri)
        {
            Content = JsonContent.Create(new { chat_id = settings.ChatId, text }, options: JsonOptions)
        };
        return await SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task<TelegramDeliveryResult> SendPdfAsync(TelegramAlertSettings settings, string caption,
        byte[] pdfBytes, string fileName, CancellationToken cancellationToken = default)
    {
        if (!IsValid(settings) || string.IsNullOrWhiteSpace(caption) || caption.Length > 1024
            || pdfBytes is not { Length: > 0 and <= MaximumPdfBytes }
            || string.IsNullOrWhiteSpace(fileName) || fileName.Length > 120
            || fileName.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_')))
            return new(TelegramDeliveryStatus.INVALID_CONFIGURATION, "INVALID_CONFIGURATION");

        using var form = new MultipartFormDataContent();
        form.Add(new StringContent(settings.ChatId), "chat_id");
        form.Add(new StringContent(caption), "caption");
        var document = new ByteArrayContent(pdfBytes);
        document.Headers.ContentType = new MediaTypeHeaderValue("application/pdf");
        form.Add(document, "document", fileName);
        using var request = new HttpRequestMessage(HttpMethod.Post, Endpoint(settings.BotToken, "sendDocument")) { Content = form };
        return await SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TelegramDeliveryResult> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        try
        {
            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return new(TelegramDeliveryStatus.REJECTED, $"HTTP_{(int)response.StatusCode}");
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var body = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            return body.RootElement.ValueKind == JsonValueKind.Object
                && body.RootElement.TryGetProperty("ok", out var ok)
                && ok.ValueKind == JsonValueKind.True
                ? new(TelegramDeliveryStatus.SENT, "OK")
                : new(TelegramDeliveryStatus.REJECTED, "BOT_API_REJECTED");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(TelegramDeliveryStatus.UNAVAILABLE, "TIMEOUT");
        }
        catch (HttpRequestException)
        {
            return new(TelegramDeliveryStatus.UNAVAILABLE, "NETWORK_ERROR");
        }
        catch (JsonException)
        {
            return new(TelegramDeliveryStatus.REJECTED, "INVALID_API_RESPONSE");
        }
    }

    private static Uri Endpoint(string token, string method)
        => new($"https://api.telegram.org/bot{token}/{method}", UriKind.Absolute);

    private static bool IsValid(TelegramAlertSettings? settings)
        => settings is not null && TelegramAlertSettingsStore.IsValidBotToken(settings.BotToken)
            && TelegramAlertSettingsStore.IsValidChatId(settings.ChatId);
}

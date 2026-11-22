using System.Globalization;
using System.Text.Json;

namespace SentinelCore.Demon2.Core;

public static class SessionContextResponseValidator
{
    public static bool TryValidate(InterDaemonEnvelope message, DateTimeOffset nowUtc,
        out SessionContextResponse? response, out string? error)
    {
        response = null;
        error = "Invalid SESSION_CONTEXT_RESPONSE.";
        nowUtc = nowUtc.ToUniversalTime();
        if (message.MessageId == Guid.Empty || string.IsNullOrWhiteSpace(message.CorrelationId)
            || message.CorrelationId.Length > 128 || message.CorrelationId.Any(char.IsControl)
            || message.SourceDaemon != "RiskResponseGuard" || message.Destination != "ThreatMonitor"
            || message.MessageType != "SESSION_CONTEXT_RESPONSE" || message.SchemaVersion != 1
            || message.TimestampUtc.Offset != TimeSpan.Zero || message.ExpiresAtUtc.Offset != TimeSpan.Zero
            || message.TimestampUtc > nowUtc.AddSeconds(30)
            || message.ExpiresAtUtc <= nowUtc || message.ExpiresAtUtc <= message.TimestampUtc
            || message.Payload.ValueKind != JsonValueKind.Object)
            return false;

        var payload = message.Payload;
        if (!HasExactProperties(payload, ["status", "observedAtUtc"], ["context", "status", "observedAtUtc"])
            || !TryReadUtc(payload, "observedAtUtc", out var observedAt)
            || observedAt > nowUtc.AddSeconds(30)
            || !payload.TryGetProperty("status", out var statusValue) || statusValue.ValueKind != JsonValueKind.String)
            return false;

        if (string.Equals(statusValue.GetString(), nameof(SessionContextAvailability.NOT_AVAILABLE), StringComparison.Ordinal))
        {
            if (payload.TryGetProperty("context", out var unavailableContext)
                && unavailableContext.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)) return false;
            response = new(SessionContextAvailability.NOT_AVAILABLE, observedAt, null);
            error = null;
            return true;
        }

        if (!string.Equals(statusValue.GetString(), nameof(SessionContextAvailability.AVAILABLE), StringComparison.Ordinal)
            || !payload.TryGetProperty("context", out var context) || context.ValueKind != JsonValueKind.Object
            || !HasExactProperties(context, ["sessionState", "localOrRemote", "recentAuthBand"])) return false;

        if (!TryReadEnum<SessionStateCategory>(context, "sessionState", out var sessionState)
            || !TryReadEnum<SessionLocationCategory>(context, "localOrRemote", out var localOrRemote)
            || !TryReadEnum<RecentAuthenticationCategory>(context, "recentAuthBand", out var recentAuthBand)) return false;

        response = new(SessionContextAvailability.AVAILABLE, observedAt,
            new SessionSecurityContext(sessionState, localOrRemote, recentAuthBand));
        error = null;
        return true;
    }

    private static bool TryReadUtc(JsonElement parent, string name, out DateTimeOffset value)
    {
        value = default;
        return parent.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
            && DateTimeOffset.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out value)
            && value.Offset == TimeSpan.Zero;
    }

    private static bool TryReadEnum<TEnum>(JsonElement parent, string name, out TEnum value) where TEnum : struct, Enum
    {
        value = default;
        return parent.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.String
            && Enum.TryParse(element.GetString(), ignoreCase: false, out value) && Enum.IsDefined(value)
            && string.Equals(value.ToString(), element.GetString(), StringComparison.Ordinal);
    }

    private static bool HasExactProperties(JsonElement value, params string[][] accepted)
    {
        var properties = value.EnumerateObject().Select(x => x.Name).ToArray();
        if (properties.Distinct(StringComparer.Ordinal).Count() != properties.Length) return false;
        var names = properties.ToHashSet(StringComparer.Ordinal);
        return accepted.Any(expected => names.SetEquals(expected));
    }
}

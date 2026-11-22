using System.Security.Cryptography;
using System.Text.Json;

namespace SentinelCore.Demon1.Learning;

/// <summary>Short-lived, single-use handoff proving that the local controller authorized one collector launch.</summary>
public static class OneTimeAuthorizationTicket
{
    private sealed record Ticket(string Sid, DateTimeOffset CreatedUtc, string Nonce, string Purpose);

    public static string Create(string path, string sid)
        => CreateScoped(path, sid, "learning-collector");

    /// <summary>Creates a one-use authorization for the D1 background request broker only.</summary>
    public static string CreateBackgroundBroker(string path, string sid)
        => CreateScoped(path, sid, "d1-background-broker");

    private static string CreateScoped(string path, string sid, string purpose)
    {
        var nonce = RandomNumberGenerator.GetBytes(32);
        var clear = JsonSerializer.SerializeToUtf8Bytes(new Ticket(sid, DateTimeOffset.UtcNow, Convert.ToBase64String(nonce), purpose));
        var protectedData = CurrentUserDpapi.Protect(clear, sid);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
            using var ticketFile = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            ticketFile.Write(protectedData);
            ticketFile.Flush(flushToDisk: true);
            return Convert.ToBase64String(nonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(clear);
            CryptographicOperations.ZeroMemory(protectedData);
        }
    }

    public static bool Consume(string path, string proof, string sid)
        => ConsumeScoped(path, proof, sid, "learning-collector");

    /// <summary>Consumes a ticket that is valid only for starting the background broker.</summary>
    public static bool ConsumeBackgroundBroker(string path, string proof, string sid)
        => ConsumeScoped(path, proof, sid, "d1-background-broker");

    private static bool ConsumeScoped(string path, string proof, string sid, string purpose)
    {
        if (!File.Exists(path)) return false;
        var claimedPath = path + ".consuming-" + Guid.NewGuid().ToString("N");
        try { File.Move(path, claimedPath); }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
        byte[]? protectedData = null;
        try
        {
            protectedData = File.ReadAllBytes(claimedPath);
            var clear = CurrentUserDpapi.Unprotect(protectedData, sid);
            try
            {
                var ticket = JsonSerializer.Deserialize<Ticket>(clear);
                if (ticket is null || !StringComparer.Ordinal.Equals(ticket.Sid, sid)
                    || !StringComparer.Ordinal.Equals(ticket.Purpose, purpose)) return false;
                var age = DateTimeOffset.UtcNow - ticket.CreatedUtc;
                if (age < TimeSpan.Zero || age > TimeSpan.FromSeconds(30)) return false;
                var expected = Convert.FromBase64String(ticket.Nonce);
                var actual = Convert.FromBase64String(proof);
                try { return CryptographicOperations.FixedTimeEquals(expected, actual); }
                finally { CryptographicOperations.ZeroMemory(expected); CryptographicOperations.ZeroMemory(actual); }
            }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        catch (Exception ex) when (ex is IOException or CryptographicException or FormatException or JsonException or ArgumentException) { return false; }
        finally
        {
            if (protectedData is not null) CryptographicOperations.ZeroMemory(protectedData);
            try { File.Delete(claimedPath); } catch (IOException) { }
        }
    }
}

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SentinelCore.Demon1.Learning.Controller;

public sealed class AuthStore
{
    private const int Iterations = 600_000;
    private readonly string _path;
    private readonly string _sid;
    private bool _authenticatedInThisProcess;

    internal bool IsAuthenticatedInThisProcess => _authenticatedInThisProcess;

    internal void MarkOwnerAuthenticated() => _authenticatedInThisProcess = true;

    public AuthStore(string? dataRoot = null)
    {
        _path = Path.Combine(dataRoot ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SentinelCore", "Demon1Learning"), "auth.bin");
        _sid = WindowsIdentity.GetCurrent().User?.Value ?? throw new InvalidOperationException("Compte Windows introuvable.");
    }
    public bool IsConfigured => File.Exists(_path);

    public void SetPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(32);
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            var verifier = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, Iterations, HashAlgorithmName.SHA256, 32);
            var stored = JsonSerializer.SerializeToUtf8Bytes(new Credential(1, _sid, Convert.ToBase64String(salt), Convert.ToBase64String(verifier), Iterations));
            var protectedBytes = Dpapi.Protect(stored, Encoding.UTF8.GetBytes(_sid));
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllBytes(_path, protectedBytes);
            _authenticatedInThisProcess = true;
            CryptographicOperations.ZeroMemory(verifier);
            CryptographicOperations.ZeroMemory(stored);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); CryptographicOperations.ZeroMemory(salt); }
    }

    public bool VerifyPassword(string password)
    {
        if (!File.Exists(_path)) return false;
        var protectedBytes = File.ReadAllBytes(_path);
        var clear = Dpapi.Unprotect(protectedBytes, Encoding.UTF8.GetBytes(_sid));
        try
        {
            var credential = JsonSerializer.Deserialize<Credential>(clear) ?? throw new InvalidDataException("Configuration d’authentification illisible.");
            if (credential.Version != 1 || credential.UserSid != _sid) return false;
            var salt = Convert.FromBase64String(credential.Salt);
            var expected = Convert.FromBase64String(credential.Verifier);
            var bytes = Encoding.UTF8.GetBytes(password);
            try
            {
                var actual = Rfc2898DeriveBytes.Pbkdf2(bytes, salt, credential.Iterations, HashAlgorithmName.SHA256, expected.Length);
                var valid = CryptographicOperations.FixedTimeEquals(actual, expected);
                if (valid) _authenticatedInThisProcess = true;
                CryptographicOperations.ZeroMemory(actual);
                return valid;
            }
            finally { CryptographicOperations.ZeroMemory(bytes); CryptographicOperations.ZeroMemory(salt); CryptographicOperations.ZeroMemory(expected); }
        }
        finally { CryptographicOperations.ZeroMemory(clear); CryptographicOperations.ZeroMemory(protectedBytes); }
    }

    private sealed record Credential(int Version, string UserSid, string Salt, string Verifier, int Iterations);

    private static class Dpapi
    {
        [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref Blob input, string? description, ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptUnprotectData(ref Blob input, out IntPtr description, ref Blob entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
        [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
        public static byte[] Protect(byte[] input, byte[] entropy) => Transform(input, entropy, protect: true);
        public static byte[] Unprotect(byte[] input, byte[] entropy) => Transform(input, entropy, protect: false);
        private static byte[] Transform(byte[] input, byte[] entropy, bool protect)
        {
            var inputPtr = Marshal.AllocHGlobal(input.Length); var entropyPtr = Marshal.AllocHGlobal(entropy.Length);
            try
            {
                Marshal.Copy(input, 0, inputPtr, input.Length); Marshal.Copy(entropy, 0, entropyPtr, entropy.Length);
                var inputBlob = new Blob { Length = input.Length, Data = inputPtr }; var entropyBlob = new Blob { Length = entropy.Length, Data = entropyPtr };
                Blob output;
                IntPtr description = IntPtr.Zero;
                var ok = protect ? CryptProtectData(ref inputBlob, null, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, 0, out output)
                    : CryptUnprotectData(ref inputBlob, out description, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, 0, out output);
                if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Windows n’a pas pu protéger la configuration du mot de passe maître.");
                try { var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, output.Length); return result; }
                finally { LocalFree(output.Data); if (description != IntPtr.Zero) LocalFree(description); }
            }
            finally { Marshal.FreeHGlobal(inputPtr); Marshal.FreeHGlobal(entropyPtr); }
        }
    }
}

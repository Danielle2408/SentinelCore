using System.Runtime.InteropServices;

namespace SentinelCore.Demon1.Learning.Controller;

internal sealed record WindowsInteractiveSessionContextSnapshot(
    string SessionState,
    string LocalOrRemote,
    string RecentAuthBand,
    DateTimeOffset ObservedAtUtc);

/// <summary>Reads only coarse Windows session categories for D3/D2 correlation.</summary>
internal static class WindowsInteractiveSessionContext
{
    private const int SmRemoteSession = 0x1000;
    private const int SessionLock = 0x7;
    private const int SessionUnlock = 0x8;
    private static readonly TimeSpan IdleThreshold = TimeSpan.FromMinutes(5);

    public static WindowsInteractiveSessionContextSnapshot Capture(bool lockStateKnown, bool locked)
    {
        var sessionState = locked ? "LOCKED"
            : !lockStateKnown || !TryGetIdleDuration(out var idle) ? "UNKNOWN"
            : idle >= IdleThreshold ? "IDLE" : "ACTIVE";
        var location = OperatingSystem.IsWindows()
            ? GetSystemMetrics(SmRemoteSession) != 0 ? "REMOTE" : "LOCAL"
            : "UNKNOWN";
        return new(sessionState, location, "UNKNOWN", DateTimeOffset.UtcNow);
    }

    public static bool TryClassifyLockEvent(int eventType, out bool locked)
    {
        if (eventType == SessionLock) { locked = true; return true; }
        if (eventType == SessionUnlock) { locked = false; return true; }
        locked = false;
        return false;
    }

    private static bool TryGetIdleDuration(out TimeSpan duration)
    {
        duration = TimeSpan.Zero;
        if (!OperatingSystem.IsWindows()) return false;
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info)) return false;
        var elapsedMilliseconds = unchecked((uint)Environment.TickCount - info.Time);
        duration = TimeSpan.FromMilliseconds(elapsedMilliseconds);
        return true;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetLastInputInfo(ref LastInputInfo lastInputInfo);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);
}

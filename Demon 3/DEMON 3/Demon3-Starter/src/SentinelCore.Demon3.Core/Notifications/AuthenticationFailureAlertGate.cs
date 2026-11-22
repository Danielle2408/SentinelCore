namespace SentinelCore.Demon3.Core.Notifications;

/// <summary>Raises exactly one notification when a single authentication dialog reaches its failure threshold.</summary>
public sealed class AuthenticationFailureAlertGate
{
    private readonly int _threshold;
    private int _failures;
    private int _alerted;

    public AuthenticationFailureAlertGate(int threshold = 2)
    {
        if (threshold < 1) throw new ArgumentOutOfRangeException(nameof(threshold));
        _threshold = threshold;
    }

    public bool RecordFailure()
    {
        if (Interlocked.Increment(ref _failures) < _threshold) return false;
        return Interlocked.CompareExchange(ref _alerted, 1, 0) == 0;
    }
}

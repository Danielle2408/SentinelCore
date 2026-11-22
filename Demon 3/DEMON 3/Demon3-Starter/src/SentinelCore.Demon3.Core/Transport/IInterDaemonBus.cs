using SentinelCore.Demon3.Core.Contracts;

namespace SentinelCore.Demon3.Core.Transport;

public interface IInterDaemonBus
{
    ValueTask SendAsync(DaemonEnvelope message, CancellationToken cancellationToken = default);
    IAsyncEnumerable<DaemonEnvelope> ReadAllAsync(CancellationToken cancellationToken = default);
}

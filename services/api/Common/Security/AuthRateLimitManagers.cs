namespace MaintenX.Api.Common.Security;

using MaintenX.Api.Configuration;
using Microsoft.Extensions.Options;

/// <summary>
/// Container holding policy-specific BoundedPartitionManagers for registration, login, and refresh rate limiters.
/// Guarantees that high traffic on one endpoint does not consume slot capacity on another endpoint.
/// </summary>
public sealed class AuthRateLimitManagers
{
    public BoundedPartitionManager Registration { get; }
    public BoundedPartitionManager Login { get; }
    public BoundedPartitionManager Refresh { get; }

    public AuthRateLimitManagers(IOptions<RateLimitingOptions> options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        var opt = options.Value;
        var window = TimeSpan.FromSeconds(opt.WindowSeconds);

        Registration = new BoundedPartitionManager("registration", opt.MaxTrackedPartitions, window, timeProvider);
        Login = new BoundedPartitionManager("login", opt.MaxTrackedPartitions, window, timeProvider);
        Refresh = new BoundedPartitionManager("refresh", opt.MaxTrackedPartitions, window, timeProvider);
    }
}


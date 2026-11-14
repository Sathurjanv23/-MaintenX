namespace MaintenX.Api.Common.Security;

using System.Collections.Concurrent;
using System.Net;

/// <summary>
/// Memory-bounded partition manager for rate limiting.
/// Enforces an upper bound on concurrent tracked IP partitions to protect against memory exhaustion
/// from high-cardinality IP traffic, while guaranteeing that active throttled IPs cannot be evicted
/// to bypass security limits.
/// </summary>
public sealed class BoundedPartitionTracker
{
    private readonly int _maxPartitions;
    private readonly TimeSpan _windowDuration;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _activeIps = new(StringComparer.Ordinal);

    public int ActiveTrackedCount => _activeIps.Count;

    public BoundedPartitionTracker(int maxPartitions, TimeSpan windowDuration, TimeProvider? timeProvider = null)
    {
        _maxPartitions = maxPartitions > 0 ? maxPartitions : 10_000;
        _windowDuration = windowDuration > TimeSpan.Zero ? windowDuration : TimeSpan.FromSeconds(60);
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Resolves an authoritative partition key for the given client IP and policy.
    /// Returns:
    /// - "unresolved_{policy}" if IP is null (routed to 1-permit fixed window).
    /// - "tracked_{policy}_{ip}" if tracked within memory limits (routed to standard sliding window).
    /// - "overflow_{policy}" if capacity is saturated and cannot safely evict active entries (routed to constrained overflow).
    /// </summary>
    public string ResolvePartitionKey(string policyPrefix, IPAddress? clientIp)
    {
        if (clientIp == null)
        {
            return $"unresolved_{policyPrefix}";
        }

        var ipStr = clientIp.ToString();
        var now = _timeProvider.GetUtcNow();

        // 1. If IP is already tracked, refresh its activity and keep its individual partition
        if (_activeIps.ContainsKey(ipStr))
        {
            _activeIps[ipStr] = now;
            return $"tracked_{policyPrefix}_{ipStr}";
        }

        // 2. If at capacity, perform an inline prune of expired entries whose window has elapsed
        if (_activeIps.Count >= _maxPartitions)
        {
            PruneExpiredEntries(now);
        }

        // 3. Try admitting the new IP if space is available
        if (_activeIps.Count < _maxPartitions)
        {
            _activeIps[ipStr] = now;
            return $"tracked_{policyPrefix}_{ipStr}";
        }

        // 4. Bounded fallback: All partitions are currently active in the sliding window.
        // To prevent attackers from evicting throttled IPs (brute-force bypass), do NOT evict active entries.
        // Route excess high-cardinality traffic to a shared overflow partition.
        return $"overflow_{policyPrefix}";
    }

    /// <summary>
    /// Evicts entries whose last seen timestamp is older than the configured sliding window.
    /// Safe because any sliding window rate limiter state for that IP has already elapsed.
    /// </summary>
    public int PruneExpiredEntries(DateTimeOffset? referenceTime = null)
    {
        var now = referenceTime ?? _timeProvider.GetUtcNow();
        var pruned = 0;

        foreach (var (ip, lastSeen) in _activeIps)
        {
            if (now - lastSeen >= _windowDuration)
            {
                if (_activeIps.TryRemove(ip, out _))
                {
                    pruned++;
                }
            }
        }

        return pruned;
    }
}


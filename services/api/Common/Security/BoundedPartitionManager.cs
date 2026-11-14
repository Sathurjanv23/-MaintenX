namespace MaintenX.Api.Common.Security;

using System.Net;

/// <summary>
/// Identifies the admission classification of a client IP partition request.
/// </summary>
public enum PartitionKind
{
    /// <summary>
    /// IP is admitted and mapped to a dedicated bounded slot.
    /// </summary>
    Tracked,

    /// <summary>
    /// IP is absent or unresolvable; routed to the restricted fallback partition.
    /// </summary>
    Unresolved,

    /// <summary>
    /// Bounded capacity is saturated with active entries; routed to the constrained overflow partition.
    /// </summary>
    Overflow
}

/// <summary>
/// Resolution result containing the authoritative framework partition key and partition kind.
/// </summary>
public readonly record struct PartitionResolution(string PartitionKey, PartitionKind Kind);

/// <summary>
/// Concurrency-safe, memory-bounded partition slot manager for ASP.NET Core rate limiting.
/// Enforces a hard upper bound on both:
/// 1. IP tracking metadata (in-memory slot mapping dictionary).
/// 2. Actual ASP.NET Core PartitionedRateLimiter limiter instances / partition state.
///
/// Guaranteed Properties:
/// - Partition keys issued to ASP.NET Core are strictly bounded to:
///   MaxPartitions slots ("{policy}_slot_{0..N-1}") + 1 overflow ("overflow_{policy}") + 1 unresolved ("unresolved_{policy}").
///   Therefore, the framework's internal limiter cache can NEVER exceed (MaxPartitions + 2) instances.
/// - Admission is atomic under lock; concurrent requests cannot exceed MaxPartitions.
/// - Active entries are never evicted before their sliding window elapses, preventing brute-force quota reset attacks.
/// - Reclaimed slots are only reused after their full sliding window duration has elapsed, guaranteeing replenished permits.
/// </summary>
public sealed class BoundedPartitionManager
{
    private readonly string _policyName;
    private readonly int _maxPartitions;
    private readonly TimeSpan _windowDuration;
    private readonly TimeProvider _timeProvider;
    private readonly object _syncRoot = new();

    private readonly Dictionary<string, int> _ipToSlotId = new(StringComparer.Ordinal);
    private readonly Queue<int> _freeSlotIds = new();
    private readonly DateTimeOffset[] _slotLastSeen;
    private readonly string?[] _slotAssignedIp;
    private readonly HashSet<string> _everIssuedKeys = new(StringComparer.Ordinal);

    public int MaxPartitions => _maxPartitions;

    public int ActiveTrackedCount
    {
        get
        {
            lock (_syncRoot)
            {
                return _ipToSlotId.Count;
            }
        }
    }

    public int DistinctPartitionKeysEverIssued
    {
        get
        {
            lock (_syncRoot)
            {
                return _everIssuedKeys.Count;
            }
        }
    }

    public BoundedPartitionManager(
        string policyName,
        int maxPartitions,
        TimeSpan windowDuration,
        TimeProvider? timeProvider = null)
    {
        _policyName = !string.IsNullOrWhiteSpace(policyName) ? policyName.Trim().ToLowerInvariant() : "default";
        _maxPartitions = maxPartitions > 0 ? maxPartitions : 10_000;
        _windowDuration = windowDuration > TimeSpan.Zero ? windowDuration : TimeSpan.FromSeconds(60);
        _timeProvider = timeProvider ?? TimeProvider.System;

        _slotLastSeen = new DateTimeOffset[_maxPartitions];
        _slotAssignedIp = new string?[_maxPartitions];

        for (int i = 0; i < _maxPartitions; i++)
        {
            _freeSlotIds.Enqueue(i);
        }
    }

    /// <summary>
    /// Atomically resolves a partition key for the given client IP.
    /// </summary>
    public PartitionResolution ResolvePartition(IPAddress? clientIp)
    {
        var now = _timeProvider.GetUtcNow();

        if (clientIp == null)
        {
            var unresolvedKey = $"unresolved_{_policyName}";
            RecordKey(unresolvedKey);
            return new PartitionResolution(unresolvedKey, PartitionKind.Unresolved);
        }

        var ipStr = clientIp.ToString();

        lock (_syncRoot)
        {
            // 1. IP is already bound to an active slot
            if (_ipToSlotId.TryGetValue(ipStr, out var slotId))
            {
                _slotLastSeen[slotId] = now;
                var trackedKey = $"{_policyName}_slot_{slotId}";
                RecordKey(trackedKey);
                return new PartitionResolution(trackedKey, PartitionKind.Tracked);
            }

            // 2. Not bound. If free queue is empty, attempt to reclaim slots whose idle time >= WindowDuration
            if (_freeSlotIds.Count == 0)
            {
                PruneExpiredSlotsLocked(now);
            }

            // 3. If a slot is available (either initially or reclaimed), bind it atomically
            if (_freeSlotIds.TryDequeue(out var freeSlotId))
            {
                _slotAssignedIp[freeSlotId] = ipStr;
                _slotLastSeen[freeSlotId] = now;
                _ipToSlotId[ipStr] = freeSlotId;

                var trackedKey = $"{_policyName}_slot_{freeSlotId}";
                RecordKey(trackedKey);
                return new PartitionResolution(trackedKey, PartitionKind.Tracked);
            }

            // 4. Capacity saturated: all slots are actively communicating within the sliding window.
            // Route to constrained overflow partition to prevent quota bypass and protect system resources.
            var overflowKey = $"overflow_{_policyName}";
            RecordKey(overflowKey);
            return new PartitionResolution(overflowKey, PartitionKind.Overflow);
        }
    }

    private void PruneExpiredSlotsLocked(DateTimeOffset now)
    {
        for (int slotId = 0; slotId < _maxPartitions; slotId++)
        {
            var assignedIp = _slotAssignedIp[slotId];
            if (assignedIp != null && now - _slotLastSeen[slotId] >= _windowDuration)
            {
                _ipToSlotId.Remove(assignedIp);
                _slotAssignedIp[slotId] = null;
                _freeSlotIds.Enqueue(slotId);
            }
        }
    }

    private void RecordKey(string key)
    {
        lock (_syncRoot)
        {
            _everIssuedKeys.Add(key);
        }
    }

    public void PruneExpiredEntries(DateTimeOffset? referenceTime = null)
    {
        var now = referenceTime ?? _timeProvider.GetUtcNow();
        lock (_syncRoot)
        {
            PruneExpiredSlotsLocked(now);
        }
    }
}


namespace MaintenX.UnitTests.Security;

using System.Net;
using MaintenX.Api.Common.Security;
using Xunit;

public class BoundedPartitionManagerTests
{
    [Fact]
    public void ResolvePartition_WithNullClientIp_ReturnsUnresolvedPartition()
    {
        var manager = new BoundedPartitionManager("login", maxPartitions: 10, windowDuration: TimeSpan.FromSeconds(60));

        var resolution = manager.ResolvePartition(null);

        Assert.Equal("unresolved_login", resolution.PartitionKey);
        Assert.Equal(PartitionKind.Unresolved, resolution.Kind);
        Assert.Equal(0, manager.ActiveTrackedCount);
        Assert.Equal(1, manager.DistinctPartitionKeysEverIssued);
    }

    [Fact]
    public void ResolvePartition_WithDistinctIpsUnderCapacity_AssignsDistinctBoundedSlots()
    {
        var manager = new BoundedPartitionManager("login", maxPartitions: 5, windowDuration: TimeSpan.FromSeconds(60));

        var ip1 = IPAddress.Parse("192.168.1.1");
        var ip2 = IPAddress.Parse("192.168.1.2");

        var res1 = manager.ResolvePartition(ip1);
        var res2 = manager.ResolvePartition(ip2);

        Assert.Equal(PartitionKind.Tracked, res1.Kind);
        Assert.Equal(PartitionKind.Tracked, res2.Kind);
        Assert.NotEqual(res1.PartitionKey, res2.PartitionKey);
        Assert.StartsWith("login_slot_", res1.PartitionKey);
        Assert.StartsWith("login_slot_", res2.PartitionKey);
        Assert.Equal(2, manager.ActiveTrackedCount);
    }

    [Fact]
    public void ResolvePartition_HighCardinalityTraffic_CannotGrowActualLimiterKeysBeyondBound()
    {
        const int maxPartitions = 5;
        var manager = new BoundedPartitionManager("registration", maxPartitions: maxPartitions, windowDuration: TimeSpan.FromSeconds(60));

        // Send 1,000 distinct IPs into the manager
        for (int i = 1; i <= 1000; i++)
        {
            var ip = IPAddress.Parse($"10.{i / 256}.{i % 256}.1");
            var resolution = manager.ResolvePartition(ip);

            if (i <= maxPartitions)
            {
                Assert.Equal(PartitionKind.Tracked, resolution.Kind);
            }
            else
            {
                Assert.Equal(PartitionKind.Overflow, resolution.Kind);
                Assert.Equal("overflow_registration", resolution.PartitionKey);
            }
        }

        // Active tracked metadata count in memory is strictly bounded by maxPartitions
        Assert.Equal(maxPartitions, manager.ActiveTrackedCount);

        // Distinct partition keys ever passed to ASP.NET Core limiter cannot exceed (maxPartitions + 1 for overflow)
        Assert.True(manager.DistinctPartitionKeysEverIssued <= maxPartitions + 1);
        Assert.Equal(maxPartitions + 1, manager.DistinctPartitionKeysEverIssued);
    }

    [Fact]
    public async Task ResolvePartition_ConcurrentRequests_CannotExceedConfiguredCapacity()
    {
        const int maxPartitions = 10;
        var manager = new BoundedPartitionManager("login", maxPartitions: maxPartitions, windowDuration: TimeSpan.FromSeconds(60));

        // 100 concurrent tasks racing to admit distinct IPs simultaneously
        var tasks = Enumerable.Range(1, 100).Select(i => Task.Run(() =>
        {
            var ip = IPAddress.Parse($"172.16.0.{i}");
            return manager.ResolvePartition(ip);
        }));

        var results = await Task.WhenAll(tasks);

        var trackedCount = results.Count(r => r.Kind == PartitionKind.Tracked);
        var overflowCount = results.Count(r => r.Kind == PartitionKind.Overflow);

        // Exactly maxPartitions were tracked; all remaining were routed to overflow
        Assert.Equal(maxPartitions, trackedCount);
        Assert.Equal(90, overflowCount);

        // Active tracked count under lock never exceeded maxPartitions
        Assert.Equal(maxPartitions, manager.ActiveTrackedCount);
    }

    [Fact]
    public void ResolvePartition_ExistingThrottledClient_CannotResetQuotaBySendingRequestsFromNewIps()
    {
        const int maxPartitions = 3;
        var t0 = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new TestTimeProvider(t0);
        var manager = new BoundedPartitionManager("login", maxPartitions, TimeSpan.FromSeconds(60), timeProvider);

        var attackerIp = IPAddress.Parse("203.0.113.50");
        var victimIp = IPAddress.Parse("203.0.113.51");
        var regularIp = IPAddress.Parse("203.0.113.52");

        var attackerRes = manager.ResolvePartition(attackerIp);
        manager.ResolvePartition(victimIp);
        manager.ResolvePartition(regularIp);

        Assert.Equal(3, manager.ActiveTrackedCount);

        // 10 seconds later, attacker floods with 100 new IPs to attempt to evict their throttled slot
        timeProvider.Advance(TimeSpan.FromSeconds(10));
        for (int i = 1; i <= 100; i++)
        {
            var floodRes = manager.ResolvePartition(IPAddress.Parse($"198.51.100.{i}"));
            Assert.Equal(PartitionKind.Overflow, floodRes.Kind);
        }

        // Attacker IP must still map to the exact same slot; it was not evicted!
        var recheckedAttacker = manager.ResolvePartition(attackerIp);
        Assert.Equal(PartitionKind.Tracked, recheckedAttacker.Kind);
        Assert.Equal(attackerRes.PartitionKey, recheckedAttacker.PartitionKey);
        Assert.Equal(3, manager.ActiveTrackedCount);
    }

    [Fact]
    public void PruneExpiredEntries_SafelyReclaimsSlots_OnlyAfterSlidingWindowDuration()
    {
        const int maxPartitions = 2;
        var t0 = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new TestTimeProvider(t0);
        var manager = new BoundedPartitionManager("refresh", maxPartitions, TimeSpan.FromSeconds(60), timeProvider);

        var ip1 = IPAddress.Parse("10.0.0.1");
        var ip2 = IPAddress.Parse("10.0.0.2");

        manager.ResolvePartition(ip1);
        manager.ResolvePartition(ip2);
        Assert.Equal(2, manager.ActiveTrackedCount);

        // 30 seconds later (within window): entries are active and CANNOT be reclaimed
        timeProvider.Advance(TimeSpan.FromSeconds(30));
        manager.PruneExpiredEntries();
        Assert.Equal(2, manager.ActiveTrackedCount);

        // Advance 35 more seconds (total 65s): window (60s) has elapsed
        timeProvider.Advance(TimeSpan.FromSeconds(35));

        // When a new IP arrives, expired entries are reclaimed and slot is granted
        var ip3 = IPAddress.Parse("10.0.0.3");
        var res3 = manager.ResolvePartition(ip3);

        Assert.Equal(PartitionKind.Tracked, res3.Kind);
        Assert.Equal(1, manager.ActiveTrackedCount);
    }
}


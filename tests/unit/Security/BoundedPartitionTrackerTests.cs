namespace MaintenX.UnitTests.Security;

using System.Net;
using MaintenX.Api.Common.Security;
using Xunit;

public class BoundedPartitionTrackerTests
{
    [Fact]
    public void ResolvePartitionKey_WithNullClientIp_ReturnsUnresolvedPartition()
    {
        var tracker = new BoundedPartitionTracker(maxPartitions: 10, windowDuration: TimeSpan.FromSeconds(60));

        var key = tracker.ResolvePartitionKey("login", null);

        Assert.Equal("unresolved_login", key);
        Assert.Equal(0, tracker.ActiveTrackedCount);
    }

    [Fact]
    public void ResolvePartitionKey_WithDistinctIpsUnderCapacity_TracksEachIpIndividually()
    {
        var tracker = new BoundedPartitionTracker(maxPartitions: 5, windowDuration: TimeSpan.FromSeconds(60));

        var ip1 = IPAddress.Parse("192.168.1.1");
        var ip2 = IPAddress.Parse("192.168.1.2");

        var key1 = tracker.ResolvePartitionKey("login", ip1);
        var key2 = tracker.ResolvePartitionKey("login", ip2);

        Assert.Equal("tracked_login_192.168.1.1", key1);
        Assert.Equal("tracked_login_192.168.1.2", key2);
        Assert.Equal(2, tracker.ActiveTrackedCount);
    }

    [Fact]
    public void ResolvePartitionKey_WhenCapacityReached_HardBoundsActivePartitions_AndRoutesExcessToOverflow()
    {
        const int maxPartitions = 5;
        var tracker = new BoundedPartitionTracker(maxPartitions: maxPartitions, windowDuration: TimeSpan.FromSeconds(60));

        // Fill capacity with 5 active IPs
        for (int i = 1; i <= maxPartitions; i++)
        {
            var ip = IPAddress.Parse($"10.0.0.{i}");
            var key = tracker.ResolvePartitionKey("registration", ip);
            Assert.Equal($"tracked_registration_10.0.0.{i}", key);
        }

        Assert.Equal(maxPartitions, tracker.ActiveTrackedCount);

        // Send requests from 50 additional high-cardinality attacker IPs
        for (int i = 10; i <= 60; i++)
        {
            var floodIp = IPAddress.Parse($"172.16.0.{i}");
            var floodKey = tracker.ResolvePartitionKey("registration", floodIp);

            // Excess high-cardinality traffic must route to constrained overflow partition
            Assert.Equal("overflow_registration", floodKey);
        }

        // Active tracked partitions in memory must remain strictly bounded at maxPartitions
        Assert.Equal(maxPartitions, tracker.ActiveTrackedCount);
    }

    [Fact]
    public void ResolvePartitionKey_ActiveTrackedIpCannotBeEvictedByNewTraffic_PreventingBruteForceBypass()
    {
        const int maxPartitions = 3;
        var t0 = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new TestTimeProvider(t0);
        var tracker = new BoundedPartitionTracker(maxPartitions, TimeSpan.FromSeconds(60), timeProvider);

        var attackerIp = IPAddress.Parse("203.0.113.50");
        var victimIp = IPAddress.Parse("203.0.113.51");
        var regularIp = IPAddress.Parse("203.0.113.52");

        tracker.ResolvePartitionKey("login", attackerIp);
        tracker.ResolvePartitionKey("login", victimIp);
        tracker.ResolvePartitionKey("login", regularIp);

        Assert.Equal(3, tracker.ActiveTrackedCount);

        // Flood with 100 new IPs 10 seconds later (within sliding window, so attacker is still active)
        timeProvider.Advance(TimeSpan.FromSeconds(10));
        for (int i = 1; i <= 100; i++)
        {
            tracker.ResolvePartitionKey("login", IPAddress.Parse($"198.51.100.{i}"));
        }

        // Attacker IP must NOT have been evicted; it must still map to its existing partition
        var attackerKey = tracker.ResolvePartitionKey("login", attackerIp);
        Assert.Equal("tracked_login_203.0.113.50", attackerKey);
        Assert.Equal(3, tracker.ActiveTrackedCount);
    }

    [Fact]
    public void PruneExpiredEntries_SafelyReclaimsPartitions_AfterSlidingWindowDuration()
    {
        const int maxPartitions = 2;
        var t0 = new DateTimeOffset(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
        var timeProvider = new TestTimeProvider(t0);
        var tracker = new BoundedPartitionTracker(maxPartitions, TimeSpan.FromSeconds(60), timeProvider);

        var ip1 = IPAddress.Parse("10.0.0.1");
        var ip2 = IPAddress.Parse("10.0.0.2");

        tracker.ResolvePartitionKey("refresh", ip1);
        tracker.ResolvePartitionKey("refresh", ip2);
        Assert.Equal(2, tracker.ActiveTrackedCount);

        // Advance time past the 60-second window
        timeProvider.Advance(TimeSpan.FromSeconds(65));

        // When a new IP arrives, expired entries are pruned inline and new IP is admitted
        var ip3 = IPAddress.Parse("10.0.0.3");
        var key3 = tracker.ResolvePartitionKey("refresh", ip3);

        Assert.Equal("tracked_refresh_10.0.0.3", key3);
        // The 2 expired entries were evicted, leaving only ip3
        Assert.Equal(1, tracker.ActiveTrackedCount);
    }
}


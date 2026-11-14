namespace MaintenX.UnitTests.Security;

using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

public class SecurityStampValidatorTests
{
    private readonly MemoryCache _memoryCache;
    private readonly FakeUserSecurityStampStore _store;
    private readonly SecurityStampValidator _sut;

    public SecurityStampValidatorTests()
    {
        _memoryCache = new MemoryCache(new MemoryCacheOptions());
        _store = new FakeUserSecurityStampStore();
        _sut = new SecurityStampValidator(_store, _memoryCache, NullLogger<SecurityStampValidator>.Instance);
    }

    [Fact]
    public async Task ValidateAsync_OnCacheMiss_QueriesDatabaseAndPopulatesCache()
    {
        var userId = Guid.NewGuid();
        var securityStamp = "active-valid-stamp";
        _store.Users[userId] = new UserSecurityStampRecord(securityStamp, UserStatus.Active);

        Assert.Equal(0, _store.QueryCount);

        var result = await _sut.ValidateAsync(userId, securityStamp);

        Assert.True(result);
        Assert.Equal(1, _store.QueryCount);

        // Second call should hit the in-memory cache and not call the store again
        var cachedResult = await _sut.ValidateAsync(userId, securityStamp);

        Assert.True(cachedResult);
        Assert.Equal(1, _store.QueryCount);
    }

    [Fact]
    public async Task ValidateAsync_WithStampMismatch_ReturnsFalse()
    {
        var userId = Guid.NewGuid();
        _store.Users[userId] = new UserSecurityStampRecord("correct-stamp", UserStatus.Active);

        var result = await _sut.ValidateAsync(userId, "wrong-stamp");

        Assert.False(result);
    }

    [Theory]
    [InlineData(UserStatus.Suspended)]
    [InlineData(UserStatus.Deactivated)]
    public async Task ValidateAsync_WhenUserNotActive_ReturnsFalse_EvenIfStampMatches(UserStatus status)
    {
        var userId = Guid.NewGuid();
        var securityStamp = "valid-stamp";
        _store.Users[userId] = new UserSecurityStampRecord(securityStamp, status);

        var result = await _sut.ValidateAsync(userId, securityStamp);

        Assert.False(result);
    }

    [Fact]
    public async Task ValidateAsync_WhenUserNotFound_ReturnsFalse()
    {
        var userId = Guid.NewGuid();

        var result = await _sut.ValidateAsync(userId, "any-stamp");

        Assert.False(result);
        Assert.Equal(1, _store.QueryCount);
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000", "some-stamp")]
    [InlineData("11111111-1111-1111-1111-111111111111", "")]
    [InlineData("11111111-1111-1111-1111-111111111111", "   ")]
    [InlineData("11111111-1111-1111-1111-111111111111", null)]
    public async Task ValidateAsync_WithEmptyInputs_ReturnsFalseImmediatelyWithoutQueryingDatabase(string userIdStr, string? stamp)
    {
        var userId = Guid.Parse(userIdStr);

        var result = await _sut.ValidateAsync(userId, stamp!);

        Assert.False(result);
        Assert.Equal(0, _store.QueryCount);
    }

    [Fact]
    public async Task Invalidate_EvictsCachedEntry_ForcingSubsequentQueryToHitDatabase()
    {
        var userId = Guid.NewGuid();
        var originalStamp = "stamp-v1";
        _store.Users[userId] = new UserSecurityStampRecord(originalStamp, UserStatus.Active);

        // 1. Initial query: cache miss -> DB query count = 1
        var firstResult = await _sut.ValidateAsync(userId, originalStamp);
        Assert.True(firstResult);
        Assert.Equal(1, _store.QueryCount);

        // 2. Cache hit -> DB query count remains 1
        var cachedResult = await _sut.ValidateAsync(userId, originalStamp);
        Assert.True(cachedResult);
        Assert.Equal(1, _store.QueryCount);

        // 3. User rotates security stamp in DB
        var rotatedStamp = "stamp-v2";
        _store.Users[userId] = new UserSecurityStampRecord(rotatedStamp, UserStatus.Active);

        // 4. Invalidate cache
        _sut.Invalidate(userId);

        // 5. Next validation must query the store again -> DB query count = 2
        var revalidatedResult = await _sut.ValidateAsync(userId, rotatedStamp);
        Assert.True(revalidatedResult);
        Assert.Equal(2, _store.QueryCount);

        // Old stamp now fails against newly cached value
        var oldStampResult = await _sut.ValidateAsync(userId, originalStamp);
        Assert.False(oldStampResult);
        Assert.Equal(2, _store.QueryCount);
    }

    private sealed class FakeUserSecurityStampStore : IUserSecurityStampStore
    {
        public Dictionary<Guid, UserSecurityStampRecord> Users { get; } = new();
        public int QueryCount { get; private set; }

        public Task<UserSecurityStampRecord?> GetSecurityStampAsync(Guid userId, CancellationToken cancellationToken = default)
        {
            QueryCount++;
            Users.TryGetValue(userId, out var record);
            return Task.FromResult(record);
        }
    }
}

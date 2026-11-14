namespace MaintenX.IntegrationTests;

using MaintenX.Api.Common.Security;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Integration tests verifying security services against real PostgreSQL 16 database.
/// Tests <see cref="EfUserSecurityStampStore"/> and <see cref="SecurityStampValidator"/> integration
/// with actual persistence, caching boundaries, and stamp invalidations.
/// </summary>
public class SecurityServicesIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public SecurityServicesIntegrationTests()
    {
        _configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        var (admin, test) = TestDatabaseGuard.ValidateConnectionConfiguration(_configuration);
        _adminConnectionString = admin;
        _testConnectionString = test;
    }

    public async Task InitializeAsync()
    {
        var (dbName, connStr) = await TestDatabaseGuard.ProvisionAndInitializeAsync(
            _adminConnectionString,
            _testConnectionString,
            _configuration,
            async (conn) =>
            {
                var options = new DbContextOptionsBuilder<MaintenXDbContext>()
                    .UseNpgsql(conn)
                    .Options;

                using var context = new MaintenXDbContext(options);
                await context.Database.MigrateAsync();
            });

        _databaseName = dbName;
        _isolatedConnectionString = connStr;
    }

    public async Task DisposeAsync()
    {
        if (!string.IsNullOrWhiteSpace(_databaseName))
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(_databaseName, _adminConnectionString);
        }
    }

    private MaintenXDbContext CreateDbContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options);
    }

    [Fact]
    public async Task SecurityStampValidator_QueriesPostgresOnMiss_AndCachesForSubsequentCalls()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var user = User.Create("validator-cache-test@example.com", "hash-val-1");

        await using (var seedContext = CreateDbContext())
        {
            seedContext.Users.Add(user);
            await seedContext.SaveChangesAsync();
        }

        await using (var testContext = CreateDbContext())
        {
            var store = new EfUserSecurityStampStore(testContext);
            var validator = new SecurityStampValidator(store, cache, NullLogger<SecurityStampValidator>.Instance);

            // 1. First validation: cache miss -> queries PostgreSQL
            var valid = await validator.ValidateAsync(user.Id, user.SecurityStamp);
            Assert.True(valid);
        }

        // 2. Second validation using a new DbContext: should hit the in-memory cache
        await using (var secondContext = CreateDbContext())
        {
            var store = new EfUserSecurityStampStore(secondContext);
            var validator = new SecurityStampValidator(store, cache, NullLogger<SecurityStampValidator>.Instance);

            var validCached = await validator.ValidateAsync(user.Id, user.SecurityStamp);
            Assert.True(validCached);
        }
    }

    [Fact]
    public async Task SecurityStampValidator_WhenStampRotatedInDb_AndCacheInvalidated_ReadsNewStamp()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var user = User.Create("validator-rotate-test@example.com", "hash-val-2");
        var originalStamp = user.SecurityStamp;

        await using (var seedContext = CreateDbContext())
        {
            seedContext.Users.Add(user);
            await seedContext.SaveChangesAsync();
        }

        await using (var testContext = CreateDbContext())
        {
            var store = new EfUserSecurityStampStore(testContext);
            var validator = new SecurityStampValidator(store, cache, NullLogger<SecurityStampValidator>.Instance);

            // Populate cache
            Assert.True(await validator.ValidateAsync(user.Id, originalStamp));
        }

        // Rotate stamp in DB
        string newStamp;
        await using (var mutateContext = CreateDbContext())
        {
            var loadedUser = await mutateContext.Users.SingleAsync(u => u.Id == user.Id);
            loadedUser.RotateSecurityStamp(DateTime.UtcNow);
            newStamp = loadedUser.SecurityStamp;
            await mutateContext.SaveChangesAsync();
        }

        // Without invalidation, cache still returns true for old stamp
        await using (var cachedContext = CreateDbContext())
        {
            var store = new EfUserSecurityStampStore(cachedContext);
            var validator = new SecurityStampValidator(store, cache, NullLogger<SecurityStampValidator>.Instance);

            Assert.True(await validator.ValidateAsync(user.Id, originalStamp));

            // Now explicitly invalidate
            validator.Invalidate(user.Id);

            // Next query hits DB -> old stamp fails, new stamp succeeds
            Assert.False(await validator.ValidateAsync(user.Id, originalStamp));
            Assert.True(await validator.ValidateAsync(user.Id, newStamp));
        }
    }

    [Fact]
    public async Task SecurityStampValidator_WhenUserSuspendedInDb_ReturnsFalse()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var user = User.Create("validator-suspended-test@example.com", "hash-val-3");
        user.Suspend(DateTime.UtcNow);

        await using (var seedContext = CreateDbContext())
        {
            seedContext.Users.Add(user);
            await seedContext.SaveChangesAsync();
        }

        await using (var testContext = CreateDbContext())
        {
            var store = new EfUserSecurityStampStore(testContext);
            var validator = new SecurityStampValidator(store, cache, NullLogger<SecurityStampValidator>.Instance);

            var valid = await validator.ValidateAsync(user.Id, user.SecurityStamp);
            Assert.False(valid);
        }
    }

    [Fact]
    public async Task SecurityStampValidator_WhenUserDoesNotExistInDb_ReturnsFalse()
    {
        using var cache = new MemoryCache(new MemoryCacheOptions());

        await using var testContext = CreateDbContext();
        var store = new EfUserSecurityStampStore(testContext);
        var validator = new SecurityStampValidator(store, cache, NullLogger<SecurityStampValidator>.Instance);

        var valid = await validator.ValidateAsync(Guid.NewGuid(), "nonexistent-stamp");
        Assert.False(valid);
    }
}

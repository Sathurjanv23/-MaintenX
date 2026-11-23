namespace MaintenX.IntegrationTests;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Integration test suite for FEAT-003 Task 3.5.2 Tenant Creation & Onboarding Services.
/// Executes against a disposable, isolated PostgreSQL 16 database.
/// Validates atomic tenant + owner membership persistence, slug uniqueness enforcement,
/// concurrent race condition handling, and tenant boundary preservation.
/// </summary>
public class TenantOnboardingIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public TenantOnboardingIntegrationTests()
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

    private MaintenXDbContext CreateContext()
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options);
    }

    private async Task<User> CreateTestUserAsync(string prefix, UserStatus status = UserStatus.Active)
    {
        using var db = CreateContext();
        var email = $"{prefix}_{Guid.NewGuid():N}@maintenx.internal";
        var user = User.Create(email, "hashed_password", status);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    [Fact]
    public async Task CreateTenantAsync_ValidRequest_CreatesTenantAndOwnerMembershipAtomically()
    {
        var creator = await CreateTestUserAsync("creator");
        var slug = $"tenant-{Guid.NewGuid():N}"[..18];
        var displayName = "Acme Maintenance Facilities";

        using var db = CreateContext();
        var service = new TenantService(db, TimeProvider.System, NullLogger<TenantService>.Instance);

        var request = new CreateTenantRequest(slug, displayName);
        var result = await service.CreateTenantAsync(creator.Id, request);

        // 1. Verify Application Result
        Assert.True(result.IsSuccess);
        Assert.Equal(201, result.StatusCode);
        Assert.NotNull(result.Response);
        Assert.Equal(slug, result.Response.Slug);
        Assert.Equal(displayName, result.Response.DisplayName);
        Assert.Equal(TenantStatus.PendingOnboarding.ToString(), result.Response.Status);
        Assert.NotEqual(Guid.Empty, result.Response.TenantId);

        // 2. Verify Database Durability
        using var verifyDb = CreateContext();
        using (verifyDb.CreatePrivilegedTenantBypassScope("verify"))
        {
            var tenant = await verifyDb.Tenants.FirstOrDefaultAsync(t => t.Id == result.Response.TenantId);
            Assert.NotNull(tenant);
            Assert.Equal(slug, tenant.Slug);
            Assert.Equal(displayName, tenant.DisplayName);
            Assert.Equal(TenantStatus.PendingOnboarding, tenant.Status);

            var memberships = await verifyDb.TenantMemberships
                .Where(m => m.TenantId == tenant.Id)
                .ToListAsync();

            Assert.Single(memberships);
            var ownerMembership = memberships[0];
            Assert.Equal(creator.Id, ownerMembership.UserId);
            Assert.Equal(TenantMembershipRole.Owner, ownerMembership.Role);
            Assert.Equal(TenantMembershipStatus.Active, ownerMembership.Status);
        }
    }

    [Fact]
    public async Task CreateTenantAsync_DuplicateSlug_ReturnsConflict_DoesNotCreateOrphanMembership()
    {
        var creator = await CreateTestUserAsync("dup_creator");
        var slug = $"dup-{Guid.NewGuid():N}"[..18];

        using (var seedDb = CreateContext())
        {
            var existingTenant = Tenant.Create(slug, "Pre-existing Tenant");
            seedDb.Tenants.Add(existingTenant);
            await seedDb.SaveChangesAsync();
        }

        using var db = CreateContext();
        var service = new TenantService(db, TimeProvider.System, NullLogger<TenantService>.Instance);

        var request = new CreateTenantRequest(slug, "Second Tenant With Same Slug");
        var result = await service.CreateTenantAsync(creator.Id, request);

        Assert.False(result.IsSuccess);
        Assert.Equal(409, result.StatusCode);
        Assert.Equal("TENANT_SLUG_CONFLICT", result.ErrorCode);

        // Verify no orphan memberships were created
        using var verifyDb = CreateContext();
        using (verifyDb.CreatePrivilegedTenantBypassScope("verify"))
        {
            var membershipsForUser = await verifyDb.TenantMemberships
                .Where(m => m.UserId == creator.Id)
                .ToListAsync();
            Assert.Empty(membershipsForUser);
        }
    }

    [Fact]
    public async Task CreateTenantAsync_InactiveUser_ReturnsForbidden()
    {
        var suspendedUser = await CreateTestUserAsync("susp", UserStatus.Suspended);
        using var db = CreateContext();
        var service = new TenantService(db, TimeProvider.System, NullLogger<TenantService>.Instance);

        var request = new CreateTenantRequest($"tenant-{Guid.NewGuid():N}"[..18], "Suspended User Org");
        var result = await service.CreateTenantAsync(suspendedUser.Id, request);

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }

    [Fact]
    public async Task CreateTenantAsync_NonExistentUser_ReturnsUnauthorized()
    {
        using var db = CreateContext();
        var service = new TenantService(db, TimeProvider.System, NullLogger<TenantService>.Instance);

        var request = new CreateTenantRequest($"tenant-{Guid.NewGuid():N}"[..18], "Ghost User Org");
        var result = await service.CreateTenantAsync(Guid.NewGuid(), request);

        Assert.False(result.IsSuccess);
        Assert.Equal(401, result.StatusCode);
        Assert.Equal("UNAUTHORIZED", result.ErrorCode);
    }

    [Fact]
    public async Task CreateTenantAsync_ConcurrentCreationWithSameSlug_OneSucceedsOneConflicts()
    {
        var user1 = await CreateTestUserAsync("user1");
        var user2 = await CreateTestUserAsync("user2");
        var sharedSlug = $"race-{Guid.NewGuid():N}"[..18];

        using var db1 = CreateContext();
        using var db2 = CreateContext();

        var service1 = new TenantService(db1, TimeProvider.System, NullLogger<TenantService>.Instance);
        var service2 = new TenantService(db2, TimeProvider.System, NullLogger<TenantService>.Instance);

        var request1 = new CreateTenantRequest(sharedSlug, "Org Attempt 1");
        var request2 = new CreateTenantRequest(sharedSlug, "Org Attempt 2");

        var task1 = service1.CreateTenantAsync(user1.Id, request1);
        var task2 = service2.CreateTenantAsync(user2.Id, request2);

        var results = await Task.WhenAll(task1, task2);

        var successCount = results.Count(r => r.IsSuccess && r.StatusCode == 201);
        var conflictCount = results.Count(r => !r.IsSuccess && r.StatusCode == 409);

        Assert.Equal(1, successCount);
        Assert.Equal(1, conflictCount);

        // Exactly one tenant exists with this slug in PostgreSQL
        using var verifyDb = CreateContext();
        var tenantsWithSlug = await verifyDb.Tenants.Where(t => t.Slug == sharedSlug).ToListAsync();
        Assert.Single(tenantsWithSlug);
    }
}

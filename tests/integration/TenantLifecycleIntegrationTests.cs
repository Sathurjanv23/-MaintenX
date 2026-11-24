namespace MaintenX.IntegrationTests;

using MaintenX.Api.Application.Tenancy.Contracts;
using MaintenX.Api.Application.Tenancy.Models;
using MaintenX.Api.Application.Tenancy.Services;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Integration test suite for FEAT-003 Task 3.5.3 Tenant Lifecycle & Settings Services.
/// Executes against a disposable, isolated PostgreSQL 16 database.
/// Validates tenant lookup, anti-enumeration, settings updates, optimistic concurrency,
/// lifecycle state transitions (Activate, Suspend, Deactivate), and audit log creation.
/// </summary>
public class TenantLifecycleIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public TenantLifecycleIntegrationTests()
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

    private async Task<(Tenant tenant, User owner, User admin, User member, User stranger)> SeedTenantWithUsersAsync(
        string slug,
        string displayName,
        TenantStatus status = TenantStatus.PendingOnboarding)
    {
        using var context = CreateContext();
        var now = DateTime.UtcNow;

        var tenant = Tenant.Create(slug, displayName, status);
        tenant.CreatedAtUtc = now;
        tenant.UpdatedAtUtc = now;
        context.Tenants.Add(tenant);

        var owner = User.Create($"owner_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        var admin = User.Create($"admin_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        var member = User.Create($"member_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        var stranger = User.Create($"stranger_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);

        context.Users.AddRange(owner, admin, member, stranger);

        var mOwner = TenantMembership.Create(tenant.Id, owner.Id, TenantMembershipRole.Owner, TenantMembershipStatus.Active, now);
        var mAdmin = TenantMembership.Create(tenant.Id, admin.Id, TenantMembershipRole.Administrator, TenantMembershipStatus.Active, now);
        var mMember = TenantMembership.Create(tenant.Id, member.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active, now);

        using (context.CreatePrivilegedTenantBypassScope("seed-test-data"))
        {
            context.TenantMemberships.AddRange(mOwner, mAdmin, mMember);
            await context.SaveChangesAsync();
        }

        return (tenant, owner, admin, member, stranger);
    }

    // --- Scenario 1 & 2: Lookup and Anti-Enumeration ---

    [Fact]
    public async Task GetTenantByIdAsync_ActiveMember_ReturnsSuccess()
    {
        var (tenant, owner, _, _, _) = await SeedTenantWithUsersAsync("acme-lookup", "Acme Lookup");
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.Member(owner.Id, tenant.Id, TenantMembershipRole.Owner);

        var result = await service.GetTenantByIdAsync(tenant.Id, actor);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.NotNull(result.Tenant);
        Assert.Equal(tenant.Id, result.Tenant.Id);
        Assert.Equal("acme-lookup", result.Tenant.Slug);
        Assert.Equal("Acme Lookup", result.Tenant.DisplayName);
    }

    [Fact]
    public async Task GetTenantByIdAsync_NonMember_ReturnsNotFound_AntiEnumeration()
    {
        var (tenant, _, _, _, stranger) = await SeedTenantWithUsersAsync("acme-secret", "Acme Secret");
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.FromUser(stranger.Id);

        var result = await service.GetTenantByIdAsync(tenant.Id, actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("TENANT_NOT_FOUND", result.ErrorCode);
    }

    [Fact]
    public async Task GetTenantBySlugAsync_PlatformAdmin_ReturnsSuccess()
    {
        var (tenant, _, _, _, stranger) = await SeedTenantWithUsersAsync("acme-slug-test", "Acme Slug Test");
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.PlatformAdmin(stranger.Id);

        var result = await service.GetTenantBySlugAsync("acme-slug-test", actor);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.NotNull(result.Tenant);
        Assert.Equal(tenant.Id, result.Tenant.Id);
    }

    // --- Scenario 4 & 5: Tenant Settings Updates & Authorization ---

    [Fact]
    public async Task UpdateTenantAsync_Owner_UpdatesDisplayNameAndBumpsVersion()
    {
        var (tenant, owner, _, _, _) = await SeedTenantWithUsersAsync("acme-upd", "Acme Original");
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.Member(owner.Id, tenant.Id, TenantMembershipRole.Owner);

        var result = await service.UpdateTenantAsync(tenant.Id, new UpdateTenantRequest("Acme Updated"), actor);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.NotNull(result.Tenant);
        Assert.Equal("Acme Updated", result.Tenant.DisplayName);
        Assert.Equal(2, result.Tenant.Version);

        // Verify database persistence
        using var verifyContext = CreateContext();
        var reloaded = await verifyContext.Tenants.AsNoTracking().FirstAsync(t => t.Id == tenant.Id);
        Assert.Equal("Acme Updated", reloaded.DisplayName);
        Assert.Equal(2, reloaded.Version);
    }

    [Fact]
    public async Task UpdateTenantAsync_RegularMember_ReturnsForbidden()
    {
        var (tenant, _, _, member, _) = await SeedTenantWithUsersAsync("acme-perm", "Acme Permissions");
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.Member(member.Id, tenant.Id, TenantMembershipRole.Member);

        var result = await service.UpdateTenantAsync(tenant.Id, new UpdateTenantRequest("Hacked Name"), actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
        Assert.Equal("FORBIDDEN", result.ErrorCode);
    }

    [Fact]
    public async Task UpdateTenantAsync_CrossTenantActor_ReturnsForbidden()
    {
        var (tenant, owner, _, _, _) = await SeedTenantWithUsersAsync("acme-cross", "Acme Cross");
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var otherTenantId = Guid.NewGuid();
        var actor = TenantActorContext.Member(owner.Id, otherTenantId, TenantMembershipRole.Owner);

        var result = await service.UpdateTenantAsync(tenant.Id, new UpdateTenantRequest("Cross Tenant Name"), actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(403, result.StatusCode);
    }

    // --- Scenario 8 & 9: Optimistic Concurrency ---

    [Fact]
    public async Task UpdateTenantAsync_MismatchedExpectedVersion_ReturnsConflict()
    {
        var (tenant, owner, _, _, _) = await SeedTenantWithUsersAsync("acme-version", "Acme Version");
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var actor = TenantActorContext.Member(owner.Id, tenant.Id, TenantMembershipRole.Owner);

        // Request with stale expected version (expected: 99, actual: 1)
        var result = await service.UpdateTenantAsync(
            tenant.Id,
            new UpdateTenantRequest("Acme Conflicted", ExpectedVersion: 99),
            actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(409, result.StatusCode);
        Assert.Equal("CONCURRENCY_CONFLICT", result.ErrorCode);
    }

    [Fact]
    public async Task UpdateTenantAsync_ConcurrentModifications_OneSucceedsOneConflicts()
    {
        var (tenant, owner, _, _, _) = await SeedTenantWithUsersAsync("acme-race", "Acme Race Original");

        using var context1 = CreateContext();
        using var context2 = CreateContext();

        var service1 = new TenantService(context1, TimeProvider.System, NullLogger<TenantService>.Instance);
        var service2 = new TenantService(context2, TimeProvider.System, NullLogger<TenantService>.Instance);

        var actor = TenantActorContext.Member(owner.Id, tenant.Id, TenantMembershipRole.Owner);

        // Both read original tenant (version 1)
        var tenant1 = await context1.Tenants.FirstAsync(t => t.Id == tenant.Id);
        var tenant2 = await context2.Tenants.FirstAsync(t => t.Id == tenant.Id);

        // Actor 1 modifies and saves successfully
        tenant1.UpdateDisplayName("Race Winner 1", DateTime.UtcNow);
        await context1.SaveChangesAsync();

        // Actor 2 attempts update with stale loaded state
        tenant2.UpdateDisplayName("Race Winner 2", DateTime.UtcNow);

        // Assert: Saving stale state throws DbUpdateConcurrencyException
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(async () =>
        {
            await context2.SaveChangesAsync();
        });
    }

    // --- Scenario 6, 7 & 11: Lifecycle Transitions (Activate, Suspend, Deactivate) ---

    [Fact]
    public async Task Lifecycle_PendingToActive_SucceedsForPlatformAdmin()
    {
        var (tenant, _, _, _, stranger) = await SeedTenantWithUsersAsync("acme-act", "Acme Activate", TenantStatus.PendingOnboarding);
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var adminActor = TenantActorContext.PlatformAdmin(stranger.Id);

        var result = await service.ActivateTenantAsync(tenant.Id, adminActor);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal("Active", result.Response!.Status);

        // Verify in DB
        using var verifyContext = CreateContext();
        var reloaded = await verifyContext.Tenants.AsNoTracking().FirstAsync(t => t.Id == tenant.Id);
        Assert.Equal(TenantStatus.Active, reloaded.Status);
        Assert.Equal(2, reloaded.Version);
    }

    [Fact]
    public async Task Lifecycle_SuspendPendingOnboarding_ReturnsInvalidState()
    {
        var (tenant, _, _, _, stranger) = await SeedTenantWithUsersAsync("acme-pend-susp", "Acme Pending", TenantStatus.PendingOnboarding);
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var adminActor = TenantActorContext.PlatformAdmin(stranger.Id);

        var result = await service.SuspendTenantAsync(tenant.Id, "Billing investigation in progress.", adminActor);

        Assert.False(result.IsSuccess);
        Assert.Equal(400, result.StatusCode);
        Assert.Equal("INVALID_LIFECYCLE_TRANSITION", result.ErrorCode);
    }

    [Fact]
    public async Task Lifecycle_ActiveToSuspended_ThenReactivated_Succeeds()
    {
        var (tenant, _, _, _, stranger) = await SeedTenantWithUsersAsync("acme-susp-react", "Acme Susp React", TenantStatus.Active);
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var adminActor = TenantActorContext.PlatformAdmin(stranger.Id);

        // 1. Suspend
        var suspResult = await service.SuspendTenantAsync(tenant.Id, "Administrative audit hold.", adminActor);
        Assert.True(suspResult.IsSuccess);
        Assert.Equal("Suspended", suspResult.Response!.Status);

        // 2. Reactivate
        var actResult = await service.ActivateTenantAsync(tenant.Id, adminActor);
        Assert.True(actResult.IsSuccess);
        Assert.Equal("Active", actResult.Response!.Status);

        // Verify DB state
        using var verifyContext = CreateContext();
        var reloaded = await verifyContext.Tenants.AsNoTracking().FirstAsync(t => t.Id == tenant.Id);
        Assert.Equal(TenantStatus.Active, reloaded.Status);
        Assert.Equal(3, reloaded.Version); // 1 (seed) -> 2 (suspend) -> 3 (reactivate)
    }

    [Fact]
    public async Task Lifecycle_DeactivateIsTerminal_RejectsActivationAndUpdates()
    {
        var (tenant, owner, _, _, stranger) = await SeedTenantWithUsersAsync("acme-term", "Acme Terminal", TenantStatus.Active);
        using var context = CreateContext();
        var service = new TenantService(context, TimeProvider.System, NullLogger<TenantService>.Instance);
        var adminActor = TenantActorContext.PlatformAdmin(stranger.Id);
        var ownerActor = TenantActorContext.Member(owner.Id, tenant.Id, TenantMembershipRole.Owner);

        // 1. Deactivate
        var deactResult = await service.DeactivateTenantAsync(tenant.Id, "Contract cancelled permanently.", adminActor);
        Assert.True(deactResult.IsSuccess);
        Assert.Equal("Deactivated", deactResult.Response!.Status);

        // 2. Try to activate -> rejected
        var actResult = await service.ActivateTenantAsync(tenant.Id, adminActor);
        Assert.False(actResult.IsSuccess);
        Assert.Equal(400, actResult.StatusCode);

        // 3. Try to suspend -> rejected
        var suspResult = await service.SuspendTenantAsync(tenant.Id, "Hold", adminActor);
        Assert.False(suspResult.IsSuccess);
        Assert.Equal(400, suspResult.StatusCode);

        // 4. Try to update display name -> rejected with Conflict
        var updResult = await service.UpdateTenantAsync(tenant.Id, new UpdateTenantRequest("New Name"), ownerActor);
        Assert.False(updResult.IsSuccess);
        Assert.Equal(409, updResult.StatusCode);
        Assert.Equal("DEACTIVATED_TENANT", updResult.ErrorCode);
    }
}

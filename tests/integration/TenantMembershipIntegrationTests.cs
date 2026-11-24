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
/// Integration test suite for FEAT-003 Task 3.5.4 Tenant Membership Application Services.
/// Executes against a disposable, isolated PostgreSQL 16 database.
/// Validates tenant-neutral membership discovery, multi-tenant workspace switching,
/// role-based administrative query boundaries, cross-tenant isolation, and non-disclosing anti-enumeration.
/// </summary>
public class TenantMembershipIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public TenantMembershipIntegrationTests()
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

    private async Task<(Tenant tenant, User user, TenantMembership membership)> CreateTenantAndMemberAsync(
        string slug,
        string displayName,
        TenantMembershipRole role = TenantMembershipRole.Member,
        TenantMembershipStatus status = TenantMembershipStatus.Active,
        TenantStatus tenantStatus = TenantStatus.Active)
    {
        using var context = CreateContext();
        var now = DateTime.UtcNow;

        var tenant = Tenant.Create(slug, displayName, tenantStatus);
        tenant.CreatedAtUtc = now;
        tenant.UpdatedAtUtc = now;
        context.Tenants.Add(tenant);

        var user = User.Create($"user_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        context.Users.Add(user);

        var membership = TenantMembership.Create(
            tenant.Id,
            user.Id,
            role,
            status == TenantMembershipStatus.Revoked ? TenantMembershipStatus.Active : status,
            now);

        if (status == TenantMembershipStatus.Revoked)
        {
            membership.Revoke(now);
        }

        using (context.CreatePrivilegedTenantBypassScope("seed-test-data"))
        {
            context.TenantMemberships.Add(membership);
            await context.SaveChangesAsync();
        }

        return (tenant, user, membership);
    }

    // --- Scenario 1: User retrieves their own active membership ---

    [Fact]
    public async Task GetUserMembershipsAsync_OwnActiveMembership_ReturnsMembershipWithTenantDetails()
    {
        var (tenant, user, membership) = await CreateTenantAndMemberAsync("acme-disc", "Acme Discovery");
        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetUserMembershipsAsync(user.Id, actor);

        Assert.NotNull(result);
        var item = Assert.Single(result);
        Assert.Equal(membership.Id, item.MembershipId);
        Assert.Equal(tenant.Id, item.TenantId);
        Assert.Equal("acme-disc", item.TenantSlug);
        Assert.Equal("Acme Discovery", item.TenantDisplayName);
        Assert.Equal("Member", item.Role);
        Assert.Equal("Active", item.Status);
        Assert.Equal("Active", item.TenantStatus);
        Assert.True(item.IsSelectable);
    }

    // --- Scenario 2: User with multiple organizations receives only their authorized records ordered deterministically ---

    [Fact]
    public async Task GetUserMembershipsAsync_MultipleOrganizations_ReturnsAllMembershipsDeterministically()
    {
        using var context = CreateContext();
        var now = DateTime.UtcNow;

        var user = User.Create($"multi_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        context.Users.Add(user);

        var tenantZ = Tenant.Create("zebra-corp", "Zebra Corp", TenantStatus.Active);
        var tenantA = Tenant.Create("alpha-corp", "Alpha Corp", TenantStatus.Active);
        context.Tenants.AddRange(tenantZ, tenantA);

        var mZ = TenantMembership.Create(tenantZ.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active, now);
        var mA = TenantMembership.Create(tenantA.Id, user.Id, TenantMembershipRole.Administrator, TenantMembershipStatus.Active, now);

        using (context.CreatePrivilegedTenantBypassScope("seed-test-data"))
        {
            context.TenantMemberships.AddRange(mZ, mA);
            await context.SaveChangesAsync();
        }

        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetUserMembershipsAsync(user.Id, actor);

        Assert.Equal(2, result.Count);
        // Deterministic ordering: Alpha Corp before Zebra Corp
        Assert.Equal("Alpha Corp", result[0].TenantDisplayName);
        Assert.Equal("Administrator", result[0].Role);
        Assert.Equal("Zebra Corp", result[1].TenantDisplayName);
        Assert.Equal("Member", result[1].Role);
    }

    // --- Scenario 3: User with zero memberships receives empty list ---

    [Fact]
    public async Task GetUserMembershipsAsync_ZeroMemberships_ReturnsEmptyList()
    {
        using var context = CreateContext();
        var user = User.Create($"zero_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, DateTime.UtcNow);
        context.Users.Add(user);
        await context.SaveChangesAsync();

        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetUserMembershipsAsync(user.Id, actor);

        Assert.NotNull(result);
        Assert.Empty(result);
    }

    // --- Scenario 4: Membership discovery works without active tenant context ---

    [Fact]
    public async Task GetUserMembershipsAsync_WithoutActiveTenantContext_Succeeds()
    {
        var (tenant, user, _) = await CreateTenantAndMemberAsync("no-ctx", "No Context");
        using var context = CreateContext();

        // Pass null context accessor representing uncontexted pre-tenant-selection state
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetUserMembershipsAsync(user.Id, actor);

        Assert.Single(result);
        Assert.Equal(tenant.Id, result[0].TenantId);
    }

    // --- Scenario 5: User A cannot retrieve User B memberships ---

    [Fact]
    public async Task GetUserMembershipsAsync_UserACannotRetrieveUserBMemberships()
    {
        var (_, userA, _) = await CreateTenantAndMemberAsync("tenant-a", "Tenant A");
        var (_, userB, _) = await CreateTenantAndMemberAsync("tenant-b", "Tenant B");

        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actorA = TenantActorContext.FromUser(userA.Id);

        // User A attempts to discover User B's memberships
        var result = await service.GetUserMembershipsAsync(userB.Id, actorA);

        Assert.NotNull(result);
        Assert.Empty(result); // Anti-enumeration: returns empty, preventing disclosure
    }

    // --- Scenario 6: User retrieves their own membership details via GetMembershipAsync ---

    [Fact]
    public async Task GetMembershipAsync_OwnMembership_ReturnsSuccessWithDetails()
    {
        var (tenant, user, membership) = await CreateTenantAndMemberAsync("self-mem", "Self Membership");
        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetMembershipAsync(tenant.Id, user.Id, actor);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.NotNull(result.Membership);
        Assert.Equal(membership.Id, result.Membership.MembershipId);
        Assert.Equal(tenant.Id, result.Membership.TenantId);
        Assert.Equal(user.Id, result.Membership.UserId);
        Assert.Equal("Member", result.Membership.Role);
        Assert.Equal("Active", result.Membership.Status);
    }

    // --- Scenario 7: Tenant Owner can retrieve another member's record in the same tenant ---

    [Fact]
    public async Task GetMembershipAsync_TenantOwner_CanRetrieveMemberRecordInSameTenant()
    {
        using var context = CreateContext();
        var now = DateTime.UtcNow;

        var tenant = Tenant.Create("owner-query", "Owner Query", TenantStatus.Active);
        var owner = User.Create($"owner_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        var member = User.Create($"member_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        context.Tenants.Add(tenant);
        context.Users.AddRange(owner, member);

        var mOwner = TenantMembership.Create(tenant.Id, owner.Id, TenantMembershipRole.Owner, TenantMembershipStatus.Active, now);
        var mMember = TenantMembership.Create(tenant.Id, member.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active, now);

        using (context.CreatePrivilegedTenantBypassScope("seed-test-data"))
        {
            context.TenantMemberships.AddRange(mOwner, mMember);
            await context.SaveChangesAsync();
        }

        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var ownerActor = TenantActorContext.FromUser(owner.Id);

        var result = await service.GetMembershipAsync(tenant.Id, member.Id, ownerActor);

        Assert.True(result.IsSuccess);
        Assert.Equal(200, result.StatusCode);
        Assert.Equal(mMember.Id, result.Membership!.MembershipId);
        Assert.Equal("Member", result.Membership.Role);
    }

    // --- Scenario 8: Ordinary member cannot retrieve another member's record in the same tenant ---

    [Fact]
    public async Task GetMembershipAsync_OrdinaryMember_CannotRetrieveAnotherMemberRecord()
    {
        using var context = CreateContext();
        var now = DateTime.UtcNow;

        var tenant = Tenant.Create("mem-priv", "Member Privacy", TenantStatus.Active);
        var member1 = User.Create($"m1_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        var member2 = User.Create($"m2_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        context.Tenants.Add(tenant);
        context.Users.AddRange(member1, member2);

        var m1 = TenantMembership.Create(tenant.Id, member1.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active, now);
        var m2 = TenantMembership.Create(tenant.Id, member2.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active, now);

        using (context.CreatePrivilegedTenantBypassScope("seed-test-data"))
        {
            context.TenantMemberships.AddRange(m1, m2);
            await context.SaveChangesAsync();
        }

        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var member1Actor = TenantActorContext.FromUser(member1.Id);

        // Member 1 attempts to query Member 2
        var result = await service.GetMembershipAsync(tenant.Id, member2.Id, member1Actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("MEMBERSHIP_NOT_FOUND", result.ErrorCode);
    }

    // --- Scenario 9: Tenant A caller cannot retrieve unauthorized Tenant B membership details ---

    [Fact]
    public async Task GetMembershipAsync_CrossTenantCaller_ReturnsNotFound()
    {
        var (tenantA, ownerA, _) = await CreateTenantAndMemberAsync("cross-a", "Tenant A", TenantMembershipRole.Owner);
        var (tenantB, userB, _) = await CreateTenantAndMemberAsync("cross-b", "Tenant B", TenantMembershipRole.Member);

        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var ownerActorA = TenantActorContext.FromUser(ownerA.Id);

        // Owner of Tenant A attempts to query User B's membership in Tenant B
        var result = await service.GetMembershipAsync(tenantB.Id, userB.Id, ownerActorA);

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
        Assert.Equal("MEMBERSHIP_NOT_FOUND", result.ErrorCode);
    }

    // --- Scenario 10: PendingOnboarding organization remains discoverable by its owner ---

    [Fact]
    public async Task GetUserMembershipsAsync_PendingOnboardingTenant_IsDiscoverableByOwner()
    {
        var (tenant, owner, _) = await CreateTenantAndMemberAsync(
            "onboarding-disc",
            "Onboarding Discovery",
            TenantMembershipRole.Owner,
            TenantMembershipStatus.Active,
            TenantStatus.PendingOnboarding);

        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var ownerActor = TenantActorContext.FromUser(owner.Id);

        var result = await service.GetUserMembershipsAsync(owner.Id, ownerActor);

        var item = Assert.Single(result);
        Assert.Equal(tenant.Id, item.TenantId);
        Assert.Equal("Owner", item.Role);
        Assert.Equal("Active", item.Status);
        Assert.Equal("PendingOnboarding", item.TenantStatus);
        Assert.False(item.IsSelectable);
    }

    // --- Scenario 11: Revoked membership is excluded from discovery ---

    [Fact]
    public async Task GetUserMembershipsAsync_RevokedMembership_IsExcludedFromDiscovery()
    {
        var (_, user, _) = await CreateTenantAndMemberAsync(
            "revoked-t",
            "Revoked Tenant",
            TenantMembershipRole.Member,
            TenantMembershipStatus.Revoked);

        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetUserMembershipsAsync(user.Id, actor);

        Assert.NotNull(result);
        Assert.Empty(result); // Revoked memberships are excluded from workspace selection
    }

    // --- Scenario 12: Revocation followed by re-invitation returns the current active membership ---

    [Fact]
    public async Task GetUserMembershipsAsync_RevocationFollowedByReinvitation_ReturnsCurrentMembership()
    {
        using var context = CreateContext();
        var now = DateTime.UtcNow;

        var tenant = Tenant.Create("reinvite-t", "Reinvitation Tenant", TenantStatus.Active);
        var user = User.Create($"reinvite_{Guid.NewGuid():N}@maintenx.dev", "dummy-hash", UserStatus.Active, now);
        context.Tenants.Add(tenant);
        context.Users.Add(user);

        // Historical revoked membership
        var oldRevoked = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active, now.AddDays(-10));
        oldRevoked.Revoke(now.AddDays(-5));

        // New active membership from re-invitation
        var newActive = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Administrator, TenantMembershipStatus.Active, now);

        using (context.CreatePrivilegedTenantBypassScope("seed-test-data"))
        {
            context.TenantMemberships.AddRange(oldRevoked, newActive);
            await context.SaveChangesAsync();
        }

        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetUserMembershipsAsync(user.Id, actor);

        var item = Assert.Single(result);
        Assert.Equal(newActive.Id, item.MembershipId);
        Assert.Equal("Administrator", item.Role);
        Assert.Equal("Active", item.Status);
    }

    // --- Scenario 13: Revoked membership lookup returns NotFound via GetMembershipAsync ---

    [Fact]
    public async Task GetMembershipAsync_RevokedMembership_ReturnsNotFound()
    {
        var (tenant, user, _) = await CreateTenantAndMemberAsync(
            "rev-direct",
            "Revoked Direct",
            TenantMembershipRole.Member,
            TenantMembershipStatus.Revoked);

        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        var result = await service.GetMembershipAsync(tenant.Id, user.Id, actor);

        Assert.False(result.IsSuccess);
        Assert.Equal(404, result.StatusCode);
    }

    // --- Scenario 14: Membership queries are strictly read-only and do not mutate records ---

    [Fact]
    public async Task MembershipQueries_DoNotMutateDatabaseState()
    {
        var (tenant, user, membership) = await CreateTenantAndMemberAsync("ro-check", "Read-Only Check");

        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);
        var actor = TenantActorContext.FromUser(user.Id);

        // Execute queries
        await service.GetUserMembershipsAsync(user.Id, actor);
        await service.GetMembershipAsync(tenant.Id, user.Id, actor);

        // Verify in DB that versions and counts are unchanged
        using var verifyContext = CreateContext();
        using (verifyContext.CreatePrivilegedTenantBypassScope("verify-state-unmutated"))
        {
            var reloadedTenant = await verifyContext.Tenants.AsNoTracking().FirstAsync(t => t.Id == tenant.Id);
            var reloadedMembership = await verifyContext.TenantMemberships.AsNoTracking().FirstAsync(m => m.Id == membership.Id);
            var auditCount = await verifyContext.TenantAuditEvents.CountAsync();

            Assert.Equal(tenant.Version, reloadedTenant.Version);
            Assert.Equal(membership.Version, reloadedMembership.Version);
            Assert.Equal(0, auditCount); // Read-only queries produce zero audit records
        }
    }

    // --- Scenario 15: Concurrent discovery requests from different users do not leak results ---

    [Fact]
    public async Task ConcurrentDiscovery_FromDifferentUsers_DoesNotLeakResults()
    {
        var (tenant1, user1, _) = await CreateTenantAndMemberAsync("conc-1", "Concurrent 1");
        var (tenant2, user2, _) = await CreateTenantAndMemberAsync("conc-2", "Concurrent 2");

        using var context1 = CreateContext();
        using var context2 = CreateContext();
        var service1 = new TenantMembershipService(context1, null, NullLogger<TenantMembershipService>.Instance);
        var service2 = new TenantMembershipService(context2, null, NullLogger<TenantMembershipService>.Instance);

        var task1 = service1.GetUserMembershipsAsync(user1.Id, TenantActorContext.FromUser(user1.Id));
        var task2 = service2.GetUserMembershipsAsync(user2.Id, TenantActorContext.FromUser(user2.Id));

        await Task.WhenAll(task1, task2);

        var result1 = await task1;
        var result2 = await task2;

        var item1 = Assert.Single(result1);
        var item2 = Assert.Single(result2);

        Assert.Equal(tenant1.Id, item1.TenantId);
        Assert.Equal(tenant2.Id, item2.TenantId);
    }

    // --- Scenario 16: Privileged bypass disposal restores normal tenant query filtering ---

    [Fact]
    public async Task PrivilegedBypass_DisposalRestoresNormalTenantIsolation()
    {
        var (tenant, user, _) = await CreateTenantAndMemberAsync("bypass-test", "Bypass Test");

        using var context = CreateContext();
        var service = new TenantMembershipService(context, null, NullLogger<TenantMembershipService>.Instance);

        // Before query: filter is active
        Assert.False(context.IsTenantFilterDisabled);

        await service.GetUserMembershipsAsync(user.Id, TenantActorContext.FromUser(user.Id));

        // After query: filter is restored
        Assert.False(context.IsTenantFilterDisabled);
    }
}

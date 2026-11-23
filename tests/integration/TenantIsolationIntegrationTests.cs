namespace MaintenX.IntegrationTests;

using System.Security;
using MaintenX.Api.Application.Tenancy.Context;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Xunit;

/// <summary>
/// Integration test suite verifying multi-tenant data isolation and security enforcement.
/// Executes against a disposable, isolated PostgreSQL 16 database.
/// Validates EF Core global query filtering, write-side ownership enforcement,
/// cross-tenant write/mutation rejection, zero-leakage uncontexted reads,
/// and privileged bypass auditing.
/// </summary>
public class TenantIsolationIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public TenantIsolationIntegrationTests()
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

    private MaintenXDbContext CreateContext(ITenantContextAccessor? accessor = null)
    {
        var options = new DbContextOptionsBuilder<MaintenXDbContext>()
            .UseNpgsql(_isolatedConnectionString)
            .Options;

        return new MaintenXDbContext(options, accessor);
    }

    private sealed class TestTenantContextAccessor : ITenantContextAccessor
    {
        public ITenantContext? Current { get; set; }
        public bool HasContext => Current != null;

        public TestTenantContextAccessor(Guid? tenantId = null)
        {
            if (tenantId.HasValue)
            {
                Current = new TenantContext(
                    tenantId.Value,
                    $"tenant-{tenantId.Value:N}"[..18],
                    "Test Tenant",
                    Guid.NewGuid(),
                    Guid.NewGuid(),
                    TenantMembershipRole.Owner,
                    TenantMembershipStatus.Active,
                    DateTime.UtcNow);
            }
        }
    }

    // =========================================================================
    // 1. READ ISOLATION & GLOBAL QUERY FILTERS
    // =========================================================================

    [Fact]
    public async Task Query_WhenTenantAContextActive_ReturnsOnlyTenantAEntities()
    {
        var tenantAId = Guid.NewGuid();
        var tenantBId = Guid.NewGuid();
        var userAId = Guid.NewGuid();
        var userBId = Guid.NewGuid();

        // Seed data using privileged bypass
        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenantA = Tenant.Create("tenant-a-query", "Tenant A Org");
                var tenantB = Tenant.Create("tenant-b-query", "Tenant B Org");
                var userA = User.Create("user.a.query@maintenx.internal", "hash1");
                var userB = User.Create("user.b.query@maintenx.internal", "hash2");

                seedDb.Tenants.AddRange(tenantA, tenantB);
                seedDb.Users.AddRange(userA, userB);
                await seedDb.SaveChangesAsync();

                tenantAId = tenantA.Id;
                tenantBId = tenantB.Id;
                userAId = userA.Id;
                userBId = userB.Id;

                var memberA = TenantMembership.Create(tenantAId, userAId, TenantMembershipRole.Owner);
                var memberB = TenantMembership.Create(tenantBId, userBId, TenantMembershipRole.Owner);

                seedDb.TenantMemberships.AddRange(memberA, memberB);
                await seedDb.SaveChangesAsync();
            }
        }

        // Query with Tenant A context
        var accessorA = new TestTenantContextAccessor(tenantAId);
        using var dbA = CreateContext(accessorA);

        var membershipsA = await dbA.TenantMemberships.ToListAsync();

        Assert.NotEmpty(membershipsA);
        Assert.All(membershipsA, m => Assert.Equal(tenantAId, m.TenantId));
        Assert.DoesNotContain(membershipsA, m => m.TenantId == tenantBId);
    }

    [Fact]
    public async Task Query_DirectPrimaryKeyLookup_ForCrossTenantEntity_ReturnsNull()
    {
        var tenantAId = Guid.NewGuid();
        var tenantBId = Guid.NewGuid();
        Guid memberBId;

        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenantA = Tenant.Create("tenant-a-lookup", "Tenant A Lookup");
                var tenantB = Tenant.Create("tenant-b-lookup", "Tenant B Lookup");
                var userB = User.Create("user.b.lookup@maintenx.internal", "hash1");

                seedDb.Tenants.AddRange(tenantA, tenantB);
                seedDb.Users.Add(userB);
                await seedDb.SaveChangesAsync();

                tenantAId = tenantA.Id;
                tenantBId = tenantB.Id;

                var memberB = TenantMembership.Create(tenantBId, userB.Id, TenantMembershipRole.Member);
                seedDb.TenantMemberships.Add(memberB);
                await seedDb.SaveChangesAsync();

                memberBId = memberB.Id;
            }
        }

        // Query Tenant B entity by ID while Tenant A is active
        var accessorA = new TestTenantContextAccessor(tenantAId);
        using var dbA = CreateContext(accessorA);

        var queried = await dbA.TenantMemberships.FirstOrDefaultAsync(m => m.Id == memberBId);

        // Filter must ensure null is returned, preventing existence leak via direct PK lookup
        Assert.Null(queried);
    }

    [Fact]
    public async Task Query_WhenNoTenantContextActive_ReturnsZeroRowsForTenantEntities()
    {
        Guid tenantId;
        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenant = Tenant.Create("tenant-uncontexted", "Uncontexted Test Org");
                var user = User.Create("user.uncontexted@maintenx.internal", "hash1");
                seedDb.Tenants.Add(tenant);
                seedDb.Users.Add(user);
                await seedDb.SaveChangesAsync();

                tenantId = tenant.Id;
                var member = TenantMembership.Create(tenantId, user.Id, TenantMembershipRole.Administrator);
                seedDb.TenantMemberships.Add(member);
                await seedDb.SaveChangesAsync();
            }
        }

        // Query with uncontexted accessor (no tenant established)
        var uncontextedAccessor = new TestTenantContextAccessor(null);
        using var db = CreateContext(uncontextedAccessor);

        var results = await db.TenantMemberships.ToListAsync();

        // Must evaluate to false and return ZERO records (never leak across tenants when context missing)
        Assert.Empty(results);

        // However, global platform entities remain accessible
        var tenants = await db.Tenants.Where(t => t.Id == tenantId).ToListAsync();
        Assert.Single(tenants);
    }

    // =========================================================================
    // 2. WRITE-SIDE ISOLATION ENFORCEMENT
    // =========================================================================

    [Fact]
    public async Task SaveChanges_CrossTenantInsert_ThrowsSecurityException()
    {
        var tenantAId = Guid.NewGuid();
        var tenantBId = Guid.NewGuid();
        var userBId = Guid.NewGuid();

        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenantA = Tenant.Create("tenant-a-write", "Tenant A Org");
                var tenantB = Tenant.Create("tenant-b-write", "Tenant B Org");
                var userB = User.Create("user.b.write@maintenx.internal", "hash1");

                seedDb.Tenants.AddRange(tenantA, tenantB);
                seedDb.Users.Add(userB);
                await seedDb.SaveChangesAsync();

                tenantAId = tenantA.Id;
                tenantBId = tenantB.Id;
                userBId = userB.Id;
            }
        }

        // Active context is Tenant A, but attempt to insert membership for Tenant B
        var accessorA = new TestTenantContextAccessor(tenantAId);
        using var dbA = CreateContext(accessorA);

        var crossTenantMembership = TenantMembership.Create(tenantBId, userBId, TenantMembershipRole.Member);
        dbA.TenantMemberships.Add(crossTenantMembership);

        var ex = await Assert.ThrowsAsync<SecurityException>(() => dbA.SaveChangesAsync());
        Assert.Contains("cross-tenant write", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SaveChanges_InsertWithNoTenantContext_ThrowsSecurityException()
    {
        Guid tenantId;
        Guid userId;

        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenant = Tenant.Create("tenant-no-ctx", "No Context Org");
                var user = User.Create("user.no.ctx@maintenx.internal", "hash1");
                seedDb.Tenants.Add(tenant);
                seedDb.Users.Add(user);
                await seedDb.SaveChangesAsync();

                tenantId = tenant.Id;
                userId = user.Id;
            }
        }

        // Uncontexted accessor
        var uncontextedAccessor = new TestTenantContextAccessor(null);
        using var db = CreateContext(uncontextedAccessor);

        var membership = TenantMembership.Create(tenantId, userId, TenantMembershipRole.Member);
        db.TenantMemberships.Add(membership);

        var ex = await Assert.ThrowsAsync<SecurityException>(() => db.SaveChangesAsync());
        Assert.Contains("without an active, verified tenant context", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SaveChanges_InsertWithEmptyTenantId_ThrowsSecurityException()
    {
        var tenantAId = Guid.NewGuid();
        Guid userId;

        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenantA = Tenant.Create("tenant-empty-id", "Tenant Empty ID Org");
                var user = User.Create("user.empty.id@maintenx.internal", "hash1");
                seedDb.Tenants.Add(tenantA);
                seedDb.Users.Add(user);
                await seedDb.SaveChangesAsync();

                tenantAId = tenantA.Id;
                userId = user.Id;
            }
        }

        var accessorA = new TestTenantContextAccessor(tenantAId);
        using var dbA = CreateContext(accessorA);

        // Construct invalid membership with Guid.Empty via domain reflection or constructor bypass
        var membership = TenantMembership.Create(tenantAId, userId, TenantMembershipRole.Member);
        // Force TenantId to Guid.Empty
        typeof(TenantMembership).GetProperty(nameof(TenantMembership.TenantId))!
            .SetValue(membership, Guid.Empty);

        dbA.TenantMemberships.Add(membership);

        var ex = await Assert.ThrowsAsync<SecurityException>(() => dbA.SaveChangesAsync());
        Assert.Contains("empty TenantId", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SaveChanges_TenantIdMutationOnModifiedEntity_ThrowsSecurityException()
    {
        var tenantAId = Guid.NewGuid();
        var tenantBId = Guid.NewGuid();
        Guid membershipId;

        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenantA = Tenant.Create("tenant-a-mutate", "Tenant A Org");
                var tenantB = Tenant.Create("tenant-b-mutate", "Tenant B Org");
                var user = User.Create("user.mutate@maintenx.internal", "hash1");

                seedDb.Tenants.AddRange(tenantA, tenantB);
                seedDb.Users.Add(user);
                await seedDb.SaveChangesAsync();

                tenantAId = tenantA.Id;
                tenantBId = tenantB.Id;

                var membership = TenantMembership.Create(tenantAId, user.Id, TenantMembershipRole.Member);
                seedDb.TenantMemberships.Add(membership);
                await seedDb.SaveChangesAsync();

                membershipId = membership.Id;
            }
        }

        // Load entity under Tenant A context
        var accessorA = new TestTenantContextAccessor(tenantAId);
        using var dbA = CreateContext(accessorA);

        var entity = await dbA.TenantMemberships.FirstAsync(m => m.Id == membershipId);

        // Attempt to mutate TenantId
        dbA.Entry(entity).Property(m => m.TenantId).CurrentValue = tenantBId;

        var ex = await Assert.ThrowsAsync<SecurityException>(() => dbA.SaveChangesAsync());
        Assert.Contains("strictly immutable", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SaveChanges_CrossTenantDeletion_ThrowsSecurityException()
    {
        var tenantAId = Guid.NewGuid();
        var tenantBId = Guid.NewGuid();
        TenantMembership memberB;

        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenantA = Tenant.Create("tenant-a-del", "Tenant A Org");
                var tenantB = Tenant.Create("tenant-b-del", "Tenant B Org");
                var userB = User.Create("user.b.del@maintenx.internal", "hash1");

                seedDb.Tenants.AddRange(tenantA, tenantB);
                seedDb.Users.Add(userB);
                await seedDb.SaveChangesAsync();

                tenantAId = tenantA.Id;
                tenantBId = tenantB.Id;

                memberB = TenantMembership.Create(tenantBId, userB.Id, TenantMembershipRole.Member);
                seedDb.TenantMemberships.Add(memberB);
                await seedDb.SaveChangesAsync();
            }
        }

        // Active context is Tenant A, but attempt to delete Tenant B entity
        var accessorA = new TestTenantContextAccessor(tenantAId);
        using var dbA = CreateContext(accessorA);

        // Attach Tenant B's entity to context A and mark for deletion
        dbA.TenantMemberships.Attach(memberB);
        dbA.TenantMemberships.Remove(memberB);

        var ex = await Assert.ThrowsAsync<SecurityException>(() => dbA.SaveChangesAsync());
        Assert.Contains("cross-tenant deletion", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    // =========================================================================
    // 3. PRIVILEGED TENANT BYPASS SCOPE
    // =========================================================================

    [Fact]
    public async Task PrivilegedBypassScope_AllowsCrossTenantReadAndRestoresIsolationOnDispose()
    {
        var tenantAId = Guid.NewGuid();
        var tenantBId = Guid.NewGuid();

        using (var seedDb = CreateContext())
        {
            using (seedDb.CreatePrivilegedTenantBypassScope("seed"))
            {
                var tenantA = Tenant.Create("tenant-a-bypass", "Tenant A Org");
                var tenantB = Tenant.Create("tenant-b-bypass", "Tenant B Org");
                var userA = User.Create("user.a.bypass@maintenx.internal", "hash1");
                var userB = User.Create("user.b.bypass@maintenx.internal", "hash2");

                seedDb.Tenants.AddRange(tenantA, tenantB);
                seedDb.Users.AddRange(userA, userB);
                await seedDb.SaveChangesAsync();

                tenantAId = tenantA.Id;
                tenantBId = tenantB.Id;

                var memberA = TenantMembership.Create(tenantAId, userA.Id, TenantMembershipRole.Administrator);
                var memberB = TenantMembership.Create(tenantBId, userB.Id, TenantMembershipRole.Administrator);
                seedDb.TenantMemberships.AddRange(memberA, memberB);
                await seedDb.SaveChangesAsync();
            }
        }

        var accessorA = new TestTenantContextAccessor(tenantAId);
        using var dbA = CreateContext(accessorA);

        // 1. Normal query: Only Tenant A records returned
        var initialList = await dbA.TenantMemberships.ToListAsync();
        Assert.Single(initialList);
        Assert.Equal(tenantAId, initialList[0].TenantId);

        // 2. Within privileged bypass scope: All records returned
        using (dbA.CreatePrivilegedTenantBypassScope("maintenance_cross_tenant_aggregation"))
        {
            Assert.True(dbA.IsTenantFilterDisabled);
            var bypassedList = await dbA.TenantMemberships.ToListAsync();
            Assert.Equal(2, bypassedList.Count);
        }

        // 3. After scope disposal: Isolation is strictly restored
        Assert.False(dbA.IsTenantFilterDisabled);
        var restoredList = await dbA.TenantMemberships.ToListAsync();
        Assert.Single(restoredList);
        Assert.Equal(tenantAId, restoredList[0].TenantId);
    }

    [Fact]
    public void PrivilegedBypassScope_RequiresNonEmptyReason()
    {
        using var db = CreateContext();

        Assert.Throws<ArgumentException>(() => db.CreatePrivilegedTenantBypassScope(string.Empty));
        Assert.Throws<ArgumentException>(() => db.CreatePrivilegedTenantBypassScope("   "));
    }

    // =========================================================================
    // 4. UNFILTERED GLOBAL ENTITIES REMAIN OPERATIONAL
    // =========================================================================

    [Fact]
    public async Task GlobalEntities_UsersAndTenants_AreNeverFilteredOrBlockedByTenantContext()
    {
        var tenantId = Guid.NewGuid();
        var accessor = new TestTenantContextAccessor(tenantId);
        using var db = CreateContext(accessor);

        var uniqueEmail = $"global.{Guid.NewGuid():N}@maintenx.internal";
        var user = User.Create(uniqueEmail, "pwd_hash");
        var tenant = Tenant.Create($"tenant-{Guid.NewGuid():N}"[..20], "Global Test");

        db.Users.Add(user);
        db.Tenants.Add(tenant);
        await db.SaveChangesAsync();

        var queriedUser = await db.Users.FirstOrDefaultAsync(u => u.Id == user.Id);
        var queriedTenant = await db.Tenants.FirstOrDefaultAsync(t => t.Id == tenant.Id);

        Assert.NotNull(queriedUser);
        Assert.NotNull(queriedTenant);
    }
}

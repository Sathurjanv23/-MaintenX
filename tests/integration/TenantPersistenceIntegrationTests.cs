namespace MaintenX.IntegrationTests;

using System.Data;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

/// <summary>
/// Comprehensive PostgreSQL 16 integration tests for TenantMembership persistence.
/// Verifies schema mappings, foreign key cascades, partial unique indexes,
/// terminal revocation lifecycle support, check constraints, optimistic concurrency,
/// and migration application/rollback.
/// </summary>
public class TenantPersistenceIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public TenantPersistenceIntegrationTests()
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

        var context = new MaintenXDbContext(options);
        context.CreatePrivilegedTenantBypassScope("persistence-testing");
        return context;
    }

    private async Task<(Tenant Tenant, User User)> CreateTenantAndUserAsync(string suffix)
    {
        using var db = CreateContext();
        var now = DateTime.UtcNow;

        var tenant = Tenant.Create($"tenant-{suffix}", $"Tenant Organization {suffix}", TenantStatus.Active);
        db.Tenants.Add(tenant);

        var user = User.Create($"user.{suffix}@maintenx.internal", "hashed_pwd", UserStatus.Active, now);
        db.Users.Add(user);

        await db.SaveChangesAsync();
        return (tenant, user);
    }

    [Fact]
    public async Task Migration_CreatesTenantMembershipsTableInPlatformSchema()
    {
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'platform'
              AND table_name = 'tenant_memberships';";

        var tableName = (string?)await cmd.ExecuteScalarAsync();
        Assert.Equal("tenant_memberships", tableName);
    }

    [Fact]
    public async Task TenantMembership_PersistsAndRoundTrips_Successfully()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("roundtrip");
        var now = DateTime.UtcNow;

        using var insertDb = CreateContext();
        var membership = TenantMembership.Create(
            tenant.Id,
            user.Id,
            TenantMembershipRole.Owner,
            TenantMembershipStatus.Active,
            now);

        insertDb.TenantMemberships.Add(membership);
        await insertDb.SaveChangesAsync();

        using var verifyDb = CreateContext();
        var loaded = await verifyDb.TenantMemberships.FindAsync(membership.Id);

        Assert.NotNull(loaded);
        Assert.Equal(membership.Id, loaded.Id);
        Assert.Equal(tenant.Id, loaded.TenantId);
        Assert.Equal(user.Id, loaded.UserId);
        Assert.Equal(TenantMembershipRole.Owner, loaded.Role);
        Assert.Equal(TenantMembershipStatus.Active, loaded.Status);
        Assert.True(loaded.IsActive);
        Assert.True((loaded.CreatedAtUtc - now).Duration() < TimeSpan.FromMilliseconds(10));
        Assert.True((loaded.UpdatedAtUtc - now).Duration() < TimeSpan.FromMilliseconds(10));
        Assert.Null(loaded.DeactivatedAtUtc);
        Assert.Equal(1, loaded.Version);
    }

    [Fact]
    public async Task TenantMembership_ForeignKey_NonExistentTenant_ThrowsDbUpdateException()
    {
        var (_, user) = await CreateTenantAndUserAsync("fktarget-user");

        using var db = CreateContext();
        var invalidMembership = TenantMembership.Create(
            Guid.NewGuid(), // Non-existent tenant
            user.Id,
            TenantMembershipRole.Member);

        db.TenantMemberships.Add(invalidMembership);

        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        var postgresEx = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, postgresEx.SqlState);
        Assert.Equal("fk_tenant_memberships_tenants_tenant_id", postgresEx.ConstraintName);
    }

    [Fact]
    public async Task TenantMembership_ForeignKey_NonExistentUser_ThrowsDbUpdateException()
    {
        var (tenant, _) = await CreateTenantAndUserAsync("fktarget-tenant");

        using var db = CreateContext();
        var invalidMembership = TenantMembership.Create(
            tenant.Id,
            Guid.NewGuid(), // Non-existent user
            TenantMembershipRole.Member);

        db.TenantMemberships.Add(invalidMembership);

        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        var postgresEx = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.ForeignKeyViolation, postgresEx.SqlState);
        Assert.Equal("fk_tenant_memberships_users_user_id", postgresEx.ConstraintName);
    }

    [Fact]
    public async Task TenantMembership_CascadeDeletes_WhenTenantDeleted()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("cascade-tenant");

        using var db = CreateContext();
        var membership = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member);
        db.TenantMemberships.Add(membership);
        await db.SaveChangesAsync();

        var membershipId = membership.Id;
        var tenantId = tenant.Id;
        var userId = user.Id;

        // Delete Tenant
        using var deleteDb = CreateContext();
        var tenantToDelete = await deleteDb.Tenants.FindAsync(tenantId);
        deleteDb.Tenants.Remove(tenantToDelete!);
        await deleteDb.SaveChangesAsync();

        // Verify membership is deleted via cascade, but user survives
        using var assertDb = CreateContext();
        Assert.Null(await assertDb.Tenants.FindAsync(tenantId));
        Assert.Null(await assertDb.TenantMemberships.FindAsync(membershipId));
        Assert.NotNull(await assertDb.Users.FindAsync(userId));
    }

    [Fact]
    public async Task TenantMembership_CascadeDeletes_WhenUserDeleted()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("cascade-user");

        using var db = CreateContext();
        var membership = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member);
        db.TenantMemberships.Add(membership);
        await db.SaveChangesAsync();

        var membershipId = membership.Id;
        var tenantId = tenant.Id;
        var userId = user.Id;

        // Delete User
        using var deleteDb = CreateContext();
        var userToDelete = await deleteDb.Users.FindAsync(userId);
        deleteDb.Users.Remove(userToDelete!);
        await deleteDb.SaveChangesAsync();

        // Verify membership is deleted via cascade, but tenant survives
        using var assertDb = CreateContext();
        Assert.Null(await assertDb.Users.FindAsync(userId));
        Assert.Null(await assertDb.TenantMemberships.FindAsync(membershipId));
        Assert.NotNull(await assertDb.Tenants.FindAsync(tenantId));
    }

    [Fact]
    public async Task TenantMembership_Uniqueness_DuplicateNonRevokedMembership_ThrowsUniqueViolation()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("unique-active");

        using var db1 = CreateContext();
        var membership1 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active);
        db1.TenantMemberships.Add(membership1);
        await db1.SaveChangesAsync();

        using var db2 = CreateContext();
        var membership2 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Administrator, TenantMembershipStatus.Active);
        db2.TenantMemberships.Add(membership2);

        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db2.SaveChangesAsync());
        var postgresEx = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.UniqueViolation, postgresEx.SqlState);
        Assert.Equal("ix_tenant_memberships_tenant_id_user_id_non_revoked", postgresEx.ConstraintName);
    }

    [Fact]
    public async Task TenantMembership_Uniqueness_ActiveAndPendingConflict_ThrowsUniqueViolation()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("unique-pending");

        using var db1 = CreateContext();
        var membership1 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active);
        db1.TenantMemberships.Add(membership1);
        await db1.SaveChangesAsync();

        using var db2 = CreateContext();
        var membership2 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Pending);
        db2.TenantMemberships.Add(membership2);

        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db2.SaveChangesAsync());
        var postgresEx = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.UniqueViolation, postgresEx.SqlState);
    }

    [Fact]
    public async Task TenantMembership_Uniqueness_ActiveAndSuspendedConflict_ThrowsUniqueViolation()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("unique-suspended");

        using var db1 = CreateContext();
        var membership1 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active);
        db1.TenantMemberships.Add(membership1);
        await db1.SaveChangesAsync();

        using var db2 = CreateContext();
        var membership2 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Suspended);
        db2.TenantMemberships.Add(membership2);

        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db2.SaveChangesAsync());
        var postgresEx = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.UniqueViolation, postgresEx.SqlState);
    }

    [Fact]
    public async Task TenantMembership_RevocationAndReinvitation_PreservesHistoryAndAllowsNewMembership()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("reinvitation");

        // 1. Initial membership created and activated
        using var db1 = CreateContext();
        var initialMembership = TenantMembership.Create(
            tenant.Id,
            user.Id,
            TenantMembershipRole.Member,
            TenantMembershipStatus.Active,
            DateTime.UtcNow.AddDays(-10));

        db1.TenantMemberships.Add(initialMembership);
        await db1.SaveChangesAsync();

        var initialId = initialMembership.Id;

        // 2. Initial membership is revoked (terminal state)
        using var revokeDb = CreateContext();
        var membershipToRevoke = await revokeDb.TenantMemberships.FindAsync(initialId);
        Assert.NotNull(membershipToRevoke);

        var revokeTime = DateTime.UtcNow.AddDays(-2);
        membershipToRevoke.Revoke(revokeTime);
        await revokeDb.SaveChangesAsync();

        // 3. User is re-invited with a new membership entity
        using var reinviteDb = CreateContext();
        var newMembership = TenantMembership.Create(
            tenant.Id,
            user.Id,
            TenantMembershipRole.Administrator,
            TenantMembershipStatus.Active,
            DateTime.UtcNow);

        reinviteDb.TenantMemberships.Add(newMembership);
        // This succeeds without violating the partial index because the original row has status = 'Revoked'
        await reinviteDb.SaveChangesAsync();

        var newId = newMembership.Id;

        // 4. Verify both rows coexist in the database
        using var assertDb = CreateContext();
        var allMemberships = await assertDb.TenantMemberships
            .Where(m => m.TenantId == tenant.Id && m.UserId == user.Id)
            .OrderBy(m => m.CreatedAtUtc)
            .ToListAsync();

        Assert.Equal(2, allMemberships.Count);

        var historicalRevoked = allMemberships[0];
        Assert.Equal(initialId, historicalRevoked.Id);
        Assert.Equal(TenantMembershipStatus.Revoked, historicalRevoked.Status);
        Assert.False(historicalRevoked.IsActive);
        Assert.NotNull(historicalRevoked.DeactivatedAtUtc);

        var currentActive = allMemberships[1];
        Assert.Equal(newId, currentActive.Id);
        Assert.Equal(TenantMembershipStatus.Active, currentActive.Status);
        Assert.Equal(TenantMembershipRole.Administrator, currentActive.Role);
        Assert.True(currentActive.IsActive);
        Assert.Null(currentActive.DeactivatedAtUtc);
    }

    [Fact]
    public async Task TenantMembership_MultipleRevokedMemberships_CanCoexistWithoutConflict()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("multi-revoked");

        // Insert first membership and revoke it
        using (var db = CreateContext())
        {
            var m1 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active);
            m1.Revoke(DateTime.UtcNow.AddDays(-10));
            db.TenantMemberships.Add(m1);
            await db.SaveChangesAsync();
        }

        // Insert second membership and revoke it
        using (var db = CreateContext())
        {
            var m2 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Administrator, TenantMembershipStatus.Active);
            m2.Revoke(DateTime.UtcNow.AddDays(-5));
            db.TenantMemberships.Add(m2);
            await db.SaveChangesAsync();
        }

        // Insert third membership as Active
        using (var db = CreateContext())
        {
            var m3 = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Owner, TenantMembershipStatus.Active);
            db.TenantMemberships.Add(m3);
            await db.SaveChangesAsync();
        }

        // Verify all 3 records exist
        using var assertDb = CreateContext();
        var records = await assertDb.TenantMemberships
            .Where(m => m.TenantId == tenant.Id && m.UserId == user.Id)
            .ToListAsync();

        Assert.Equal(3, records.Count);
        Assert.Equal(2, records.Count(m => m.Status == TenantMembershipStatus.Revoked));
        Assert.Equal(1, records.Count(m => m.Status == TenantMembershipStatus.Active));
    }

    [Fact]
    public async Task TenantMembership_CheckConstraints_EnforceRoleAndStatus()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("ck-constraints");

        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        // 1. Invalid Role
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT INTO platform.tenant_memberships (id, tenant_id, user_id, role, status, created_at_utc, updated_at_utc, version)
                VALUES (@id, @tenant_id, @user_id, 'SuperAdmin', 'Active', NOW(), NOW(), 1);";
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());
            cmd.Parameters.AddWithValue("tenant_id", tenant.Id);
            cmd.Parameters.AddWithValue("user_id", user.Id);

            var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
            Assert.Equal("ck_tenant_memberships_role", ex.ConstraintName);
        }

        // 2. Invalid Status
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT INTO platform.tenant_memberships (id, tenant_id, user_id, role, status, created_at_utc, updated_at_utc, version)
                VALUES (@id, @tenant_id, @user_id, 'Member', 'Banned', NOW(), NOW(), 1);";
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());
            cmd.Parameters.AddWithValue("tenant_id", tenant.Id);
            cmd.Parameters.AddWithValue("user_id", user.Id);

            var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
            Assert.Equal("ck_tenant_memberships_status", ex.ConstraintName);
        }
    }

    [Fact]
    public async Task TenantMembership_OptimisticConcurrency_ThrowsDbUpdateConcurrencyException_OnVersionMismatch()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("concurrency");

        using var setupDb = CreateContext();
        var membership = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member, TenantMembershipStatus.Active);
        setupDb.TenantMemberships.Add(membership);
        await setupDb.SaveChangesAsync();

        var membershipId = membership.Id;

        // Context 1 and Context 2 load the same entity
        using var db1 = CreateContext();
        using var db2 = CreateContext();

        var entity1 = await db1.TenantMemberships.FindAsync(membershipId);
        var entity2 = await db2.TenantMemberships.FindAsync(membershipId);

        Assert.NotNull(entity1);
        Assert.NotNull(entity2);
        Assert.Equal(1, entity1.Version);
        Assert.Equal(1, entity2.Version);

        // Context 1 changes role and saves (version becomes 2)
        entity1.ChangeRole(TenantMembershipRole.Administrator, DateTime.UtcNow);
        await db1.SaveChangesAsync();

        // Context 2 attempts to suspend using stale version 1
        entity2.Suspend(DateTime.UtcNow);

        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => db2.SaveChangesAsync());
    }

    [Fact]
    public async Task MigrationRollback_DowngradesToAuthEntitiesAndReappliesCleanly()
    {
        var (tenant, user) = await CreateTenantAndUserAsync("rollback-test");

        using (var db = CreateContext())
        {
            var membership = TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Member);
            db.TenantMemberships.Add(membership);
            await db.SaveChangesAsync();
        }

        using var context = CreateContext();
        var migrator = context.GetInfrastructure().GetRequiredService<IMigrator>();

        // 1. Rollback migration to 20261114000000_AddAuthPersistenceEntities
        await migrator.MigrateAsync("20261114000000_AddAuthPersistenceEntities");

        // Verify platform.tenant_memberships is dropped, but platform.tenants and platform.users survive
        using (var conn = new NpgsqlConnection(_isolatedConnectionString))
        {
            await conn.OpenAsync();

            using var cmdTables = conn.CreateCommand();
            cmdTables.CommandText = @"
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'platform'
                  AND table_name = 'tenant_memberships';";

            var count = (long)(await cmdTables.ExecuteScalarAsync())!;
            Assert.Equal(0, count);

            // Tenants and Users still exist
            using var cmdTenants = conn.CreateCommand();
            cmdTenants.CommandText = "SELECT COUNT(*) FROM platform.tenants WHERE id = @id;";
            cmdTenants.Parameters.AddWithValue("id", tenant.Id);
            Assert.Equal(1L, (long)(await cmdTenants.ExecuteScalarAsync())!);

            using var cmdUsers = conn.CreateCommand();
            cmdUsers.CommandText = "SELECT COUNT(*) FROM platform.users WHERE id = @id;";
            cmdUsers.Parameters.AddWithValue("id", user.Id);
            Assert.Equal(1L, (long)(await cmdUsers.ExecuteScalarAsync())!);
        }

        // 2. Re-apply migration to latest
        await context.Database.MigrateAsync();

        // Verify platform.tenant_memberships is restored
        using (var conn = new NpgsqlConnection(_isolatedConnectionString))
        {
            await conn.OpenAsync();

            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'platform'
                  AND table_name = 'tenant_memberships';";

            var count = (long)(await cmd.ExecuteScalarAsync())!;
            Assert.Equal(1, count);
        }
    }
}

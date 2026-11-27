namespace MaintenX.IntegrationTests;

using System.Data;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Domain.Authorization;
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
/// Comprehensive PostgreSQL 16 physical database integrity tests for platform.platform_role_grants.
/// Covers schema metadata, check constraints, NULL semantics, whitespace/UUID validation,
/// partial unique index, concurrent duplicate protection, restrictive FK deletion,
/// EF Core lifecycle round-trip, and migration upgrade/rollback safety.
/// </summary>
public class PlatformRoleGrantDatabaseIntegrityTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public PlatformRoleGrantDatabaseIntegrityTests()
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

    private async Task<User> CreateUserAsync(string suffix)
    {
        using var db = CreateContext();
        var user = User.Create($"rbac.{suffix}@maintenx.internal", "hashed_pwd", UserStatus.Active, DateTime.UtcNow);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        return user;
    }

    private async Task<int> ExecuteRawGrantInsertAsync(
        Guid id,
        Guid userId,
        string? role,
        string? status,
        DateTime? grantedAtUtc,
        Guid? grantedByUserId,
        DateTime? revokedAtUtc = null,
        Guid? revokedByUserId = null,
        string? revocationReason = null,
        long? version = 1)
    {
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO platform.platform_role_grants
                (id, user_id, role, status, granted_at_utc, granted_by_user_id, revoked_at_utc, revoked_by_user_id, revocation_reason, version)
            VALUES
                (@id, @user_id, @role, @status, @granted_at_utc, @granted_by_user_id, @revoked_at_utc, @revoked_by_user_id, @revocation_reason, @version);";

        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("user_id", userId);
        cmd.Parameters.AddWithValue("role", (object?)role ?? DBNull.Value);
        cmd.Parameters.AddWithValue("status", (object?)status ?? DBNull.Value);
        cmd.Parameters.AddWithValue("granted_at_utc", (object?)grantedAtUtc ?? DBNull.Value);
        cmd.Parameters.AddWithValue("granted_by_user_id", (object?)grantedByUserId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("revoked_at_utc", (object?)revokedAtUtc ?? DBNull.Value);
        cmd.Parameters.AddWithValue("revoked_by_user_id", (object?)revokedByUserId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("revocation_reason", (object?)revocationReason ?? DBNull.Value);
        cmd.Parameters.AddWithValue("version", (object?)version ?? DBNull.Value);

        return await cmd.ExecuteNonQueryAsync();
    }

    // =========================================================================
    // 1. Physical Schema Metadata Verification (information_schema + pg_catalog)
    // =========================================================================

    [Fact]
    public async Task PhysicalSchema_ColumnsTypesNullabilityAndNoTenantIdOrIsActive()
    {
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT column_name, data_type, is_nullable, character_maximum_length
            FROM information_schema.columns
            WHERE table_schema = 'platform'
              AND table_name = 'platform_role_grants'
            ORDER BY ordinal_position;";

        var columns = new Dictionary<string, (string DataType, string IsNullable, int? MaxLength)>();
        using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            columns[reader.GetString(0)] = (
                reader.GetString(1),
                reader.GetString(2),
                reader.IsDBNull(3) ? null : reader.GetInt32(3));
        }

        Assert.Equal(10, columns.Count);
        Assert.False(columns.ContainsKey("tenant_id"));
        Assert.False(columns.ContainsKey("is_active"));

        Assert.Equal(("uuid", "NO", null), columns["id"]);
        Assert.Equal(("uuid", "NO", null), columns["user_id"]);
        Assert.Equal(("character varying", "NO", 50), columns["role"]);
        Assert.Equal(("character varying", "NO", 50), columns["status"]);
        Assert.Equal(("timestamp with time zone", "NO", null), columns["granted_at_utc"]);
        Assert.Equal(("uuid", "NO", null), columns["granted_by_user_id"]);
        Assert.Equal(("timestamp with time zone", "YES", null), columns["revoked_at_utc"]);
        Assert.Equal(("uuid", "YES", null), columns["revoked_by_user_id"]);
        Assert.Equal(("character varying", "YES", 500), columns["revocation_reason"]);
        Assert.Equal(("bigint", "NO", null), columns["version"]);
    }

    [Fact]
    public async Task PhysicalSchema_ConstraintsAndIndexesMatchSpecification()
    {
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmdConstraints = conn.CreateCommand();
        cmdConstraints.CommandText = @"
            SELECT conname, contype::text, pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conrelid = 'platform.platform_role_grants'::regclass;";

        var constraints = new Dictionary<string, (string Type, string Def)>();
        using (var reader = await cmdConstraints.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                constraints[reader.GetString(0)] = (reader.GetString(1), reader.GetString(2));
            }
        }

        Assert.True(constraints.ContainsKey("pk_platform_role_grants"));
        Assert.Equal("p", constraints["pk_platform_role_grants"].Type);

        Assert.True(constraints.ContainsKey("fk_platform_role_grants_users_user_id"));
        Assert.Equal("f", constraints["fk_platform_role_grants_users_user_id"].Type);
        Assert.Contains("REFERENCES platform.users(id)", constraints["fk_platform_role_grants_users_user_id"].Def);
        Assert.DoesNotContain("ON DELETE CASCADE", constraints["fk_platform_role_grants_users_user_id"].Def);

        var expectedChecks = new[]
        {
            "ck_platform_role_grants_id_non_empty",
            "ck_platform_role_grants_user_id_non_empty",
            "ck_platform_role_grants_granted_by_non_empty",
            "ck_platform_role_grants_role",
            "ck_platform_role_grants_status",
            "ck_platform_role_grants_version_positive",
            "ck_platform_role_grants_revocation_consistency"
        };

        foreach (var ck in expectedChecks)
        {
            Assert.True(constraints.ContainsKey(ck), $"Missing check constraint: {ck}");
            Assert.Equal("c", constraints[ck].Type);
        }

        using var cmdIndexes = conn.CreateCommand();
        cmdIndexes.CommandText = @"
            SELECT indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = 'platform'
              AND tablename = 'platform_role_grants';";

        var indexes = new Dictionary<string, string>();
        using (var reader = await cmdIndexes.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                indexes[reader.GetString(0)] = reader.GetString(1);
            }
        }

        Assert.True(indexes.ContainsKey("ix_platform_role_grants_user_id"));
        Assert.True(indexes.ContainsKey("ix_platform_role_grants_status"));
        Assert.True(indexes.ContainsKey("ix_platform_role_grants_user_id_role_active"));
        Assert.Contains("CREATE UNIQUE INDEX", indexes["ix_platform_role_grants_user_id_role_active"]);
        Assert.Contains("(user_id, role)", indexes["ix_platform_role_grants_user_id_role_active"]);
        Assert.Contains("WHERE ((status)::text = 'Active'::text)", indexes["ix_platform_role_grants_user_id_role_active"]);
    }

    // =========================================================================
    // 2. UUID, Role, Status, Version & NULL Enforcement
    // =========================================================================

    [Fact]
    public async Task CheckConstraints_EmptyUuids_AreRejectedWith23514()
    {
        var user = await CreateUserAsync("empty-uuids");
        var now = DateTime.UtcNow;

        // Empty id (PK)
        var exId = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.Empty, user.Id, "PlatformAdministrator", "Active", now, user.Id));
        Assert.Equal("23514", exId.SqlState);
        Assert.Equal("ck_platform_role_grants_id_non_empty", exId.ConstraintName);

        // Empty user_id
        var exUser = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), Guid.Empty, "PlatformAdministrator", "Active", now, user.Id));
        Assert.Equal("23514", exUser.SqlState);
        Assert.Equal("ck_platform_role_grants_user_id_non_empty", exUser.ConstraintName);

        // Empty granted_by_user_id
        var exGrantedBy = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Active", now, Guid.Empty));
        Assert.Equal("23514", exGrantedBy.SqlState);
        Assert.Equal("ck_platform_role_grants_granted_by_non_empty", exGrantedBy.ConstraintName);

        // Empty revoked_by_user_id on Revoked grant
        var exRevokedBy = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(
                Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id,
                now.AddMinutes(1), Guid.Empty, "Valid revocation reason"));
        Assert.Equal("23514", exRevokedBy.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", exRevokedBy.ConstraintName);
    }

    [Theory]
    [InlineData("TenantOwner", "Active", 1, "ck_platform_role_grants_role")]
    [InlineData("", "Active", 1, "ck_platform_role_grants_role")]
    [InlineData("platformadministrator", "Active", 1, "ck_platform_role_grants_role")]
    [InlineData("PlatformAdministrator", "Suspended", 1, "ck_platform_role_grants_status")]
    [InlineData("PlatformAdministrator", "", 1, "ck_platform_role_grants_status")]
    [InlineData("PlatformAdministrator", "active", 1, "ck_platform_role_grants_status")]
    [InlineData("PlatformAdministrator", "Active", 0, "ck_platform_role_grants_version_positive")]
    [InlineData("PlatformAdministrator", "Active", -1, "ck_platform_role_grants_version_positive")]
    public async Task CheckConstraints_InvalidRoleStatusOrVersion_AreRejectedWith23514(
        string role, string status, long version, string expectedConstraint)
    {
        var user = await CreateUserAsync(Guid.NewGuid().ToString("N")[..8]);
        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, role, status, DateTime.UtcNow, user.Id, version: version));

        Assert.Equal("23514", ex.SqlState);
        if (expectedConstraint == "ck_platform_role_grants_status")
        {
            // PostgreSQL evaluates CHECK constraints alphabetically; both revocation_consistency and status reject invalid status values.
            Assert.Contains(ex.ConstraintName, new[] { "ck_platform_role_grants_status", "ck_platform_role_grants_revocation_consistency" });
        }
        else
        {
            Assert.Equal(expectedConstraint, ex.ConstraintName);
        }
    }

    [Fact]
    public async Task NotNullConstraints_RequiredNullValues_AreRejectedWith23502()
    {
        var user = await CreateUserAsync("null-checks");
        var now = DateTime.UtcNow;

        var exRole = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, null, "Active", now, user.Id));
        Assert.Equal("23502", exRole.SqlState);

        var exStatus = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", null, now, user.Id));
        Assert.Equal("23502", exStatus.SqlState);

        var exGrantedAt = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Active", null, user.Id));
        Assert.Equal("23502", exGrantedAt.SqlState);

        var exGrantedBy = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Active", now, null));
        Assert.Equal("23502", exGrantedBy.SqlState);

        var exVersion = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Active", now, user.Id, version: null));
        Assert.Equal("23502", exVersion.SqlState);
    }

    // =========================================================================
    // 3. Revocation Consistency & Whitespace Boundary Validation
    // =========================================================================

    [Fact]
    public async Task RevocationConsistency_ActiveWithRevocationMetadata_AndRevokedWithMissingOrPrecedingMetadata_RejectedWith23514()
    {
        var user = await CreateUserAsync("revocation-consistency");
        var now = DateTime.UtcNow;

        // Active with revoked_at_utc
        var ex1 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Active", now, user.Id, revokedAtUtc: now));
        Assert.Equal("23514", ex1.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex1.ConstraintName);

        // Active with revoked_by_user_id
        var ex2 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Active", now, user.Id, revokedByUserId: user.Id));
        Assert.Equal("23514", ex2.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex2.ConstraintName);

        // Active with revocation_reason
        var ex3 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Active", now, user.Id, revocationReason: "Unexpected reason"));
        Assert.Equal("23514", ex3.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex3.ConstraintName);

        // Revoked with missing timestamp
        var ex4 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, null, user.Id, "Valid reason"));
        Assert.Equal("23514", ex4.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex4.ConstraintName);

        // Revoked with missing actor
        var ex5 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now, null, "Valid reason"));
        Assert.Equal("23514", ex5.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex5.ConstraintName);

        // Revoked with missing reason
        var ex6 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now, user.Id, null));
        Assert.Equal("23514", ex6.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex6.ConstraintName);

        // Revoked before grant creation
        var ex7 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now.AddSeconds(-1), user.Id, "Valid reason"));
        Assert.Equal("23514", ex7.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex7.ConstraintName);

        // Revoked exactly at grant creation succeeds (matches domain utcNow < GrantedAtUtc rule)
        var rows = await ExecuteRawGrantInsertAsync(
            Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now, user.Id, "Valid reason");
        Assert.Equal(1, rows);
    }

    [Theory]
    [InlineData("", "23514")]
    [InlineData("a", "23514")]
    [InlineData("ab", "23514")]
    [InlineData("   ", "23514")]
    [InlineData("\t\t\t", "23514")]
    [InlineData("\n\n\n", "23514")]
    [InlineData("\r\n\t ", "23514")]
    [InlineData("\u00A0\u00A0\u00A0", "23514")]
    [InlineData("  a  ", "23514")]
    [InlineData("  ab\t", "23514")]
    public async Task RevocationReason_InvalidOrWhitespaceOnly_RejectedWith23514(string reason, string expectedSqlState)
    {
        var user = await CreateUserAsync(Guid.NewGuid().ToString("N")[..8]);
        var now = DateTime.UtcNow;

        var ex = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now, user.Id, reason));

        Assert.Equal(expectedSqlState, ex.SqlState);
        Assert.Equal("ck_platform_role_grants_revocation_consistency", ex.ConstraintName);
    }

    [Fact]
    public async Task RevocationReason_Boundaries_3CharsAnd500CharsSucceed_501CharsRejectedWith22001()
    {
        var user = await CreateUserAsync("reason-bounds");
        var now = DateTime.UtcNow;

        Assert.Equal(1, await ExecuteRawGrantInsertAsync(
            Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now, user.Id, "abc"));

        Assert.Equal(1, await ExecuteRawGrantInsertAsync(
            Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now, user.Id, new string('x', 500)));

        var ex501 = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(
                Guid.NewGuid(), user.Id, "PlatformAdministrator", "Revoked", now, user.Id, now, user.Id, new string('x', 501)));
        Assert.Equal("22001", ex501.SqlState);
    }

    // =========================================================================
    // 4. Partial Unique Index, Concurrency & Historical Retention
    // =========================================================================

    [Fact]
    public async Task PartialUniqueIndex_EnforcesSingleActiveGrantPerUserRole_AllowsMultipleUsersAndRevokedHistory()
    {
        var userA = await CreateUserAsync("uniq-a");
        var userB = await CreateUserAsync("uniq-b");
        var now = DateTime.UtcNow;

        // A. First active grant for User A
        var grantA1 = PlatformRoleGrant.Create(userA.Id, PlatformRole.PlatformAdministrator, userB.Id, now);
        using (var db = CreateContext())
        {
            db.PlatformRoleGrants.Add(grantA1);
            await db.SaveChangesAsync();
        }

        // B. Second active grant for User A, same role -> 23505 on ix_platform_role_grants_user_id_role_active
        var grantA2 = PlatformRoleGrant.Create(userA.Id, PlatformRole.PlatformAdministrator, userB.Id, now.AddSeconds(1));
        using (var dbDup = CreateContext())
        {
            dbDup.PlatformRoleGrants.Add(grantA2);
            var dbEx = await Assert.ThrowsAsync<DbUpdateException>(() => dbDup.SaveChangesAsync());
            var pgEx = Assert.IsType<PostgresException>(dbEx.InnerException);
            Assert.Equal("23505", pgEx.SqlState);
            Assert.Equal("ix_platform_role_grants_user_id_role_active", pgEx.ConstraintName);
        }

        // C. Active grant for User B -> succeeds
        var grantB1 = PlatformRoleGrant.Create(userB.Id, PlatformRole.PlatformAdministrator, userA.Id, now.AddSeconds(2));
        using (var dbB = CreateContext())
        {
            dbB.PlatformRoleGrants.Add(grantB1);
            await dbB.SaveChangesAsync();
        }

        // D & E & F & G. Revoke User A's active grant, create another revoked grant, and re-grant active
        using (var dbRevoke = CreateContext())
        {
            var loaded = await dbRevoke.PlatformRoleGrants.SingleAsync(g => g.Id == grantA1.Id);
            loaded.Revoke(userB.Id, "Temporary suspension for audit", now.AddMinutes(5));
            await dbRevoke.SaveChangesAsync();
        }

        var grantA3Revoked = PlatformRoleGrant.Create(userA.Id, PlatformRole.PlatformAdministrator, userB.Id, now.AddMinutes(6));
        grantA3Revoked.Revoke(userB.Id, "Second historical revoked grant", now.AddMinutes(7));

        var grantA4Active = PlatformRoleGrant.Create(userA.Id, PlatformRole.PlatformAdministrator, userB.Id, now.AddMinutes(8));

        using (var dbRegrant = CreateContext())
        {
            dbRegrant.PlatformRoleGrants.Add(grantA3Revoked);
            dbRegrant.PlatformRoleGrants.Add(grantA4Active);
            await dbRegrant.SaveChangesAsync();
        }

        using (var dbVerify = CreateContext())
        {
            var allUserAGrants = await dbVerify.PlatformRoleGrants
                .AsNoTracking()
                .Where(g => g.UserId == userA.Id)
                .OrderBy(g => g.GrantedAtUtc)
                .ToListAsync();

            Assert.Equal(3, allUserAGrants.Count);
            Assert.Equal(2, allUserAGrants.Count(g => g.Status == PlatformRoleGrantStatus.Revoked));
            Assert.Equal(1, allUserAGrants.Count(g => g.Status == PlatformRoleGrantStatus.Active));
            Assert.Equal(3, allUserAGrants.Select(g => g.Id).Distinct().Count());
            Assert.Equal(grantA4Active.Id, allUserAGrants.Single(g => g.Status == PlatformRoleGrantStatus.Active).Id);
        }
    }

    [Fact]
    public async Task PartialUniqueIndex_ConcurrentActiveInserts_OnlyOneSucceeds()
    {
        var user = await CreateUserAsync("concurrent-uniq");
        var actor = await CreateUserAsync("concurrent-actor");
        var now = DateTime.UtcNow;

        using var db1 = CreateContext();
        using var db2 = CreateContext();

        db1.PlatformRoleGrants.Add(PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, actor.Id, now));
        db2.PlatformRoleGrants.Add(PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, actor.Id, now));

        var tasks = new[]
        {
            db1.SaveChangesAsync(),
            db2.SaveChangesAsync()
        };

        var completed = await Task.WhenAll(tasks.Select(async t =>
        {
            try
            {
                await t;
                return (Success: true, Ex: (DbUpdateException?)null);
            }
            catch (DbUpdateException ex)
            {
                return (Success: false, Ex: ex);
            }
        }));

        Assert.Equal(1, completed.Count(r => r.Success));
        var failure = completed.Single(r => !r.Success);
        var pgEx = Assert.IsType<PostgresException>(failure.Ex!.InnerException);
        Assert.Equal("23505", pgEx.SqlState);
        Assert.Equal("ix_platform_role_grants_user_id_role_active", pgEx.ConstraintName);
    }

    // =========================================================================
    // 5. Foreign Key & Restrictive Deletion Protection
    // =========================================================================

    [Fact]
    public async Task ForeignKey_NonexistentUserRejected_AndHardDeletingUserWithActiveOrRevokedGrantBlockedWith23503()
    {
        var admin = await CreateUserAsync("fk-admin");
        var targetActive = await CreateUserAsync("fk-active");
        var targetRevoked = await CreateUserAsync("fk-revoked");
        var now = DateTime.UtcNow;

        // Nonexistent target user rejected with 23503
        var exMissing = await Assert.ThrowsAsync<PostgresException>(() =>
            ExecuteRawGrantInsertAsync(Guid.NewGuid(), Guid.NewGuid(), "PlatformAdministrator", "Active", now, admin.Id));
        Assert.Equal("23503", exMissing.SqlState);
        Assert.Equal("fk_platform_role_grants_users_user_id", exMissing.ConstraintName);

        using (var db = CreateContext())
        {
            var gActive = PlatformRoleGrant.Create(targetActive.Id, PlatformRole.PlatformAdministrator, admin.Id, now);
            var gRevoked = PlatformRoleGrant.Create(targetRevoked.Id, PlatformRole.PlatformAdministrator, admin.Id, now);
            gRevoked.Revoke(admin.Id, "Revoked before user delete check", now.AddMinutes(1));
            db.PlatformRoleGrants.AddRange(gActive, gRevoked);
            await db.SaveChangesAsync();
        }

        // Hard delete user with Active grant -> 23503
        using (var dbDelActive = CreateContext())
        {
            var userEntity = await dbDelActive.Users.SingleAsync(u => u.Id == targetActive.Id);
            dbDelActive.Users.Remove(userEntity);
            var ex = await Assert.ThrowsAsync<DbUpdateException>(() => dbDelActive.SaveChangesAsync());
            var pgEx = Assert.IsType<PostgresException>(ex.InnerException);
            Assert.Equal("23503", pgEx.SqlState);
            Assert.Equal("fk_platform_role_grants_users_user_id", pgEx.ConstraintName);
        }

        // Hard delete user with historical Revoked grant -> 23503
        using (var dbDelRevoked = CreateContext())
        {
            var userEntity = await dbDelRevoked.Users.SingleAsync(u => u.Id == targetRevoked.Id);
            dbDelRevoked.Users.Remove(userEntity);
            var ex = await Assert.ThrowsAsync<DbUpdateException>(() => dbDelRevoked.SaveChangesAsync());
            var pgEx = Assert.IsType<PostgresException>(ex.InnerException);
            Assert.Equal("23503", pgEx.SqlState);
            Assert.Equal("fk_platform_role_grants_users_user_id", pgEx.ConstraintName);
        }

        // Rejected deletions preserve all grant records
        using (var dbVerify = CreateContext())
        {
            Assert.Equal(2, await dbVerify.PlatformRoleGrants.CountAsync());
        }
    }

    // =========================================================================
    // 6. EF Core Lifecycle Round-Trip & Optimistic Concurrency
    // =========================================================================

    [Fact]
    public async Task EfCoreRoundTrip_CreateRevokeIdempotentAndOptimisticConcurrency()
    {
        var user = await CreateUserAsync("roundtrip");
        var actor = await CreateUserAsync("roundtrip-actor");
        var now = new DateTime(2026, 11, 27, 12, 0, 0, DateTimeKind.Utc);

        var grant = PlatformRoleGrant.Create(user.Id, PlatformRole.PlatformAdministrator, actor.Id, now);
        Assert.Equal(1, grant.Version);

        using (var db1 = CreateContext())
        {
            db1.PlatformRoleGrants.Add(grant);
            await db1.SaveChangesAsync();
        }

        using (var db2 = CreateContext())
        using (var dbStale = CreateContext())
        {
            var loaded = await db2.PlatformRoleGrants.SingleAsync(g => g.Id == grant.Id);
            var staleCopy = await dbStale.PlatformRoleGrants.SingleAsync(g => g.Id == grant.Id);

            Assert.Equal(1, loaded.Version);
            Assert.Equal(PlatformRoleGrantStatus.Active, loaded.Status);

            var revokeTime = now.AddMinutes(10);
            loaded.Revoke(actor.Id, "  Role rotation completed  ", revokeTime);
            Assert.Equal(2, loaded.Version);
            Assert.Equal("Role rotation completed", loaded.RevocationReason);

            // Repeated idempotent revocation preserves original metadata and Version
            loaded.Revoke(Guid.NewGuid(), "Different reason ignored", revokeTime.AddMinutes(5));
            Assert.Equal(2, loaded.Version);
            Assert.Equal("Role rotation completed", loaded.RevocationReason);
            Assert.Equal(revokeTime, loaded.RevokedAtUtc);
            Assert.Equal(actor.Id, loaded.RevokedByUserId);

            await db2.SaveChangesAsync();

            // Stale concurrency token fails
            staleCopy.Revoke(actor.Id, "Stale revocation attempt", revokeTime.AddMinutes(1));
            await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => dbStale.SaveChangesAsync());
        }
    }

    // =========================================================================
    // 7. Migration Upgrade Safety With Existing Data (Isolated Disposable DB)
    // =========================================================================

    [Fact]
    public async Task MigrationUpgrade_FromPreviousMigrationWithExistingRecords_PreservesDataAndAddsTable()
    {
        var (upgradeDb, upgradeConnStr) = await TestDatabaseGuard.ProvisionAndInitializeAsync(
            _adminConnectionString,
            _testConnectionString,
            _configuration,
            async (conn) =>
            {
                var options = new DbContextOptionsBuilder<MaintenXDbContext>()
                    .UseNpgsql(conn)
                    .Options;

                using var ctx = new MaintenXDbContext(options);
                var migrator = ctx.GetInfrastructure().GetRequiredService<IMigrator>();
                await migrator.MigrateAsync("20261124000000_AddTenantAuditPersistence");
            });

        try
        {
            Guid tenantId;
            Guid userId;

            var options = new DbContextOptionsBuilder<MaintenXDbContext>()
                .UseNpgsql(upgradeConnStr)
                .Options;

            using (var seedCtx = new MaintenXDbContext(options))
            {
                seedCtx.CreatePrivilegedTenantBypassScope("upgrade-seed");
                var now = DateTime.UtcNow;
                var tenant = Tenant.Create("upgrade-tenant", "Upgrade Tenant", TenantStatus.Active);
                var user = User.Create("upgrade.user@maintenx.internal", "hash", UserStatus.Active, now);
                seedCtx.Tenants.Add(tenant);
                seedCtx.Users.Add(user);
                seedCtx.TenantMemberships.Add(TenantMembership.Create(tenant.Id, user.Id, TenantMembershipRole.Owner));
                await seedCtx.SaveChangesAsync();
                tenantId = tenant.Id;
                userId = user.Id;
            }

            using (var upgradeCtx = new MaintenXDbContext(options))
            {
                await upgradeCtx.Database.MigrateAsync();
                Assert.False(upgradeCtx.Database.HasPendingModelChanges());

                upgradeCtx.CreatePrivilegedTenantBypassScope("upgrade-verify");
                Assert.NotNull(await upgradeCtx.Tenants.SingleOrDefaultAsync(t => t.Id == tenantId));
                Assert.NotNull(await upgradeCtx.Users.SingleOrDefaultAsync(u => u.Id == userId));
                Assert.Equal(1, await upgradeCtx.TenantMemberships.CountAsync(m => m.TenantId == tenantId && m.UserId == userId));
                Assert.Equal(0, await upgradeCtx.PlatformRoleGrants.CountAsync());
            }
        }
        finally
        {
            await TestDatabaseGuard.DropDatabaseSafelyAsync(upgradeDb, _adminConnectionString);
        }
    }
}

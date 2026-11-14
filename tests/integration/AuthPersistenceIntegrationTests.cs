namespace MaintenX.IntegrationTests;

using System.Data;
using MaintenX.Api.Domain.Auth;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

/// <summary>
/// Comprehensive integration tests for authentication persistence entities on PostgreSQL 16.
/// Verifies schema mappings, foreign key cascades, unique indexes, database check constraints,
/// JSONB metadata round-tripping, audit durability, and migration application/rollback.
/// </summary>
public class AuthPersistenceIntegrationTests : IAsyncLifetime
{
    private readonly IConfiguration _configuration;
    private readonly string _adminConnectionString;
    private readonly string _testConnectionString;
    private string _databaseName = string.Empty;
    private string _isolatedConnectionString = string.Empty;

    public AuthPersistenceIntegrationTests()
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

    [Fact]
    public async Task Migration_CreatesAllFourAuthTablesInPlatformSchema()
    {
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'platform'
              AND table_name IN ('users', 'user_sessions', 'refresh_tokens', 'security_audit_events')
            ORDER BY table_name;";

        var tables = new List<string>();
        using (var reader = await cmd.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                tables.Add(reader.GetString(0));
            }
        }

        Assert.Equal(4, tables.Count);
        Assert.Contains("users", tables);
        Assert.Contains("user_sessions", tables);
        Assert.Contains("refresh_tokens", tables);
        Assert.Contains("security_audit_events", tables);
    }

    [Fact]
    public async Task User_EmailUniqueIndex_PreventsDuplicateEmailInsertion()
    {
        using var db1 = CreateContext();
        var now = DateTime.UtcNow;

        var user1 = User.Create("auth.test.unique@maintenx.internal", "hashed_pwd_1", UserStatus.Active, now);
        db1.Users.Add(user1);
        await db1.SaveChangesAsync();

        using var db2 = CreateContext();
        var user2 = User.Create("auth.test.unique@maintenx.internal", "hashed_pwd_2", UserStatus.Active, now);
        db2.Users.Add(user2);

        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db2.SaveChangesAsync());
        var postgresEx = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.UniqueViolation, postgresEx.SqlState);
    }

    [Fact]
    public async Task User_EmailLowercaseCheckConstraint_RejectsUppercaseDirectInsertion()
    {
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO platform.users (id, email, password_hash, security_stamp, status, failed_login_attempts, created_at_utc, updated_at_utc, version)
            VALUES (@id, @email, 'pwd_hash', 'stamp', 'Active', 0, NOW(), NOW(), 1);";
        cmd.Parameters.AddWithValue("id", Guid.NewGuid());
        cmd.Parameters.AddWithValue("email", "UPPERCASE@MAINTENX.INTERNAL");

        var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
        Assert.Equal("ck_users_email_lowercase", ex.ConstraintName);
    }

    [Fact]
    public async Task User_CheckConstraints_EnforceStatusAndNonnegativeFailedAttempts()
    {
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        // 1. Invalid status
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT INTO platform.users (id, email, password_hash, security_stamp, status, failed_login_attempts, created_at_utc, updated_at_utc, version)
                VALUES (@id, 'invalid.status@maintenx.internal', 'pwd_hash', 'stamp', 'InvalidStatus', 0, NOW(), NOW(), 1);";
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());

            var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
            Assert.Equal("ck_users_status", ex.ConstraintName);
        }

        // 2. Negative failed attempts
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT INTO platform.users (id, email, password_hash, security_stamp, status, failed_login_attempts, created_at_utc, updated_at_utc, version)
                VALUES (@id, 'negative.attempts@maintenx.internal', 'pwd_hash', 'stamp', 'Active', -1, NOW(), NOW(), 1);";
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());

            var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
            Assert.Equal("ck_users_failed_login_attempts", ex.ConstraintName);
        }
    }

    [Fact]
    public async Task UserSession_CheckConstraint_RejectsUnapprovedRevocationReason()
    {
        using var db = CreateContext();
        var now = DateTime.UtcNow;
        var user = User.Create("session.check@maintenx.internal", "pwd_hash", UserStatus.Active, now);
        db.Users.Add(user);
        await db.SaveChangesAsync();

        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO platform.user_sessions (id, user_id, created_at_utc, last_used_at_utc, expires_at_utc, revoked_at_utc, revocation_reason, version)
            VALUES (@id, @userId, NOW(), NOW(), NOW() + INTERVAL '1 hour', NOW(), 'UnapprovedReasonArbitrary', 1);";
        cmd.Parameters.AddWithValue("id", Guid.NewGuid());
        cmd.Parameters.AddWithValue("userId", user.Id);

        var ex = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
        Assert.Equal("ck_user_sessions_revocation_reason", ex.ConstraintName);
    }

    [Fact]
    public async Task RefreshToken_UniqueIndexAndCheckConstraints_EnforceTokenHashRules()
    {
        using var db = CreateContext();
        var now = DateTime.UtcNow;
        var user = User.Create("token.rules@maintenx.internal", "pwd_hash", UserStatus.Active, now);
        db.Users.Add(user);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(8));
        db.UserSessions.Add(session);
        await db.SaveChangesAsync();

        var validHash = new string('a', 64);
        var token1 = RefreshToken.Create(session, validHash, now, TimeSpan.FromHours(1));
        db.RefreshTokens.Add(token1);
        await db.SaveChangesAsync();

        // 1. Duplicate token hash violates unique index
        using var db2 = CreateContext();
        var token2 = RefreshToken.Create(session, validHash, now, TimeSpan.FromHours(1));
        db2.RefreshTokens.Add(token2);
        var ex = await Assert.ThrowsAsync<DbUpdateException>(() => db2.SaveChangesAsync());
        var pgEx = Assert.IsType<PostgresException>(ex.InnerException);
        Assert.Equal(PostgresErrorCodes.UniqueViolation, pgEx.SqlState);

        // 2. Direct SQL insertion with non-hex token hash violates check constraint
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO platform.refresh_tokens (id, session_id, token_hash, created_at_utc, expires_at_utc)
            VALUES (@id, @sessionId, 'not_a_valid_64_hex_hash_string', NOW(), NOW() + INTERVAL '1 hour');";
        cmd.Parameters.AddWithValue("id", Guid.NewGuid());
        cmd.Parameters.AddWithValue("sessionId", session.Id);

        var checkEx = await Assert.ThrowsAsync<PostgresException>(() => cmd.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, checkEx.SqlState);
    }

    [Fact]
    public async Task ForeignKeyCascade_UserDeletion_CascadesToSessionsAndRefreshTokens()
    {
        using var db = CreateContext();
        var now = DateTime.UtcNow;

        var user = User.Create("cascade.test@maintenx.internal", "pwd_hash", UserStatus.Active, now);
        db.Users.Add(user);

        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(8));
        db.UserSessions.Add(session);

        var tokenHash = new string('b', 64);
        var token = RefreshToken.Create(session, tokenHash, now, TimeSpan.FromHours(1));
        db.RefreshTokens.Add(token);

        await db.SaveChangesAsync();

        var sessionId = session.Id;
        var tokenId = token.Id;
        var userId = user.Id;

        // Verify entities exist
        using var verifyDb = CreateContext();
        Assert.NotNull(await verifyDb.Users.FindAsync(userId));
        Assert.NotNull(await verifyDb.UserSessions.FindAsync(sessionId));
        Assert.NotNull(await verifyDb.RefreshTokens.FindAsync(tokenId));

        // Delete user
        verifyDb.Users.Remove((await verifyDb.Users.FindAsync(userId))!);
        await verifyDb.SaveChangesAsync();

        // Verify cascade deletion
        using var assertDb = CreateContext();
        Assert.Null(await assertDb.Users.FindAsync(userId));
        Assert.Null(await assertDb.UserSessions.FindAsync(sessionId));
        Assert.Null(await assertDb.RefreshTokens.FindAsync(tokenId));
    }

    [Fact]
    public async Task SecurityAuditEvent_SurvivesUserAndSessionDeletion_ZeroForeignKeys()
    {
        using var db = CreateContext();
        var now = DateTime.UtcNow;

        var user = User.Create("audit.survive@maintenx.internal", "pwd_hash", UserStatus.Active, now);
        db.Users.Add(user);
        var session = UserSession.Create(user.Id, now, TimeSpan.FromHours(8));
        db.UserSessions.Add(session);

        var meta = SecurityAuditMetadata.Create(
            SecurityAuditMetadata.Reasons.StandardLogin,
            SecurityAuditMetadata.Lineages.RootSession,
            SecurityAuditMetadata.Actions.SessionCreated);

        var auditEvent = SecurityAuditEvent.Create(
            SecurityAuditEventType.LoginSuccess,
            now,
            user.Id,
            session.Id,
            "192.168.1.100",
            meta);

        db.SecurityAuditEvents.Add(auditEvent);
        await db.SaveChangesAsync();

        var auditId = auditEvent.Id;
        var userId = user.Id;
        var sessionId = session.Id;

        // Delete the user (which cascades to session)
        using var deleteDb = CreateContext();
        var userToDelete = await deleteDb.Users.FindAsync(userId);
        deleteDb.Users.Remove(userToDelete!);
        await deleteDb.SaveChangesAsync();

        // Verify user and session are gone, but audit event STILL EXISTS
        using var assertDb = CreateContext();
        Assert.Null(await assertDb.Users.FindAsync(userId));
        Assert.Null(await assertDb.UserSessions.FindAsync(sessionId));

        var survivingEvent = await assertDb.SecurityAuditEvents.FindAsync(auditId);
        Assert.NotNull(survivingEvent);
        Assert.Equal(userId, survivingEvent.UserId);
        Assert.Equal(sessionId, survivingEvent.SessionId);
        Assert.Equal("192.168.1.100", survivingEvent.ClientIp);
        Assert.NotNull(survivingEvent.Metadata);
        Assert.Equal(SecurityAuditMetadata.Reasons.StandardLogin, survivingEvent.Metadata.Reason);
    }

    [Fact]
    public async Task SecurityAuditMetadata_JsonbRoundTrip_PersistsAndMaterializesCorrectly()
    {
        using var db = CreateContext();
        var now = DateTime.UtcNow;

        var meta = SecurityAuditMetadata.Create(
            SecurityAuditMetadata.Reasons.TokenReplay,
            SecurityAuditMetadata.Lineages.ReplayDetected,
            SecurityAuditMetadata.Actions.SessionRevoked);

        var auditEvent = SecurityAuditEvent.Create(
            SecurityAuditEventType.TokenReplayDetected,
            now,
            clientIp: "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            metadata: meta);

        var nullMetaEvent = SecurityAuditEvent.Create(
            SecurityAuditEventType.UserRegistered,
            now,
            clientIp: "10.0.0.1",
            metadata: null);

        db.SecurityAuditEvents.AddRange(auditEvent, nullMetaEvent);
        await db.SaveChangesAsync();

        // Reload via fresh context
        using var queryDb = CreateContext();
        var loadedMetaEvent = await queryDb.SecurityAuditEvents.FindAsync(auditEvent.Id);
        Assert.NotNull(loadedMetaEvent);
        Assert.NotNull(loadedMetaEvent.Metadata);
        Assert.Equal(SecurityAuditMetadata.Reasons.TokenReplay, loadedMetaEvent.Metadata.Reason);
        Assert.Equal(SecurityAuditMetadata.Lineages.ReplayDetected, loadedMetaEvent.Metadata.DetectedLineage);
        Assert.Equal(SecurityAuditMetadata.Actions.SessionRevoked, loadedMetaEvent.Metadata.ActionTaken);

        var loadedNullEvent = await queryDb.SecurityAuditEvents.FindAsync(nullMetaEvent.Id);
        Assert.NotNull(loadedNullEvent);
        Assert.Null(loadedNullEvent.Metadata);

        // Verify directly in PostgreSQL that details_json is genuine jsonb
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            SELECT details_json->>'reason', details_json->>'detectedLineage', details_json->>'actionTaken'
            FROM platform.security_audit_events
            WHERE id = @id;";
        cmd.Parameters.AddWithValue("id", auditEvent.Id);

        using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(SecurityAuditMetadata.Reasons.TokenReplay, reader.GetString(0));
        Assert.Equal(SecurityAuditMetadata.Lineages.ReplayDetected, reader.GetString(1));
        Assert.Equal(SecurityAuditMetadata.Actions.SessionRevoked, reader.GetString(2));
    }

    [Fact]
    public async Task UserSession_LastUsedAtUtcAndRecordActivity_UpdatesPersistenceAccurately()
    {
        using var db = CreateContext();
        var created = DateTime.UtcNow;
        var user = User.Create("activity.test@maintenX.internal", "pwd_hash", UserStatus.Active, created);
        db.Users.Add(user);
        var session = UserSession.Create(user.Id, created, TimeSpan.FromHours(8));
        db.UserSessions.Add(session);
        await db.SaveChangesAsync();

        Assert.Equal(created, session.CreatedAtUtc);
        Assert.Equal(created, session.LastUsedAtUtc);
        Assert.Equal(1, session.Version);

        // Record activity
        using var activityDb = CreateContext();
        var loadedSession = await activityDb.UserSessions.FindAsync(session.Id);
        Assert.NotNull(loadedSession);

        var activityTime = created.AddMinutes(15);
        loadedSession.RecordActivity(activityTime);
        await activityDb.SaveChangesAsync();

        // Reload and verify
        using var assertDb = CreateContext();
        var reloaded = await assertDb.UserSessions.FindAsync(session.Id);
        Assert.NotNull(reloaded);
        Assert.True((reloaded.CreatedAtUtc - created).Duration() < TimeSpan.FromMilliseconds(1));
        Assert.True((reloaded.LastUsedAtUtc - activityTime).Duration() < TimeSpan.FromMilliseconds(1));
        Assert.Equal(2, reloaded.Version);
    }

    [Fact]
    public async Task MigrationRollback_DowngradesAndReappliesCleanly()
    {
        using var context = CreateContext();
        var migrator = context.GetInfrastructure().GetRequiredService<IMigrator>();

        // 1. Rollback migration to 20261113000001_HardenTenantSlugConstraints
        await migrator.MigrateAsync("20261113000001_HardenTenantSlugConstraints");

        // Verify the 4 auth tables are gone
        using var conn = new NpgsqlConnection(_isolatedConnectionString);
        await conn.OpenAsync();

        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'platform'
                  AND table_name IN ('users', 'user_sessions', 'refresh_tokens', 'security_audit_events');";

            var count = (long)(await cmd.ExecuteScalarAsync())!;
            Assert.Equal(0, count);
        }

        // 2. Re-apply AddAuthPersistenceEntities
        await migrator.MigrateAsync("20261114000000_AddAuthPersistenceEntities");

        // Verify the 4 auth tables are back
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'platform'
                  AND table_name IN ('users', 'user_sessions', 'refresh_tokens', 'security_audit_events');";

            var count = (long)(await cmd.ExecuteScalarAsync())!;
            Assert.Equal(4, count);
        }
    }
}

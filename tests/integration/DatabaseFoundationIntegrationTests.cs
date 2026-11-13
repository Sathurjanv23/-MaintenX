namespace MaintenX.IntegrationTests;

using System.Data;
using MaintenX.Api.Domain.Tenants;
using MaintenX.Api.Infrastructure.Persistence;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

/// <summary>
/// Integration test suite for MaintenX PostgreSQL Database Foundation (FEAT-001).
/// Verifies schema creation, EF Core migrations, entity persistence, constraints,
/// indexes, optimistic concurrency, and credential security against real PostgreSQL.
/// </summary>
public class DatabaseFoundationIntegrationTests : IClassFixture<WebApplicationFactory<Program>>, IAsyncLifetime
{
    private readonly WebApplicationFactory<Program> _factory;

    public DatabaseFoundationIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    public async Task InitializeAsync()
    {
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
        // Ensure migrations are applied prior to running test suite
        await dbContext.Database.MigrateAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task DB001_DbContext_ResolvesFromDependencyInjection()
    {
        // Arrange & Act
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetService<MaintenXDbContext>();

        // Assert
        Assert.NotNull(dbContext);
        var canConnect = await dbContext.Database.CanConnectAsync();
        Assert.True(canConnect, "DbContext must successfully connect to the PostgreSQL instance.");
    }

    [Fact]
    public async Task DB002_InitialMigration_AppliesSuccessfully()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        // Act
        var appliedMigrations = (await dbContext.Database.GetAppliedMigrationsAsync()).ToList();

        // Assert
        Assert.NotEmpty(appliedMigrations);
        Assert.Contains("20261113000000_InitialDatabaseFoundation", appliedMigrations);
    }

    [Fact]
    public async Task DB003_Tenant_CanBePersistedAndRetrieved()
    {
        // Arrange
        using var scope1 = _factory.Services.CreateScope();
        var context1 = scope1.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var slug = "facility-corp-" + Guid.NewGuid().ToString("N")[..8];
        var tenant = Tenant.Create(slug, "Facility Management Corp", TenantStatus.Active);

        // Act
        context1.Tenants.Add(tenant);
        var rowsSaved = await context1.SaveChangesAsync();
        Assert.Equal(1, rowsSaved);

        // Retrieve in separate scope to ensure true persistence
        using var scope2 = _factory.Services.CreateScope();
        var context2 = scope2.ServiceProvider.GetRequiredService<MaintenXDbContext>();
        var retrieved = await context2.Tenants.FirstOrDefaultAsync(t => t.Id == tenant.Id);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(slug, retrieved.Slug);
        Assert.Equal("Facility Management Corp", retrieved.DisplayName);
        Assert.Equal(TenantStatus.Active, retrieved.Status);
        Assert.Equal(1, retrieved.Version);
    }

    [Fact]
    public async Task DB004_DuplicateNormalizedSlug_IsRejected()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var slug = "dup-test-" + Guid.NewGuid().ToString("N")[..8];
        var tenant1 = Tenant.Create(slug, "First Tenant");
        var tenant2 = Tenant.Create(slug.ToUpperInvariant(), "Second Tenant With Same Normalized Slug");

        dbContext.Tenants.Add(tenant1);
        await dbContext.SaveChangesAsync();

        // Act & Assert
        dbContext.Tenants.Add(tenant2);
        await Assert.ThrowsAsync<DbUpdateException>(async () =>
        {
            await dbContext.SaveChangesAsync();
        });
    }

    [Fact]
    public async Task DB005_RequiredDatabaseConstraints_AreEnforced()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var invalidStatusSql = @"
            INSERT INTO platform.tenants (id, slug, display_name, status, created_at_utc, updated_at_utc, version)
            VALUES ({0}, {1}, {2}, {3}, {4}, {5}, {6});";

        var id = Guid.NewGuid();
        var slug = "invalid-status-" + id.ToString("N")[..8];
        var now = DateTime.UtcNow;

        // Act & Assert: Inserting an unconstrained status value must violate ck_tenants_status
        await Assert.ThrowsAsync<PostgresException>(async () =>
        {
            await dbContext.Database.ExecuteSqlRawAsync(
                invalidStatusSql,
                id,
                slug,
                "Invalid Status Org",
                "NonExistentStatus",
                now,
                now,
                1L);
        });
    }

    [Fact]
    public async Task DB006_UuidKeys_PersistCorrectly()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var customId = Guid.NewGuid();
        var slug = "uuid-test-" + customId.ToString("N")[..8];
        var tenant = Tenant.Create(slug, "UUID Org");
        tenant.Id = customId;

        // Act
        dbContext.Tenants.Add(tenant);
        await dbContext.SaveChangesAsync();

        var persisted = await dbContext.Tenants.AsNoTracking().FirstOrDefaultAsync(t => t.Id == customId);

        // Assert
        Assert.NotNull(persisted);
        Assert.Equal(customId, persisted.Id);
    }

    [Fact]
    public async Task DB007_UtcTimestamps_RoundTripCorrectly()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        var slug = "timestamp-test-" + Guid.NewGuid().ToString("N")[..8];
        var tenant = Tenant.Create(slug, "Timestamp Org");
        var originalCreated = tenant.CreatedAtUtc;

        // Act
        dbContext.Tenants.Add(tenant);
        await dbContext.SaveChangesAsync();

        var retrieved = await dbContext.Tenants.AsNoTracking().FirstAsync(t => t.Id == tenant.Id);

        // Assert
        Assert.Equal(DateTimeKind.Utc, retrieved.CreatedAtUtc.Kind);
        Assert.Equal(DateTimeKind.Utc, retrieved.UpdatedAtUtc.Kind);
        Assert.True((retrieved.CreatedAtUtc - originalCreated).Duration() < TimeSpan.FromMilliseconds(50));
    }

    [Fact]
    public async Task DB008_OptimisticConcurrencyConflict_IsDetected()
    {
        // Arrange: Create and persist initial tenant
        var slug = "concurrency-" + Guid.NewGuid().ToString("N")[..8];
        var tenant = Tenant.Create(slug, "Original Name");

        using (var setupScope = _factory.Services.CreateScope())
        {
            var setupContext = setupScope.ServiceProvider.GetRequiredService<MaintenXDbContext>();
            setupContext.Tenants.Add(tenant);
            await setupContext.SaveChangesAsync();
        }

        // Simulate two concurrent actors loading the same entity
        using var scope1 = _factory.Services.CreateScope();
        var context1 = scope1.ServiceProvider.GetRequiredService<MaintenXDbContext>();
        var actor1Tenant = await context1.Tenants.FirstAsync(t => t.Id == tenant.Id);

        using var scope2 = _factory.Services.CreateScope();
        var context2 = scope2.ServiceProvider.GetRequiredService<MaintenXDbContext>();
        var actor2Tenant = await context2.Tenants.FirstAsync(t => t.Id == tenant.Id);

        // Act: Actor 1 updates and saves successfully (Version increments from 1 -> 2)
        actor1Tenant.DisplayName = "Updated By Actor 1";
        await context1.SaveChangesAsync();

        // Actor 2 tries to update with stale Version token (holds Version 1)
        actor2Tenant.DisplayName = "Updated By Actor 2";

        // Assert: EF Core must detect concurrency token mismatch and throw DbUpdateConcurrencyException
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(async () =>
        {
            await context2.SaveChangesAsync();
        });
    }

    [Fact]
    public async Task DB009_MigrationHistory_IsPresent()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        // Act: Query the platform.__EFMigrationsHistory table directly
        var connection = dbContext.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync();
        }

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT \"MigrationId\" FROM platform.\"__EFMigrationsHistory\";";
        using var reader = await cmd.ExecuteReaderAsync();

        var historyList = new List<string>();
        while (await reader.ReadAsync())
        {
            historyList.Add(reader.GetString(0));
        }

        // Assert
        Assert.NotEmpty(historyList);
        Assert.Contains("20261113000000_InitialDatabaseFoundation", historyList);
    }

    [Fact]
    public async Task DB010_ApplyingMigrationsAgain_IsSafe()
    {
        // Arrange
        using var scope = _factory.Services.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<MaintenXDbContext>();

        // Act: Execute migration a second time to verify idempotency
        var exception = await Record.ExceptionAsync(async () =>
        {
            await dbContext.Database.MigrateAsync();
        });

        // Assert
        Assert.Null(exception);
    }

    [Fact]
    public async Task DB011_NewDatabase_CanBeInitializedUsingCommittedMigrations()
    {
        // Arrange: Generate a unique disposable database name
        var disposableDbName = "maintenx_disp_" + Guid.NewGuid().ToString("N")[..8];
        var config = _factory.Services.GetRequiredService<IConfiguration>();
        var defaultConnection = config.GetConnectionString("DefaultConnection")
            ?? "Host=localhost;Port=5432;Database=maintenx_dev;Username=maintenx_app;Password=maintenx_dev_password_change_in_prod;";

        var builder = new NpgsqlConnectionStringBuilder(defaultConnection);
        var originalDb = builder.Database;

        // Connect to maintenance database to create the disposable test database
        builder.Database = "postgres";
        using (var adminConn = new NpgsqlConnection(builder.ConnectionString))
        {
            await adminConn.OpenAsync();
            using var createCmd = adminConn.CreateCommand();
            createCmd.CommandText = $"CREATE DATABASE {disposableDbName};";
            await createCmd.ExecuteNonQueryAsync();
        }

        try
        {
            // Act: Build DbContext targeting the clean disposable database
            builder.Database = disposableDbName;
            var optionsBuilder = new DbContextOptionsBuilder<MaintenXDbContext>();
            optionsBuilder.UseNpgsql(builder.ConnectionString, npgsql =>
            {
                npgsql.MigrationsHistoryTable("__EFMigrationsHistory", MaintenXDbContext.DefaultSchema);
            });

            using (var freshContext = new MaintenXDbContext(optionsBuilder.Options))
            {
                // Apply migrations from scratch
                await freshContext.Database.MigrateAsync();

                // Verify applied migrations
                var applied = await freshContext.Database.GetAppliedMigrationsAsync();
                Assert.Contains("20261113000000_InitialDatabaseFoundation", applied);

                // Verify table exists and can persist data
                var testTenant = Tenant.Create("fresh-tenant-" + Guid.NewGuid().ToString("N")[..8], "Fresh Tenant Org");
                freshContext.Tenants.Add(testTenant);
                await freshContext.SaveChangesAsync();

                var retrieved = await freshContext.Tenants.FirstOrDefaultAsync(t => t.Id == testTenant.Id);
                Assert.NotNull(retrieved);
            }
        }
        finally
        {
            // Cleanup: Drop the disposable database
            builder.Database = "postgres";
            using var dropConn = new NpgsqlConnection(builder.ConnectionString);
            await dropConn.OpenAsync();
            using var dropCmd = dropConn.CreateCommand();
            dropCmd.CommandText = $"DROP DATABASE IF EXISTS {disposableDbName} WITH (FORCE);";
            await dropCmd.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task DB012_PersistenceFailures_DoNotExposeConnectionStringsOrCredentials()
    {
        // Arrange: Point to an invalid host with sensitive fake credentials
        var secretPassword = "super_secret_db_password_never_expose!";
        var invalidConnection = $"Host=127.0.0.1;Port=59999;Database=fake_db;Username=fake_user;Password={secretPassword};Timeout=1;";

        var optionsBuilder = new DbContextOptionsBuilder<MaintenXDbContext>();
        optionsBuilder.UseNpgsql(invalidConnection);

        using var brokenContext = new MaintenXDbContext(optionsBuilder.Options);

        // Act & Assert
        var ex = await Assert.ThrowsAnyAsync<Exception>(async () =>
        {
            await brokenContext.Tenants.FirstOrDefaultAsync();
        });

        // Verify public exception message does not leak the password
        Assert.NotNull(ex.Message);
        Assert.DoesNotContain(secretPassword, ex.Message);
    }
}
